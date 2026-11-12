import json, logging, sys, time, uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from .config_store import get_config
from .core.config import get_settings
from .db import close_db, db, ensure_indexes, init_db
from .seed import seed


class JsonFormatter(logging.Formatter):
    def format(self, r):
        d = {"ts": self.formatTime(r), "level": r.levelname, "logger": r.name, "msg": r.getMessage()}
        if r.exc_info:
            d["exc"] = self.formatException(r.exc_info)
        return json.dumps(d)


def setup_logging():
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    s = get_settings()
    if s.is_prod and not s.cookie_secure:
        raise RuntimeError("COOKIE_SECURE must be true in production")
    await init_db()
    await ensure_indexes()
    await seed()
    yield
    await close_db()


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="ZeroDay's LLM Rakshak API", version="1.0.0", lifespan=lifespan, docs_url=None if s.is_prod else "/api/docs", redoc_url=None, openapi_url=None if s.is_prod else "/api/openapi.json")
    app.add_middleware(CORSMiddleware, allow_origins=[s.frontend_origin], allow_credentials=True, allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"])

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        rid = uuid.uuid4().hex[:12]
        t = time.monotonic()
        p = request.url.path
        if p.startswith("/api") and not p.startswith(("/api/auth", "/api/admin", "/api/health", "/api/docs", "/api/openapi", "/api/billing/webhook")) and request.method != "OPTIONS":
            try:
                if (await get_config())["maintenance_mode"]:
                    return JSONResponse({"detail": "ZeroDay's LLM Rakshak is in maintenance mode. Please try again shortly."}, status_code=503, headers={"Retry-After": "300"})
            except Exception:  # noqa
                pass
        if int(request.headers.get("content-length") or 0) > 2_000_000:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        resp = await call_next(request)
        resp.headers.update({"X-Request-ID": rid, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                             "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cross-Origin-Opener-Policy": "same-origin"})
        if s.is_prod:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if "cache-control" not in resp.headers and p.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        logging.getLogger("llmguard.http").info("%s %s %s %dms rid=%s", request.method, p, resp.status_code, (time.monotonic() - t) * 1000, rid)
        return resp

    @app.exception_handler(StarletteHTTPException)
    async def http_exc(request, exc):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def val_exc(request, exc):
        errs = [{"field": ".".join(str(x) for x in e["loc"][1:]), "message": e["msg"]} for e in exc.errors()[:8]]
        return JSONResponse({"detail": "Validation failed", "errors": errs}, status_code=422)

    @app.exception_handler(Exception)
    async def any_exc(request, exc):
        logging.getLogger("llmguard").exception("unhandled error")
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    @app.get("/api/health")
    async def health():
        try:
            await db().command("ping")
            return {"status": "ok"}
        except Exception:  # noqa
            return JSONResponse({"status": "unavailable"}, status_code=503)

    @app.get("/api/public/status")
    async def public_status():
        c = await get_config()
        return {"registration_open": c["registration_open"], "maintenance_mode": c["maintenance_mode"], "announcement": c["announcement"] if c["announcement"].get("active") else None,
                "payments_enabled": get_settings().payments_enabled}

    from .routers import admin, assessments, attacks, auth, billing, dashboard, notifications, orgs, reports, users, vulns
    for r in (auth, users, attacks, assessments, vulns, reports, notifications, dashboard, orgs, billing, admin):
        app.include_router(r.router)
    return app


app = create_app()
