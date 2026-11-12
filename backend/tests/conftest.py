import asyncio, os, socket, threading, time
os.environ.update({"LLMGUARD_ENV": "test", "LLMGUARD_JWT_SECRET": "t" * 48, "LLMGUARD_MONGODB_DB": "llmguard_test", "LLMGUARD_REDIS_URL": "redis://127.0.0.1:6379/15",
                   "LLMGUARD_COOKIE_SECURE": "false", "LLMGUARD_TASK_BACKEND": "inline", "LLMGUARD_ALLOW_PRIVATE_TARGETS": "true", "LLMGUARD_ALLOW_HTTP_TARGETS": "true",
                   "LLMGUARD_PROVIDER_MIN_INTERVAL": "0"})
from cryptography.fernet import Fernet
os.environ.setdefault("LLMGUARD_ENCRYPTION_KEYS", Fernet.generate_key().decode())
import httpx, pytest, pytest_asyncio, uvicorn
from app import jobs
from app.cli import create_admin
from app.core import ratelimit
from app.db import close_db, db, ensure_indexes, init_db
from app.engine import runner
from app.main import create_app
from app.seed import seed
from tests import mock_llm

runner.BACKOFF_BASE = 0.01
EMAILS: list[tuple[str, str, str]] = []
PW = "Str0ng-Passw0rd!x"


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture(scope="session")
def llm_url():
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(mock_llm.build(), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True); t.start()
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close(); break
        except OSError:
            time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _db():
    d = await init_db()
    await d.client.drop_database("llmguard_test")
    await ensure_indexes(); await seed()
    yield
    await jobs.wait_inline()
    await close_db()


@pytest_asyncio.fixture(autouse=True)
async def _flush(monkeypatch):
    ratelimit.reset_redis()
    await ratelimit.get_redis().flushdb()
    EMAILS.clear()
    async def fake(to, subject, body):
        EMAILS.append((to, subject, body)); return True
    for mod in ("app.routers.auth", "app.routers.orgs"):
        monkeypatch.setattr(f"{mod}.send_email", fake)
    yield


class Client:
    def __init__(self, app):
        self.c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    async def req(self, method, url, csrf=True, **kw):
        h = kw.pop("headers", {})
        if csrf and method not in ("GET", "HEAD"):
            t = self.c.cookies.get("lg_csrf")
            if t:
                h["X-CSRF-Token"] = t
        return await self.c.request(method, url, headers=h, **kw)

    get = lambda s, u, **k: s.req("GET", u, **k)
    post = lambda s, u, **k: s.req("POST", u, **k)
    put = lambda s, u, **k: s.req("PUT", u, **k)
    patch = lambda s, u, **k: s.req("PATCH", u, **k)
    delete = lambda s, u, **k: s.req("DELETE", u, **k)


@pytest.fixture(scope="session")
def app():
    return create_app()


@pytest.fixture
def anon(app):
    return Client(app)


async def make_user(app, email: str, role: str = "user", name="Test User") -> Client:
    cl = Client(app)
    r = await cl.post("/api/auth/register", json={"email": email, "password": PW, "name": name})
    assert r.status_code == 202, r.text
    tok = EMAILS[-1][2].split("token=")[1].strip().split()[0]
    assert (await cl.post("/api/auth/verify-email", json={"token": tok})).status_code == 200
    if role != "user":
        await db().users.update_one({"email": email}, {"$set": {"role": role}})
    r = await cl.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return cl


async def make_admin(app, email="root@example.com", role="super_admin") -> Client:
    if not await db().users.find_one({"email": email}):
        await create_admin(email, "Root", role, PW) if False else await _create_admin_noclose(email, role)
    cl = Client(app)
    r = await cl.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return cl


async def _create_admin_noclose(email, role):
    from app.core import security
    from app.util import now
    t = now()
    u = await db().users.insert_one({"email": email, "name": "Root", "password_hash": security.hash_password(PW), "role": role, "is_active": True, "email_verified": True, "mfa_enabled": False, "failed_attempts": 0, "created_at": t})
    o = await db().organizations.insert_one({"name": "Root org", "slug": "root-" + email[:3], "owner_id": u.inserted_id, "created_at": t})
    await db().organization_members.insert_one({"org_id": o.inserted_id, "user_id": u.inserted_id, "role": "owner", "created_at": t})
    await db().subscriptions.insert_one({"org_id": o.inserted_id, "plan": "enterprise", "status": "active", "provider": "admin", "created_at": t})
    await db().users.update_one({"_id": u.inserted_id}, {"$set": {"active_org_id": o.inserted_id}})
