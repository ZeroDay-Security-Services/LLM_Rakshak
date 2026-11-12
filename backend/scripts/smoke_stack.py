"""Integrated smoke test: Next.js (production server) -> rewrite proxy -> FastAPI -> MongoDB/Redis.
Run from backend/:  python scripts/smoke_stack.py   (needs `npm run build` in ../frontend, mongod, redis)"""
import os, secrets, socket, subprocess, sys, time
import httpx, pymongo, pyotp
from cryptography.fernet import Fernet

def port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
api, web = 18765, port()
ENV = {**os.environ, "LLMGUARD_ENV": "test", "LLMGUARD_JWT_SECRET": secrets.token_hex(24), "LLMGUARD_ENCRYPTION_KEYS": Fernet.generate_key().decode(), "LLMGUARD_MONGODB_DB": "llmguard_stack",
       "LLMGUARD_REDIS_URL": "redis://127.0.0.1:6379/13", "LLMGUARD_COOKIE_SECURE": "false", "LLMGUARD_TASK_BACKEND": "inline", "LLMGUARD_FRONTEND_ORIGIN": f"http://127.0.0.1:{web}",
       "BACKEND_URL": f"http://127.0.0.1:{api}", "PYTHONPATH": os.getcwd()}
procs = []
# NOTE: Next.js bakes rewrites() at build time, so BACKEND_URL must be set when building.
subprocess.run(["npx", "next", "build"], cwd="../frontend", env=ENV, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def spawn(cmd, cwd=None):
    p = subprocess.Popen(cmd, env=ENV, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True); procs.append(p); return p
def wait(url):
    for _ in range(150):
        try:
            if httpx.get(url, timeout=1).status_code < 500: return
        except Exception: time.sleep(0.2)
    raise SystemExit("timeout " + url)
try:
    pymongo.MongoClient().drop_database("llmguard_stack")
    spawn([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(api), "--log-level", "warning"])
    spawn(["npx", "next", "start", "-p", str(web)], cwd="../frontend")
    wait(f"http://127.0.0.1:{api}/api/health"); wait(f"http://127.0.0.1:{web}/login")
    c = httpx.Client(base_url=f"http://127.0.0.1:{web}", timeout=20, follow_redirects=False)
    r = c.get("/"); assert r.status_code == 200 and "before attackers do" in r.text, "landing"
    hdr = r.headers; assert "default-src 'self'" in hdr["content-security-policy"] and hdr["x-frame-options"] == "DENY" and "x-powered-by" not in hdr, "frontend security headers"
    for p in ("/login", "/register", "/pricing", "/docs", "/features", "/privacy", "/terms", "/forgot-password", "/dashboard", "/assessments/new", "/admin"):
        assert c.get(p).status_code == 200, p
    assert c.get("/nope").status_code == 404
    assert c.get("/api/health").json() == {"status": "ok"}, "proxy health"
    pw = "Str0ng-Passw0rd!x"
    assert c.post("/api/auth/register", json={"email": "ui@example.com", "password": pw, "name": "UI"}, headers={"Origin": f"http://127.0.0.1:{web}"}).status_code == 202
    db = pymongo.MongoClient()["llmguard_stack"]; db.users.update_one({"email": "ui@example.com"}, {"$set": {"email_verified": True}})
    r = c.post("/api/auth/login", json={"email": "ui@example.com", "password": pw}); assert r.status_code == 200, r.text
    assert {"lg_access", "lg_refresh", "lg_csrf"} <= set(c.cookies.keys()), "cookies through proxy"
    me = c.get("/api/auth/me"); assert me.status_code == 200 and me.json()["user"]["email"] == "ui@example.com" and me.json()["plan"]["name"] == "free"
    assert c.post("/api/auth/logout-all").status_code == 403, "CSRF enforced through proxy"
    t = c.cookies.get("lg_csrf"); assert c.post("/api/models", json={}, headers={"X-CSRF-Token": t}).status_code == 422
    sec = c.post("/api/auth/mfa/setup", headers={"X-CSRF-Token": t}).json()["secret"]
    assert c.post("/api/auth/mfa/enable", json={"code": pyotp.TOTP(sec).now()}, headers={"X-CSRF-Token": t}).status_code == 200
    r = httpx.post(f"http://127.0.0.1:{web}/api/auth/login", json={"email": "ui@example.com", "password": pw})
    assert r.status_code == 401 and r.headers.get("x-mfa-required") == "true", "MFA header survives proxy (login UI relies on it)"
    d = c.get("/api/dashboard").json(); assert d["empty"] is True
    print("STACK SMOKE OK: landing/SSR pages, CSP headers, proxy, cookies, CSRF, MFA header, dashboard empty-state")
finally:
    for p in procs: p.terminate()
