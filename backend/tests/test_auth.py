import pyotp
from app.db import db
from tests.conftest import EMAILS, PW, Client, make_user


async def test_register_enumeration_safe_verify_login_cookies(app, anon):
    body = {"email": "a1@example.com", "password": PW, "name": "A One"}
    r1 = await anon.post("/api/auth/register", json=body)
    r2 = await anon.post("/api/auth/register", json=body)          # duplicate: identical response
    assert r1.status_code == r2.status_code == 202 and r1.json() == r2.json()
    u = await db().users.find_one({"email": "a1@example.com"})
    assert u["password_hash"].startswith("$argon2id$") and u["email_verified"] is False
    r = await anon.post("/api/auth/login", json={"email": "a1@example.com", "password": PW})
    assert r.status_code == 403                                      # unverified
    tok = [e for e in EMAILS if "verify-email" in e[2]][0][2].split("token=")[1].split()[0]
    assert (await anon.post("/api/auth/verify-email", json={"token": tok})).status_code == 200
    assert (await anon.post("/api/auth/verify-email", json={"token": tok})).status_code == 400   # single use
    r = await anon.post("/api/auth/login", json={"email": "a1@example.com", "password": PW})
    assert r.status_code == 200
    sc = " ".join(r.headers.get_list("set-cookie")).lower()
    assert "lg_access=" in sc and "httponly" in sc and "lg_refresh=" in sc and "path=/api/auth" in sc and "samesite=lax" in sc
    assert "password_hash" not in r.text
    # unknown vs wrong password: same status/body
    a = await anon.post("/api/auth/login", json={"email": "nobody@example.com", "password": PW})
    b = await anon.post("/api/auth/login", json={"email": "a1@example.com", "password": PW + "x"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


async def test_weak_password_and_closed_registration(anon):
    r = await anon.post("/api/auth/register", json={"email": "w@example.com", "password": "short", "name": "W"})
    assert r.status_code == 422
    await db().platform_settings.update_one({"_id": "config"}, {"$set": {"registration_open": False}}, upsert=True)
    r = await anon.post("/api/auth/register", json={"email": "w2@example.com", "password": PW, "name": "W"})
    assert r.status_code == 403
    await db().platform_settings.update_one({"_id": "config"}, {"$set": {"registration_open": True}})


async def test_csrf_required_for_cookie_sessions(app):
    cl = await make_user(app, "csrf@example.com")
    assert (await cl.get("/api/auth/me")).status_code == 200
    r = await cl.post("/api/auth/logout-all", csrf=False)
    assert r.status_code == 403 and "CSRF" in r.text
    r = await cl.c.post("/api/auth/change-password", json={}, headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403
    r = await cl.c.post("/api/models", json={}, headers={"Origin": "https://evil.example", "X-CSRF-Token": cl.c.cookies.get("lg_csrf")})
    assert r.status_code == 403


async def test_refresh_rotation_and_reuse_detection(app):
    cl = await make_user(app, "rot@example.com")
    old_refresh = cl.c.cookies.get("lg_refresh")
    assert (await cl.post("/api/auth/refresh")).status_code == 200
    new_refresh = cl.c.cookies.get("lg_refresh")
    assert new_refresh != old_refresh
    # replay the old token well after the grace window => session revoked
    await db().sessions.update_many({}, {"$set": {"rotated_at": __import__("datetime").datetime(2020, 1, 1, tzinfo=__import__("datetime").timezone.utc)}})
    thief = Client(app)
    thief.c.cookies.set("lg_refresh", old_refresh, path="/api/auth"); thief.c.cookies.set("lg_csrf", "x")
    r = await thief.c.post("/api/auth/refresh", headers={"X-CSRF-Token": "x"})
    assert r.status_code == 401
    assert (await cl.get("/api/auth/me")).status_code == 401           # legitimate session also killed
    assert (await db().audit_logs.find_one({"action": "auth.refresh_reuse_detected"})) is not None


async def test_lockout_and_rate_limit_without_enumeration(app, anon):
    await make_user(app, "lock@example.com")
    for _ in range(5):
        assert (await anon.post("/api/auth/login", json={"email": "lock@example.com", "password": "Wrong-Passw0rd!!"})).status_code == 401
    r = await anon.post("/api/auth/login", json={"email": "lock@example.com", "password": PW})   # correct password but locked
    assert r.status_code == 401
    for _ in range(12):
        r = await anon.post("/api/auth/login", json={"email": "ghost@example.com", "password": "Wrong-Passw0rd!!"})
    assert r.status_code == 429 and "retry-after" in r.headers          # applies to non-existent accounts too


async def test_logout_invalidates_session_and_password_reset_revokes_all(app, anon):
    cl = await make_user(app, "pr@example.com")
    assert (await cl.post("/api/auth/forgot-password", json={"email": "pr@example.com"})).status_code == 202
    assert (await anon.post("/api/auth/forgot-password", json={"email": "none@example.com"})).status_code == 202
    tok = [e for e in EMAILS if "reset-password" in e[2]][0][2].split("token=")[1].split()[0]
    assert (await anon.post("/api/auth/reset-password", json={"token": tok, "password": "weak"})).status_code in (400, 422)
    r = await anon.post("/api/auth/reset-password", json={"token": tok, "password": "An0ther-Str0ng-Pass!"})
    if r.status_code == 400:       # token consumed by the failed weak attempt? it must be single-use only on success
        raise AssertionError(r.text)
    assert (await cl.get("/api/auth/me")).status_code == 401
    assert (await anon.post("/api/auth/reset-password", json={"token": tok, "password": "An0ther-Str0ng-Pass!"})).status_code == 400
    r = await anon.post("/api/auth/login", json={"email": "pr@example.com", "password": "An0ther-Str0ng-Pass!"})
    assert r.status_code == 200
    assert (await anon.post("/api/auth/logout")).status_code == 200
    assert (await anon.get("/api/auth/me")).status_code == 401


async def test_mfa_totp_flow_with_replay_protection(app):
    cl = await make_user(app, "mfa@example.com")
    s = (await cl.post("/api/auth/mfa/setup")).json()
    assert (await cl.post("/api/auth/mfa/enable", json={"code": "000000"})).status_code == 400
    code = pyotp.TOTP(s["secret"]).now()
    assert (await cl.post("/api/auth/mfa/enable", json={"code": code})).status_code == 200
    u = await db().users.find_one({"email": "mfa@example.com"})
    assert s["secret"] not in str(u)                                     # TOTP secret encrypted at rest
    fresh = Client(app)
    r = await fresh.post("/api/auth/login", json={"email": "mfa@example.com", "password": PW})
    assert r.status_code == 401 and r.headers.get("x-mfa-required") == "true"
    r = await fresh.post("/api/auth/login", json={"email": "mfa@example.com", "password": PW, "totp_code": code})
    assert r.status_code == 401                                          # same code as enrolment => replay rejected
    t = pyotp.TOTP(s["secret"])
    import time
    nxt = t.at(int(time.time()) + 30)
    r = await fresh.post("/api/auth/login", json={"email": "mfa@example.com", "password": PW, "totp_code": nxt})
    assert r.status_code == 200


async def test_sessions_list_and_revoke_and_history(app):
    cl = await make_user(app, "ses@example.com")
    other = Client(app)
    await other.post("/api/auth/login", json={"email": "ses@example.com", "password": PW})
    ss = (await cl.get("/api/auth/sessions")).json()
    assert len(ss) == 2 and sum(s["current"] for s in ss) == 1
    victim = next(s for s in ss if not s["current"])
    assert (await cl.delete(f"/api/auth/sessions/{victim['id']}")).status_code == 200
    assert (await other.get("/api/auth/me")).status_code == 401
    h = (await cl.get("/api/auth/login-history")).json()
    assert h and h[0]["success"] is True
