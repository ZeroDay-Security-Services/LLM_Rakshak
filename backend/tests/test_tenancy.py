import json
from app.db import db
from tests.conftest import PW, make_user

KEY = "sk-test-AAAABBBBCCCCDDDDEEEEFFFFGGGG1234"


async def setup_target(cl, llm_url, mode="vuln", name="m"):
    r = await cl.put("/api/credentials/custom", json={"api_key": KEY, "endpoint": f"{llm_url}/{mode}/v1"})
    assert r.status_code == 200, r.text
    r = await cl.post("/api/models", json={"name": name, "provider": "custom", "model": "mock-1", "endpoint": f"{llm_url}/{mode}/v1", "system_prompt": ""})
    assert r.status_code == 201, r.text
    return r.json()


async def test_cross_tenant_isolation_and_idor(app, llm_url):
    a = await make_user(app, "ta@example.com")
    b = await make_user(app, "tb@example.com")
    m = await setup_target(a, llm_url)
    asm = await a.post("/api/assessments", json={"name": "A1", "model_config_id": m["id"], "preset": "quick", "limits": {"max_requests": 60},
                                                  "authorization": {"confirmed": True, "statement": "I own this test endpoint and authorise testing.", "endpoint_owner_confirmed": True}})
    assert asm.status_code == 201, asm.text
    aid = asm.json()["id"]
    # B cannot see/touch anything of A: identical 404 as for non-existent ids
    ghost = "0" * 24
    for path in (f"/api/models/{m['id']}", f"/api/assessments/{aid}", f"/api/assessments/{aid}/progress", f"/api/assessments/{aid}/executions", f"/api/assessments/{aid}/logs", f"/api/assessments/{aid}/export"):
        rb, rg = await b.get(path), await b.get(path.replace(m["id"], ghost).replace(aid, ghost))
        assert rb.status_code == 404 == rg.status_code and rb.json() == rg.json(), path
    for method, path in (("post", f"/api/assessments/{aid}/start"), ("post", f"/api/assessments/{aid}/cancel"), ("delete", f"/api/assessments/{aid}"), ("delete", f"/api/models/{m['id']}"), ("post", f"/api/models/{m['id']}/test")):
        assert (await getattr(b, method)(path)).status_code == 404, path
    assert (await b.get("/api/assessments")).json()["total"] == 0 and (await b.get("/api/models")).json()["total"] == 0
    # B cannot build an assessment on A's model, nor read A's credential
    r = await b.post("/api/assessments", json={"name": "x", "model_config_id": m["id"], "preset": "quick", "authorization": {"confirmed": True, "statement": "I own this test endpoint and authorise testing.", "endpoint_owner_confirmed": True}})
    assert r.status_code == 404
    assert (await b.get("/api/credentials")).json() == {}
    # NoSQL operator injection is rejected by typing
    r = await b.get("/api/vulnerabilities", params={"severity": '{"$ne": null}'})
    assert r.status_code == 200 and r.json()["total"] == 0
    r = await b.post("/api/auth/login", json={"email": {"$ne": ""}, "password": {"$ne": ""}})
    assert r.status_code == 422


async def test_credentials_never_exposed_and_encrypted_at_rest(app, llm_url):
    a = await make_user(app, "cred@example.com")
    await setup_target(a, llm_url)
    for p in ("/api/credentials", "/api/models", "/api/auth/me", "/api/preferences"):
        assert KEY not in (await a.get(p)).text
    c = await a.get("/api/credentials")
    assert c.json()["custom"]["preview"] == "sk-…1234" and "encrypted" not in c.text
    raw = await db().api_credentials.find_one({})
    assert KEY not in json.dumps(raw, default=str)                        # ciphertext only
    assert (await a.delete("/api/credentials/custom")).status_code == 200
    assert (await a.delete("/api/credentials/custom")).status_code == 404
    assert not any(KEY in str(x) for x in [e async for e in db().audit_logs.find({})])   # never in the audit log


async def test_ssrf_rejected_at_configuration_time(app):
    a = await make_user(app, "ssrf@example.com")
    for ep in ("http://169.254.169.254/v1", "http://100.100.100.200/v1", "ftp://x.example.com", "http://user:p@example.com/v1", "http://example.com:6379/v1"):
        r = await a.post("/api/models", json={"name": "x", "provider": "custom", "model": "m", "endpoint": ep})
        assert r.status_code == 422, (ep, r.text)
        r = await a.put("/api/credentials/custom", json={"api_key": "abcdefgh12345", "endpoint": ep})
        assert r.status_code == 422, ep


async def test_rbac_viewer_cannot_write_and_admin_routes_forbidden(app, llm_url):
    v = await make_user(app, "viewer@example.com", role="viewer")
    assert (await v.get("/api/assessments")).status_code == 200
    assert (await v.post("/api/models", json={"name": "x", "provider": "custom", "model": "m", "endpoint": f"{llm_url}/vuln/v1"})).status_code == 403
    assert (await v.put("/api/credentials/openai", json={"api_key": "abcdefgh12345"})).status_code == 403
    u = await make_user(app, "plain@example.com")
    for p in ("/api/admin/stats", "/api/admin/users", "/api/admin/audit", "/api/admin/health", "/api/admin/settings"):
        assert (await u.get(p)).status_code == 403, p
    assert (await u.put("/api/admin/settings", json={"maintenance_mode": True})).status_code == 403
    anon = (await make_user(app, "x2@example.com")).c
    anon.cookies.clear()
    assert (await anon.get("/api/assessments")).status_code == 401
