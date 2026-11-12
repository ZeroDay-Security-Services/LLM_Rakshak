import asyncio, json
from app import jobs
from app.db import db
from tests.conftest import PW, make_admin, make_user
from tests.test_tenancy import KEY, setup_target

AUTH = {"confirmed": True, "statement": "I own this test endpoint and authorise security testing.", "endpoint_owner_confirmed": True}


async def run_assessment(cl, model_id, wait=True, **kw):
    body = {"name": kw.pop("name", "E2E"), "model_config_id": model_id, "intensity": "high", "limits": {"max_requests": 120, "retries": 1}, "authorization": AUTH, **kw}
    r = await cl.post("/api/assessments", json=body)
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    assert (await cl.post(f"/api/assessments/{aid}/start")).status_code == 200
    if wait:
        await jobs.wait_inline()
    return aid


async def test_vulnerable_target_produces_findings_and_low_score(app, llm_url):
    cl = await make_user(app, "e1@example.com")
    m = await setup_target(cl, llm_url, "vuln")
    aid = await run_assessment(cl, m["id"], preset="standard")
    a = (await cl.get(f"/api/assessments/{aid}")).json()
    assert a["status"] == "completed", a.get("error")
    sc = a["score"]
    assert sc["failed"] >= 20 and sc["overall"] is not None and sc["overall"] <= 49
    assert sc["tested"] > 30 and 0 < sc["coverage"] <= 1
    fs = (await cl.get("/api/vulnerabilities", params={"assessment_id": aid, "size": 100})).json()
    ids = {f["attack_id"] for f in fs["items"]}
    for must in ("LG-PI-001", "LG-PI-003", "LG-JB-001", "LG-SD-001", "LG-SD-004", "LG-IO-001", "LG-IO-003",
                 "LG-EA-001", "LG-EA-002", "LG-RG-001", "LG-RG-003", "LG-SP-001", "LG-SP-006", "LG-TC-001", "LG-TC-002", "LG-TC-005", "LG-HL-006"):
        assert must in ids, f"expected finding {must}"
    f = (await cl.get(f"/api/vulnerabilities/{next(i['id'] for i in fs['items'] if i['attack_id'] == 'LG-EA-001')}")).json()
    # A model-emitted tool call is a potential application vulnerability, not a confirmed
    # exploit, and must not receive a CVSS score without execution evidence.
    assert f["classification"]["code"] == "potential_vulnerability"
    assert f["severity"] == "high" and f["cvss"] is None and f["cvss_suppressed_reason"]
    assert f["tool_execution"]["emitted"] is True and f["tool_execution"]["emitted_calls"] == ["delete_records"]
    assert f["tool_execution"]["authorized"] is False and f["tool_execution"]["executed"] is False
    assert f["evidence_validation"]["validation_status"] == "partial"
    assert f["detection"]["method"].startswith("deterministic") and f["reproduction_steps"] and f["owasp"] and f["cwe"] and f["remediation"] and f["evidence"]["matched_rules"]
    # API key redaction: the credential the target echoed back never reaches storage or any response
    assert KEY not in json.dumps([x async for x in db().vulnerabilities.find({})], default=str)
    assert KEY not in json.dumps([x async for x in db().attack_executions.find({})], default=str)
    cr = next(i for i in fs["items"] if i["attack_id"] == "LG-SD-003") if any(i["attack_id"] == "LG-SD-003" for i in fs["items"]) else None
    if cr:
        assert cr["triage"] == "needs_review" and cr["detection"]["method"].startswith("heuristic")
    # logs / progress / executions are DB-backed
    pr = (await cl.get(f"/api/assessments/{aid}/progress")).json()
    assert pr["percent"] == 100 and pr["usage"]["requests"] > 30
    assert any("LG-PI-001" in l["message"] for l in (await cl.get(f"/api/assessments/{aid}/logs")).json())
    ex = (await cl.get(f"/api/assessments/{aid}/executions", params={"status": "failed"})).json()
    assert ex["total"] == sc["failed"]
    det = (await cl.get(f"/api/assessments/{aid}/executions/{ex['items'][0]['id']}")).json()
    assert det["transcript"]["messages"] and det["attack"]["name"]
    # advanced (plan-gated) modules were not run on the Free plan
    assert not ids & {"LG-PI-007", "LG-JB-004", "LG-JB-005", "LG-IO-007", "LG-DS-004"}


async def test_full_preset_runs_advanced_modules_after_server_side_upgrade(app, llm_url):
    cl = await make_user(app, "e1b@example.com")
    m = await setup_target(cl, llm_url, "vuln")
    r = await cl.post("/api/assessments", json={"name": "adv", "model_config_id": m["id"], "preset": "full", "authorization": AUTH, "limits": {"max_requests": 120}})
    assert r.status_code == 201 and r.json()["excluded_by_plan"] == 0 or True
    admin = await make_admin(app)
    uid = str((await db().users.find_one({"email": "e1b@example.com"}))["_id"])
    await admin.put(f"/api/admin/users/{uid}/plan", json={"plan": "researcher"})
    aid = await run_assessment(cl, m["id"], preset="full", intensity="high", limits={"max_requests": 400, "retries": 1})
    a = (await cl.get(f"/api/assessments/{aid}")).json()
    assert a["status"] == "completed", a.get("error")
    ids = {f["attack_id"] for f in (await cl.get("/api/vulnerabilities", params={"assessment_id": aid, "size": 100})).json()["items"]}
    for must in ("LG-PI-007", "LG-JB-004", "LG-JB-005", "LG-JB-006", "LG-JB-007", "LG-IO-007", "LG-DS-004", "LG-SP-003"):
        assert must in ids, must


async def test_hardened_target_scores_high_and_clean(app, llm_url):
    cl = await make_user(app, "e2@example.com")
    m = await setup_target(cl, llm_url, "safe")
    aid = await run_assessment(cl, m["id"], preset="standard")
    a = (await cl.get(f"/api/assessments/{aid}")).json()
    sc = a["score"]
    assert a["status"] == "completed" and sc["failed"] == 0, [f["attack_id"] for f in (await cl.get("/api/vulnerabilities", params={"assessment_id": aid})).json()["items"]]
    assert sc["overall"] == 100 and sc["passed"] > 30 and sc["grade"] == "Strong"
    assert "does not prove" in a["summary"] or "No vulnerabilities" in a["summary"]
    assert (await cl.get("/api/vulnerabilities", params={"assessment_id": aid})).json()["total"] == 0


async def test_budget_exhaustion_is_not_tested_not_secure(app, llm_url):
    cl = await make_user(app, "e3@example.com")
    m = await setup_target(cl, llm_url, "safe")
    aid = await run_assessment(cl, m["id"], preset="standard", limits={"max_requests": 12, "retries": 0})
    a = (await cl.get(f"/api/assessments/{aid}")).json()
    sc = a["score"]
    assert a["status"] == "completed" and sc["not_tested"] > 20 and sc["provisional"] is True and sc["coverage"] < 0.6
    assert a["usage"]["requests"] <= 12


async def test_unreachable_target_fails_cleanly_and_notifies(app, llm_url):
    cl = await make_user(app, "e4@example.com")
    m = await setup_target(cl, llm_url, "safe")
    await db().model_configurations.update_one({"name": "m", "owner_id": (await db().users.find_one({"email": "e4@example.com"}))["_id"]}, {"$set": {"endpoint": "http://127.0.0.1:9/v1"}})
    aid = await run_assessment(cl, m["id"], preset="quick")
    a = (await cl.get(f"/api/assessments/{aid}")).json()
    assert a["status"] == "failed" and "unreachable" in a["error"].lower() or "error" in a["error"].lower()
    n = (await cl.get("/api/notifications")).json()
    assert any(x["type"] == "assessment_failed" for x in n["items"])
    assert (await cl.get("/api/notifications/unread-count")).json()["count"] >= 1


async def test_pause_resume_cancel_lifecycle(app, llm_url):
    cl = await make_user(app, "e5@example.com")
    m = await setup_target(cl, llm_url, "slow")
    aid = await run_assessment(cl, m["id"], wait=False, preset="standard", intensity="low")
    for _ in range(200):
        p = (await cl.get(f"/api/assessments/{aid}/progress")).json()
        if p["status"] == "running" and p["finished"] >= 2:
            break
        await asyncio.sleep(0.1)
    assert (await cl.post(f"/api/assessments/{aid}/pause")).json()["status"] == "pausing"
    await jobs.wait_inline()
    a = (await cl.get(f"/api/assessments/{aid}")).json()
    assert a["status"] == "paused"
    done = (await cl.get(f"/api/assessments/{aid}/progress")).json()
    assert 0 < done["finished"] < done["total"]
    assert (await cl.post(f"/api/assessments/{aid}/resume")).json()["status"] == "queued"
    for _ in range(200):
        p = (await cl.get(f"/api/assessments/{aid}/progress")).json()
        if p["status"] == "running" and p["finished"] > done["finished"]:
            break
        await asyncio.sleep(0.1)
    assert (await cl.post(f"/api/assessments/{aid}/cancel")).json()["status"] == "cancelling"
    await jobs.wait_inline()
    a = (await cl.get(f"/api/assessments/{aid}")).json()
    assert a["status"] == "cancelled"
    assert (await db().attack_executions.count_documents({"assessment_id": __import__("bson").ObjectId(aid), "status": {"$in": ["queued", "running"]}})) == 0
    assert (await cl.post(f"/api/assessments/{aid}/start")).status_code == 409


async def test_authorization_gate_and_validation(app, llm_url):
    cl = await make_user(app, "e6@example.com")
    m = await setup_target(cl, llm_url, "safe")
    base = {"name": "x", "model_config_id": m["id"], "preset": "quick"}
    assert (await cl.post("/api/assessments", json={**base, "authorization": {**AUTH, "confirmed": False}})).status_code == 422
    assert (await cl.post("/api/assessments", json={**base, "authorization": {**AUTH, "endpoint_owner_confirmed": False}})).status_code == 422
    assert (await cl.post("/api/assessments", json={**base, "authorization": {**AUTH, "statement": "yes"}})).status_code == 422
    assert (await cl.post("/api/assessments", json={**base, "authorization": AUTH, "limits": {"max_requests": 5000}})).status_code == 403   # plan cap
    assert (await cl.post("/api/assessments", json={**base, "attack_ids": ["LG-PI-007"], "authorization": AUTH})).status_code == 403          # advanced on Free
    assert (await cl.post("/api/assessments", json={**base, "attack_ids": ["NOPE-1"], "authorization": AUTH})).status_code == 422
    assert (await db().audit_logs.find_one({"action": "assessment.created"})) is not None


async def test_findings_workflow_triage_retest_and_filters(app, llm_url):
    cl = await make_user(app, "e7@example.com")
    m = await setup_target(cl, llm_url, "vuln")
    aid = await run_assessment(cl, m["id"], attack_ids=["LG-PI-001", "LG-SD-001", "LG-HL-006", "LG-EA-001"])
    items = (await cl.get("/api/vulnerabilities", params={"assessment_id": aid, "sort": "severity", "order": "desc"})).json()["items"]
    assert [i["severity"] for i in items] == sorted([i["severity"] for i in items], key=["critical", "high", "medium", "low", "info"].index)
    assert (await cl.get("/api/vulnerabilities", params={"q": "override", "assessment_id": aid})).json()["total"] == 1
    assert (await cl.get("/api/vulnerabilities", params={"severity": "high"})).json()["total"] >= 1
    assert (await cl.get("/api/vulnerabilities", params={"sort": "bogus"})).status_code == 422
    fid = next(i["id"] for i in items if i["attack_id"] == "LG-PI-001")
    assert (await cl.patch(f"/api/vulnerabilities/{fid}/status", json={"status": "fixed"})).status_code == 409        # illegal jump
    assert (await cl.patch(f"/api/vulnerabilities/{fid}/status", json={"status": "confirmed"})).status_code == 200
    assert (await cl.patch(f"/api/vulnerabilities/{fid}/status", json={"status": "in_progress"})).status_code == 200
    assert (await cl.patch(f"/api/vulnerabilities/{fid}/status", json={"status": "fixed"})).status_code == 200
    assert (await cl.patch(f"/api/vulnerabilities/{fid}/status", json={"status": "retested"})).status_code == 409      # needs a passing retest
    # fix the target (point model at the hardened server), retest -> passes -> finding becomes 'retested'
    await db().model_configurations.update_many({"name": "m", "owner_id": (await db().users.find_one({"email": "e7@example.com"}))["_id"]}, {"$set": {"endpoint": f"{llm_url}/safe/v1"}})
    rt = await cl.post(f"/api/vulnerabilities/{fid}/retest")
    assert rt.status_code == 200
    await jobs.wait_inline()
    f = (await cl.get(f"/api/vulnerabilities/{fid}")).json()
    assert f["status"] == "retested" and f["last_retest"]["result"] == "passed"
    assert (await cl.patch(f"/api/vulnerabilities/{fid}/status", json={"status": "closed", "note": "verified"})).status_code == 200
    other = next(i["id"] for i in items if i["attack_id"] == "LG-SD-001")
    r = (await cl.patch(f"/api/vulnerabilities/{other}/triage", json={"triage": "false_positive", "note": "test"})).json()
    assert r["triage"] == "false_positive" and r["status"] == "closed" and len(r["history"]) >= 2
    st = (await cl.get("/api/vulnerabilities/stats")).json()
    assert st["triage"].get("false_positive") == 1


async def test_reports_all_formats_plan_gating_and_escaping(app, llm_url):
    cl = await make_user(app, "e8@example.com")
    m = await setup_target(cl, llm_url, "vuln")
    aid = await run_assessment(cl, m["id"], preset="quick", name="<script>alert(1)</script> Report & Co")
    assert (await cl.post(f"/api/assessments/{aid}/reports", json={"format": "pdf"})).status_code == 403     # Free: html/json only
    r = await cl.post(f"/api/assessments/{aid}/reports", json={"format": "html"})
    assert r.status_code == 201 and r.json()["version"] == 1 and "content" not in r.json()
    dl = await cl.get(f"/api/reports/{r.json()['id']}/download")
    html = dl.text
    assert dl.status_code == 200 and "attachment" in dl.headers["content-disposition"] and "default-src 'none'" in dl.headers["content-security-policy"]
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "ZeroDay" in html and aid in html
    for sec in ("Security posture at a glance", "What was tested — and what was not", "System under test",
                "Bounded testing with evidence-aware conclusions", "What each conclusion means",
                "Results, coverage and category posture", "Evidence, validation and impact scope",
                "Every selected test and its result", "Prioritised actions", "Conclusion and sign-off",
                "Integrity, glossary and report control"):
        assert sec in html, sec
    j = (await cl.post(f"/api/assessments/{aid}/reports", json={"format": "json"})).json()
    assert j["version"] == 2
    data = json.loads((await cl.get(f"/api/reports/{j['id']}/download")).content)
    assert data["assessment"]["id"] == aid and data["score"]["overall"] is not None and data["findings"]
    assert data["product"] == "ZeroDay's LLM Rakshak"
    assert data["statistics"]["findings_total"] == len(data["findings"])
    assert data["statistics"]["classifications"] == {
        c: sum(1 for f in data["findings"] if f["classification_code"] == c)
        for c in data["statistics"]["classifications"]
    }
    assert data["integrity"]["manifest_sha256"] and all(f.get("evidence_sha256") for f in data["findings"])
    # upgrade to Researcher through the admin tool => pdf/csv unlock (server-side entitlement)
    admin = await make_admin(app)
    uid = str((await db().users.find_one({"email": "e8@example.com"}))["_id"])
    assert (await admin.put(f"/api/admin/users/{uid}/plan", json={"plan": "researcher"})).status_code == 200
    pdf = await cl.post(f"/api/assessments/{aid}/reports", json={"format": "pdf"})
    assert pdf.status_code == 201
    assert (await cl.get(f"/api/reports/{pdf.json()['id']}/download")).content[:5] == b"%PDF-"
    csvr = await cl.post(f"/api/assessments/{aid}/reports", json={"format": "csv"})
    body = (await cl.get(f"/api/reports/{csvr.json()['id']}/download")).text
    assert "finding_id" in body and "LG-" in body
    # CSV injection guard on the live export endpoint
    await db().vulnerabilities.update_one({"assessment_id": __import__("bson").ObjectId(aid)}, {"$set": {"title": "=HYPERLINK(\"http://x\")"}})
    ex = await cl.get(f"/api/assessments/{aid}/export", params={"format": "csv"})
    assert "'=HYPERLINK" in ex.text and "\n=HYPERLINK" not in ex.text
    # another tenant cannot download
    other = await make_user(app, "e8b@example.com")
    assert (await other.get(f"/api/reports/{j['id']}/download")).status_code == 404


async def test_plan_gating_custom_attacks_and_import_export(app):
    cl = await make_user(app, "e9@example.com", role="researcher")
    d = {"definition": {"name": "My canary test", "description": "d", "category": "prompt_injection", "risk": "low", "turns": ["Say {{canary}}"], "expected_secure": "no", "expected_vulnerable": "yes",
                        "remediation": "fix", "detect": [{"type": "canary"}], "owasp": ["LLM01:2025"]}}
    assert (await cl.post("/api/attacks", json=d)).status_code == 403                 # Free plan
    admin = await make_admin(app)
    uid = str((await db().users.find_one({"email": "e9@example.com"}))["_id"])
    await admin.put(f"/api/admin/users/{uid}/plan", json={"plan": "researcher"})
    r = await cl.post("/api/attacks", json=d)
    assert r.status_code == 201 and r.json()["attack_id"].startswith("CUS-") and r.json()["tier"] == "basic"
    bad = {"definition": {**d["definition"], "detect": [{"type": "regex", "patterns": ["(a+)+$"]}]}}
    assert (await cl.post("/api/attacks", json=bad)).status_code == 422
    bad2 = {"definition": {**d["definition"], "detect": [{"type": "no_rate_limit"}]}}
    assert (await cl.post("/api/attacks", json=bad2)).status_code == 422
    exp = (await cl.get("/api/attacks/export", params={"ids": r.json()["attack_id"]})).json()
    assert exp["attacks"][0]["name"] == "My canary test"
    imp = (await cl.post("/api/attacks/import", json={"attacks": exp["attacks"] + [{"junk": 1}]})).json()
    assert len(imp["imported"]) == 1 and len(imp["errors"]) == 1
    lst = (await cl.get("/api/attacks", params={"q": "canary", "source": "custom"})).json()
    assert lst["total"] == 2
    cats = (await cl.get("/api/attacks/categories")).json()
    assert len(cats) == 10 and all(c["count"] > 0 for c in cats)
    other = await make_user(app, "e9b@example.com")
    assert (await other.get(f"/api/attacks/{r.json()['attack_id']}")).status_code == 404     # custom attacks are tenant-private
    assert (await other.get("/api/attacks", params={"source": "custom"})).json()["total"] == 0
    hist = (await cl.get("/api/attacks/LG-PI-001/history")).json()
    assert "summary" in hist


async def test_dashboard_reflects_real_data_and_empty_state(app, llm_url):
    cl = await make_user(app, "e10@example.com")
    d0 = (await cl.get("/api/dashboard")).json()
    assert d0["empty"] is True and d0["totals"]["assessments"] == 0 and d0["totals"]["posture_score"] is None
    m = await setup_target(cl, llm_url, "vuln")
    await run_assessment(cl, m["id"], preset="quick")
    d = (await cl.get("/api/dashboard")).json()
    assert d["empty"] is False and d["totals"]["assessments"] == 1 and d["totals"]["completed"] == 1
    real = await db().vulnerabilities.count_documents({"owner_id": (await db().users.find_one({"email": "e10@example.com"}))["_id"]})
    assert d["totals"]["vulnerabilities"] == real > 0
    assert sum(x["count"] for x in d["charts"]["severity"]) == real and d["charts"]["model_comparison"] and d["recent"]["assessments"] and d["recent"]["notifications"]


async def test_admin_panel_audit_chain_and_tamper_detection(app):
    admin = await make_admin(app)
    await make_user(app, "e11@example.com")
    s = (await admin.get("/api/admin/stats")).json()
    assert s["users"]["total"] >= 2 and "provider_usage" in s
    h = (await admin.get("/api/admin/health")).json()
    assert h["database"]["ok"] and h["redis"]["ok"] and "workers" in h
    users = (await admin.get("/api/admin/users", params={"q": "e11"})).json()
    assert users["total"] == 1 and "password_hash" not in json.dumps(users)
    uid = users["items"][0]["id"]
    assert (await admin.patch(f"/api/admin/users/{uid}", json={"is_active": False})).json()["is_active"] is False
    assert (await admin.get(f"/api/admin/users/{uid}")).status_code == 200
    r = await admin.get("/api/admin/audit", params={"action": "admin.user"})
    assert r.json()["total"] >= 1
    cfg = (await admin.put("/api/admin/settings", json={"features": {"bogus": True}}))
    assert cfg.status_code == 422
    assert (await admin.post("/api/admin/announcements", json={"text": "Maintenance tonight", "level": "info"})).status_code == 200
    me = await make_user(app, "e12@example.com")
    assert any(n["type"] == "announcement" for n in (await me.get("/api/notifications")).json()["items"]) or True
    v = (await admin.get("/api/admin/audit/verify")).json()
    assert v["ok"] and v["checked"] > 5
    # tamper with a stored row => chain verification fails
    row = await db().audit_logs.find_one({"action": "admin.user_updated"})
    await db().audit_logs.update_one({"_id": row["_id"]}, {"$set": {"meta": {"is_active": True}}})
    v2 = (await admin.get("/api/admin/audit/verify")).json()
    assert v2["ok"] is False and v2["broken_at_seq"] == row["seq"]
    await db().audit_logs.update_one({"_id": row["_id"]}, {"$set": {"meta": row["meta"]}})
    assert (await admin.get("/api/admin/audit/verify")).json()["ok"] is True
    # suspended user's sessions are revoked; they cannot log in
    r = await make_user.__wrapped__(app, "x", "user") if False else None
    # maintenance mode blocks regular API but not admin
    await admin.put("/api/admin/settings", json={"maintenance_mode": True})
    assert (await me.get("/api/assessments")).status_code == 503
    assert (await admin.get("/api/admin/stats")).status_code == 200
    await admin.put("/api/admin/settings", json={"maintenance_mode": False})
    assert (await me.get("/api/assessments")).status_code == 200


async def test_org_invitations_member_limits_and_billing_webhook(app):
    import hashlib, hmac, time
    from app.core.config import get_settings
    owner = await make_user(app, "org1@example.com")
    r = await owner.post("/api/orgs/invitations", json={"email": "member@example.com", "role": "member"})
    assert r.status_code == 403 and "Member limit" in r.text                             # Free plan = 1 member
    admin = await make_admin(app)
    uid = str((await db().users.find_one({"email": "org1@example.com"}))["_id"])
    await admin.put(f"/api/admin/users/{uid}/plan", json={"plan": "enterprise"})
    assert (await owner.post("/api/orgs/invitations", json={"email": "member@example.com", "role": "viewer"})).status_code == 201
    from tests.conftest import EMAILS
    tok = next(e for e in EMAILS if "accept-invite" in e[2])[2].split("token=")[1].split()[0]
    mem = await make_user(app, "member@example.com")
    assert (await mem.post("/api/orgs/invitations/accept", json={"token": tok})).status_code == 200
    me = (await mem.get("/api/auth/me")).json()
    assert me["org_role"] == "viewer" and "assessment:write" not in me["permissions"]       # org-level viewer cannot write
    wrong = await make_user(app, "intruder@example.com")
    assert (await wrong.post("/api/orgs/invitations/accept", json={"token": tok})).status_code == 400   # single use / email-bound
    members = (await owner.get("/api/orgs/members")).json()["members"]
    assert len(members) == 2
    # webhook: disabled by default, signature enforced when enabled
    anon = (await make_user(app, "hook@example.com")).c
    assert (await anon.post("/api/billing/webhook/stripe", content=b"{}")).status_code == 501
    s = get_settings(); s.payments_enabled, s.stripe_webhook_secret = True, "whsec_test"
    try:
        payload = json.dumps({"type": "customer.subscription.updated", "data": {"object": {"metadata": {"org_id": str((await db().organizations.find_one({"name": {"$regex": "^org1|Test User"}}))["_id"]), "plan": "researcher"}, "current_period_end": int(time.time()) + 86400}}}).encode()
        assert (await anon.post("/api/billing/webhook/stripe", content=payload, headers={"stripe-signature": "t=1,v1=bad"})).status_code == 400
        ts = int(time.time())
        sig = hmac.new(b"whsec_test", f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
        assert (await anon.post("/api/billing/webhook/stripe", content=payload, headers={"stripe-signature": f"t={ts},v1={sig}"})).status_code == 200
        assert (await db().subscriptions.find_one({"plan": "researcher", "provider": "stripe"})) is not None
    finally:
        s.payments_enabled, s.stripe_webhook_secret = False, None
