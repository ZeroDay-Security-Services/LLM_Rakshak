"""Real-process smoke test: uvicorn API + Celery worker + Redis broker + MongoDB + a local mock target.
Usage: python scripts/smoke_celery.py   (requires mongod on 27017 and redis on 6379)"""
import os, subprocess, sys, time, socket, secrets, threading
import httpx
from cryptography.fernet import Fernet

ENV = {**os.environ, "LLMGUARD_ENV": "test", "LLMGUARD_JWT_SECRET": secrets.token_hex(24), "LLMGUARD_ENCRYPTION_KEYS": Fernet.generate_key().decode(), "LLMGUARD_MONGODB_DB": "llmguard_smoke",
       "LLMGUARD_REDIS_URL": "redis://127.0.0.1:6379/14", "LLMGUARD_COOKIE_SECURE": "false", "LLMGUARD_TASK_BACKEND": "celery", "LLMGUARD_ALLOW_PRIVATE_TARGETS": "true", "LLMGUARD_ALLOW_HTTP_TARGETS": "true",
       "PYTHONPATH": os.getcwd()}
procs = []


def port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def spawn(*a):
    p = subprocess.Popen(a, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True); procs.append(p); return p


def wait(url, n=100):
    for _ in range(n):
        try:
            if httpx.get(url, timeout=1).status_code < 500: return
        except Exception: time.sleep(0.2)
    raise SystemExit(f"timeout waiting for {url}")


try:
    import pymongo
    pymongo.MongoClient().drop_database("llmguard_smoke")
    llm, api = port(), port()
    spawn(sys.executable, "-c", f"import uvicorn; from tests.mock_llm import build; uvicorn.run(build(), host='127.0.0.1', port={llm}, log_level='error')")
    spawn(sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(api), "--log-level", "warning")
    worker = spawn(sys.executable, "-m", "celery", "-A", "app.worker.celery_app", "worker", "-l", "warning", "--concurrency=2", "-Q", "celery")
    wait(f"http://127.0.0.1:{api}/api/health"); time.sleep(3)
    c = httpx.Client(base_url=f"http://127.0.0.1:{api}", timeout=30)
    pw = "Str0ng-Passw0rd!x"
    import asyncio
    from motor.motor_asyncio import AsyncIOMotorClient
    db = pymongo.MongoClient()["llmguard_smoke"]
    assert c.post("/api/auth/register", json={"email": "s@example.com", "password": pw, "name": "Smoke"}).status_code == 202
    db.users.update_one({"email": "s@example.com"}, {"$set": {"email_verified": True}})
    assert c.post("/api/auth/login", json={"email": "s@example.com", "password": pw}).status_code == 200
    H = lambda: {"X-CSRF-Token": c.cookies.get("lg_csrf")}
    ep = f"http://127.0.0.1:{llm}/vuln/v1"
    assert c.put("/api/credentials/custom", json={"api_key": "sk-smoke-0123456789abcdef", "endpoint": ep}, headers=H()).status_code == 200
    m = c.post("/api/models", json={"name": "t", "provider": "custom", "model": "mock", "endpoint": ep}, headers=H()).json()
    a = c.post("/api/assessments", json={"name": "celery smoke", "model_config_id": m["id"], "preset": "quick", "intensity": "high", "limits": {"max_requests": 60},
                                         "authorization": {"confirmed": True, "statement": "I own this local mock target.", "endpoint_owner_confirmed": True}}, headers=H()).json()
    assert c.post(f"/api/assessments/{a['id']}/start", headers=H()).status_code == 200
    for _ in range(120):
        pr = c.get(f"/api/assessments/{a['id']}/progress").json()
        if pr["status"] in ("completed", "failed"): break
        time.sleep(0.5)
    print("status:", pr["status"], "| finished:", pr["finished"], "/", pr["total"], "| score:", (pr.get("score") or {}).get("overall"), "| failed tests:", (pr.get("score") or {}).get("failed"))
    job = db.assessment_jobs.find_one({"assessment_id": __import__("bson").ObjectId(a["id"])})
    print("job:", job["status"], "| celery task id:", job.get("celery_id"))
    assert pr["status"] == "completed" and job["status"] == "completed" and job.get("celery_id")
    print("CELERY SMOKE OK")
finally:
    for p in procs:
        p.terminate()
