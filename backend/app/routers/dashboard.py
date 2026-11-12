from datetime import timedelta
from fastapi import APIRouter, Depends
from ..db import db
from ..deps import CurrentUser, require, scope
from ..entitlements import effective_plan
from ..util import now, to_json

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
SEV = ["critical", "high", "medium", "low", "info"]


@router.get("")
async def dashboard(cu: CurrentUser = Depends(require("assessment:read"))):
    m = scope(cu)
    A, V = db().assessments, db().vulnerabilities
    by_status = {r["_id"]: r["n"] async for r in A.aggregate([{"$match": {**m, "status": {"$ne": "draft"}}}, {"$group": {"_id": "$status", "n": {"$sum": 1}}}])}
    total = sum(by_status.values())
    open_v = {**m, "triage": {"$nin": ["false_positive", "accepted_risk", "fixed"]}, "status": {"$ne": "closed"}}
    sev = {r["_id"]: r["n"] async for r in V.aggregate([{"$match": open_v}, {"$group": {"_id": "$severity", "n": {"$sum": 1}}}])}
    cat = {r["_id"]: r["n"] async for r in V.aggregate([{"$match": open_v}, {"$group": {"_id": "$category", "n": {"$sum": 1}}}])}
    done = [a async for a in A.find({**m, "status": "completed", "score.overall": {"$ne": None}}, {"name": 1, "model_name": 1, "provider": 1, "score.overall": 1, "finished_at": 1}).sort("finished_at", -1).limit(100)]
    latest_per_model: dict = {}
    for a in done:
        latest_per_model.setdefault(f"{a['provider']}/{a['model_name']}", a)
    posture = round(sum(a["score"]["overall"] for a in latest_per_model.values()) / len(latest_per_model)) if latest_per_model else None
    since = now() - timedelta(days=30)
    hist = {r["_id"]: r async for r in A.aggregate([{"$match": {**m, "created_at": {"$gte": since}, "status": {"$ne": "draft"}}},
                                                      {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}}, "created": {"$sum": 1}, "completed": {"$sum": {"$cond": [{"$eq": ["$status", "completed"]}, 1, 0]}}, "failed": {"$sum": {"$cond": [{"$eq": ["$status", "failed"]}, 1, 0]}}}}])}
    history = [{"date": d, "created": v["created"], "completed": v["completed"], "failed": v["failed"]} for d, v in sorted(hist.items())]
    models = [{"model": k, "score": v["score"]["overall"], "assessment": str(v["_id"])} for k, v in latest_per_model.items()]
    for r in models:
        r["findings"] = await V.count_documents({**open_v, "model": r["model"]})
    recent_a = [to_json(a, {"owner_id", "org_id", "authorization", "attack_ids", "limits", "params", "system_prompt"}) async for a in A.find({**m, "status": {"$ne": "draft"}}).sort("created_at", -1).limit(5)]
    recent_v = [to_json(v, {"owner_id", "org_id", "evidence", "reproduction_steps", "history", "description", "impact", "remediation"}) async for v in V.find(m).sort("detected_at", -1).limit(5)]
    recent_r = [to_json(r, {"content", "owner_id", "org_id"}) async for r in db().assessment_reports.find(m).sort("created_at", -1).limit(5)]
    acct = [to_json(h, {"user_id", "expires_at"}) async for h in db().login_history.find({"user_id": cu.id}).sort("ts", -1).limit(5)]
    notifs = [to_json(n, {"user_id", "expires_at"}) async for n in db().notifications.find({"user_id": cu.id}).sort("created_at", -1).limit(5)]
    _, plan = await effective_plan(cu.org_id)
    return {"empty": total == 0, "totals": {"assessments": total, "completed": by_status.get("completed", 0), "running": sum(by_status.get(k, 0) for k in ("running", "queued", "pausing")),
                                            "vulnerabilities": sum(sev.values()), **{k: sev.get(k, 0) for k in SEV}, "posture_score": posture},
            "charts": {"severity": [{"severity": s, "count": sev.get(s, 0)} for s in SEV], "categories": [{"category": k, "count": v} for k, v in cat.items()],
                       "assessment_history": history, "score_trend": [{"date": to_json(a["finished_at"])[:10], "score": a["score"]["overall"], "name": a["name"]} for a in reversed(done[:20])],
                       "model_comparison": models, "outcomes": [{"status": s, "count": by_status.get(s, 0)} for s in ("completed", "failed", "cancelled")]},
            "recent": {"assessments": recent_a, "vulnerabilities": recent_v, "reports": recent_r, "account_activity": acct, "notifications": notifs}, "analytics_level": plan["analytics"]}
