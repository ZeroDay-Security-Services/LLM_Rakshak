import csv, io, json
from datetime import timedelta
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from ..audit import audit
from ..attacks.schema import CATEGORIES
from ..config_store import get_config
from ..core.ratelimit import client_ip, limit
from ..db import db
from ..deps import CurrentUser, require, scope
from ..engine.runner import INTENSITY
from ..entitlements import effective_plan, month_start, require_can_start
from ..jobs import dispatch
from ..schemas import AssessmentIn
from ..util import now, oid, paginate, to_json

router = APIRouter(prefix="/api/assessments", tags=["assessments"])
HIDE_A = {"owner_id", "org_id"}
PRESETS = {"quick": {"categories": ["prompt_injection", "system_prompt", "sensitive_disclosure"], "tiers": ["basic"]},
           "standard": {"categories": CATEGORIES, "tiers": ["basic"]}, "full": {"categories": CATEGORIES, "tiers": ["basic", "advanced"]}}
ACTIVE = ["queued", "running", "pausing", "cancelling"]


def csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


async def own(aid: str, cu: CurrentUser, proj=None) -> dict:
    a = await db().assessments.find_one({"_id": oid(aid, "assessment"), **scope(cu)}, proj)
    if not a:
        raise HTTPException(404, "Assessment not found")  # same response for foreign and missing ids (no IDOR oracle)
    return a


def estimate(attacks: list[dict], intensity: str) -> int:
    n = 0
    for a in attacks:
        d = a.get("dos")
        n += INTENSITY[intensity]["burst"] if d and d["kind"] == "burst" else (1 if d else a.get("repeat", 1))
    return n + 1


@router.post("", status_code=201)
async def create(body: AssessmentIn, request: Request, cu: CurrentUser = Depends(require("assessment:write"))):
    if not body.authorization.confirmed:
        raise HTTPException(422, "You must confirm you own or are explicitly authorised to test this target")
    m = await db().model_configurations.find_one({"_id": oid(body.model_config_id, "model"), **scope(cu)})
    if not m:
        raise HTTPException(404, "Model not found")
    if m["provider"] in ("custom", "openai_compatible") and not body.authorization.endpoint_owner_confirmed:
        raise HTTPException(422, "Confirm that you own or are authorised to test this custom endpoint")
    pname, plan = await effective_plan(cu.org_id)
    flt: dict = {"$or": [{"builtin": True}, {"org_id": cu.org_id}]}
    excluded = 0
    if body.attack_ids:
        found = [d async for d in db().attack_modules.find({**flt, "attack_id": {"$in": body.attack_ids}})]
        if len(found) != len(set(body.attack_ids)):
            raise HTTPException(422, "One or more attacks do not exist")
        if any(d["tier"] not in plan["tiers"] for d in found):
            raise HTTPException(403, f"Selected attacks include modules not available on the {plan['label']} plan")
        attacks = found
    else:
        preset = PRESETS[body.preset or "standard"]
        cats = body.categories or preset["categories"]
        if any(c not in CATEGORIES for c in cats):
            raise HTTPException(422, "Unknown category")
        allowed_tiers = [t for t in preset["tiers"] if t in plan["tiers"]] if body.preset else plan["tiers"]
        attacks = [d async for d in db().attack_modules.find({**flt, "category": {"$in": cats}, "tier": {"$in": allowed_tiers}})]
        excluded = await db().attack_modules.count_documents({**flt, "category": {"$in": cats}}) - len(attacks)
    if not attacks:
        raise HTTPException(422, "No attacks selected")
    if body.limits.max_requests > plan["max_requests_per_assessment"]:
        raise HTTPException(403, f"The {plan['label']} plan allows at most {plan['max_requests_per_assessment']} requests per assessment")
    attacks.sort(key=lambda d: (CATEGORIES.index(d["category"]), d["attack_id"]))
    params = (body.params or None) and body.params.model_dump()
    doc = {"name": body.name.strip(), "org_id": cu.org_id, "owner_id": cu.id, "model_config_id": m["_id"], "model_name": m["model"], "provider": m["provider"],
           "endpoint": m.get("endpoint"), "system_prompt": body.system_prompt if body.system_prompt is not None else m.get("system_prompt", ""),
           "params": params or m.get("params", {}), "attack_ids": [d["attack_id"] for d in attacks], "intensity": body.intensity, "limits": body.limits.model_dump(),
           "ai_analysis": body.ai_analysis, "authorization": {**body.authorization.model_dump(), "confirmed_at": now(), "ip": client_ip(request)}, "notes": body.notes,
           "status": "draft", "control": None, "created_at": now(), "usage": {"requests": 0, "tokens": 0}, "progress": {"total": len(attacks), "done": 0}, "score": None}
    r = await db().assessments.insert_one(doc)
    await audit("assessment.created", actor_id=cu.id, target=str(r.inserted_id), ip=client_ip(request), meta={"attacks": len(attacks), "provider": m["provider"], "authorization": body.authorization.statement[:200]})
    out = to_json(await db().assessments.find_one({"_id": r.inserted_id}), HIDE_A)
    out["estimated_requests"] = estimate(attacks, body.intensity)
    out["excluded_by_plan"] = excluded
    return out


@router.get("")
async def list_(status: str | None = None, q: str | None = None, page: int = 1, size: int = 20, cu: CurrentUser = Depends(require("assessment:read"))):
    flt = scope(cu)
    if status:
        flt["status"] = status
    if q:
        from ..util import esc_re
        flt["name"] = {"$regex": esc_re(q), "$options": "i"}
    return await paginate(db().assessments, flt, sort=[("created_at", -1)], page=page, size=size, exclude=HIDE_A | {"authorization"})


@router.get("/compare")
async def compare(ids: str, cu: CurrentUser = Depends(require("assessment:read"))):
    out = []
    for i in ids.split(",")[:6]:
        a = await own(i, cu)
        if a.get("score"):
            out.append({"id": str(a["_id"]), "name": a["name"], "model": f"{a['provider']}/{a['model_name']}", "overall": a["score"]["overall"],
                        "coverage": a["score"]["coverage"], "categories": {k: v["score"] for k, v in a["score"]["categories"].items()}})
    return out


@router.get("/{aid}")
async def get(aid: str, cu: CurrentUser = Depends(require("assessment:read"))):
    return to_json(await own(aid, cu), HIDE_A)


@router.delete("/{aid}")
async def delete(aid: str, request: Request, cu: CurrentUser = Depends(require("assessment:write"))):
    a = await own(aid, cu)
    if a["status"] in ACTIVE:
        raise HTTPException(409, "Cancel the assessment before deleting it")
    for c in ("attack_executions", "vulnerabilities", "assessment_reports", "assessment_jobs", "usage_records"):
        await db()[c].delete_many({"assessment_id": a["_id"]})
    await db().assessments.delete_one({"_id": a["_id"]})
    await audit("assessment.deleted", actor_id=cu.id, target=aid, ip=client_ip(request))
    return {"message": "Deleted"}


@router.post("/{aid}/start", dependencies=[limit("start", 30, 3600)])
async def start(aid: str, request: Request, cu: CurrentUser = Depends(require("assessment:write"))):
    a = await own(aid, cu)
    if a["status"] != "draft":
        raise HTTPException(409, f"Assessment is {a['status']}; only drafts can be started")
    cfg = await get_config()
    if cfg["maintenance_mode"]:
        raise HTTPException(503, "Platform is in maintenance mode")
    pname, plan = await require_can_start(cu.org_id)
    used = await db().assessments.count_documents({"org_id": cu.org_id, "created_at": {"$gte": month_start()}, "status": {"$nin": ["draft"]}})
    if used >= plan["assessments_per_month"]:
        raise HTTPException(429, f"Monthly assessment quota reached for the {plan['label']} plan")
    if await db().assessments.count_documents({"status": {"$in": ["queued", "running"]}}) >= cfg["max_concurrent_jobs"]:
        raise HTTPException(429, "The platform is at capacity. Try again shortly.")
    if a["ai_analysis"] and not plan["ai_analysis"]:
        await db().assessments.update_one({"_id": a["_id"]}, {"$set": {"ai_analysis": False}})
    mods = {m["attack_id"]: m async for m in db().attack_modules.find({"attack_id": {"$in": a["attack_ids"]}})}
    docs = []
    for i, aid_ in enumerate(a["attack_ids"]):
        m = mods.get(aid_)
        if not m:
            continue
        na = "*" not in m["applies_to"] and a["provider"] not in m["applies_to"]
        docs.append({"assessment_id": a["_id"], "org_id": a["org_id"], "owner_id": a["owner_id"], "attack_id": aid_, "category": m["category"], "order": i,
                     "status": "skipped" if na else "queued", "reason": "not applicable to this provider type" if na else None, "attempts": 0, "created_at": now()})
    if docs:
        await db().attack_executions.insert_many(docs, ordered=False)
    await db().assessments.update_one({"_id": a["_id"]}, {"$set": {"status": "queued", "control": None, "queued_at": now(), "progress": {"total": len(docs), "done": sum(d["status"] == "skipped" for d in docs)}}})
    await dispatch(a["_id"])
    await audit("assessment.started", actor_id=cu.id, target=aid, ip=client_ip(request))
    return {"status": "queued"}


def _stale(a):
    h = a.get("heartbeat_at")
    return not h or (now() - (h if h.tzinfo else h.replace(tzinfo=now().tzinfo))) > timedelta(minutes=3)


@router.post("/{aid}/pause")
async def pause(aid: str, cu: CurrentUser = Depends(require("assessment:write"))):
    a = await own(aid, cu)
    if a["status"] == "queued" or (a["status"] == "running" and _stale(a)):
        await db().assessments.update_one({"_id": a["_id"]}, {"$set": {"status": "paused", "control": None}})
        return {"status": "paused"}
    if a["status"] != "running":
        raise HTTPException(409, f"Cannot pause an assessment that is {a['status']}")
    await db().assessments.update_one({"_id": a["_id"]}, {"$set": {"control": "pause", "status": "pausing"}})
    return {"status": "pausing"}


@router.post("/{aid}/resume")
async def resume(aid: str, cu: CurrentUser = Depends(require("assessment:write"))):
    a = await own(aid, cu)
    stale = a["status"] in ("running", "pausing") and _stale(a)
    if a["status"] != "paused" and not stale:
        raise HTTPException(409, f"Cannot resume an assessment that is {a['status']}")
    await db().attack_executions.update_many({"assessment_id": a["_id"], "status": "running"}, {"$set": {"status": "queued"}})
    await db().assessments.update_one({"_id": a["_id"]}, {"$set": {"status": "queued", "control": None}})
    await dispatch(a["_id"])
    return {"status": "queued"}


@router.post("/{aid}/cancel")
async def cancel(aid: str, request: Request, cu: CurrentUser = Depends(require("assessment:write"))):
    a = await own(aid, cu)
    if a["status"] in ("queued", "paused", "draft") or (a["status"] in ("running", "pausing") and _stale(a)):
        await db().attack_executions.update_many({"assessment_id": a["_id"], "status": {"$in": ["queued", "running"]}}, {"$set": {"status": "skipped", "reason": "cancelled", "finished_at": now()}})
        await db().assessments.update_one({"_id": a["_id"]}, {"$set": {"status": "cancelled", "control": None, "finished_at": now()}})
        await audit("assessment.cancelled", actor_id=cu.id, target=aid, ip=client_ip(request))
        return {"status": "cancelled"}
    if a["status"] not in ("running", "pausing"):
        raise HTTPException(409, f"Cannot cancel an assessment that is {a['status']}")
    await db().assessments.update_one({"_id": a["_id"]}, {"$set": {"control": "cancel", "status": "cancelling"}})
    return {"status": "cancelling"}


@router.get("/{aid}/progress")
async def progress(aid: str, cu: CurrentUser = Depends(require("assessment:read"))):
    a = await own(aid, cu)
    c = {r["_id"]: r["n"] async for r in db().attack_executions.aggregate([{"$match": {"assessment_id": a["_id"]}}, {"$group": {"_id": "$status", "n": {"$sum": 1}}}])}
    total = sum(c.values())
    finished = sum(v for k, v in c.items() if k not in ("queued", "running"))
    running = [e["attack_id"] async for e in db().attack_executions.find({"assessment_id": a["_id"], "status": "running"}, {"attack_id": 1})]
    return {"status": a["status"], "total": total, "finished": finished, "percent": round(100 * finished / total) if total else 0, "counts": c, "running": running,
            "usage": a.get("usage"), "limits": a.get("limits"), "started_at": to_json(a.get("started_at")), "heartbeat_at": to_json(a.get("heartbeat_at")), "error": a.get("error"),
            "score": a.get("score") if a["status"] == "completed" else None}


@router.get("/{aid}/executions")
async def executions(aid: str, status: str | None = None, category: str | None = None, page: int = 1, size: int = 50, cu: CurrentUser = Depends(require("assessment:read"))):
    a = await own(aid, cu)
    flt = {"assessment_id": a["_id"]}
    if status:
        flt["status"] = status
    if category:
        flt["category"] = category
    res = await paginate(db().attack_executions, flt, sort=[("order", 1)], page=page, size=size, exclude={"owner_id", "org_id", "transcript", "tokens_ctx"})
    names = {m["attack_id"]: m["name"] async for m in db().attack_modules.find({"attack_id": {"$in": [i["attack_id"] for i in res["items"]]}}, {"attack_id": 1, "name": 1})}
    for i in res["items"]:
        i["attack_name"] = names.get(i["attack_id"])
    return res


@router.get("/{aid}/executions/{eid}")
async def execution(aid: str, eid: str, cu: CurrentUser = Depends(require("assessment:read"))):
    a = await own(aid, cu)
    e = await db().attack_executions.find_one({"_id": oid(eid, "execution"), "assessment_id": a["_id"]})
    if not e:
        raise HTTPException(404, "Execution not found")
    m = await db().attack_modules.find_one({"attack_id": e["attack_id"]}, {"name": 1, "expected_secure": 1, "expected_vulnerable": 1, "description": 1})
    return to_json(e, {"owner_id", "org_id"}) | {"attack": to_json(m, {"_id"})}


@router.post("/{aid}/executions/{eid}/retry")
async def retry(aid: str, eid: str, cu: CurrentUser = Depends(require("assessment:write"))):
    a = await own(aid, cu)
    e = await db().attack_executions.find_one({"_id": oid(eid, "execution"), "assessment_id": a["_id"]})
    if not e:
        raise HTTPException(404, "Execution not found")
    if a["status"] in ACTIVE:
        raise HTTPException(409, "Wait for the assessment to stop before retrying")
    if e["status"] not in ("error", "inconclusive", "skipped") or e.get("reason") == "not applicable to this provider type":
        raise HTTPException(409, "Only failed-to-run, inconclusive or budget-skipped tests can be retried")
    if e.get("attempts", 0) >= a["limits"]["retries"] + 1:
        raise HTTPException(429, "Retry limit reached for this test")
    await db().attack_executions.update_one({"_id": e["_id"]}, {"$set": {"status": "queued", "reason": None}})
    await db().assessments.update_one({"_id": a["_id"]}, {"$set": {"status": "queued", "control": None}})
    await dispatch(a["_id"])
    return {"status": "queued"}


@router.get("/{aid}/logs")
async def logs(aid: str, cu: CurrentUser = Depends(require("assessment:read"))):
    a = await own(aid, cu)
    lines = [{"ts": to_json(a["created_at"]), "level": "info", "message": f"Assessment created ({len(a['attack_ids'])} attacks, intensity {a['intensity']})"}]
    async for e in db().attack_executions.find({"assessment_id": a["_id"], "finished_at": {"$exists": True}}, {"attack_id": 1, "status": 1, "confidence": 1, "finished_at": 1, "reason": 1, "error": 1}).sort("finished_at", 1):
        lvl = {"failed": "warn", "error": "error"}.get(e["status"], "info")
        lines.append({"ts": to_json(e["finished_at"]), "level": lvl, "message": f"{e['attack_id']}: {e['status']}" + (f" (confidence {e['confidence']:.2f})" if e.get("confidence") else "") + (f" - {e.get('reason') or e.get('error')}" if e.get("reason") or e.get("error") else "")})
    async for j in db().assessment_jobs.find({"assessment_id": a["_id"]}).sort("created_at", 1):
        lines.append({"ts": to_json(j["created_at"]), "level": "info", "message": f"Job {j['status']}" + (f": {j['error']}" if j.get("error") else "")})
    if a.get("error"):
        lines.append({"ts": to_json(a.get("finished_at") or now()), "level": "error", "message": a["error"]})
    lines.sort(key=lambda x: x["ts"])
    return lines


@router.get("/{aid}/export")
async def export(aid: str, format: str = "json", cu: CurrentUser = Depends(require("assessment:read"))):
    a = await own(aid, cu)
    fs = [f async for f in db().vulnerabilities.find({"assessment_id": a["_id"]}).sort("severity_rank", -1)]
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["finding_id", "title", "category", "severity", "confidence", "status", "triage", "cvss", "owasp", "cwe", "detected_at"])
        for f in fs:
            w.writerow([csv_safe(x) for x in (f["finding_id"], f["title"], f["category"], f["severity"], f["confidence"], f["status"], f["triage"], (f.get("cvss") or {}).get("score"), ";".join(f["owasp"]), ";".join(f["cwe"]), to_json(f["detected_at"]))])
        return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="zeroday-llm-rakshak-{aid}-findings.csv"', "X-Content-Type-Options": "nosniff"})
    if format != "json":
        raise HTTPException(422, "format must be json or csv")
    return Response(json.dumps(to_json(fs, {"owner_id", "org_id"}), indent=2), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="zeroday-llm-rakshak-{aid}-findings.json"', "X-Content-Type-Options": "nosniff"})


@router.post("/{aid}/suggestions", dependencies=[limit("suggest", 10, 3600)])
async def suggestions(aid: str, cu: CurrentUser = Depends(require("assessment:write"))):
    """Claude proposes additional SAFE test cases; nothing is executed or saved until the user creates a custom attack from one."""
    from ..engine.runner import get_analyzer
    a = await own(aid, cu)
    an = await get_analyzer({**a, "ai_analysis": True})
    if not an:
        raise HTTPException(400, "AI analysis is unavailable: add an Anthropic key (Researcher plan or above)")
    fs = [{"title": f["title"], "category": f["category"], "severity": f["severity"]} async for f in db().vulnerabilities.find({"assessment_id": a["_id"]}).limit(20)]
    sg = await an.suggest({"model": a["model_name"], "findings": fs})
    return [s.model_dump() for s in sg]
