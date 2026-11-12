from fastapi import APIRouter, Depends, HTTPException, Request
from ..audit import audit
from ..core.ratelimit import client_ip
from ..db import db
from ..deps import CurrentUser, require, scope
from ..entitlements import require_can_start
from ..jobs import dispatch
from ..schemas import FindingStatusIn, TriageIn
from ..util import esc_re, now, oid, paginate, to_json

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])
TRANSITIONS = {"new": {"confirmed", "closed"}, "confirmed": {"in_progress", "closed"}, "in_progress": {"fixed", "confirmed"},
               "fixed": {"retested", "in_progress"}, "retested": {"closed", "in_progress"}, "closed": {"new"}}
SORTS = {"detected_at": "detected_at", "severity": "severity_rank", "confidence": "confidence", "title": "title"}
HIDE = {"owner_id", "org_id"}


async def own(vid: str, cu: CurrentUser) -> dict:
    v = await db().vulnerabilities.find_one({"_id": oid(vid, "finding"), **scope(cu)})
    if not v:
        raise HTTPException(404, "Finding not found")
    return v


@router.get("")
async def list_(severity: str | None = None, status: str | None = None, triage: str | None = None, category: str | None = None, assessment_id: str | None = None,
                model: str | None = None, q: str | None = None, sort: str = "detected_at", order: str = "desc", page: int = 1, size: int = 20,
                cu: CurrentUser = Depends(require("finding:read"))):
    flt = scope(cu)
    for k, v in (("severity", severity), ("status", status), ("triage", triage), ("category", category), ("model", model)):
        if v:
            flt[k] = v
    if assessment_id:
        flt["assessment_id"] = oid(assessment_id, "assessment")
    if q:
        r = {"$regex": esc_re(q), "$options": "i"}
        flt["$or"] = [{"title": r}, {"finding_id": r}, {"description": r}]
    if sort not in SORTS or order not in ("asc", "desc"):
        raise HTTPException(422, "invalid sort")
    return await paginate(db().vulnerabilities, flt, sort=[(SORTS[sort], 1 if order == "asc" else -1), ("_id", -1)], page=page, size=size,
                          exclude=HIDE | {"evidence", "reproduction_steps", "history"})


@router.get("/stats")
async def stats(cu: CurrentUser = Depends(require("finding:read"))):
    m = scope(cu)
    by = lambda f: db().vulnerabilities.aggregate([{"$match": m}, {"$group": {"_id": f"${f}", "n": {"$sum": 1}}}])
    return {"severity": {r["_id"]: r["n"] async for r in by("severity")}, "status": {r["_id"]: r["n"] async for r in by("status")}, "triage": {r["_id"]: r["n"] async for r in by("triage")}}


@router.get("/{vid}")
async def get(vid: str, cu: CurrentUser = Depends(require("finding:read"))):
    return to_json(await own(vid, cu), HIDE)


@router.patch("/{vid}/status")
async def set_status(vid: str, body: FindingStatusIn, request: Request, cu: CurrentUser = Depends(require("finding:write"))):
    v = await own(vid, cu)
    if body.status not in TRANSITIONS[v["status"]]:
        raise HTTPException(409, f"Cannot move from '{v['status']}' to '{body.status}'. Allowed: {', '.join(sorted(TRANSITIONS[v['status']]))}")
    upd = {"status": body.status}
    if body.status == "retested" and (v.get("last_retest") or {}).get("result") != "passed":
        raise HTTPException(409, "A finding is 'retested' only after a passing retest. Use the retest action.")
    await db().vulnerabilities.update_one({"_id": v["_id"]}, {"$set": upd, "$push": {"history": {"ts": now(), "event": f"status {v['status']} → {body.status}", "by": str(cu.id), "note": body.note}}})
    await audit("finding.status", actor_id=cu.id, target=vid, ip=client_ip(request), meta={"to": body.status})
    return to_json(await db().vulnerabilities.find_one({"_id": v["_id"]}), HIDE)


@router.patch("/{vid}/triage")
async def set_triage(vid: str, body: TriageIn, request: Request, cu: CurrentUser = Depends(require("finding:write"))):
    v = await own(vid, cu)
    upd = {"triage": body.triage}
    if body.triage == "confirmed" and v["status"] == "new":
        upd["status"] = "confirmed"
    if body.triage == "false_positive":
        upd["status"] = "closed"
    if body.triage == "fixed" and v["status"] in ("new", "confirmed", "in_progress"):
        upd["status"] = "fixed"
    await db().vulnerabilities.update_one({"_id": v["_id"]}, {"$set": upd, "$push": {"history": {"ts": now(), "event": f"triage → {body.triage}", "by": str(cu.id), "note": body.note}}})
    await audit("finding.triage", actor_id=cu.id, target=vid, ip=client_ip(request), meta={"triage": body.triage})
    return to_json(await db().vulnerabilities.find_one({"_id": v["_id"]}), HIDE)


@router.post("/{vid}/retest")
async def retest(vid: str, request: Request, cu: CurrentUser = Depends(require("assessment:write"))):
    v = await own(vid, cu)
    a = await db().assessments.find_one({"_id": v["assessment_id"], "org_id": cu.org_id})
    if not a:
        raise HTTPException(404, "Original assessment no longer exists")
    await require_can_start(cu.org_id)
    doc = {k: a[k] for k in ("org_id", "owner_id", "model_config_id", "model_name", "provider", "endpoint", "system_prompt", "params", "intensity", "limits", "ai_analysis", "authorization")}
    doc.update(name=f"Retest {v['finding_id']}", attack_ids=[v["attack_id"]], status="queued", control=None, created_at=now(), usage={"requests": 0, "tokens": 0},
               progress={"total": 1, "done": 0}, score=None, retest_of_finding=v["_id"], owner_id=cu.id)
    r = await db().assessments.insert_one(doc)
    await db().attack_executions.insert_one({"assessment_id": r.inserted_id, "org_id": cu.org_id, "owner_id": cu.id, "attack_id": v["attack_id"], "category": v["category"], "order": 0, "status": "queued", "attempts": 0, "created_at": now()})
    await dispatch(r.inserted_id)
    await audit("finding.retest", actor_id=cu.id, target=vid, ip=client_ip(request))
    return {"assessment_id": str(r.inserted_id)}
