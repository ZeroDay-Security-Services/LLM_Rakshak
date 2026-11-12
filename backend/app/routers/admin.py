import asyncio
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Literal
from ..audit import audit, verify_chain
from ..config_store import DEFAULTS, get_config
from ..core.ratelimit import client_ip, get_redis
from ..db import db
from ..deps import CurrentUser, HIDDEN_USER, require
from ..entitlements import PLANS, effective_plan, usage_this_month
from ..rbac import ROLES
from ..util import esc_re, now, oid, paginate, to_json

router = APIRouter(prefix="/api/admin", tags=["admin"])
ADM = require("admin:access")


class UserPatch(BaseModel):
    is_active: bool | None = None
    role: Literal["super_admin", "admin", "researcher", "user", "viewer"] | None = None


class ConfigPatch(BaseModel):
    registration_open: bool | None = None
    max_concurrent_jobs: int | None = Field(default=None, ge=1, le=500)
    enabled_providers: list[Literal["anthropic", "openai", "gemini", "openai_compatible", "custom"]] | None = None
    features: dict[str, bool] | None = None
    maintenance_mode: bool | None = None


class Announcement(BaseModel):
    text: str = Field(min_length=1, max_length=500)
    level: Literal["info", "warning", "critical"] = "info"
    active: bool = True


class PlanPatch(BaseModel):
    plan: Literal["free", "researcher", "enterprise"]
    days: int | None = Field(default=None, ge=1, le=3650)


@router.get("/stats")
async def stats(cu: CurrentUser = Depends(require("admin:read"))):
    U, A = db().users, db().assessments
    since = now() - timedelta(days=30)
    prov = {f"{r['_id']['provider']}": r async for r in db().usage_records.aggregate([{"$group": {"_id": {"provider": "$provider"}, "requests": {"$sum": "$requests"}, "tokens": {"$sum": "$tokens"}, "n": {"$sum": 1}}}])}
    return {"users": {"total": await U.count_documents({}), "active": await U.count_documents({"is_active": True}), "suspended": await U.count_documents({"is_active": False}),
                      "new_30d": await U.count_documents({"created_at": {"$gte": since}}), "active_30d": await U.count_documents({"last_login_at": {"$gte": since}})},
            "assessments": {"total": await A.count_documents({"status": {"$ne": "draft"}}), "by_status": {r["_id"]: r["n"] async for r in A.aggregate([{"$group": {"_id": "$status", "n": {"$sum": 1}}}])}},
            "vulnerabilities": {"total": await db().vulnerabilities.count_documents({}), "by_severity": {r["_id"]: r["n"] async for r in db().vulnerabilities.aggregate([{"$group": {"_id": "$severity", "n": {"$sum": 1}}}])}},
            "provider_usage": {k: {"requests": v["requests"], "tokens": v["tokens"], "assessments": v["n"]} for k, v in prov.items()},
            "api_requests_total": sum(v["requests"] for v in prov.values()),
            "errors": {"failed_assessments_7d": await A.count_documents({"status": "failed", "finished_at": {"$gte": now() - timedelta(days=7)}}), "failed_jobs_7d": await db().assessment_jobs.count_documents({"status": "failed", "created_at": {"$gte": now() - timedelta(days=7)}})},
            "plans": {r["_id"]: r["n"] async for r in db().subscriptions.aggregate([{"$group": {"_id": "$plan", "n": {"$sum": 1}}}])}}


async def _series(coll: str, field: str, since, flt: dict | None = None):
    pipe = [{"$match": {field: {"$gte": since}, **(flt or {})}}, {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": f"${field}"}}, "n": {"$sum": 1}}}, {"$sort": {"_id": 1}}]
    return [{"date": r["_id"], "count": r["n"]} async for r in db()[coll].aggregate(pipe)]


@router.get("/analytics")
async def analytics(cu: CurrentUser = Depends(require("admin:read"))):
    since = now() - timedelta(days=30)
    return {"signups": await _series("users", "created_at", since), "assessments": await _series("assessments", "created_at", since, {"status": {"$ne": "draft"}}),
            "findings": await _series("vulnerabilities", "detected_at", since), "logins": await _series("login_history", "ts", since, {"success": True}),
            "top_categories": [{"category": r["_id"], "count": r["n"]} async for r in db().vulnerabilities.aggregate([{"$group": {"_id": "$category", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}])]}


@router.get("/health")
async def health(cu: CurrentUser = Depends(require("admin:read"))):
    out = {"database": {"ok": False}, "redis": {"ok": False}, "workers": {"ok": False, "count": 0}, "queue": {}}
    try:
        await db().command("ping"); out["database"] = {"ok": True}
    except Exception as e:  # noqa
        out["database"] = {"ok": False, "error": type(e).__name__}
    try:
        r = get_redis(); await r.ping(); out["redis"] = {"ok": True, "queue_depth": await r.llen("celery")}
    except Exception as e:  # noqa
        out["redis"] = {"ok": False, "error": type(e).__name__}
    try:
        from ..worker import celery_app
        pong = await asyncio.wait_for(asyncio.to_thread(lambda: celery_app.control.ping(timeout=1.0)), 3)
        out["workers"] = {"ok": bool(pong), "count": len(pong or [])}
    except Exception as e:  # noqa
        out["workers"] = {"ok": False, "count": 0, "error": type(e).__name__}
    out["jobs"] = {r["_id"]: r["n"] async for r in db().assessment_jobs.aggregate([{"$match": {"created_at": {"$gte": now() - timedelta(days=1)}}}, {"$group": {"_id": "$status", "n": {"$sum": 1}}}])}
    out["status"] = "ok" if out["database"]["ok"] and out["redis"]["ok"] else "degraded"
    return out


@router.get("/users")
async def users(q: str | None = None, role: str | None = None, active: bool | None = None, page: int = 1, size: int = 25, cu: CurrentUser = Depends(require("admin:users"))):
    flt: dict = {}
    if q:
        r = {"$regex": esc_re(q), "$options": "i"}
        flt["$or"] = [{"email": r}, {"name": r}]
    if role:
        if role not in ROLES:
            raise HTTPException(422, "invalid role")
        flt["role"] = role
    if active is not None:
        flt["is_active"] = active
    return await paginate(db().users, flt, sort=[("created_at", -1)], page=page, size=size, exclude=HIDDEN_USER | {"preferences"})


@router.get("/users/{uid}")
async def user_detail(uid: str, cu: CurrentUser = Depends(require("admin:users"))):
    u = await db().users.find_one({"_id": oid(uid, "user")})
    if not u:
        raise HTTPException(404, "User not found")
    mem = await db().organization_members.find_one({"user_id": u["_id"]})
    return {"user": to_json(u, HIDDEN_USER | {"preferences"}), "usage": await usage_this_month(mem["org_id"]) if mem else None,
            "plan": (await effective_plan(mem["org_id"]))[0] if mem else None,
            "assessments": await db().assessments.count_documents({"owner_id": u["_id"], "status": {"$ne": "draft"}}),
            "activity": [to_json(a, {"_id", "hash", "prev"}) async for a in db().audit_logs.find({"actor_id": uid}).sort("seq", -1).limit(30)],
            "logins": [to_json(h, {"user_id", "expires_at"}) async for h in db().login_history.find({"user_id": u["_id"]}).sort("ts", -1).limit(15)]}


@router.patch("/users/{uid}")
async def patch_user(uid: str, body: UserPatch, request: Request, cu: CurrentUser = Depends(require("admin:users"))):
    u = await db().users.find_one({"_id": oid(uid, "user")})
    if not u:
        raise HTTPException(404, "User not found")
    upd = {}
    if body.role is not None and body.role != u["role"]:
        if "admin:roles" not in cu.perms:
            raise HTTPException(403, "Only a super admin can change roles")
        if u["_id"] == cu.id:
            raise HTTPException(409, "You cannot change your own role")
        upd["role"] = body.role
    if body.is_active is not None and body.is_active != u["is_active"]:
        if u["_id"] == cu.id:
            raise HTTPException(409, "You cannot deactivate your own account")
        if u["role"] in ("super_admin", "admin") and cu.role != "super_admin":
            raise HTTPException(403, "Only a super admin can suspend administrators")
        upd["is_active"] = body.is_active
    if not upd:
        return to_json(u, HIDDEN_USER)
    await db().users.update_one({"_id": u["_id"]}, {"$set": upd})
    if upd.get("is_active") is False or "role" in upd:
        await db().sessions.update_many({"user_id": u["_id"]}, {"$set": {"revoked": True}})  # force re-auth with new privileges
    await audit("admin.user_updated", actor_id=cu.id, actor_email=cu.user["email"], target=uid, ip=client_ip(request), meta=upd)
    return to_json(await db().users.find_one({"_id": u["_id"]}), HIDDEN_USER)


@router.put("/users/{uid}/plan")
async def set_plan(uid: str, body: PlanPatch, request: Request, cu: CurrentUser = Depends(require("admin:billing"))):
    mem = await db().organization_members.find_one({"user_id": oid(uid, "user"), "role": "owner"})
    if not mem:
        raise HTTPException(404, "No owned organization")
    await db().subscriptions.update_one({"org_id": mem["org_id"]}, {"$set": {"plan": body.plan, "status": "active", "provider": "admin", "updated_at": now(),
                                         "current_period_end": now() + timedelta(days=body.days) if body.days else None}}, upsert=True)
    await audit("admin.plan_set", actor_id=cu.id, actor_email=cu.user["email"], target=uid, ip=client_ip(request), meta={"plan": body.plan})
    return {"plan": body.plan}


@router.get("/assessments")
async def assessments(status: str | None = None, page: int = 1, size: int = 25, cu: CurrentUser = Depends(require("admin:read"))):
    flt = {"status": status} if status else {"status": {"$ne": "draft"}}
    return await paginate(db().assessments, flt, sort=[("created_at", -1)], page=page, size=size, exclude={"system_prompt", "authorization", "attack_ids", "notes", "summary", "score"})


@router.get("/settings")
async def get_settings_(cu: CurrentUser = Depends(require("admin:read"))):
    return await get_config()


@router.put("/settings")
async def put_settings(body: ConfigPatch, request: Request, cu: CurrentUser = Depends(require("admin:config"))):
    upd = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if "features" in upd:
        unknown = set(upd["features"]) - set(DEFAULTS["features"])
        if unknown:
            raise HTTPException(422, f"Unknown feature flags: {sorted(unknown)}")
    if upd:
        await db().platform_settings.update_one({"_id": "config"}, {"$set": upd}, upsert=True)
        await audit("admin.config_changed", actor_id=cu.id, actor_email=cu.user["email"], ip=client_ip(request), meta=upd)
    return await get_config()


@router.post("/announcements")
async def announce(body: Announcement, request: Request, cu: CurrentUser = Depends(require("admin:config"))):
    await db().platform_settings.update_one({"_id": "config"}, {"$set": {"announcement": body.model_dump()}}, upsert=True)
    if body.active:
        docs = [{"user_id": u["_id"], "type": "announcement", "title": "Announcement", "body": body.text, "link": None, "read": False, "created_at": now(), "expires_at": now() + timedelta(days=30)}
                async for u in db().users.find({"is_active": True}, {"_id": 1})]
        if docs:
            await db().notifications.insert_many(docs)
    await audit("admin.announcement", actor_id=cu.id, actor_email=cu.user["email"], ip=client_ip(request), meta={"level": body.level})
    return {"message": "Published"}


@router.get("/audit")
async def audit_logs(action: str | None = None, actor: str | None = None, page: int = 1, size: int = 50, cu: CurrentUser = Depends(require("audit:read"))):
    flt: dict = {}
    if action:
        flt["action"] = {"$regex": "^" + esc_re(action), "$options": "i"}
    if actor:
        flt["$or"] = [{"actor_id": actor}, {"actor_email": {"$regex": esc_re(actor), "$options": "i"}}]
    return await paginate(db().audit_logs, flt, sort=[("seq", -1)], page=page, size=size, exclude={"prev"})


@router.get("/audit/verify")
async def audit_verify(cu: CurrentUser = Depends(require("audit:read"))):
    return await verify_chain()
