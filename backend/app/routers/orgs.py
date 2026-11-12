from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from ..audit import audit
from ..config_store import get_config
from ..core import security
from ..core.config import get_settings
from ..core.mailer import send_email
from ..core.ratelimit import client_ip, limit
from ..db import db
from ..deps import CurrentUser, current_user, require
from ..entitlements import effective_plan, usage_this_month
from ..schemas import InviteIn, MemberRoleIn, OrgPatch
from ..util import now, oid, to_json

router = APIRouter(prefix="/api/orgs", tags=["organizations"])


@router.get("/current")
async def current(cu: CurrentUser = Depends(require("org:read"))):
    o = await db().organizations.find_one({"_id": cu.org_id})
    pname, plan = await effective_plan(cu.org_id)
    return {"organization": to_json(o), "role": cu.org_role, "plan": {"name": pname, **plan}, "usage": await usage_this_month(cu.org_id)}


@router.patch("/current")
async def rename(body: OrgPatch, cu: CurrentUser = Depends(require("org:manage"))):
    await db().organizations.update_one({"_id": cu.org_id}, {"$set": {"name": body.name.strip()}})
    return to_json(await db().organizations.find_one({"_id": cu.org_id}))


@router.post("/switch")
async def switch(body: dict, cu: CurrentUser = Depends(current_user)):
    org_id = oid(str(body.get("org_id", "")), "organization")
    if not await db().organization_members.find_one({"org_id": org_id, "user_id": cu.id}):
        raise HTTPException(404, "Organization not found")
    await db().users.update_one({"_id": cu.id}, {"$set": {"active_org_id": org_id}})
    return {"message": "Switched"}


@router.get("/members")
async def members(cu: CurrentUser = Depends(require("org:read"))):
    out = []
    async for m in db().organization_members.find({"org_id": cu.org_id}):
        u = await db().users.find_one({"_id": m["user_id"]}, {"name": 1, "email": 1, "is_active": 1})
        out.append({"user_id": str(m["user_id"]), "role": m["role"], "name": (u or {}).get("name"), "email": (u or {}).get("email") if "org:manage" in cu.perms or m["user_id"] == cu.id else None, "joined_at": to_json(m["created_at"])})
    pending = [to_json(i, {"token_hash", "org_id", "invited_by"}) async for i in db().invitations.find({"org_id": cu.org_id}).sort("created_at", -1)] if "org:manage" in cu.perms else []
    return {"members": out, "invitations": pending}


@router.post("/invitations", status_code=201, dependencies=[limit("invite", 30, 3600)])
async def invite(body: InviteIn, request: Request, cu: CurrentUser = Depends(require("org:manage"))):
    cfg = await get_config()
    if not cfg["features"]["organizations"]:
        raise HTTPException(403, "Organizations are disabled")
    _, plan = await effective_plan(cu.org_id)
    pending = await db().invitations.count_documents({"org_id": cu.org_id})
    if (await usage_this_month(cu.org_id))["members"] + pending >= plan["members"]:
        raise HTTPException(403, f"Member limit reached for the {plan['label']} plan. Upgrade to invite team members.")
    email = body.email.lower()
    u = await db().users.find_one({"email": email}, {"_id": 1})
    if u and await db().organization_members.find_one({"org_id": cu.org_id, "user_id": u["_id"]}):
        raise HTTPException(409, "Already a member")
    raw, h = security.new_token()
    await db().invitations.delete_many({"org_id": cu.org_id, "email": email})
    r = await db().invitations.insert_one({"org_id": cu.org_id, "email": email, "role": body.role, "token_hash": h, "invited_by": cu.id, "created_at": now(), "expires_at": now() + timedelta(days=7)})
    await send_email(email, "You're invited to ZeroDay's LLM Rakshak", f"Accept: {get_settings().frontend_origin}/accept-invite?token={raw}")
    await audit("org.invited", actor_id=cu.id, target=email, ip=client_ip(request), meta={"role": body.role})
    return {"id": str(r.inserted_id), "email": email, "role": body.role}


@router.delete("/invitations/{iid}")
async def revoke_invite(iid: str, cu: CurrentUser = Depends(require("org:manage"))):
    r = await db().invitations.delete_one({"_id": oid(iid, "invitation"), "org_id": cu.org_id})
    if not r.deleted_count:
        raise HTTPException(404, "Invitation not found")
    return {"message": "Revoked"}


@router.post("/invitations/accept", dependencies=[limit("accept", 20, 3600)])
async def accept(body: dict, request: Request, cu: CurrentUser = Depends(current_user)):
    inv = await db().invitations.find_one_and_delete({"token_hash": security.sha256(str(body.get("token", ""))), "expires_at": {"$gt": now()}})
    if not inv or inv["email"] != cu.user["email"]:
        raise HTTPException(400, "Invalid or expired invitation")
    await db().organization_members.update_one({"org_id": inv["org_id"], "user_id": cu.id}, {"$setOnInsert": {"role": inv["role"], "created_at": now()}}, upsert=True)
    await db().users.update_one({"_id": cu.id}, {"$set": {"active_org_id": inv["org_id"]}})
    await audit("org.joined", actor_id=cu.id, target=str(inv["org_id"]), ip=client_ip(request))
    return {"message": "Joined organization"}


@router.patch("/members/{uid}")
async def set_role(uid: str, body: MemberRoleIn, request: Request, cu: CurrentUser = Depends(require("org:manage"))):
    m = await db().organization_members.find_one({"org_id": cu.org_id, "user_id": oid(uid, "member")})
    if not m or m["role"] == "owner":
        raise HTTPException(404, "Member not found or is the owner")
    if cu.org_role != "owner" and body.role == "admin":
        raise HTTPException(403, "Only the owner can grant admin")
    await db().organization_members.update_one({"_id": m["_id"]}, {"$set": {"role": body.role}})
    await audit("org.role_changed", actor_id=cu.id, target=uid, ip=client_ip(request), meta={"role": body.role})
    return {"message": "Updated"}


@router.delete("/members/{uid}")
async def remove(uid: str, request: Request, cu: CurrentUser = Depends(require("org:manage"))):
    m = await db().organization_members.find_one({"org_id": cu.org_id, "user_id": oid(uid, "member")})
    if not m or m["role"] == "owner":
        raise HTTPException(404, "Member not found or is the owner")
    await db().organization_members.delete_one({"_id": m["_id"]})
    await db().users.update_one({"_id": m["user_id"], "active_org_id": cu.org_id}, {"$unset": {"active_org_id": ""}})
    await audit("org.member_removed", actor_id=cu.id, target=uid, ip=client_ip(request))
    return {"message": "Removed"}
