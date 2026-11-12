import re
from datetime import timedelta
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from ..audit import audit
from ..config_store import get_config
from ..core import security
from ..core.config import get_settings
from ..core.mailer import send_email
from ..core.ratelimit import client_ip, hit, limit
from ..db import db
from ..deps import (ACCESS, CSRF, REFRESH, HIDDEN_USER, CurrentUser, check_csrf, clear_auth_cookies, current_user, set_auth_cookies)
from ..entitlements import PLANS, effective_plan, usage_this_month
from ..schemas import (ChangePasswordIn, CodeIn, EmailIn, LoginIn, RegisterIn, ResetIn, TokenIn)
from ..util import now, oid, to_json

router = APIRouter(prefix="/api/auth", tags=["auth"])
GENERIC = {"message": "If the request can be processed you will receive an email shortly."}
MAX_FAILS, LOCK_MIN = 5, 15


def _slug(name: str) -> str:
    return (re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] or "org") + "-" + security.new_token(4)[0][:6].lower()


def _ua(request: Request) -> str:
    return (request.headers.get("user-agent") or "unknown")[:200]


async def _problems(pw: str, email: str):
    p = security.password_problems(pw, email)
    if p:
        raise HTTPException(422, "Password must have: " + "; ".join(p))


@router.post("/register", status_code=202, dependencies=[limit("register", 5, 3600)])
async def register(body: RegisterIn, request: Request):
    cfg = await get_config()
    if not cfg["registration_open"]:
        raise HTTPException(403, "Registration is currently closed")
    email = body.email.lower()
    await _problems(body.password, email)
    pw_hash = security.hash_password(body.password)  # always hash: uniform timing whether or not the account exists
    if await db().users.find_one({"email": email}, {"_id": 1}):
        await send_email(email, "ZeroDay's LLM Rakshak sign-up attempt", "Someone tried to register with this address, but an account already exists. If this was you, use 'Forgot password'.")
        return GENERIC
    org_name = body.organization or f"{body.name}'s workspace"
    t = now()
    u = await db().users.insert_one({"email": email, "name": body.name, "password_hash": pw_hash, "role": "user", "is_active": True, "email_verified": False,
                                     "mfa_enabled": False, "failed_attempts": 0, "created_at": t, "organization": body.organization, "job_title": None,
                                     "preferences": {"theme": "dark", "timezone": "UTC"}})
    o = await db().organizations.insert_one({"name": org_name, "slug": _slug(org_name), "owner_id": u.inserted_id, "created_at": t})
    await db().organization_members.insert_one({"org_id": o.inserted_id, "user_id": u.inserted_id, "role": "owner", "created_at": t})
    await db().subscriptions.insert_one({"org_id": o.inserted_id, "plan": "free", "status": "active", "provider": None, "created_at": t})
    await db().users.update_one({"_id": u.inserted_id}, {"$set": {"active_org_id": o.inserted_id}})
    raw, h = security.new_token()
    await db().email_verifications.insert_one({"user_id": u.inserted_id, "token_hash": h, "expires_at": t + timedelta(hours=24)})
    await send_email(email, "Verify your ZeroDay's LLM Rakshak email", f"Open this link to verify your email (valid 24h):\n{get_settings().frontend_origin}/verify-email?token={raw}")
    await audit("auth.register", actor_id=u.inserted_id, actor_email=email, ip=client_ip(request))
    return GENERIC


@router.post("/verify-email", dependencies=[limit("verify", 20, 3600)])
async def verify_email(body: TokenIn):
    v = await db().email_verifications.find_one_and_delete({"token_hash": security.sha256(body.token), "expires_at": {"$gt": now()}})
    if not v:
        raise HTTPException(400, "Invalid or expired token")
    await db().users.update_one({"_id": v["user_id"]}, {"$set": {"email_verified": True}})
    await audit("auth.email_verified", actor_id=v["user_id"])
    return {"message": "Email verified"}


@router.post("/resend-verification", status_code=202, dependencies=[limit("resend", 5, 3600)])
async def resend(body: EmailIn):
    u = await db().users.find_one({"email": body.email.lower(), "email_verified": False})
    if u:
        raw, h = security.new_token()
        await db().email_verifications.insert_one({"user_id": u["_id"], "token_hash": h, "expires_at": now() + timedelta(hours=24)})
        await send_email(u["email"], "Verify your ZeroDay's LLM Rakshak email", f"{get_settings().frontend_origin}/verify-email?token={raw}")
    return GENERIC


async def _history(user_id, email, request, ok: bool, reason: str = ""):
    await db().login_history.insert_one({"user_id": user_id, "email": email, "ip": client_ip(request), "ua": _ua(request), "success": ok, "reason": reason,
                                         "ts": now(), "expires_at": now() + timedelta(days=180)})


@router.post("/login", dependencies=[limit("login-ip", 20, 300)])
async def login(body: LoginIn, request: Request, response: Response):
    s = get_settings()
    email = body.email.lower()
    ok_rate, retry = await hit(f"login-acct:{email}", 8, 900)  # applies equally to unknown emails (no enumeration)
    if not ok_rate:
        raise HTTPException(429, "Too many attempts. Try again later.", headers={"Retry-After": str(retry)})
    u = await db().users.find_one({"email": email})
    locked = bool(u and u.get("locked_until") and u["locked_until"] > now())
    valid = security.verify_password(body.password, u["password_hash"] if u else None)
    if not u or not valid or locked:
        if u and not locked:
            fails = u.get("failed_attempts", 0) + 1
            upd = {"failed_attempts": fails}
            if fails >= MAX_FAILS:
                upd.update(locked_until=now() + timedelta(minutes=LOCK_MIN), failed_attempts=0)
                await audit("auth.lockout", actor_id=u["_id"], actor_email=email, ip=client_ip(request))
            await db().users.update_one({"_id": u["_id"]}, {"$set": upd})
        if u:
            await _history(u["_id"], email, request, False, "bad_credentials" if not locked else "locked")
        await audit("auth.login_failed", actor_email=email, ip=client_ip(request))
        raise HTTPException(401, "Invalid credentials")
    if not u.get("email_verified"):
        raise HTTPException(403, "Email address not verified")
    if not u.get("is_active"):
        raise HTTPException(403, "Account is deactivated")
    step = None
    if u.get("mfa_enabled"):
        if not body.totp_code:
            raise HTTPException(401, "MFA code required", headers={"X-MFA-Required": "true"})
        step = security.totp_step_if_valid(security.decrypt(u["totp_secret_enc"]), body.totp_code, u.get("last_totp_step", 0))
        if step is None:
            await _history(u["_id"], email, request, False, "bad_mfa")
            raise HTTPException(401, "Invalid credentials")
    upd = {"failed_attempts": 0, "locked_until": None, "last_login_at": now()}
    if step:
        upd["last_totp_step"] = step
    if security.needs_rehash(u["password_hash"]):
        upd["password_hash"] = security.hash_password(body.password)
    await db().users.update_one({"_id": u["_id"]}, {"$set": upd})
    raw, h = security.new_token()
    t = now()
    sess = await db().sessions.insert_one({"user_id": u["_id"], "token_hash": h, "prev_hash": None, "revoked": False, "created_at": t, "last_used_at": t,
                                           "rotated_at": t, "expires_at": t + timedelta(days=s.refresh_ttl_days), "abs_expires_at": t + timedelta(days=s.refresh_abs_ttl_days),
                                           "ip": client_ip(request), "ua": _ua(request)})
    access = security.create_access_token(str(u["_id"]), str(sess.inserted_id), u["role"])
    csrf = security.csrf_token()
    set_auth_cookies(response, access, raw, csrf)
    await _history(u["_id"], email, request, True)
    await audit("auth.login", actor_id=u["_id"], actor_email=email, ip=client_ip(request))
    return {"user": to_json(u, HIDDEN_USER), "csrf_token": csrf}


@router.post("/refresh", dependencies=[limit("refresh", 60, 300)])
async def refresh(request: Request, response: Response):
    check_csrf(request)
    raw = request.cookies.get(REFRESH)
    if not raw:
        raise HTTPException(401, "No session")
    h = security.sha256(raw)
    t = now()
    new_raw, new_h = security.new_token()
    s = get_settings()
    sess = await db().sessions.find_one_and_update(
        {"token_hash": h, "revoked": False, "expires_at": {"$gt": t}, "abs_expires_at": {"$gt": t}},
        {"$set": {"token_hash": new_h, "prev_hash": h, "rotated_at": t, "last_used_at": t, "expires_at": min(t + timedelta(days=s.refresh_ttl_days), t + timedelta(days=s.refresh_abs_ttl_days))}})
    if not sess:
        reused = await db().sessions.find_one({"prev_hash": h, "revoked": False})
        if reused and (t - reused["rotated_at"]).total_seconds() > 10:  # reuse of a rotated token => theft suspected
            await db().sessions.update_one({"_id": reused["_id"]}, {"$set": {"revoked": True}})
            await audit("auth.refresh_reuse_detected", actor_id=reused["user_id"], ip=client_ip(request))
        clear_auth_cookies(response)
        raise HTTPException(401, "Session expired")
    u = await db().users.find_one({"_id": sess["user_id"]})
    if not u or not u.get("is_active"):
        await db().sessions.update_one({"_id": sess["_id"]}, {"$set": {"revoked": True}})
        clear_auth_cookies(response)
        raise HTTPException(401, "Account unavailable")
    csrf = security.csrf_token()
    set_auth_cookies(response, security.create_access_token(str(u["_id"]), str(sess["_id"]), u["role"]), new_raw, csrf)
    return {"csrf_token": csrf}


@router.post("/logout")
async def logout(request: Request, response: Response, cu: CurrentUser = Depends(current_user)):
    await db().sessions.update_one({"_id": cu.session_id}, {"$set": {"revoked": True}})
    clear_auth_cookies(response)
    await audit("auth.logout", actor_id=cu.id, ip=client_ip(request))
    return {"message": "Logged out"}


@router.post("/logout-all")
async def logout_all(request: Request, response: Response, cu: CurrentUser = Depends(current_user)):
    await db().sessions.update_many({"user_id": cu.id}, {"$set": {"revoked": True}})
    clear_auth_cookies(response)
    await audit("auth.logout_all", actor_id=cu.id, ip=client_ip(request))
    return {"message": "All sessions revoked"}


@router.post("/forgot-password", status_code=202, dependencies=[limit("forgot", 5, 3600)])
async def forgot(body: EmailIn):
    u = await db().users.find_one({"email": body.email.lower(), "is_active": True})
    if u:
        raw, h = security.new_token()
        await db().password_resets.insert_one({"user_id": u["_id"], "token_hash": h, "expires_at": now() + timedelta(hours=1)})
        await send_email(u["email"], "Reset your ZeroDay's LLM Rakshak password", f"Reset link (valid 1h): {get_settings().frontend_origin}/reset-password?token={raw}")
        await audit("auth.password_reset_requested", actor_id=u["_id"])
    return GENERIC


@router.post("/reset-password", dependencies=[limit("reset", 10, 3600)])
async def reset(body: ResetIn):
    h = security.sha256(body.token)
    peek = await db().password_resets.find_one({"token_hash": h, "expires_at": {"$gt": now()}})
    if not peek:
        raise HTTPException(400, "Invalid or expired token")
    u = await db().users.find_one({"_id": peek["user_id"]})
    await _problems(body.password, u["email"])  # validate BEFORE consuming the single-use token
    r = await db().password_resets.find_one_and_delete({"token_hash": h, "expires_at": {"$gt": now()}})
    if not r:  # lost a race with another request using the same token
        raise HTTPException(400, "Invalid or expired token")
    await db().users.update_one({"_id": u["_id"]}, {"$set": {"password_hash": security.hash_password(body.password), "failed_attempts": 0, "locked_until": None}})
    await db().sessions.update_many({"user_id": u["_id"]}, {"$set": {"revoked": True}})
    await db().password_resets.delete_many({"user_id": u["_id"]})
    await audit("auth.password_reset", actor_id=u["_id"])
    return {"message": "Password updated. Please sign in."}


@router.post("/change-password", dependencies=[limit("chpw", 10, 3600)])
async def change_password(body: ChangePasswordIn, request: Request, cu: CurrentUser = Depends(current_user)):
    if not security.verify_password(body.current_password, cu.user["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    await _problems(body.new_password, cu.user["email"])
    await db().users.update_one({"_id": cu.id}, {"$set": {"password_hash": security.hash_password(body.new_password)}})
    await db().sessions.update_many({"user_id": cu.id, "_id": {"$ne": cu.session_id}}, {"$set": {"revoked": True}})
    await audit("auth.password_changed", actor_id=cu.id, ip=client_ip(request))
    return {"message": "Password changed; other sessions were signed out"}


@router.get("/me")
async def me(cu: CurrentUser = Depends(current_user)):
    org = await db().organizations.find_one({"_id": cu.org_id})
    pname, plan = await effective_plan(cu.org_id)
    return {"user": {**to_json(cu.user, HIDDEN_USER), "has_avatar": bool(cu.user.get("avatar"))},
            "organization": to_json(org), "org_role": cu.org_role, "permissions": sorted(cu.perms),
            "plan": {"name": pname, **plan}, "usage": await usage_this_month(cu.org_id),
            "orgs": [to_json({"id": m["org_id"], "role": m["role"]}) for m in await db().organization_members.find({"user_id": cu.id}).to_list(50)]}


@router.get("/sessions")
async def sessions(cu: CurrentUser = Depends(current_user)):
    out = []
    async for s in db().sessions.find({"user_id": cu.id, "revoked": False, "expires_at": {"$gt": now()}}).sort("last_used_at", -1):
        out.append({"id": str(s["_id"]), "ip": s.get("ip"), "device": s.get("ua"), "created_at": to_json(s["created_at"]), "last_used_at": to_json(s["last_used_at"]), "current": s["_id"] == cu.session_id})
    return out


@router.delete("/sessions/{sid}")
async def revoke(sid: str, cu: CurrentUser = Depends(current_user)):
    r = await db().sessions.update_one({"_id": oid(sid), "user_id": cu.id}, {"$set": {"revoked": True}})
    if not r.matched_count:
        raise HTTPException(404, "Session not found")
    return {"message": "Session revoked"}


@router.get("/login-history")
async def history(cu: CurrentUser = Depends(current_user)):
    return [to_json(h, {"expires_at", "user_id"}) async for h in db().login_history.find({"user_id": cu.id}).sort("ts", -1).limit(50)]


@router.post("/mfa/setup", dependencies=[limit("mfa", 10, 600)])
async def mfa_setup(cu: CurrentUser = Depends(current_user)):
    if cu.user.get("mfa_enabled"):
        raise HTTPException(400, "MFA is already enabled")
    sec = security.new_totp_secret()
    await db().users.update_one({"_id": cu.id}, {"$set": {"totp_pending_enc": security.encrypt(sec)}})
    return {"secret": sec, "otpauth_uri": security.totp_provisioning_uri(sec, cu.user["email"])}


@router.post("/mfa/enable", dependencies=[limit("mfa", 10, 600)])
async def mfa_enable(body: CodeIn, request: Request, cu: CurrentUser = Depends(current_user)):
    if not cu.user.get("totp_pending_enc"):
        raise HTTPException(400, "Start MFA setup first")
    step = security.totp_step_if_valid(security.decrypt(cu.user["totp_pending_enc"]), body.code)
    if step is None:
        raise HTTPException(400, "Invalid code")
    await db().users.update_one({"_id": cu.id}, {"$set": {"mfa_enabled": True, "totp_secret_enc": cu.user["totp_pending_enc"], "last_totp_step": step}, "$unset": {"totp_pending_enc": ""}})
    await audit("auth.mfa_enabled", actor_id=cu.id, ip=client_ip(request))
    return {"message": "MFA enabled"}


@router.post("/mfa/disable", dependencies=[limit("mfa", 10, 600)])
async def mfa_disable(body: CodeIn, request: Request, cu: CurrentUser = Depends(current_user)):
    if not cu.user.get("mfa_enabled"):
        raise HTTPException(400, "MFA is not enabled")
    if not body.password or not security.verify_password(body.password, cu.user["password_hash"]):
        raise HTTPException(400, "Password required")
    if security.totp_step_if_valid(security.decrypt(cu.user["totp_secret_enc"]), body.code, cu.user.get("last_totp_step", 0)) is None:
        raise HTTPException(400, "Invalid code")
    await db().users.update_one({"_id": cu.id}, {"$set": {"mfa_enabled": False}, "$unset": {"totp_secret_enc": "", "last_totp_step": ""}})
    await audit("auth.mfa_disabled", actor_id=cu.id, ip=client_ip(request))
    return {"message": "MFA disabled"}
