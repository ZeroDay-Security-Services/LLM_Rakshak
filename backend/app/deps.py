from dataclasses import dataclass, field
from fastapi import Depends, HTTPException, Request, Response
from .core import security
from .core.config import get_settings
from .db import db
from .rbac import perms_for
from .util import now

ACCESS, REFRESH, CSRF = "lg_access", "lg_refresh", "lg_csrf"
SAFE = {"GET", "HEAD", "OPTIONS"}
HIDDEN_USER = {"password_hash", "totp_secret_enc", "totp_pending_enc", "avatar", "avatar_ct", "last_totp_step", "failed_attempts", "locked_until"}


@dataclass
class CurrentUser:
    user: dict
    org_id: object
    org_role: str
    session_id: object
    perms: set = field(default_factory=set)

    @property
    def id(self):
        return self.user["_id"]

    @property
    def role(self):
        return self.user["role"]

    def can(self, p: str) -> bool:
        return p in self.perms


def set_auth_cookies(resp: Response, access: str, refresh: str, csrf: str) -> None:
    s = get_settings()
    kw = dict(secure=s.cookie_secure, samesite="lax", domain=s.cookie_domain)
    resp.set_cookie(ACCESS, access, max_age=s.access_ttl_minutes * 60, httponly=True, path="/", **kw)
    resp.set_cookie(REFRESH, refresh, max_age=s.refresh_ttl_days * 86400, httponly=True, path="/api/auth", **kw)
    resp.set_cookie(CSRF, csrf, max_age=s.refresh_ttl_days * 86400, httponly=False, path="/", **kw)


def clear_auth_cookies(resp: Response) -> None:
    s = get_settings()
    for n, p in ((ACCESS, "/"), (REFRESH, "/api/auth"), (CSRF, "/")):
        resp.delete_cookie(n, path=p, domain=s.cookie_domain)


def check_csrf(request: Request) -> None:
    if request.method in SAFE:
        return
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != get_settings().frontend_origin.rstrip("/"):
        raise HTTPException(403, "Cross-origin request blocked")
    c, h = request.cookies.get(CSRF), request.headers.get("x-csrf-token")
    if not c or not h or not security.constant_eq(c, h):
        raise HTTPException(403, "CSRF validation failed")


async def current_user(request: Request) -> CurrentUser:
    token = request.cookies.get(ACCESS)
    via_cookie = bool(token)
    if not token:
        ah = request.headers.get("authorization", "")
        token = ah[7:] if ah.lower().startswith("bearer ") else None
    claims = security.decode_access_token(token) if token else None
    if not claims:
        raise HTTPException(401, "Not authenticated")
    if via_cookie:
        check_csrf(request)
    from bson import ObjectId
    try:
        uid, sid = ObjectId(claims["sub"]), ObjectId(claims["sid"])
    except Exception:  # noqa
        raise HTTPException(401, "Not authenticated")
    sess = await db().sessions.find_one({"_id": sid, "user_id": uid, "revoked": False})
    if not sess:
        raise HTTPException(401, "Session expired")
    user = await db().users.find_one({"_id": uid})
    if not user or not user.get("is_active") or user.get("deleted"):
        raise HTTPException(401, "Account unavailable")
    mem = await db().organization_members.find_one({"org_id": user.get("active_org_id"), "user_id": uid})
    if not mem:
        mem = await db().organization_members.find_one({"user_id": uid})
        if not mem:
            raise HTTPException(403, "No organization membership")
    cu = CurrentUser(user, mem["org_id"], mem["role"], sid)
    cu.perms = perms_for(user["role"], mem["role"])
    request.state.user = cu
    return cu


def require(*perms: str):
    async def dep(cu: CurrentUser = Depends(current_user)) -> CurrentUser:
        missing = [p for p in perms if p not in cu.perms]
        if missing:
            raise HTTPException(403, "You do not have permission to perform this action")
        return cu
    return dep


def scope(cu: CurrentUser) -> dict:
    """Tenant + ownership filter applied to every query of user-owned resources."""
    base = {"org_id": cu.org_id}
    if "org:manage" not in cu.perms:
        base["owner_id"] = cu.id
    return base
