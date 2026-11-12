ROLES = ["super_admin", "admin", "researcher", "user", "viewer"]
_VIEW = {"assessment:read", "attack:read", "finding:read", "report:read", "notification:read", "model:read", "org:read"}
_USER = _VIEW | {"assessment:write", "finding:write", "report:write", "credential:manage", "model:write", "org:read"}
_RESEARCH = _USER | {"attack:write", "attack:import"}
_ADMIN = _RESEARCH | {"admin:access", "admin:users", "admin:read", "audit:read"}
_SUPER = _ADMIN | {"admin:config", "admin:roles", "admin:billing"}
ROLE_PERMS = {"viewer": _VIEW, "user": _USER, "researcher": _RESEARCH, "admin": _ADMIN, "super_admin": _SUPER}
ORG_ROLES = ["owner", "admin", "member", "viewer"]
ORG_MANAGERS = {"owner", "admin"}


def perms_for(role: str, org_role: str | None) -> set[str]:
    p = set(ROLE_PERMS.get(role, set()))
    if org_role == "viewer":  # org-level viewer can never write, even with a higher platform role
        p = {x for x in p if not x.endswith((":write", ":manage", ":import"))}
    if org_role in ORG_MANAGERS:
        p.add("org:manage")
    return p
