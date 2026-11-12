import json, secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ValidationError
from ..attacks.schema import CATEGORIES, CATEGORY_LABELS, USER_RULE_TYPES, AttackDef
from ..audit import audit
from ..core.ratelimit import client_ip, limit
from ..db import db
from ..deps import CurrentUser, require
from ..entitlements import effective_plan
from ..util import esc_re, now, oid, paginate, to_json

router = APIRouter(prefix="/api/attacks", tags=["attacks"])
HIDE = {"_id", "owner_id", "org_id"}


def _visible(cu: CurrentUser) -> dict:
    return {"$or": [{"builtin": True}, {"org_id": cu.org_id}]}


def _lock(doc: dict, plan: dict) -> dict:
    d = to_json(doc, {"owner_id", "org_id"})
    d["locked"] = doc.get("tier") not in plan["tiers"]
    d["source"] = "builtin" if doc.get("builtin") else "custom"
    if d["locked"]:  # advanced procedure content is a plan feature
        d["turns"], d["detect"] = [], []
    return d


@router.get("/categories")
async def categories(cu: CurrentUser = Depends(require("attack:read"))):
    counts = {}
    async for r in db().attack_modules.aggregate([{"$match": _visible(cu)}, {"$group": {"_id": "$category", "n": {"$sum": 1}}}]):
        counts[r["_id"]] = r["n"]
    return [{"key": c, "label": CATEGORY_LABELS[c], "count": counts.get(c, 0)} for c in CATEGORIES]


@router.get("")
async def list_attacks(q: str | None = None, category: str | None = None, tier: str | None = None, risk: str | None = None,
                       source: str | None = None, page: int = 1, size: int = 25, cu: CurrentUser = Depends(require("attack:read"))):
    flt: dict = {"$and": [_visible(cu)]}
    if q:
        r = {"$regex": esc_re(q), "$options": "i"}
        flt["$and"].append({"$or": [{"name": r}, {"attack_id": r}, {"description": r}]})
    for k, v, allowed in (("category", category, CATEGORIES), ("tier", tier, ["basic", "advanced"]), ("risk", risk, ["critical", "high", "medium", "low", "info"])):
        if v:
            if v not in allowed:
                raise HTTPException(422, f"invalid {k}")
            flt["$and"].append({k: v})
    if source in ("builtin", "custom"):
        flt["$and"].append({"builtin": source == "builtin"})
    _, plan = await effective_plan(cu.org_id)
    res = await paginate(db().attack_modules, flt, sort=[("category", 1), ("attack_id", 1)], page=page, size=size, exclude={"owner_id", "org_id", "turns", "detect"})
    for it in res["items"]:
        it["locked"] = it.get("tier") not in plan["tiers"]
        it["source"] = "builtin" if it.get("builtin") else "custom"
    return res


@router.get("/export")
async def export_attacks(ids: str | None = None, cu: CurrentUser = Depends(require("attack:read"))):
    flt = {"$and": [_visible(cu)]}
    if ids:
        flt["$and"].append({"attack_id": {"$in": [i for i in ids.split(",")[:200]]}})
    _, plan = await effective_plan(cu.org_id)
    out = []
    async for d in db().attack_modules.find(flt):
        if d.get("tier") not in plan["tiers"]:
            continue
        out.append(AttackDef(**d).model_dump())
    return {"format": "zeroday-llm-rakshak-attacks/1", "exported_at": now().isoformat(), "attacks": out}


class CustomAttackIn(BaseModel):
    definition: dict


def _validate_custom(raw: dict) -> dict:
    raw = {k: v for k, v in raw.items() if k in AttackDef.model_fields}
    raw["attack_id"] = "CUS-" + secrets.token_hex(4).upper()
    raw.pop("dos", None)
    raw["tier"] = "basic"
    try:
        d = AttackDef(**raw)
    except ValidationError as e:
        raise HTTPException(422, "Invalid attack definition: " + "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors()[:5]))
    if d.repeat > 3 or len(d.turns) > 6:
        raise HTTPException(422, "Custom attacks are limited to 6 turns and 3 repeats")
    for r in d.detect:
        if r.type not in USER_RULE_TYPES:
            raise HTTPException(422, f"Rule type '{r.type}' is not allowed in custom attacks")
        if any(len(p) > 200 for p in r.patterns):
            raise HTTPException(422, "Custom patterns are limited to 200 characters")
    return d.model_dump()


async def _need_custom(cu):
    _, plan = await effective_plan(cu.org_id)
    if not plan["custom_attacks"]:
        raise HTTPException(403, "Custom attacks require the Researcher or Enterprise plan")


@router.post("", status_code=201, dependencies=[limit("custom-attack", 60, 3600)])
async def create_custom(body: CustomAttackIn, request: Request, cu: CurrentUser = Depends(require("attack:write"))):
    await _need_custom(cu)
    d = _validate_custom(body.definition)
    d.update(builtin=False, org_id=cu.org_id, owner_id=cu.id, created_at=now(), updated_at=now())
    await db().attack_modules.insert_one(d)
    await audit("attack.created", actor_id=cu.id, target=d["attack_id"], ip=client_ip(request))
    return to_json(d, {"owner_id", "org_id"})


@router.post("/import", dependencies=[limit("attack-import", 10, 3600)])
async def import_attacks(body: dict, request: Request, cu: CurrentUser = Depends(require("attack:import"))):
    await _need_custom(cu)
    items = body.get("attacks")
    if not isinstance(items, list) or not 0 < len(items) <= 50:
        raise HTTPException(422, "Provide 1-50 attack definitions in 'attacks'")
    ok, errors = [], []
    for i, raw in enumerate(items):
        try:
            if not isinstance(raw, dict):
                raise HTTPException(422, "not an object")
            d = _validate_custom(raw)
            d.update(builtin=False, org_id=cu.org_id, owner_id=cu.id, created_at=now(), updated_at=now())
            await db().attack_modules.insert_one(d)
            ok.append(d["attack_id"])
        except HTTPException as e:
            errors.append({"index": i, "error": e.detail})
    await audit("attack.imported", actor_id=cu.id, ip=client_ip(request), meta={"imported": len(ok), "rejected": len(errors)})
    return {"imported": ok, "errors": errors}


async def _own_custom(aid: str, cu):
    d = await db().attack_modules.find_one({"attack_id": aid, "builtin": False, "org_id": cu.org_id})
    if not d:
        raise HTTPException(404, "Custom attack not found")
    return d


@router.put("/{attack_id}")
async def update_custom(attack_id: str, body: CustomAttackIn, cu: CurrentUser = Depends(require("attack:write"))):
    old = await _own_custom(attack_id, cu)
    d = _validate_custom(body.definition)
    d["attack_id"] = old["attack_id"]
    d.update(updated_at=now(), version=old.get("version", 1) + 1)
    await db().attack_modules.update_one({"_id": old["_id"]}, {"$set": d})
    return to_json(await db().attack_modules.find_one({"_id": old["_id"]}), {"owner_id", "org_id"})


@router.delete("/{attack_id}")
async def delete_custom(attack_id: str, request: Request, cu: CurrentUser = Depends(require("attack:write"))):
    d = await _own_custom(attack_id, cu)
    await db().attack_modules.delete_one({"_id": d["_id"]})
    await audit("attack.deleted", actor_id=cu.id, target=attack_id, ip=client_ip(request))
    return {"message": "Deleted"}


@router.get("/{attack_id}")
async def get_attack(attack_id: str, cu: CurrentUser = Depends(require("attack:read"))):
    d = await db().attack_modules.find_one({"attack_id": attack_id, **_visible(cu)})
    if not d:
        raise HTTPException(404, "Attack not found")
    _, plan = await effective_plan(cu.org_id)
    return _lock(d, plan)


@router.get("/{attack_id}/history")
async def attack_history(attack_id: str, cu: CurrentUser = Depends(require("attack:read"))):
    if not await db().attack_modules.find_one({"attack_id": attack_id, **_visible(cu)}, {"_id": 1}):
        raise HTTPException(404, "Attack not found")
    base = {"attack_id": attack_id, "org_id": cu.org_id}
    if "org:manage" not in cu.perms:
        base["owner_id"] = cu.id
    summary = {r["_id"]: r["n"] async for r in db().attack_executions.aggregate([{"$match": base}, {"$group": {"_id": "$status", "n": {"$sum": 1}}}])}
    recent = [to_json(e, {"transcript", "owner_id", "org_id", "tokens_ctx"}) async for e in db().attack_executions.find(base).sort("finished_at", -1).limit(20)]
    return {"summary": summary, "recent": recent}
