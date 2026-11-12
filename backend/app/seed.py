from .attacks.builtin import ATTACKS
from .attacks.schema import AttackDef
from .db import db
from .engine.providers import PROVIDER_CATALOG
from .util import now


async def seed() -> dict:
    n = 0
    for a in ATTACKS:
        d = AttackDef(**a).model_dump()
        d.update(builtin=True, org_id=None, owner_id=None, updated_at=now())
        await db().attack_modules.update_one({"attack_id": d["attack_id"]}, {"$set": d, "$setOnInsert": {"created_at": now()}}, upsert=True)
        n += 1
    for p in PROVIDER_CATALOG:
        await db().llm_providers.update_one({"key": p["key"]}, {"$set": p, "$setOnInsert": {"enabled": True}}, upsert=True)
    await db().platform_settings.update_one({"_id": "config"}, {"$setOnInsert": {"registration_open": True}}, upsert=True)
    return {"attacks": n, "providers": len(PROVIDER_CATALOG)}
