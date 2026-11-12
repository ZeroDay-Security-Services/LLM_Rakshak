from .db import db

DEFAULTS = {"registration_open": True, "max_concurrent_jobs": 20, "enabled_providers": ["anthropic", "openai", "gemini", "openai_compatible", "custom"],
            "features": {"ai_analysis": True, "custom_attacks": True, "payments": False, "organizations": True},
            "maintenance_mode": False, "announcement": {"active": False, "text": "", "level": "info"}}


async def get_config() -> dict:
    d = await db().platform_settings.find_one({"_id": "config"}) or {}
    out = {**DEFAULTS, **{k: v for k, v in d.items() if k != "_id"}}
    out["features"] = {**DEFAULTS["features"], **d.get("features", {})}
    return out
