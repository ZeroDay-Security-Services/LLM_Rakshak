from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING as A, DESCENDING as D, IndexModel
from .core.config import get_settings

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None

COLLECTIONS = ["users", "organizations", "organization_members", "sessions", "email_verifications", "password_resets",
               "api_credentials", "llm_providers", "model_configurations", "assessments", "assessment_jobs",
               "attack_modules", "attack_executions", "vulnerabilities", "assessment_reports", "notifications",
               "subscriptions", "usage_records", "audit_logs", "platform_settings", "login_history", "invitations"]


async def init_db(uri: str | None = None, name: str | None = None) -> AsyncIOMotorDatabase:
    global _client, _db
    s = get_settings()
    _client = AsyncIOMotorClient(uri or s.mongodb_uri, tz_aware=True, serverSelectionTimeoutMS=8000,
                                 uuidRepresentation="standard", retryWrites=True)
    _db = _client[name or s.mongodb_db]
    return _db


def db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("database not initialised")
    return _db


async def close_db() -> None:
    global _client, _db
    if _client:
        _client.close()
    _client = _db = None


SCHEMA_VERSION = 1


def _ttl(field, secs=0):
    return IndexModel([(field, A)], expireAfterSeconds=secs, name=f"ttl_{field}")


async def ensure_indexes() -> None:
    d = db()
    spec: dict[str, list[IndexModel]] = {
        "users": [IndexModel([("email", A)], unique=True), IndexModel([("role", A), ("is_active", A)]),
                  IndexModel([("created_at", D)])],
        "organizations": [IndexModel([("slug", A)], unique=True), IndexModel([("owner_id", A)])],
        "organization_members": [IndexModel([("org_id", A), ("user_id", A)], unique=True), IndexModel([("user_id", A)])],
        "sessions": [IndexModel([("token_hash", A)]), IndexModel([("prev_hash", A)], sparse=True),
                     IndexModel([("user_id", A), ("revoked", A)]), _ttl("abs_expires_at")],
        "email_verifications": [IndexModel([("token_hash", A)], unique=True), _ttl("expires_at")],
        "password_resets": [IndexModel([("token_hash", A)], unique=True), _ttl("expires_at")],
        "invitations": [IndexModel([("token_hash", A)], unique=True), IndexModel([("org_id", A), ("email", A)]),
                        _ttl("expires_at")],
        "api_credentials": [IndexModel([("owner_id", A), ("provider", A)], unique=True)],
        "llm_providers": [IndexModel([("key", A)], unique=True)],
        "model_configurations": [IndexModel([("org_id", A), ("owner_id", A), ("created_at", D)])],
        "assessments": [IndexModel([("org_id", A), ("owner_id", A), ("created_at", D)]),
                        IndexModel([("status", A), ("heartbeat_at", A)]), IndexModel([("org_id", A), ("status", A)])],
        "assessment_jobs": [IndexModel([("assessment_id", A), ("created_at", D)]), IndexModel([("status", A)])],
        "attack_modules": [IndexModel([("attack_id", A)], unique=True),
                           IndexModel([("category", A), ("tier", A)]), IndexModel([("org_id", A)], sparse=True),
                           IndexModel([("name", "text"), ("description", "text")], name="attack_text")],
        "attack_executions": [IndexModel([("assessment_id", A), ("attack_id", A)], unique=True),
                              IndexModel([("org_id", A), ("attack_id", A), ("finished_at", D)]),
                              IndexModel([("assessment_id", A), ("status", A)])],
        "vulnerabilities": [IndexModel([("org_id", A), ("owner_id", A), ("severity", A), ("detected_at", D)]),
                            IndexModel([("assessment_id", A), ("attack_id", A)], unique=True),
                            IndexModel([("finding_id", A)], unique=True),
                            IndexModel([("title", "text"), ("description", "text")], name="vuln_text")],
        "assessment_reports": [IndexModel([("assessment_id", A), ("created_at", D)]), IndexModel([("owner_id", A)])],
        "notifications": [IndexModel([("user_id", A), ("read", A), ("created_at", D)]),
                          _ttl("expires_at")],
        "subscriptions": [IndexModel([("org_id", A)], unique=True)],
        "usage_records": [IndexModel([("org_id", A), ("created_at", D)]), IndexModel([("assessment_id", A)])],
        "audit_logs": [IndexModel([("seq", A)], unique=True), IndexModel([("action", A), ("ts", D)]),
                       IndexModel([("actor_id", A), ("ts", D)])],
        "platform_settings": [],
        "login_history": [IndexModel([("user_id", A), ("ts", D)]), _ttl("expires_at")],
    }
    existing = set(await d.list_collection_names())
    for name, idx in spec.items():
        if name not in existing:
            await d.create_collection(name)
        if idx:
            await d[name].create_indexes(idx)
    await d.platform_settings.update_one({"_id": "schema"}, {"$setOnInsert": {"version": SCHEMA_VERSION}}, upsert=True)
