import io, json
from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile
from PIL import Image, UnidentifiedImageError
from ..audit import audit
from ..config_store import get_config
from ..core import security
from ..core.config import get_settings
from ..core.ratelimit import client_ip, limit
from ..core.ssrf import SSRFError, resolve_and_validate, safe_request
from ..db import db
from ..deps import HIDDEN_USER, CurrentUser, current_user, require, scope
from ..engine.providers import build_provider
from ..schemas import CredentialIn, ModelIn, PreferencesIn, ProfileIn, Provider
from ..util import now, oid, paginate, to_json

router = APIRouter(prefix="/api", tags=["settings"])
HOSTED = {"anthropic", "openai", "gemini"}


@router.patch("/profile")
async def patch_profile(body: ProfileIn, cu: CurrentUser = Depends(current_user)):
    upd = {k: v.strip() for k, v in body.model_dump(exclude_none=True).items()}
    if upd:
        await db().users.update_one({"_id": cu.id}, {"$set": upd})
    u = await db().users.find_one({"_id": cu.id})
    return to_json(u, HIDDEN_USER)


@router.get("/preferences")
async def get_prefs(cu: CurrentUser = Depends(current_user)):
    return PreferencesIn(**(cu.user.get("preferences") or {})).model_dump()


@router.put("/preferences")
async def put_prefs(body: PreferencesIn, cu: CurrentUser = Depends(current_user)):
    await db().users.update_one({"_id": cu.id}, {"$set": {"preferences": body.model_dump()}})
    return body.model_dump()


@router.post("/profile/avatar", dependencies=[limit("avatar", 10, 3600)])
async def upload_avatar(file: UploadFile = File(...), cu: CurrentUser = Depends(current_user)):
    data = await file.read(600_000)
    if len(data) > 512_000:
        raise HTTPException(413, "Image too large (max 500 KB)")
    try:  # decode + re-encode: strips metadata/polyglots, enforces real image type
        img = Image.open(io.BytesIO(data))
        if img.format not in ("PNG", "JPEG", "WEBP"):
            raise HTTPException(415, "Only PNG, JPEG or WebP images are accepted")
        img.verify()
        img = Image.open(io.BytesIO(data)).convert("RGB")
        img.thumbnail((256, 256))
        out = io.BytesIO()
        img.save(out, "PNG")
    except HTTPException:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, SyntaxError):
        raise HTTPException(415, "Invalid image")
    await db().users.update_one({"_id": cu.id}, {"$set": {"avatar": out.getvalue(), "avatar_ct": "image/png"}})
    return {"message": "Avatar updated"}


@router.get("/profile/avatar")
async def get_avatar(cu: CurrentUser = Depends(current_user)):
    if not cu.user.get("avatar"):
        raise HTTPException(404, "No avatar")
    return Response(cu.user["avatar"], media_type="image/png", headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "private, max-age=300"})


@router.delete("/profile/avatar")
async def del_avatar(cu: CurrentUser = Depends(current_user)):
    await db().users.update_one({"_id": cu.id}, {"$unset": {"avatar": "", "avatar_ct": ""}})
    return {"message": "Avatar removed"}


# ---------------- API credentials (BYOK) ----------------
@router.get("/credentials")
async def list_credentials(cu: CurrentUser = Depends(require("credential:manage"))):
    out = {}
    async for c in db().api_credentials.find({"owner_id": cu.id}):
        out[c["provider"]] = {"provider": c["provider"], "has_key": True, "preview": c["preview"], "endpoint": c.get("endpoint"),
                              "auth_header": c.get("auth_header"), "updated_at": to_json(c["updated_at"])}
    return out  # ciphertext is never returned


@router.put("/credentials/{provider}", dependencies=[limit("cred", 30, 3600)])
async def put_credential(provider: Provider, body: CredentialIn, request: Request, cu: CurrentUser = Depends(require("credential:manage"))):
    cfg = await get_config()
    if provider not in cfg["enabled_providers"]:
        raise HTTPException(400, "This provider is disabled by the administrator")
    if body.endpoint:
        s = get_settings()
        try:
            await resolve_and_validate(body.endpoint, allow_private=s.allow_private_targets, allow_http=s.allow_http_targets)
        except SSRFError as e:
            raise HTTPException(422, f"Endpoint rejected: {e}")
    blob = {"api_key": body.api_key.strip()}
    if body.auth_header:
        blob["auth_header"] = body.auth_header
    if body.auth_scheme is not None:
        blob["auth_scheme"] = body.auth_scheme
    doc = {"encrypted": security.encrypt(json.dumps(blob)), "preview": security.mask_secret(body.api_key.strip()), "endpoint": body.endpoint,
           "auth_header": body.auth_header, "org_id": cu.org_id, "updated_at": now()}
    await db().api_credentials.update_one({"owner_id": cu.id, "provider": provider}, {"$set": doc, "$setOnInsert": {"created_at": now()}}, upsert=True)
    await audit("credential.set", actor_id=cu.id, target=provider, ip=client_ip(request))  # never logs the key
    return {"provider": provider, "has_key": True, "preview": doc["preview"]}


@router.delete("/credentials/{provider}")
async def del_credential(provider: Provider, request: Request, cu: CurrentUser = Depends(require("credential:manage"))):
    r = await db().api_credentials.delete_one({"owner_id": cu.id, "provider": provider})
    if not r.deleted_count:
        raise HTTPException(404, "No credential stored")
    await audit("credential.deleted", actor_id=cu.id, target=provider, ip=client_ip(request))
    return {"message": "Credential deleted"}


# ---------------- Providers & model configurations ----------------
@router.get("/providers")
async def providers(cu: CurrentUser = Depends(current_user)):
    cfg = await get_config()
    return [to_json(p, {"_id"}) | {"enabled": p["key"] in cfg["enabled_providers"]} async for p in db().llm_providers.find({})]


async def _validate_model(body: ModelIn) -> dict:
    cfg = await get_config()
    if body.provider not in cfg["enabled_providers"]:
        raise HTTPException(400, "This provider is disabled by the administrator")
    doc = body.model_dump()
    doc["credential_provider"] = body.credential_provider or body.provider
    if body.provider in HOSTED:
        doc["endpoint"] = None
    else:
        ep = body.endpoint
        if not ep:
            c = await db().api_credentials.find_one({"provider": doc["credential_provider"]})
            ep = (c or {}).get("endpoint")
        if not ep:
            raise HTTPException(422, "An endpoint URL is required for this provider")
        s = get_settings()
        try:
            await resolve_and_validate(ep, allow_private=s.allow_private_targets, allow_http=s.allow_http_targets)
        except SSRFError as e:
            raise HTTPException(422, f"Endpoint rejected: {e}")
        doc["endpoint"] = ep
    return doc


@router.post("/models", status_code=201)
async def create_model(body: ModelIn, request: Request, cu: CurrentUser = Depends(require("model:write"))):
    doc = await _validate_model(body)
    doc.update(org_id=cu.org_id, owner_id=cu.id, created_at=now(), updated_at=now())
    r = await db().model_configurations.insert_one(doc)
    await audit("model.created", actor_id=cu.id, target=str(r.inserted_id), ip=client_ip(request))
    return to_json(await db().model_configurations.find_one({"_id": r.inserted_id}))


@router.get("/models")
async def list_models(page: int = 1, size: int = 50, cu: CurrentUser = Depends(require("model:read"))):
    return await paginate(db().model_configurations, scope(cu), sort=[("created_at", -1)], page=page, size=size)


async def _own_model(mid: str, cu: CurrentUser) -> dict:
    m = await db().model_configurations.find_one({"_id": oid(mid, "model"), **scope(cu)})
    if not m:
        raise HTTPException(404, "Model not found")
    return m


@router.get("/models/{mid}")
async def get_model(mid: str, cu: CurrentUser = Depends(require("model:read"))):
    return to_json(await _own_model(mid, cu))


@router.put("/models/{mid}")
async def update_model(mid: str, body: ModelIn, cu: CurrentUser = Depends(require("model:write"))):
    m = await _own_model(mid, cu)
    doc = await _validate_model(body)
    doc["updated_at"] = now()
    await db().model_configurations.update_one({"_id": m["_id"]}, {"$set": doc})
    return to_json(await db().model_configurations.find_one({"_id": m["_id"]}))


@router.delete("/models/{mid}")
async def delete_model(mid: str, cu: CurrentUser = Depends(require("model:write"))):
    m = await _own_model(mid, cu)
    if await db().assessments.find_one({"model_config_id": m["_id"], "status": {"$in": ["queued", "running", "pausing", "paused"]}}):
        raise HTTPException(409, "Model is used by an active assessment")
    await db().model_configurations.delete_one({"_id": m["_id"]})
    return {"message": "Model deleted"}


@router.post("/models/{mid}/test", dependencies=[limit("modeltest", 20, 600)])
async def test_model(mid: str, cu: CurrentUser = Depends(require("model:write"))):
    m = await _own_model(mid, cu)
    c = await db().api_credentials.find_one({"owner_id": m["owner_id"], "provider": m["credential_provider"]})
    key, extra = None, {}
    if c:
        blob = json.loads(security.decrypt(c["encrypted"]))
        key, extra = blob.get("api_key"), {k: v for k, v in blob.items() if k != "api_key"}
    if not key and m["provider"] in HOSTED:
        raise HTTPException(400, f"No {m['provider']} API key configured. Add it under Settings → API configuration.")
    p = build_provider(m["provider"], m["model"], key, m.get("endpoint"), extra)
    r = await p.chat([{"role": "user", "content": "Reply with the single word OK."}], None, None, 8, None, 30)
    return {"ok": r.status == "ok", "status": r.status, "latency_ms": r.latency_ms, "error": (r.error[:200] if r.status != "ok" else None)}
