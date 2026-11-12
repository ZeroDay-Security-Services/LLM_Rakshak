import hashlib, hmac, json, time
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from ..audit import audit
from ..core.config import get_settings
from ..db import db
from ..deps import CurrentUser, require
from ..entitlements import PLANS, effective_plan, usage_this_month
from ..util import now, to_json

router = APIRouter(prefix="/api/billing", tags=["billing"])


@router.get("/plans")
async def plans():
    return [{"key": k, **v} for k, v in PLANS.items()]


@router.get("/subscription")
async def subscription(cu: CurrentUser = Depends(require("org:read"))):
    name, plan = await effective_plan(cu.org_id)
    sub = await db().subscriptions.find_one({"_id": {"$exists": True}, "org_id": cu.org_id})
    return {"plan": name, "entitlements": plan, "usage": await usage_this_month(cu.org_id), "subscription": to_json(sub, {"org_id"}), "payments_enabled": get_settings().payments_enabled}


@router.post("/checkout")
async def checkout(body: dict, cu: CurrentUser = Depends(require("org:manage"))):
    """Payment architecture hook. Disabled until a provider is configured (LLMGUARD_PAYMENTS_ENABLED + webhook secret).
    Entitlements change ONLY through the signed webhook below or an admin action, never from client input."""
    if not get_settings().payments_enabled:
        raise HTTPException(501, "Payments are not enabled on this deployment")
    raise HTTPException(501, "No payment provider adapter is configured. Implement create_checkout() in app/routers/billing.py for Stripe or Razorpay.")


def _apply(org_id, plan: str, status: str, provider: str, period_end_ts: int | None):
    return db().subscriptions.update_one({"org_id": org_id}, {"$set": {"plan": plan, "status": status, "provider": provider, "updated_at": now(),
                                         "current_period_end": None if period_end_ts is None else now().replace(microsecond=0) + timedelta(seconds=max(0, period_end_ts - int(time.time())))}}, upsert=True)


def verify_stripe(payload: bytes, header: str, secret: str, tolerance: int = 300) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts, sig = int(parts["t"]), parts["v1"]
    except Exception:  # noqa
        return False
    if abs(time.time() - ts) > tolerance:
        return False
    exp = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(exp, sig)


def verify_razorpay(payload: bytes, sig: str, secret: str) -> bool:
    return hmac.compare_digest(hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest(), sig or "")


async def _handle(provider: str, evt: dict):
    meta = (evt.get("data", {}).get("object", {}).get("metadata") if provider == "stripe" else evt.get("payload", {}).get("subscription", {}).get("entity", {}).get("notes")) or {}
    from bson import ObjectId
    try:
        org_id = ObjectId(meta.get("org_id", ""))
    except Exception:  # noqa
        raise HTTPException(400, "missing org reference")
    plan = meta.get("plan")
    if plan not in PLANS or not await db().organizations.find_one({"_id": org_id}, {"_id": 1}):
        raise HTTPException(400, "invalid plan or organisation")
    typ = evt.get("type") or evt.get("event", "")
    active = typ in ("customer.subscription.created", "customer.subscription.updated", "invoice.paid", "subscription.activated", "subscription.charged")
    cancelled = typ in ("customer.subscription.deleted", "subscription.cancelled", "subscription.halted")
    if active or cancelled:
        end = evt.get("data", {}).get("object", {}).get("current_period_end") if provider == "stripe" else evt.get("payload", {}).get("subscription", {}).get("entity", {}).get("current_end")
        await _apply(org_id, plan if active else "free", "active", provider, end if active else None)
        await audit("billing.subscription", target=str(org_id), meta={"event": typ, "plan": plan if active else "free", "provider": provider})


@router.post("/webhook/stripe")
async def stripe_hook(request: Request):
    s = get_settings()
    if not (s.payments_enabled and s.stripe_webhook_secret):
        raise HTTPException(501, "Stripe is not configured")
    body = await request.body()
    if not verify_stripe(body, request.headers.get("stripe-signature", ""), s.stripe_webhook_secret):
        raise HTTPException(400, "Invalid signature")
    await _handle("stripe", json.loads(body))
    return {"received": True}


@router.post("/webhook/razorpay")
async def razorpay_hook(request: Request):
    s = get_settings()
    if not (s.payments_enabled and s.razorpay_webhook_secret):
        raise HTTPException(501, "Razorpay is not configured")
    body = await request.body()
    if not verify_razorpay(body, request.headers.get("x-razorpay-signature", ""), s.razorpay_webhook_secret):
        raise HTTPException(400, "Invalid signature")
    await _handle("razorpay", json.loads(body))
    return {"received": True}
