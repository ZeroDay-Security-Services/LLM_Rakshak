"""Backend-enforced plans and quotas. The frontend never decides entitlements."""
from fastapi import HTTPException
from datetime import datetime, timezone
from .db import db
from .util import now

PLANS = {
    "free": {"label": "Free", "price_month_usd": 0, "assessments_per_month": 5, "max_requests_per_assessment": 120,
             "tiers": ["basic"], "report_formats": ["html", "json"], "members": 1, "concurrent_assessments": 1,
             "ai_analysis": False, "custom_attacks": False, "analytics": "basic"},
    "researcher": {"label": "Researcher", "price_month_usd": 29, "assessments_per_month": 60,
                   "max_requests_per_assessment": 1000, "tiers": ["basic", "advanced"],
                   "report_formats": ["html", "json", "csv", "pdf"], "members": 1, "concurrent_assessments": 3,
                   "ai_analysis": True, "custom_attacks": True, "analytics": "extended"},
    "enterprise": {"label": "Enterprise", "price_month_usd": None, "assessments_per_month": 1000,
                   "max_requests_per_assessment": 5000, "tiers": ["basic", "advanced"],
                   "report_formats": ["html", "json", "csv", "pdf"], "members": 200, "concurrent_assessments": 10,
                   "ai_analysis": True, "custom_attacks": True, "analytics": "extended"},
}


async def effective_plan(org_id) -> tuple[str, dict]:
    sub = await db().subscriptions.find_one({"org_id": org_id})
    name = "free"
    if sub and sub.get("status") == "active":
        end = sub.get("current_period_end")
        if end is None or (end if end.tzinfo else end.replace(tzinfo=timezone.utc)) > now():
            name = sub.get("plan", "free") if sub.get("plan") in PLANS else "free"
    return name, PLANS[name]


def month_start():
    n = now()
    return n.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


async def usage_this_month(org_id) -> dict:
    n = await db().assessments.count_documents({"org_id": org_id, "created_at": {"$gte": month_start()},
                                                 "status": {"$ne": "draft"}})
    running = await db().assessments.count_documents({"org_id": org_id, "status": {"$in": ["queued", "running", "pausing"]}})
    members = await db().organization_members.count_documents({"org_id": org_id})
    return {"assessments": n, "running": running, "members": members}


async def require_can_start(org_id) -> tuple[str, dict]:
    name, plan = await effective_plan(org_id)
    u = await usage_this_month(org_id)
    if u["running"] >= plan["concurrent_assessments"]:
        raise HTTPException(429, f"Concurrent assessment limit reached for the {plan['label']} plan")
    return name, plan
