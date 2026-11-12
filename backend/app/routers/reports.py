import hashlib
import secrets
from typing import Literal

from bson import Binary
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from .. import reports as R
from ..audit import audit
from ..core.ratelimit import client_ip, limit
from ..db import db
from ..deps import CurrentUser, require, scope
from ..entitlements import effective_plan
from ..schemas import ReportIn
from ..util import now, oid, paginate, to_json
from .assessments import own

router = APIRouter(prefix="/api", tags=["reports"])
CONTENT_DISPOSITION = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"


async def _report_payload(a: dict, cu: CurrentUser, report_id: str = "PREVIEW") -> tuple[dict, int]:
    """Build the normalised report model from persisted records only."""
    fs = [f async for f in db().vulnerabilities.find({"assessment_id": a["_id"]}).sort([("severity_rank", -1), ("detected_at", 1)])]
    ex = [e async for e in db().attack_executions.find({"assessment_id": a["_id"]}).sort("order", 1)]
    ids = sorted(({e.get("attack_id") for e in ex} | {f.get("attack_id") for f in fs}) - {None})
    attacks = {m["attack_id"]: m async for m in db().attack_modules.find({"attack_id": {"$in": ids}})}
    org = await db().organizations.find_one({"_id": a["org_id"]})
    owner = await db().users.find_one({"_id": a["owner_id"]}, {"name": 1})
    version = await db().assessment_reports.count_documents({"assessment_id": a["_id"]}) + 1
    return R.build(a, (org or {}).get("name", ""), (owner or {}).get("name", ""), fs, ex, attacks, version, report_id), version


async def _require_finished(a: dict) -> None:
    if a.get("status") not in ("completed", "cancelled", "failed", "paused"):
        raise HTTPException(409, "Reports are available once an assessment has finished or paused")


async def _require_format(cu: CurrentUser, fmt: str) -> None:
    _, plan = await effective_plan(cu.org_id)
    if fmt not in plan["report_formats"]:
        raise HTTPException(403, f"The {plan['label']} plan does not include {fmt.upper()} reports")


@router.post("/assessments/{aid}/reports", status_code=201, dependencies=[limit("report", 30, 3600)])
async def generate(aid: str, body: ReportIn, request: Request, cu: CurrentUser = Depends(require("report:write"))):
    a = await own(aid, cu)
    await _require_finished(a)
    await _require_format(cu, body.format)
    rid = "RPT-" + secrets.token_hex(4).upper()
    data, version = await _report_payload(a, cu, rid)
    fn, ctype = R.RENDER[body.format]
    content = fn(data)
    if len(content) > 8_000_000:
        raise HTTPException(413, "Report too large")
    digest = hashlib.sha256(content).hexdigest()
    doc = {
        "report_id": rid, "assessment_id": a["_id"], "org_id": a["org_id"], "owner_id": cu.id,
        "format": body.format, "version": version, "size": len(content), "sha256": digest,
        "manifest_sha256": data["integrity"]["manifest_sha256"], "content_type": ctype,
        "content": Binary(content), "created_at": now(), "name": a["name"],
        "classification_summary": data["statistics"]["classifications"],
        "finding_count": data["statistics"]["findings_total"],
        "score": data["score"].get("overall"),
    }
    r = await db().assessment_reports.insert_one(doc)
    await audit("report.generated", actor_id=cu.id, target=str(r.inserted_id), ip=client_ip(request),
                meta={"format": body.format, "assessment": aid, "findings": doc["finding_count"], "sha256": digest})
    out = to_json(doc, {"content", "owner_id", "org_id"}) | {"id": str(r.inserted_id)}
    return out


@router.get("/assessments/{aid}/reports/preview")
async def preview(aid: str, format: Literal["html", "pdf", "json", "csv"] = "html",
                  inline: int = 1, cu: CurrentUser = Depends(require("report:read"))):
    """Render a report from current records without storing it (used by the in-app preview)."""
    a = await own(aid, cu)
    await _require_finished(a)
    await _require_format(cu, format)
    data, _ = await _report_payload(a, cu, "PREVIEW")
    fn, ctype = R.RENDER[format]
    content = fn(data)
    return Response(content, media_type=ctype, headers={
        "Content-Disposition": f"inline; filename=\"zeroday-llm-rakshak-preview.{format}\"" if inline else f"attachment; filename=\"zeroday-llm-rakshak-preview.{format}\"",
        "X-Content-Type-Options": "nosniff", "Content-Security-Policy": CONTENT_DISPOSITION,
        "Cache-Control": "private, no-store",
    })


@router.get("/reports")
async def list_(assessment_id: str | None = None, page: int = 1, size: int = 20, cu: CurrentUser = Depends(require("report:read"))):
    flt = scope(cu)
    if assessment_id:
        flt["assessment_id"] = oid(assessment_id, "assessment")
    return await paginate(db().assessment_reports, flt, sort=[("created_at", -1)], page=page, size=size,
                          exclude={"content", "owner_id", "org_id"})


@router.get("/reports/{rid}/download")
async def download(rid: str, request: Request, inline: int = 0, cu: CurrentUser = Depends(require("report:read"))):
    r = await db().assessment_reports.find_one({"_id": oid(rid, "report"), **scope(cu)})
    if not r:
        raise HTTPException(404, "Report not found")
    await audit("report.downloaded", actor_id=cu.id, target=rid, ip=client_ip(request))
    ext = r["format"]
    disposition = "inline" if inline else "attachment"
    return Response(bytes(r["content"]), media_type=r["content_type"], headers={
        "Content-Disposition": f'{disposition}; filename="zeroday-llm-rakshak-{r["report_id"]}-v{r["version"]}.{ext}"',
        "X-Content-Type-Options": "nosniff", "Content-Security-Policy": CONTENT_DISPOSITION,
        "X-Report-SHA256": r.get("sha256", ""), "Cache-Control": "private, no-store",
    })


@router.delete("/reports/{rid}")
async def delete(rid: str, cu: CurrentUser = Depends(require("report:write"))):
    r = await db().assessment_reports.delete_one({"_id": oid(rid, "report"), **scope(cu)})
    if not r.deleted_count:
        raise HTTPException(404, "Report not found")
    return {"message": "Deleted"}
