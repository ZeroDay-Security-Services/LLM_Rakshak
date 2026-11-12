import asyncio, logging
from bson import ObjectId
from fastapi import HTTPException
from .core.config import get_settings
from .db import db
from .util import now

log = logging.getLogger("llmguard.jobs")
_inline: set = set()


async def _run_inline(aid, job_id):
    from .engine import runner
    try:
        await runner.run_assessment(aid, job_id)
    except Exception:  # noqa
        log.exception("inline job crashed")


async def dispatch(aid: ObjectId) -> ObjectId:
    a = await db().assessments.find_one({"_id": aid}, {"org_id": 1})
    r = await db().assessment_jobs.insert_one({"assessment_id": aid, "org_id": a["org_id"], "status": "queued", "created_at": now()})
    job_id = r.inserted_id
    if get_settings().task_backend == "inline":
        t = asyncio.create_task(_run_inline(aid, job_id))
        _inline.add(t)
        t.add_done_callback(_inline.discard)
        return job_id
    try:
        from .worker import run_assessment_task
        res = await asyncio.to_thread(run_assessment_task.apply_async, args=[str(aid), str(job_id)])
        await db().assessment_jobs.update_one({"_id": job_id}, {"$set": {"celery_id": res.id}})
    except Exception as e:  # noqa
        await db().assessment_jobs.update_one({"_id": job_id}, {"$set": {"status": "failed", "error": "queue unavailable"}})
        await db().assessments.update_one({"_id": aid}, {"$set": {"status": "failed", "error": "background queue unavailable"}})
        log.error("enqueue failed: %s", e)
        raise HTTPException(503, "Background worker queue is unavailable")
    return job_id


async def wait_inline() -> None:
    if _inline:
        await asyncio.gather(*list(_inline), return_exceptions=True)
