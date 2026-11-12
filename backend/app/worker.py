"""Celery worker. Run:  celery -A app.worker.celery_app worker -l info --concurrency=4"""
import asyncio
from bson import ObjectId
from celery import Celery
from .core.config import get_settings

s = get_settings()
celery_app = Celery("llmguard", broker=s.redis_url, backend=None)
celery_app.conf.update(task_acks_late=True, worker_prefetch_multiplier=1, task_time_limit=6 * 3600, task_soft_time_limit=6 * 3600 - 60,
                       broker_connection_retry_on_startup=True, task_reject_on_worker_lost=True, task_serializer="json", accept_content=["json"])


async def _go(aid: str, job_id: str | None) -> str:
    from .db import init_db, close_db
    from .engine import runner
    await init_db()
    try:
        return await runner.run_assessment(ObjectId(aid), ObjectId(job_id) if job_id else None)
    finally:
        await close_db()


@celery_app.task(name="llmguard.run_assessment")
def run_assessment_task(aid: str, job_id: str | None = None) -> str:
    return asyncio.run(_go(aid, job_id))


@celery_app.task(name="llmguard.ping")
def ping() -> str:
    return "pong"
