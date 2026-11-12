import logging
from fastapi import Depends, HTTPException, Request
import redis.asyncio as aioredis
from .config import get_settings

log = logging.getLogger("llmguard.ratelimit")
_LUA = """local c=redis.call('INCR',KEYS[1]); if c==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return {c, redis.call('TTL',KEYS[1])}"""
_redis: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis


def reset_redis() -> None:
    global _redis
    _redis = None


async def hit(key: str, limit: int, window: int) -> tuple[bool, int]:
    """Fixed-window counter in Redis. Returns (allowed, retry_after_seconds). Fails open (logged) if Redis is down;
    credential brute-force is additionally bounded by per-account lockout stored in MongoDB."""
    try:
        c, ttl = await get_redis().eval(_LUA, 1, f"rl:{key}", window)
        return c <= limit, max(int(ttl), 1)
    except Exception as e:  # noqa
        log.error("rate limiter unavailable: %s", e)
        return True, 0


def client_ip(request: Request) -> str:
    if get_settings().trust_proxy:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def limit(name: str, count: int, window: int):
    async def dep(request: Request):
        ok, retry = await hit(f"{name}:{client_ip(request)}", count, window)
        if not ok:
            raise HTTPException(429, "Too many requests", headers={"Retry-After": str(retry)})
    return Depends(dep)
