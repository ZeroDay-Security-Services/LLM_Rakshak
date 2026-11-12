import re
from datetime import datetime, timezone
from typing import Any, Iterable
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import HTTPException


def now() -> datetime:
    return datetime.now(timezone.utc)


def oid(v: str | ObjectId, what: str = "resource") -> ObjectId:
    if isinstance(v, ObjectId):
        return v
    try:
        if not isinstance(v, str) or len(v) != 24:
            raise InvalidId
        return ObjectId(v)
    except InvalidId:
        raise HTTPException(404, f"{what} not found")


def to_json(x: Any, exclude: Iterable[str] = ()) -> Any:
    ex = set(exclude)
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            if k in ex:
                continue
            out["id" if k == "_id" else k] = to_json(v, ex)
        return out
    if isinstance(x, list):
        return [to_json(i, ex) for i in x]
    if isinstance(x, ObjectId):
        return str(x)
    if isinstance(x, datetime):
        return (x if x.tzinfo else x.replace(tzinfo=timezone.utc)).isoformat()
    if isinstance(x, bytes):
        return None
    return x


def esc_re(s: str) -> str:
    return re.escape(s.strip()[:100])


async def paginate(coll, flt: dict, *, sort: list, page: int = 1, size: int = 20, projection: dict | None = None,
                   exclude: Iterable[str] = ()) -> dict:
    page = max(1, page)
    size = max(1, min(100, size))
    total = await coll.count_documents(flt)
    cur = coll.find(flt, projection).sort(sort).skip((page - 1) * size).limit(size)
    return {"items": [to_json(d, exclude) async for d in cur], "total": total, "page": page, "size": size}
