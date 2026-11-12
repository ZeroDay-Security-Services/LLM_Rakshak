from fastapi import APIRouter, Depends
from ..db import db
from ..deps import CurrentUser, current_user
from ..util import oid, paginate

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
async def list_(unread: bool = False, page: int = 1, size: int = 30, cu: CurrentUser = Depends(current_user)):
    flt = {"user_id": cu.id}
    if unread:
        flt["read"] = False
    return await paginate(db().notifications, flt, sort=[("created_at", -1)], page=page, size=size, exclude={"user_id", "expires_at"})


@router.get("/unread-count")
async def count(cu: CurrentUser = Depends(current_user)):
    return {"count": await db().notifications.count_documents({"user_id": cu.id, "read": False})}


@router.post("/read-all")
async def read_all(cu: CurrentUser = Depends(current_user)):
    r = await db().notifications.update_many({"user_id": cu.id, "read": False}, {"$set": {"read": True}})
    return {"updated": r.modified_count}


@router.post("/{nid}/read")
async def read(nid: str, cu: CurrentUser = Depends(current_user)):
    await db().notifications.update_one({"_id": oid(nid, "notification"), "user_id": cu.id}, {"$set": {"read": True}})
    return {"ok": True}
