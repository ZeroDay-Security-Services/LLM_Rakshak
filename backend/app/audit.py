"""Append-only, hash-chained audit log. No update/delete code path exists in the application; any tampering with a
stored row breaks the chain and is detected by verify_chain(). For defence in depth, run the app with a MongoDB
user whose role on `audit_logs` is insert/find only (see docs/DEPLOYMENT.md)."""
import hashlib, json, logging
from pymongo.errors import DuplicateKeyError
from .db import db
from .util import now

log = logging.getLogger("llmguard.audit")
GENESIS = "0" * 64


def _h(rec: dict) -> str:
    body = {k: rec[k] for k in ("seq", "ts", "actor_id", "actor_email", "action", "target", "ip", "meta", "prev")}
    body["ts"] = body["ts"].astimezone().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] if hasattr(body["ts"], "strftime") else body["ts"]
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


async def audit(action: str, *, actor_id=None, actor_email: str | None = None, target: str | None = None,
                ip: str | None = None, meta: dict | None = None) -> None:
    for _ in range(25):
        last = await db().audit_logs.find_one({}, {"seq": 1, "hash": 1}, sort=[("seq", -1)])
        seq = (last["seq"] + 1) if last else 1
        ts = now().replace(microsecond=(now().microsecond // 1000) * 1000)
        rec = {"seq": seq, "ts": ts, "actor_id": str(actor_id) if actor_id else None, "actor_email": actor_email,
               "action": action, "target": target, "ip": ip, "meta": meta or {}, "prev": last["hash"] if last else GENESIS}
        rec["hash"] = _h(rec)
        try:
            await db().audit_logs.insert_one(rec)
            return
        except DuplicateKeyError:
            continue
    log.error("audit write failed for %s", action)


async def verify_chain(limit: int = 100000) -> dict:
    prev, n = GENESIS, 0
    async for r in db().audit_logs.find({}).sort("seq", 1).limit(limit):
        n += 1
        if r["prev"] != prev or _h(r) != r["hash"] or r["seq"] != n:
            return {"ok": False, "checked": n, "broken_at_seq": r["seq"]}
        prev = r["hash"]
    return {"ok": True, "checked": n, "broken_at_seq": None}
