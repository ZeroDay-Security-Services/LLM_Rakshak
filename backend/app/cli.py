"""python -m app.cli create-admin --email you@example.com --role super_admin   (password read from LLMGUARD_ADMIN_PASSWORD or prompt)"""
import argparse, asyncio, getpass, os
from .core import security
from .db import close_db, db, ensure_indexes, init_db
from .seed import seed
from .util import now


async def create_admin(email: str, name: str, role: str, password: str):
    await init_db(); await ensure_indexes(); await seed()
    probs = security.password_problems(password, email)
    if probs:
        raise SystemExit("Weak password: " + "; ".join(probs))
    t = now(); email = email.lower()
    if await db().users.find_one({"email": email}):
        raise SystemExit("User already exists")
    u = await db().users.insert_one({"email": email, "name": name, "password_hash": security.hash_password(password), "role": role, "is_active": True, "email_verified": True,
                                     "mfa_enabled": False, "failed_attempts": 0, "created_at": t, "preferences": {"theme": "dark", "timezone": "UTC"}})
    o = await db().organizations.insert_one({"name": f"{name}'s workspace", "slug": "admin-" + security.new_token(4)[0][:6].lower(), "owner_id": u.inserted_id, "created_at": t})
    await db().organization_members.insert_one({"org_id": o.inserted_id, "user_id": u.inserted_id, "role": "owner", "created_at": t})
    await db().subscriptions.insert_one({"org_id": o.inserted_id, "plan": "enterprise", "status": "active", "provider": "admin", "created_at": t})
    await db().users.update_one({"_id": u.inserted_id}, {"$set": {"active_org_id": o.inserted_id}})
    print(f"Created {role} {email}")
    await close_db()


def main():
    p = argparse.ArgumentParser(); sp = p.add_subparsers(dest="cmd", required=True)
    a = sp.add_parser("create-admin"); a.add_argument("--email", required=True); a.add_argument("--name", default="Administrator"); a.add_argument("--role", choices=["admin", "super_admin"], default="super_admin")
    sp.add_parser("seed")
    args = p.parse_args()
    if args.cmd == "create-admin":
        pw = os.environ.get("LLMGUARD_ADMIN_PASSWORD") or getpass.getpass("Password: ")
        asyncio.run(create_admin(args.email, args.name, args.role, pw))
    else:
        async def _s():
            await init_db(); await ensure_indexes(); print(await seed()); await close_db()
        asyncio.run(_s())


if __name__ == "__main__":
    main()
