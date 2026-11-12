import hashlib, hmac, re, secrets, time
from datetime import datetime, timedelta, timezone
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from jose import jwt, JWTError
from .config import get_settings

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)  # Argon2id (library default type)
_DUMMY = _ph.hash("llmguard-dummy-password-for-timing")


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str | None) -> bool:
    """Always performs one Argon2 verification (dummy hash when user is unknown) to blunt timing-based enumeration."""
    try:
        ok = _ph.verify(hashed or _DUMMY, pw)
        return bool(ok) and hashed is not None
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _ph.check_needs_rehash(hashed)


def password_problems(pw: str, email: str = "") -> list[str]:
    errs = []
    if len(pw) < 12:
        errs.append("at least 12 characters")
    if len(pw) > 128:
        errs.append("at most 128 characters")
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
    if classes < 3:
        errs.append("at least 3 of: lowercase, uppercase, digit, symbol")
    name = email.split("@")[0].lower()
    if len(name) >= 4 and name in pw.lower():
        errs.append("must not contain your email name")
    return errs


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def new_token(nbytes: int = 32) -> tuple[str, str]:
    raw = secrets.token_urlsafe(nbytes)
    return raw, sha256(raw)


def create_access_token(user_id: str, session_id: str, role: str) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    claims = {"sub": user_id, "sid": session_id, "role": role, "iat": int(now.timestamp()),
              "exp": int((now + timedelta(minutes=s.access_ttl_minutes)).timestamp()), "typ": "access"}
    return jwt.encode(claims, s.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> dict | None:
    try:
        c = jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"])
        return c if c.get("typ") == "access" else None
    except JWTError:
        return None


def _fernet() -> MultiFernet:
    return MultiFernet([Fernet(k.encode()) for k in get_settings().fernet_keys])


def encrypt(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise ValueError("credential cannot be decrypted (key rotated or data corrupt)") from e


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "•" * len(secret)
    return f"{secret[:3]}…{secret[-4:]}"


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="ZeroDay's LLM Rakshak")


def totp_step_if_valid(secret: str, code: str, last_step: int = 0) -> int | None:
    """Returns the matched time-step (for replay protection) or None."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    t = pyotp.TOTP(secret)
    now_step = int(time.time() // 30)
    for step in (now_step - 1, now_step, now_step + 1):
        if step > last_step and hmac.compare_digest(t.at(step * 30), code):
            return step
    return None


def csrf_token() -> str:
    return secrets.token_urlsafe(24)


def constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
