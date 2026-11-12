import re
PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("card", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("password_assign", re.compile(r"(?i)\b(pass(?:word|wd)?|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{6,}")),
]
SECRET_KINDS = {k for k, _ in PATTERNS}


def _luhn(s: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if not 13 <= len(d) <= 19:
        return False
    t = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            x -= 9 if x > 9 else 0
        t += x
    return t % 10 == 0


def find_secrets(text: str) -> list[str]:
    kinds = []
    for kind, rx in PATTERNS:
        for m in rx.finditer(text or ""):
            if kind == "card" and not _luhn(m.group(0)):
                continue
            kinds.append(kind)
            break
    return kinds


def redact(text: str, extra_secrets: list[str] | None = None, limit: int = 1500) -> str:
    out = text or ""
    for s in extra_secrets or []:
        if s and len(s) >= 6:
            out = out.replace(s, "[REDACTED:credential]")
    for kind, rx in PATTERNS:
        if kind == "card":
            out = rx.sub(lambda m: "[REDACTED:card]" if _luhn(m.group(0)) else m.group(0), out)
        elif kind == "password_assign":
            out = rx.sub(lambda m: f"{m.group(1)}=[REDACTED:secret]", out)
        else:
            out = rx.sub(f"[REDACTED:{kind}]", out)
    return out if len(out) <= limit else out[:limit] + f"… [truncated {len(out) - limit} chars]"
