import logging
from email.message import EmailMessage
from .config import get_settings

log = logging.getLogger("llmguard.mail")


async def send_email(to: str, subject: str, body: str) -> bool:
    s = get_settings()
    if not s.smtp_host:
        # No SMTP configured: never log message bodies in production (they contain one-time links).
        log.warning("email to %s not sent (SMTP not configured)%s", to, "" if s.is_prod else f"\n--- {subject}\n{body}")
        return False
    import aiosmtplib
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = s.smtp_from, to, subject
    m.set_content(body)
    try:
        await aiosmtplib.send(m, hostname=s.smtp_host, port=s.smtp_port, username=s.smtp_user,
                              password=s.smtp_password, start_tls=True, timeout=15)
        return True
    except Exception as e:  # noqa
        log.error("smtp send failed: %s", type(e).__name__)
        return False
