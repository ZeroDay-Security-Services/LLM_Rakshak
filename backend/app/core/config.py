"""Environment-based configuration. No secrets have defaults: the app refuses to start without them."""
from functools import lru_cache
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_prefix="LLMGUARD_")

    env: str = "development"  # development | test | production
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_db: str = "llmguard"
    redis_url: str = "redis://127.0.0.1:6379/0"
    jwt_secret: str
    encryption_keys: str  # comma separated Fernet keys; first encrypts, all decrypt (rotation)
    frontend_origin: str = "http://localhost:3000"
    cookie_secure: bool = True
    cookie_domain: str | None = None
    trust_proxy: bool = False
    access_ttl_minutes: int = 15
    refresh_ttl_days: int = 14
    refresh_abs_ttl_days: int = 30
    task_backend: str = "celery"  # celery | inline
    allow_private_targets: bool = False  # self-hosted LLMs on private networks; metadata IPs stay blocked
    allow_http_targets: bool = False
    # Optional process-wide pacing between calls to the same hosted provider,
    # e.g. 4.2 for a 15 requests/minute quota. 0 disables pacing.
    provider_min_interval: float = 0.0
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "ZeroDay Security Services <zerodaysecurityservices@gmail.com>"
    # Platform-managed secret used for the Claude analysis layer (optional). Users may use their own BYOK key instead.
    analysis_api_key: str | None = None
    analysis_model: str = "claude-sonnet-5-5"
    stripe_webhook_secret: str | None = None
    razorpay_webhook_secret: str | None = None
    payments_enabled: bool = False
    max_dos_payload_chars: int = 64000

    @field_validator("jwt_secret")
    @classmethod
    def _jwt(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("LLMGUARD_JWT_SECRET must be at least 32 characters")
        return v

    @property
    def is_prod(self) -> bool:
        return self.env == "production"

    @property
    def fernet_keys(self) -> list[str]:
        return [k.strip() for k in self.encryption_keys.split(",") if k.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
