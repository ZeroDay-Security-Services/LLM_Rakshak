from typing import Literal
from pydantic import BaseModel, EmailStr, Field, field_validator
import re

Provider = Literal["anthropic", "openai", "gemini", "huggingface", "openai_compatible", "custom", "ollama", "vllm"]
Name = Field(min_length=1, max_length=120)


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=128)
    name: str = Field(min_length=1, max_length=100)
    organization: str | None = Field(default=None, max_length=120)

    @field_validator("name", "organization")
    @classmethod
    def _strip(cls, v):
        return re.sub(r"[\x00-\x1f<>]", "", v).strip() if isinstance(v, str) else v


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=128)
    totp_code: str | None = Field(default=None, max_length=8)


class TokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class EmailIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(max_length=128)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=128)
    new_password: str = Field(max_length=128)


class CodeIn(BaseModel):
    code: str = Field(max_length=8)
    password: str | None = Field(default=None, max_length=128)


class ProfileIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    organization: str | None = Field(default=None, max_length=120)
    job_title: str | None = Field(default=None, max_length=100)


class NotifPrefs(BaseModel):
    assessment_completed: bool = True
    assessment_failed: bool = True
    critical_vulnerability: bool = True
    high_vulnerability: bool = True
    announcement: bool = True
    email: bool = False


class DefaultAssessment(BaseModel):
    intensity: Literal["low", "medium", "high"] = "medium"
    max_requests: int = Field(default=150, ge=10, le=5000)
    ai_analysis: bool = False


class PreferencesIn(BaseModel):
    theme: Literal["dark", "light", "system"] = "dark"
    timezone: str = Field(default="UTC", max_length=64, pattern=r"^[A-Za-z_\-+/0-9]+$")
    notifications: NotifPrefs = NotifPrefs()
    default_assessment: DefaultAssessment = DefaultAssessment()
    report_format: Literal["html", "pdf", "json", "csv"] = "html"


class CredentialIn(BaseModel):
    api_key: str = Field(min_length=8, max_length=4096)
    endpoint: str | None = Field(default=None, max_length=2048)
    auth_header: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9\-]{1,64}$")
    auth_scheme: str | None = Field(default=None, max_length=32, pattern=r"^[A-Za-z0-9\-]{0,32}$")


class ModelParams(BaseModel):
    temperature: float | None = Field(default=None, ge=0, le=2)
    max_tokens: int = Field(default=400, ge=16, le=1024)


class ModelIn(BaseModel):
    name: str = Name
    provider: Provider
    model: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._:/\-]+$")
    endpoint: str | None = Field(default=None, max_length=2048)
    system_prompt: str = Field(default="", max_length=8000)
    params: ModelParams = ModelParams()
    credential_provider: Provider | None = None


class Authorization(BaseModel):
    confirmed: bool
    statement: str = Field(min_length=20, max_length=1000)
    endpoint_owner_confirmed: bool = False


class Limits(BaseModel):
    max_requests: int = Field(default=150, ge=5, le=5000)
    max_tokens: int = Field(default=200000, ge=1000, le=5000000)
    timeout: int = Field(default=45, ge=5, le=120)
    retries: int = Field(default=2, ge=0, le=3)


class AssessmentIn(BaseModel):
    name: str = Name
    model_config_id: str = Field(min_length=24, max_length=24)
    system_prompt: str | None = Field(default=None, max_length=8000)
    attack_ids: list[str] | None = Field(default=None, max_length=200)
    categories: list[str] | None = Field(default=None, max_length=10)
    preset: Literal["quick", "standard", "full"] | None = None
    intensity: Literal["low", "medium", "high"] = "medium"
    limits: Limits = Limits()
    params: ModelParams | None = None
    ai_analysis: bool = False
    authorization: Authorization
    notes: str = Field(default="", max_length=2000)


class FindingStatusIn(BaseModel):
    status: Literal["new", "confirmed", "in_progress", "fixed", "retested", "closed"]
    note: str = Field(default="", max_length=1000)


class TriageIn(BaseModel):
    triage: Literal["unreviewed", "confirmed", "false_positive", "needs_review", "accepted_risk", "fixed"]
    note: str = Field(default="", max_length=1000)


class ReportIn(BaseModel):
    format: Literal["html", "pdf", "json", "csv"]


class InviteIn(BaseModel):
    email: EmailStr
    role: Literal["admin", "member", "viewer"] = "member"


class OrgPatch(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class MemberRoleIn(BaseModel):
    role: Literal["admin", "member", "viewer"]
