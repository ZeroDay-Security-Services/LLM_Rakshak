import regex as _re
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator

CATEGORIES = ["prompt_injection", "jailbreak", "sensitive_disclosure", "insecure_output", "excessive_agency",
              "rag_security", "model_dos", "hallucination", "system_prompt", "tool_calling"]
CATEGORY_LABELS = {"prompt_injection": "Prompt Injection", "jailbreak": "Jailbreak", "sensitive_disclosure": "Sensitive Information Disclosure",
                   "insecure_output": "Insecure Output Handling", "excessive_agency": "Excessive Agency", "rag_security": "RAG Security",
                   "model_dos": "Model Denial of Service", "hallucination": "Hallucination & Reliability",
                   "system_prompt": "System Prompt Security", "tool_calling": "Tool & Function Calling Security"}
RuleType = Literal["canary", "canary_obfuscated", "secret_leak", "policy_leak", "pii_leak", "sysprompt_overlap", "regex",
                   "regex_unfenced", "tool_call", "dos_degraded", "output_amplification", "no_rate_limit",
                   "answer_mismatch", "json_inject", "credential_pattern"]
USER_RULE_TYPES = {"canary", "canary_obfuscated", "secret_leak", "policy_leak", "pii_leak", "sysprompt_overlap",
                   "regex", "regex_unfenced", "tool_call"}


class Rule(BaseModel):
    type: RuleType
    patterns: list[str] = Field(default_factory=list, max_length=8)
    names: list[str] = Field(default_factory=list, max_length=8)
    args_regex: str | None = Field(default=None, max_length=300)
    threshold: float = Field(default=0.35, ge=0.05, le=1)
    expected: str | None = Field(default=None, max_length=200)
    soft: bool = False
    strict: bool = False  # presence is a violation even if the reply also contains refusal wording
    conf: float = Field(default=0.9, ge=0.1, le=0.99)
    note: str = Field(default="", max_length=300)

    @model_validator(mode="after")
    def _valid(self):
        for p in [*self.patterns, *([self.args_regex] if self.args_regex else []), *([self.expected] if self.expected else [])]:
            if len(p) > 700:
                raise ValueError("pattern too long")
            try:  # compile + probe with a timeout (ReDoS guard); templated tokens are neutral text here
                rx = _re.compile(_re.sub(r"\{\{\w+\}\}", "X", p), _re.I)
                rx.search("a" * 5000 + "!", timeout=0.2)
            except TimeoutError:
                raise ValueError("pattern is too expensive (possible ReDoS)")
            except Exception as e:  # noqa
                raise ValueError(f"invalid pattern: {e}")
        return self


Turn = str | dict


class DosSpec(BaseModel):
    kind: Literal["long_input", "repeat_input", "amplify_output", "burst"]
    chars: int = 0


class AttackDef(BaseModel):
    attack_id: str = Field(pattern=r"^[A-Za-z0-9_.\-]{3,64}$")
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(max_length=1500)
    category: Literal[tuple(CATEGORIES)]  # type: ignore[valid-type]
    owasp: list[str] = Field(default_factory=list, max_length=6)
    cwe: list[str] = Field(default_factory=list, max_length=6)
    atlas: list[str] = Field(default_factory=list, max_length=6)
    risk: Literal["critical", "high", "medium", "low", "info"]
    cvss_vector: str | None = Field(default=None, pattern=r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$")
    tier: Literal["basic", "advanced"] = "basic"
    turns: list[Turn] = Field(default_factory=list, max_length=8)
    harness: list[Literal["secret", "policy", "pii", "approval", "viewer"]] = Field(default_factory=list)
    tools: bool = False
    repeat: int = Field(default=1, ge=1, le=5)
    dos: DosSpec | None = None
    applies_to: list[str] = Field(default_factory=lambda: ["*"])
    expected_secure: str = Field(max_length=500)
    expected_vulnerable: str = Field(max_length=500)
    detect: list[Rule] = Field(min_length=1, max_length=8)
    evidence: str = Field(default="Redacted request/response transcript and the matched detection rules.", max_length=500)
    remediation: str = Field(max_length=2000)
    version: int = 1

    @field_validator("turns")
    @classmethod
    def _turns(cls, v):
        for t in v:
            c = t if isinstance(t, str) else (t.get("content") if isinstance(t, dict) else None)
            if not isinstance(c, str) or len(c) > 6000 or (isinstance(t, dict) and t.get("role") not in ("user", "assistant")):
                raise ValueError("invalid turn")
        return v

    @model_validator(mode="after")
    def _final(self):
        if not self.dos or self.dos.kind == "burst":
            pass
        if self.turns and not isinstance(self.turns[-1], str) and self.turns[-1].get("role") != "user":
            raise ValueError("the final turn must be a user message")
        if not self.turns and not self.dos:
            raise ValueError("an attack needs turns or a dos spec")
        return self
