"""Modular AI provider layer: Anthropic, OpenAI, Gemini, OpenAI-compatible, custom self-hosted.
User-supplied URLs always go through the SSRF-safe client."""
import asyncio, json, re, time
from dataclasses import dataclass, field
import httpx
from ..core.config import get_settings
from ..core.ssrf import SSRFError, safe_request

HEADER_RE = re.compile(r"^[A-Za-z0-9\-]{1,64}$")
FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection"}


@dataclass
class ProviderResponse:
    text: str = ""
    tool_calls: list = field(default_factory=list)
    status: str = "ok"
    output_tokens: int = 0
    input_tokens: int = 0
    truncated: bool = False
    latency_ms: int = 0
    error: str = ""


def classify(code: int, body: str = "") -> str:
    if code in (401, 403):
        return "auth_error"
    if code == 429:
        return "rate_limited"
    if code >= 500:
        return "server_error"
    return "client_error"


class Provider:
    key = "base"

    def __init__(self, model: str, api_key: str | None = None, endpoint: str | None = None, extra: dict | None = None):
        self.model, self.api_key, self.endpoint, self.extra = model, api_key, endpoint, extra or {}

    async def _post(self, url: str, headers: dict, payload: dict, timeout: float, *, safe: bool) -> tuple[int, dict | None, str]:
        if safe:
            s = get_settings()
            r = await safe_request("POST", url, headers=headers, json=payload, timeout=timeout,
                                   allow_private=s.allow_private_targets, allow_http=s.allow_http_targets)
            try:
                return r.status, r.json(), r.text[:500]
            except Exception:  # noqa
                return r.status, None, r.text[:500]
        async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=False) as c:
            r = await c.post(url, headers=headers, json=payload)
            try:
                return r.status_code, r.json(), r.text[:500]
            except Exception:  # noqa
                return r.status_code, None, r.text[:500]

    async def chat(self, messages: list[dict], system: str | None, tools: list[dict] | None, max_tokens: int,
                   temperature: float | None, timeout: float) -> ProviderResponse:
        t0 = time.monotonic()
        try:
            r = await self._chat(messages, system, tools, max_tokens, temperature, timeout)
        except (httpx.TimeoutException, asyncio.TimeoutError):
            r = ProviderResponse(status="timeout", error="request timed out")
        except SSRFError as e:
            r = ProviderResponse(status="client_error", error=f"blocked by SSRF policy: {e}")
        except httpx.HTTPError as e:
            r = ProviderResponse(status="network_error", error=type(e).__name__)
        r.latency_ms = int((time.monotonic() - t0) * 1000)
        return r

    async def _chat(self, *a) -> ProviderResponse:  # pragma: no cover
        raise NotImplementedError


def _err(code, data, raw) -> ProviderResponse:
    msg = ""
    if isinstance(data, dict):
        e = data.get("error")
        msg = (e.get("message") if isinstance(e, dict) else e) or ""
    return ProviderResponse(status=classify(code), error=f"HTTP {code}: {str(msg or raw)[:300]}")


class AnthropicProvider(Provider):
    key = "anthropic"

    async def _chat(self, messages, system, tools, max_tokens, temperature, timeout):
        p = {"model": self.model, "max_tokens": max_tokens, "messages": messages}
        if system:
            p["system"] = system
        if temperature is not None:
            p["temperature"] = temperature
        if tools:
            p["tools"] = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools]
        code, d, raw = await self._post("https://api.anthropic.com/v1/messages",
                                        {"x-api-key": self.api_key or "", "anthropic-version": "2023-06-01", "content-type": "application/json"}, p, timeout, safe=False)
        if code != 200 or not isinstance(d, dict):
            return _err(code, d, raw)
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        calls = [{"name": b["name"], "arguments": b.get("input", {})} for b in d.get("content", []) if b.get("type") == "tool_use"]
        u = d.get("usage", {})
        return ProviderResponse(text=text, tool_calls=calls, output_tokens=u.get("output_tokens", 0), input_tokens=u.get("input_tokens", 0),
                                truncated=d.get("stop_reason") == "max_tokens")


class OpenAIProvider(Provider):
    key = "openai"
    compat = False

    def _url(self) -> tuple[str, bool]:
        return "https://api.openai.com/v1/chat/completions", False

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "content-type": "application/json"} if self.api_key else {"content-type": "application/json"}

    async def _chat(self, messages, system, tools, max_tokens, temperature, timeout):
        msgs = ([{"role": "system", "content": system}] if system else []) + messages
        p = {"model": self.model, "messages": msgs}
        p["max_tokens" if self.compat else "max_completion_tokens"] = max_tokens
        if temperature is not None:
            p["temperature"] = temperature
        if tools:
            p["tools"] = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}} for t in tools]
        url, safe = self._url()
        code, d, raw = await self._post(url, self._headers(), p, timeout, safe=safe)
        if code != 200 or not isinstance(d, dict) or not d.get("choices"):
            return _err(code, d, raw) if code != 200 else ProviderResponse(status="server_error", error="malformed response")
        ch = d["choices"][0]
        m = ch.get("message", {})
        calls = []
        for c in m.get("tool_calls") or []:
            fn = c.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except Exception:  # noqa
                args = {"_raw": fn.get("arguments")}
            calls.append({"name": fn.get("name", ""), "arguments": args})
        u = d.get("usage", {})
        return ProviderResponse(text=m.get("content") or "", tool_calls=calls, output_tokens=u.get("completion_tokens", 0),
                                input_tokens=u.get("prompt_tokens", 0), truncated=ch.get("finish_reason") == "length")


class OpenAICompatibleProvider(OpenAIProvider):
    key = "openai_compatible"
    compat = True

    def _url(self):
        base = (self.endpoint or "").rstrip("/")
        return (base if base.endswith("/chat/completions") else base + "/chat/completions"), True

    def _headers(self):
        h = {"content-type": "application/json"}
        if self.api_key:
            name = self.extra.get("auth_header") or "Authorization"
            scheme = self.extra.get("auth_scheme", "Bearer" if name == "Authorization" else "")
            if HEADER_RE.match(name) and name.lower() not in FORBIDDEN_HEADERS:
                h[name] = f"{scheme} {self.api_key}".strip()
        return h


class CustomProvider(OpenAICompatibleProvider):
    key = "custom"


class HuggingFaceProvider(OpenAIProvider):
    """Hugging Face Inference Providers (OpenAI-compatible chat completions).

    The default route is the HF router; self-hosted TGI/Inference Endpoints can
    be supplied as an explicit endpoint (SSRF-validated like every user URL).
    """
    key = "huggingface"
    compat = True

    def _url(self):
        base = (self.endpoint or "https://router.huggingface.co/v1").rstrip("/")
        return (base if base.endswith("/chat/completions") else base + "/chat/completions"), True

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}", "content-type": "application/json"} if self.api_key else {"content-type": "application/json"}


class GeminiProvider(Provider):
    key = "gemini"

    async def _chat(self, messages, system, tools, max_tokens, temperature, timeout):
        contents = [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]} for m in messages]
        gc = {"maxOutputTokens": max_tokens}
        if temperature is not None:
            gc["temperature"] = temperature
        p = {"contents": contents, "generationConfig": gc}
        if system:
            p["systemInstruction"] = {"parts": [{"text": system}]}
        if tools:
            p["tools"] = [{"functionDeclarations": [{"name": t["name"], "description": t["description"], "parameters": t["parameters"]} for t in tools]}]
        model = re.sub(r"[^A-Za-z0-9._\-]", "", self.model)
        code, d, raw = await self._post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                                        {"x-goog-api-key": self.api_key or "", "content-type": "application/json"}, p, timeout, safe=False)
        if code != 200 or not isinstance(d, dict):
            return _err(code, d, raw)
        cands = d.get("candidates") or []
        parts = (cands[0].get("content", {}).get("parts", []) if cands else [])
        text = "".join(x.get("text", "") for x in parts)
        calls = [{"name": x["functionCall"]["name"], "arguments": x["functionCall"].get("args", {})} for x in parts if "functionCall" in x]
        u = d.get("usageMetadata", {})
        return ProviderResponse(text=text, tool_calls=calls, output_tokens=u.get("candidatesTokenCount", 0), input_tokens=u.get("promptTokenCount", 0),
                                truncated=bool(cands) and cands[0].get("finishReason") == "MAX_TOKENS")


REGISTRY = {"anthropic": AnthropicProvider, "openai": OpenAIProvider, "gemini": GeminiProvider,
            "huggingface": HuggingFaceProvider, "openai_compatible": OpenAICompatibleProvider,
            "custom": CustomProvider}
PROVIDER_CATALOG = [
    {"key": "anthropic", "label": "Anthropic Claude", "needs_endpoint": False, "default_model": "claude-sonnet-5-5"},
    {"key": "openai", "label": "OpenAI", "needs_endpoint": False, "default_model": "gpt-4o-mini"},
    {"key": "gemini", "label": "Google Gemini", "needs_endpoint": False, "default_model": "gemini-2.0-flash"},
    {"key": "huggingface", "label": "Hugging Face Inference Providers", "needs_endpoint": False, "default_model": "meta-llama/Llama-3.3-70B-Instruct"},
    {"key": "openai_compatible", "label": "OpenAI-compatible endpoint", "needs_endpoint": True, "default_model": ""},
    {"key": "custom", "label": "Custom self-hosted endpoint", "needs_endpoint": True, "default_model": ""},
]


def build_provider(kind: str, model: str, api_key: str | None, endpoint: str | None, extra: dict | None = None) -> Provider:
    cls = REGISTRY.get(kind)
    if not cls:
        raise ValueError(f"unsupported provider {kind}")
    return cls(model, api_key, endpoint, extra)
