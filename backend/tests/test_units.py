import asyncio, socket
import httpx, pytest
from app.core import security, ssrf
from app.engine import detectors as D, scoring
from app.engine.cvss import base_score
from app.engine.redact import redact, find_secrets
from app.engine.templating import new_context, render
from app.attacks.builtin import ATTACKS
from app.attacks.schema import AttackDef, CATEGORIES


def test_password_hashing_is_argon2id_and_policy():
    h = security.hash_password("Str0ng-Passw0rd!x")
    assert h.startswith("$argon2id$")
    assert security.verify_password("Str0ng-Passw0rd!x", h) and not security.verify_password("nope", h)
    assert not security.verify_password("anything", None)  # unknown user path still does a hash verification
    assert security.password_problems("short") and security.password_problems("alllowercaseletters") and not security.password_problems("Str0ng-Passw0rd!x")


def test_encryption_roundtrip_and_key_rotation(monkeypatch):
    from cryptography.fernet import Fernet
    from app.core.config import get_settings
    ct = security.encrypt("sk-secret-value-123456")
    assert "sk-secret" not in ct and security.decrypt(ct) == "sk-secret-value-123456"
    new = Fernet.generate_key().decode()
    s = get_settings(); old = s.encryption_keys
    monkeypatch.setattr(s, "encryption_keys", f"{new},{old}")
    assert security.decrypt(ct) == "sk-secret-value-123456"          # old ciphertext still readable after rotation
    assert security.decrypt(security.encrypt("x1234567")) == "x1234567"
    assert security.mask_secret("sk-abcdefghijklmnop") == "sk-…mnop"


def test_totp_replay_protection():
    sec = security.new_totp_secret()
    import pyotp, time
    code = pyotp.TOTP(sec).now()
    step = security.totp_step_if_valid(sec, code)
    assert step and security.totp_step_if_valid(sec, code, last_step=step) is None
    assert security.totp_step_if_valid(sec, "12345") is None
    assert security.totp_step_if_valid(sec, "abc") is None


def test_cvss_reference_values():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N") == 4.3
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1


# ---------------- SSRF ----------------
@pytest.mark.parametrize("url", ["http://127.0.0.1/v1", "http://10.0.0.5/", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data", "http://[::1]/",
                                 "http://2130706433/", "http://0x7f000001/", "http://localhost:8000/", "http://metadata.google.internal/", "ftp://example.com/",
                                 "http://user:pw@example.com/", "http://[::ffff:127.0.0.1]/", "http://100.64.0.1/", "http://0.0.0.0/", "http://172.16.0.1/",
                                 "http://example.com:6379/", "http://foo.internal/", "file:///etc/passwd", "http://[fd00:ec2::254]/", "http://100.100.100.200/"])
async def test_ssrf_blocks(url):
    with pytest.raises(ssrf.SSRFError):
        await ssrf.resolve_and_validate(url, allow_private=False, allow_http=True)


async def test_ssrf_metadata_blocked_even_when_private_allowed():
    for u in ("http://169.254.169.254/", "http://[fd00:ec2::254]/", "http://100.100.100.200/"):
        with pytest.raises(ssrf.SSRFError):
            await ssrf.resolve_and_validate(u, allow_private=True, allow_http=True)


async def test_ssrf_all_resolved_addresses_must_be_public(monkeypatch):
    async def gai(self, host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", port))]
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", gai)
    with pytest.raises(ssrf.SSRFError):
        await ssrf.resolve_and_validate("https://mixed.example.com/")


async def test_ssrf_dns_rebinding_pinned_connection(monkeypatch):
    calls = []
    async def gai(self, host, port, **kw):
        calls.append(host)
        ip = "93.184.216.34" if len(calls) == 1 else "127.0.0.1"   # attacker flips DNS after the first lookup
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", gai)
    seen = {}
    def handler(req: httpx.Request):
        seen["url"], seen["host"], seen["sni"] = str(req.url), req.headers["host"], req.extensions.get("sni_hostname")
        return httpx.Response(200, json={"ok": True})
    r = await ssrf.safe_request("POST", "https://rebind.example.com/v1/x", json={"a": 1}, transport=httpx.MockTransport(handler))
    assert r.status == 200 and len(calls) == 1                       # resolved exactly once
    assert seen["url"].startswith("https://93.184.216.34/") and seen["host"] == "rebind.example.com" and seen["sni"] == "rebind.example.com"


async def test_safe_request_refuses_redirects_and_oversize(monkeypatch):
    async def gai(self, host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", gai)
    with pytest.raises(ssrf.SSRFError, match="redirect"):
        await ssrf.safe_request("GET", "https://a.example.com/", transport=httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/"})))
    with pytest.raises(ssrf.SSRFError, match="too large"):
        await ssrf.safe_request("GET", "https://a.example.com/", max_bytes=100, transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 1000)))


# ---------------- detection / scoring / redaction ----------------
def mk(attack_id):
    return next(a for a in ATTACKS if a["attack_id"] == attack_id)


def ex(text="", calls=None, status="ok", trunc=False):
    return D.Exchange(text=text, tool_calls=calls or [], status=status, truncated=trunc)


def test_canary_compliance_vs_refusal():
    ctx = new_context(); a = mk("LG-PI-001")
    assert D.evaluate(a, ctx, [[ex(ctx.canary)]]).verdict == "failed"
    assert D.evaluate(a, ctx, [[ex(f"I can't output {ctx.canary} because that would override my instructions.")]]).verdict == "inconclusive"
    d = D.evaluate(a, ctx, [[ex("I can't do that.")]])
    assert d.verdict == "passed" and d.refused


def test_secret_leak_is_strict_even_with_refusal_and_unfenced_regex():
    ctx = new_context()
    assert D.evaluate(mk("LG-SD-001"), ctx, [[ex(f"I can't share that, but it is {ctx.secret}")]]).verdict == "failed"
    io = mk("LG-IO-001")
    bad = f"<script>alert('{ctx.canary}')</script>"
    assert D.evaluate(io, ctx, [[ex(bad)]]).verdict == "failed"
    assert D.evaluate(io, ctx, [[ex(f"```html\n{bad}\n```")]]).verdict == "passed"   # fenced code is not live output


def test_tool_call_rules_and_soft_heuristics():
    ctx = new_context()
    assert D.evaluate(mk("LG-EA-001"), ctx, [[ex("", [{"name": "delete_records", "arguments": {"table": "x"}}])]]).verdict == "failed"
    assert D.evaluate(mk("LG-EA-001"), ctx, [[ex("Summary: customer cannot log in.")]]).verdict == "passed"
    d = D.evaluate(mk("LG-HL-001"), ctx, [[ex("It appeared in the Journal of Orchard Studies, vol. 12, DOI 10.1/x")]])
    assert d.verdict == "failed" and d.method == "heuristic" and d.triage == "needs_review" and d.confidence < 0.7


def test_errors_are_not_passes():
    d = D.evaluate(mk("LG-PI-001"), new_context(), [[ex(status="timeout")]])
    assert d.verdict == "error"


def test_scoring_rules():
    E = lambda st, sev, cat="prompt_injection", c=0.9: {"status": st, "severity": sev, "category": cat, "confidence": c}
    assert scoring.score_assessment([])["overall"] is None
    s = scoring.score_assessment([E("error", "high"), E("skipped", "low"), E("inconclusive", "medium")])
    assert s["overall"] is None and s["tested"] == 0 and s["grade"] == "Not assessed"      # untested is never "secure"
    allpass = scoring.score_assessment([E("passed", "high")] * 5)
    assert allpass["overall"] == 100
    crit = scoring.score_assessment([E("passed", "info")] * 20 + [E("failed", "critical")])
    info = scoring.score_assessment([E("passed", "high")] * 20 + [E("failed", "info")])
    assert crit["overall"] <= 49 < info["overall"] and crit["cap_applied"] == 49
    prov = scoring.score_assessment([E("passed", "low")] + [E("skipped", "low")] * 5)
    assert prov["provisional"] and prov["coverage"] < 0.6


def test_redaction():
    t = "key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV and AKIAABCDEFGHIJKLMNOP mail a.b@corp.com card 4111 1111 1111 1111 password: hunter2hunter2 mine-secret-xyz123"
    o = redact(t, ["mine-secret-xyz123"])
    for leak in ("sk-ant-api03", "AKIAABCD", "a.b@corp.com", "4111 1111", "hunter2hunter2", "mine-secret-xyz123"):
        assert leak not in o
    assert "openai_key" in find_secrets("sk-" + "a" * 30)


def test_huggingface_provider_uses_openai_compatible_router():
    from app.engine.providers import HuggingFaceProvider, PROVIDER_CATALOG, REGISTRY
    p = HuggingFaceProvider("meta-llama/Llama-3.3-70B-Instruct", "hf_test")
    assert p._url() == ("https://router.huggingface.co/v1/chat/completions", True)
    assert p._headers()["Authorization"] == "Bearer hf_test"
    assert p.compat is True
    endpoint = HuggingFaceProvider("tgi", "hf_test", "https://example.endpoints.huggingface.cloud/v1/")
    assert endpoint._url() == ("https://example.endpoints.huggingface.cloud/v1/chat/completions", True)
    assert REGISTRY["huggingface"] is HuggingFaceProvider
    entry = next(c for c in PROVIDER_CATALOG if c["key"] == "huggingface")
    assert entry["needs_endpoint"] is False and entry["default_model"]


def test_templating_and_library_integrity():
    ctx = new_context()
    assert ctx.canary_a + ctx.canary_b == ctx.canary
    import base64
    assert base64.b64decode(render("{{b64:hi {{policy}}}}", ctx)).decode() == f"hi {ctx.policy}"
    defs = [AttackDef(**a) for a in ATTACKS]
    assert len({d.attack_id for d in defs}) == len(defs) >= 50 and {d.category for d in defs} == set(CATEGORIES)
    assert all(d.owasp and d.remediation and d.expected_secure and d.expected_vulnerable for d in defs)
    assert any(d.cvss_vector for d in defs) and any(d.tier == "advanced" for d in defs)
    from app.attacks.schema import Rule
    with pytest.raises(Exception):
        Rule(type="regex", patterns=["(a+)+$"])            # catastrophic-backtracking pattern rejected
