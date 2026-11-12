# Test report — ZeroDay's LLM Rakshak

Executed record for the final validation pass on **11 November 2026**. This report records what was actually run; it does not claim coverage that was not exercised.

## 1. Summary

| Check | Result |
|---|---|
| Backend automated suite | **76 passed, 0 failed** in **60.81 s** |
| Live provider assessment | **84 selected, 83 tested, 55 passed, 28 failed, 1 skipped, 0 errors** (98.8% coverage) |
| Live provider | Google Gemini `gemini-3.1-flash-lite` (real network calls, low intensity, paced) |
| Evidence-aware report score | **62 / 100 — Fair** (recalculated from enriched findings; stored score 69, reconciled) |
| Report exports | HTML, PDF, JSON, CSV generated and validated for consistency |
| Branding | Supplied `logo.jpg` embedded in UI/HTML/PDF; no generated logos; no legacy product name in artifacts |
| UI responsiveness | Public pages at 8 widths and 13 authenticated routes at 375 px: no horizontal overflow |

## 2. Environment

| Component | Version / detail |
|---|---|
| Platform | Windows (win32), Python **3.11.0** |
| Test runner | pytest **9.2.0**, pytest-asyncio **1.4.1** |
| Database | MongoDB **7.0.45**, database `llmguard_test` (real server, no mocks) |
| Cache / rate limit | Redis **7.4.9**, database 15 (real server) |
| Frontend | Node.js **24.18.0**, Next.js **16.4.5** |
| Browser used for UI checks | Microsoft Edge via CDP (`127.0.0.1:9222`) |
| API under test | `127.0.0.1:8100`, frontend dev server `localhost:3100` |

Provider pacing is disabled inside the test suite (`LLMGUARD_PROVIDER_MIN_INTERVAL=0` in `backend/tests/conftest.py`) so local end-to-end tests are not delayed. The live assessment used the operational value `4.2` seconds between provider calls to stay within the Gemini free-tier quota.

## 3. Automated test suite

Command:

```powershell
cd backend
.venv\Scripts\python.exe -m pytest -q
```

Final result:

```text
........................................................................ [ 94%]
....                                                                     [100%]
76 passed in 60.81s (0:01:00)
```

| File | Tests | What is covered |
|---|---:|---|
| `tests/test_units.py` | 36 | Argon2id and password policy; encryption key rotation; TOTP replay; CVSS 3.1 reference vectors; canary/refusal detection; strict secret-leak detection; tool-call rules and soft heuristics; errors are not passes; scoring caps and untested ≠ secure; redaction and secret patterns; templating and 84-module library integrity; **Hugging Face router adapter** (URL, auth header, endpoint suffix, registry/catalog). |
| `tests/test_auth.py` | 8 | Enumeration-safe registration/verification/login; weak-password rejection and closed registration; CSRF; refresh rotation and reuse detection; lockout and rate limits; logout/session invalidation and password-reset revocation; TOTP MFA with replay protection; session list/revoke/history. |
| `tests/test_tenancy.py` | 4 | Cross-tenant isolation and IDOR (identical 404s); RBAC denials; NoSQL-operator injection rejection; credentials absent from responses/logs and encrypted at rest. |
| `tests/test_e2e.py` | 13 | Vulnerable vs hardened local OpenAI-compatible target; plan-gated advanced modules; budget exhaustion → not tested; unreachable target failure + notification; pause/resume/cancel; retries; credential redaction; findings workflow/triage/retest; reports (HTML/PDF/JSON/CSV) and versioning; cross-tenant download denial; entitlements; admin/config/maintenance/announcements/audit; billing webhook signature verification. |
| `tests/test_reporting.py` | 11 | Six-state evidence classification; confidence bounds; validation status; CVSS eligibility gating; tool/output/service state separation; redaction; missing evidence; large reports; export consistency; CSV formula-injection guard. |
| `tests/test_analysis.py` | 4 | AI analysis merge rules (never overrides strong deterministic hits); heuristic/inconclusive resolution; schema-validated judge resistant to injected output; honest deterministic summary. |

Total: **36 + 8 + 4 + 13 + 11 + 4 = 76**.

## 4. Live assessment record

| Field | Value |
|---|---|
| Assessment ID | `6af42aa6659112a7a497e7b5` |
| Name | ZeroDay Full Library Validation 2026-11-11 (84 modules) |
| Organization | ZeroDay QA Workspace |
| Owner | QA Operator |
| Authorization | Confirmed in-product for the QA workspace; harmless canary payloads only |
| Provider / model | `gemini` / `gemini-3.1-flash-lite` |
| Intensity | Low |
| Limits | 500 requests, 500,000 tokens, 45 s timeout, 3 retries |
| Started (UTC) | 2026-11-11T08:43:18.525Z |
| Finished (UTC) | 2026-11-11T08:51:11.857Z |
| Status | Completed |

### Execution counts

| Metric | Count |
|---|---:|
| Modules selected | 84 |
| Tested | 83 |
| Passed | 55 |
| Failed | 28 |
| Skipped | 1 |
| Errors | 0 |
| Coverage | 98.8% |

The one skipped test is reported as not tested, not as secure. Provider rate-limit errors from an earlier high-volume attempt were eliminated by pacing; this run recorded no provider errors.

### Evidence-aware classification (28 findings)

| Classification | Count |
|---|---:|
| Confirmed vulnerability | 14 |
| Likely vulnerability | 0 |
| Unsafe behaviour | 7 |
| Potential vulnerability | 6 |
| Inconclusive | 1 |
| False positive | 0 |

### Severity (actionable findings)

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 11 |
| Medium | 15 |
| Low | 1 |
| Informational | 0 actionable (1 inconclusive finding is shown in the finding list but excluded from the actionable severity table) |

CVSS scores were published for **3 findings** (`LG-RG-001`, `LG-PI-001`, `LG-PI-003`) — all confirmed. The other 25 findings have CVSS suppressed because the evidence did not meet the confirmed-impact threshold.

### Score reconciliation

| Value | Score |
|---|---:|
| Stored at execution time | 69 |
| Recalculated by the report from enriched evidence | **62** |
| Grade | **Fair** |

The report includes a reconciliation note stating that the recalculated value is authoritative. The difference comes from evidence-aware classification factors applied to the persisted executions.

## 5. Report artifacts

Generated from the live assessment above through the report API, then downloaded to the repository root.

| Format | Report ID | Version | Size (bytes) | SHA-256 |
|---|---|---:|---:|---|
| HTML | `RPT-EA3F145D` | 9 | 314,004 | `b9f0cc7673a0c8cd809b443af2878fe186ce6c721600cd043ff83f887ebc0114` |
| PDF | `RPT-C67D15CD` | 10 | 306,759 | `83c3c23518e75c0b0c7735720062ba8ee4e189d86de44bb465f7b0038085b7e7` |
| JSON | `RPT-FE4635C1` | 11 | 331,544 | `793edd2f0f8ac287553f07fe7a6a460976e20f0dbaa5b0721573a55cad9c793e` |
| CSV | `RPT-4510A69E` | 12 | 40,822 | `e495f2a1293bb2b1918b64c3f1b4fad4dadd43a9bc191738b4da35efcbda4216` |

Report model manifest SHA-256: `5fac40d8a4a7e9f31c2093ed6246af8cf5501d85577f6db6977e596427737839`. Per-finding evidence hashes are present for all 28 findings.

### Validation checks performed

- All four formats contain the same assessment, score (62), and 28 findings; classification and severity counts agree.
- Every finding carries a top-level `test_id` (alias of `attack_id`) in addition to `finding_id`.
- The test inventory contains all 84 modules: 55 passed, 28 failed, 1 skipped.
- Per-finding evidence block includes target, provider, timestamp, procedure, redacted request/response, expected vs actual, detection rule, confidence, validation status, and limitations. Tool execution, output security, and service impact are separate state objects.
- All published CVSS scores belong to confirmed findings; suppressed findings include a reason.
- HTML and PDF embed the supplied `logo.jpg` as base64; the PDF has a valid `%PDF` header and renders with the brand cover and per-finding evidence sections.
- No `LLMGuard` legacy product string appears in the report artifacts; user-visible branding is ZeroDay's LLM Rakshak.
- CSV output is formula-injection guarded.
- Report timestamps and evidence hashes are internally consistent between JSON, HTML, and CSV exports.

## 6. UI and responsiveness checks

Automated browser audit through Edge CDP. Overflow was measured as `document.documentElement.scrollWidth > window.innerWidth`.

| Viewport | Pages checked | Result |
|---|---|---|
| 320×568 | Public homepage | No overflow |
| 375×812 | Public homepage, login, and 13 authenticated routes | No overflow on any route |
| 430×932 | Public homepage | No overflow |
| 768×1024 | Public homepage | No overflow |
| 1024×768 | Public homepage | No overflow |
| 1366×768 | Public homepage | No overflow |
| 1440×900 | Public homepage, dashboard, assessments | No overflow |
| 1920×1080 | Public homepage | No overflow |

Authenticated routes audited at 375 px: dashboard, assessments list, new assessment, assessment detail, vulnerabilities list, vulnerability detail, attacks list, attack detail, models, reports, notifications, organization, settings. All returned `scrollWidth == innerWidth == 375`.

Screenshots retained in `screenshots/`:

- `home-{320x568,375x812,430x932,768x1024,1024x768,1366x768,1440x900,1920x1080}.png`
- `login-375x812.png`
- `dashboard-375x812.png`, `dashboard-1440x900.png`
- `assessments-1440x900.png`
- `report-html-top.png`, `report-html-findings.png` (rendered HTML report cover and per-finding evidence)

## 7. Limitations of this validation

- The live run used **Gemini only**. Anthropic, OpenAI, and Hugging Face adapters are unit-tested/compatible-path-tested but were not called live with real keys in this pass.
- Detection is based on harmless canaries and policy probes. A failed test demonstrates model/API-boundary behaviour, not downstream application exploitation.
- Tool-call and output-rendering findings remain potential/unsafe unless execution or rendering was observed.
- The assessment covers one model configuration at low intensity; results are non-deterministic and not a security guarantee.
- Load, soak, independent penetration, Atlas, SMTP, and payment-checkout paths remain outside this executed record.
- The severity table intentionally excludes the single inconclusive finding, so actionable severity counts sum to 27 while the finding list contains 28 entries.

## 8. Reproduce

```powershell
# Automated suite
cd backend
.venv\Scripts\python.exe -m pytest -q

# Reports are already generated from the recorded live assessment:
# report.html / report.pdf / report.json / report.csv in the repository root
```

See [`SCOPE.md`](SCOPE.md) for what is and is not verified, [`REPORTING_METHODOLOGY.md`](REPORTING_METHODOLOGY.md) for classification and CVSS rules, and [`SCANNING_METHODOLOGY.md`](SCANNING_METHODOLOGY.md) for the test procedure.
