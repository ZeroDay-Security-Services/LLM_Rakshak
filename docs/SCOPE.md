# Scope: what is verified and what is not

Honest status of this codebase as of **11 November 2026**. "Verified" means it was actually executed in this build environment. Anything not listed under **Verified by execution** is not claimed as proven.

## Verified by execution

| Area | How it was verified |
|---|---|
| Backend suite: **76 automated tests** | `python -m pytest -q` → **76 passed in 60.81s** against real MongoDB 7.0.45 and Redis 7.4.9 (no database mocks). Breakdown: 36 unit, 8 auth, 4 tenancy, 13 end-to-end, 11 reporting, 4 analysis. |
| Auth: Argon2id, registration/verification/login, enumeration-safe responses, lockout, rate limits, CSRF, refresh rotation + reuse detection, password reset (single-use, revokes sessions), TOTP MFA with replay protection, session list/revoke | `tests/test_auth.py` |
| Tenant isolation / IDOR (identical 404s for foreign vs missing ids), RBAC (viewer cannot write, admin routes 403), NoSQL-operator injection rejected, credentials never in responses/logs and encrypted at rest | `tests/test_tenancy.py` |
| SSRF guard: 20 blocked URL forms (loopback, RFC1918, metadata, decimal/hex IPs, IPv4-mapped IPv6, CGNAT, creds-in-URL, bad ports/schemes), mixed DNS answers, DNS-rebinding pinning (single resolution; connection to the validated IP with Host + SNI), no redirects, response cap | `tests/test_units.py` |
| Engine end-to-end against a vulnerable and a hardened local OpenAI-compatible target (real HTTP through the SSRF-pinned client): findings and a low score vs no findings and 100; plan-gated advanced modules; budget exhaustion → "not tested" (never secure); unreachable target fails cleanly and notifies; pause → resume → cancel; retries; redaction of an echoed credential | `tests/test_e2e.py` |
| Findings workflow rules, triage, retest (finding becomes *Retested* only after a real passing re-run), filters/sort/pagination | `tests/test_e2e.py` |
| Reports: HTML (output-escaped, CSP headers), JSON, CSV (formula-injection guard), PDF (`%PDF`), plan gating, version increments, cross-tenant download blocked | `tests/test_e2e.py` |
| Evidence-aware reporting: six-state classification, confidence bounds, validation status, CVSS gating, tool/output/service state separation, redaction, missing-evidence handling, large reports, export consistency, formula injection | `tests/test_reporting.py` (11 tests) |
| Entitlements enforced server-side (Free vs Researcher vs Enterprise), admin plan set, billing webhook signature verification (Stripe HMAC + timestamp) | `tests/test_e2e.py` |
| Admin panel, platform config, maintenance mode, announcements, hash-chained audit log with tamper detection | `tests/test_e2e.py` |
| AI-analysis merge rules (AI never overrides a strong deterministic hit; invalid/malicious judge output discarded) | `tests/test_analysis.py` (provider call mocked) |
| CVSS 3.1 calculator against reference vectors; scoring rules (caps, untested ≠ secure, provisional coverage) | `tests/test_units.py` |
| **Real live Gemini assessment** across the full 84-module library | Assessment `6af42aa6659112a7a497e7b5` against `gemini-3.1-flash-lite` through the live Google API: **84 selected, 83 tested, 55 passed, 28 failed, 1 skipped, 0 errors**, coverage **98.8%**. Classification: 14 confirmed, 7 unsafe behaviour, 6 potential, 1 inconclusive. Report score **62/100 (Fair)** recalculated from 69 stored, with a reconciliation note. |
| **HTML / PDF / JSON / CSV report generation** from the canonical report model | Four reports generated from the live assessment (versions 9–12). All four contain the same 28 findings and classification counts; the JSON carries per-finding `test_id` and nested evidence validation; the HTML/PDF embed the supplied `logo.jpg`; the CSV is formula-injection guarded. |
| **Branding** | User-visible product surfaces use **ZeroDay's LLM Rakshak** / **ZeroDay Security Services**. The supplied `logo.jpg` is used in the frontend and embedded in HTML/PDF reports. Generated/substitute logo assets were removed. Legacy `LLMGuard` names do not appear in the report artifacts. |
| **Frontend responsiveness** | Browser-verified in Edge via CDP at 320×568, 375×812, 430×932, 768×1024, 1024×768, 1366×768, 1440×900 and 1920×1080. Public pages have no horizontal overflow at any width. Authenticated pages were checked at 375×812 and 1440×900: dashboard, assessments (list/new/detail), vulnerabilities (list/detail), attacks (list/detail), models, reports, notifications, organization and settings; **all have `scrollWidth == innerWidth` at 375 px**. |
| Frontend type-check and production build | `tsc --noEmit` clean; Next.js production build succeeds (31 routes); production server renders public pages, CSP/security headers, API proxy, cookies + CSRF + MFA header through the proxy. |
| **Celery worker path** | `scripts/smoke_celery.py`: separate API process, worker process, Redis broker, MongoDB. |

## NOT verified (be aware before production)

1. **Anthropic, OpenAI and Hugging Face were not called live.** The adapters follow the published request/response formats, and the OpenAI-compatible path is exercised end to end against a local server, but no request was made to Anthropic, OpenAI or the Hugging Face router. Verify each with your own key, model ID and tool-calling format. Gemini **was** verified live.
2. **Claude AI analysis was not run live.** Merge and hardening logic is tested with a mocked provider. The default analysis model ID (`claude-sonnet-5-5`) is configurable.
3. **MongoDB Atlas was not used.** Tests and the live run used local MongoDB 7.0.45. Atlas-specific behaviour (network allow-list, TLS, roles, backup/restore) is untested. TTL index expiry timing was not observed.
4. **SMTP delivery was not tested** (code path only). Verification/reset/invitation emails are written to the development log when SMTP is absent.
5. **Payments:** webhook signature verification is implemented and tested; checkout/session creation for Stripe/Razorpay is intentionally not implemented (returns `501`).
6. **Ownership verification** of custom endpoints is an attestation + audit trail, not DNS/HTTP proof of control.
7. **No load/soak or independent penetration test.** The security design follows OWASP ASVS-style practice but has had no external review. Capacity and provider-cost behaviour at scale are unmeasured.
8. **Downstream integration impact is not tested by default.** Tool execution, HTML rendering, SQL/shell execution, retrieval ACLs, vector-store tenant isolation and production infrastructure are outside the assessed boundary. Findings that depend on them are classified as potential/unsafe, not confirmed.

## Known limitations / design trade-offs

- Detection uses harmless canary tokens: a "failed" test proves an instruction-hierarchy, policy, leakage or unsafe-output failure at the model/API boundary, not that the model can produce dangerous content or that a downstream application is exploitable.
- Heuristic tests (hallucination, SQL/command indicators) are flagged *needs review* with lower confidence and are not scored as confirmed vulnerabilities.
- Results are non-deterministic; a passed test is absence of an indicator in that run, not proof of security.
- The harness augments the system prompt with canary lines; targets that ignore a system role cannot be tested for planted-secret leakage (use real prompt-similarity or custom attacks).
- Rate limiting fails **open** if Redis is down (logged); login brute force is additionally bounded by per-account lockout in MongoDB.
- Provider pacing (`LLMGUARD_PROVIDER_MIN_INTERVAL`) is process-wide, not cluster-wide. With multiple worker processes, divide the quota across processes or use a shared limiter.
- Stale-job recovery is manual (Resume); there is no Celery beat sweeper. Inline task mode (`TASK_BACKEND=inline`) is for development/tests only.
- CSP allows `'unsafe-inline'` scripts (Next.js without nonce middleware). Tightening to nonces is recommended.
- Frontend route protection is client-side (UX only); all authorisation is enforced by the API.
- Schema "migrations" = a stored schema version + idempotent index creation; no migration framework.
- Cost control is by request/token budgets, not currency; there is no per-model price table.
- Legal pages are templates and require counsel review.
- The report severity distribution counts only actionable (non-inconclusive, non-false-positive) findings. In the current validation run, 28 findings include one inconclusive informational finding, so the severity table sums to 27. The classification table shows all 28.

## Reproduce the verification

```bash
cd backend
.venv/Scripts/python -m pytest -q          # 76 passed

cd ..
# Reports already generated from the recorded live assessment:
# report.html / report.pdf / report.json / report.csv
```

See [`TEST_REPORT.md`](TEST_REPORT.md) for the executed test record and [`REPORTING_METHODOLOGY.md`](REPORTING_METHODOLOGY.md) for the evidence and scoring rules.
