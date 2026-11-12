# Changelog

All notable changes to ZeroDay's LLM Rakshak. Dates are UTC.

## [2.0.0] — 2026-11-11

### Branding

- Renamed user-visible product surfaces to **ZeroDay's LLM Rakshak** / **ZeroDay Security Services**.
- Embedded the supplied `logo.jpg` in the frontend and in HTML/PDF reports; removed generated logo assets.
- Sanitised legacy product references from stored report narrative and customer-facing copy.
- Internal `LLMGUARD_*` environment variables and collection names remain for compatibility.

### Attack library

- Expanded from 58 to **84 modules** (+26) across the existing 10 categories.
- Added advanced coverage for special-token injection, forged continuations, memory bleed, SVG/data-URI/CSV output, persistent instruction poisoning, retrieval metadata/tool-call injection, recursive output expansion, fabricated legal citations, instruction continuation, debug configuration dumps, special-token tool calls, tool-output injection and confused-deputy overrides.
- Added 57 basic / 27 advanced split and preserved OWASP/CWE/ATLAS mappings, expected behaviour, detectors, remediation and CVSS candidate vectors.
- Added neutral descriptions and removed external creator/repository references.

### Evidence-aware reporting

- Added six-state classification: confirmed, likely, unsafe behaviour, potential, inconclusive, false positive.
- Added confidence bounds, validation status, evidence quality and impact scope.
- Gated CVSS to confirmed findings with a valid vector, confidence ≥ 0.70, deterministic detection and no unproven service impact.
- Separated tool state (proposed/authorized/executed), output state (rendered/executed) and service-impact state.
- Recalculated report scores from enriched findings and added stored-vs-recalculated reconciliation.
- Re-redacted persisted transcripts before report publication.
- Added per-finding test ID, target, provider, timestamps, procedure, request/response, expected vs actual, detection rule, limitations and evidence SHA-256.
- Added HTML/PDF renderers with the supplied logo, print layout, integrity manifest and report-control metadata.
- Added regression tests for classification, CVSS gating, confidence, redaction, exports, large reports, missing evidence and empty reports.

### Providers and execution

- Added a native **Hugging Face Inference Providers** adapter (OpenAI-compatible router, optional dedicated endpoint).
- Added process-wide **provider pacing** (`LLMGUARD_PROVIDER_MIN_INTERVAL`) to respect requests-per-minute quotas across assessments.
- Verified a live Gemini run across all 84 modules with 0 execution errors after pacing.
- Preserved SSRF-pinned connections, budgets, retries, pause/resume/cancel and idempotent executions.

### Frontend

- Updated homepage capability copy to 84 modules, Hugging Face and evidence-aware scoring.
- Preserved responsive layouts and ZeroDay branding.
- Browser-checked public and authenticated pages at desktop and mobile widths.

### Documentation

- Rewrote README and added architecture, API, database schema, environment setup, deployment, user/admin guides, attack library, scanning/reporting methodology, Hugging Face integration, commercial/production readiness, test report, scope and changelog.
- Updated scoring documentation for classification factors, caps and reconciliation.

### Verification

- Backend suite: 76 tests passing against real MongoDB and Redis (including a Hugging Face router adapter unit test).
- Report artifacts validated for branding, logo, classification counts, CVSS gating, timestamps and hash consistency.
- Fresh 84-module Gemini assessment: 83 tested, 55 passed, 28 failed, 1 skipped, 0 errors; report score 62 (stored 69, reconciled).

### Known gaps

- Payment checkout remains `501`.
- SMTP, Atlas-specific behaviour, independent penetration testing and load/soak testing remain unverified.
- CSP still allows inline scripts for Next.js compatibility.
- Stale-job recovery is manual.

## [1.0.0] — 2026-11-09

- Initial platform: 58 attack modules, 10 categories, 64 backend tests.
- Auth, tenancy, RBAC, SSRF, assessment engine, findings, reports, admin, billing webhooks.
- HTML/JSON/CSV/PDF reporting and public/auth/app/admin frontend routes.
