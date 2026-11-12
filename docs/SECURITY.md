# Security design

This document describes the controls implemented in ZeroDay's LLM Rakshak and the residual risks an operator must manage. It is a design record, not an independent audit.

## Threat model

Protected assets:

- customer credentials and provider API keys;
- assessment evidence, findings and reports (which may contain sensitive prompt text);
- tenant data and organization membership;
- platform configuration, plans and audit history;
- availability and provider spend.

Primary threats:

- credential stuffing, brute force and account enumeration;
- session theft, CSRF and refresh-token replay;
- broken object-level authorisation and cross-tenant access;
- injection into MongoDB queries or report renderers;
- SSRF through user-supplied model endpoints;
- secret leakage through logs, API responses or reports;
- malicious model output influencing the platform;
- abuse of the assessment engine to attack third parties or exhaust budgets;
- tampering with audit history or reports.

## Authentication and session controls

| Threat | Control |
|---|---|
| Credential stuffing / brute force | Argon2id (t=3, m=64 MiB); per-IP and per-account Redis limits (including non-existent accounts); 5 failures/15-minute lockout; uniform error bodies |
| Account enumeration | Register/forgot/resend return 202 with identical bodies; dummy password hash on unknown users; login failures are uniform |
| Session theft | HTTP-only SameSite=Lax cookies; 15-minute access token; rotating refresh token; reuse detection revokes the session; revoke-all on password reset, role change or suspension |
| CSRF | Double-submit `lg_csrf` cookie plus `X-CSRF-Token`; Origin check on unsafe cookie-authenticated methods |
| MFA | TOTP with replay protection; encrypted secret; pending enrolment secret separated from the active secret |
| Session inventory | Users can list and revoke sessions; login history retained with TTL |

Bearer authentication is supported for automation. Bearer requests do not rely on cookies but still pass through the same authorization and entitlement checks.

## Authorisation and tenancy

- Central `deps.scope()` applies `org_id` + `owner_id` to user-owned queries. Foreign IDs and missing IDs produce identical 404s.
- Platform roles (`super_admin`, `admin`, `researcher`, `user`, `viewer`) and organization roles (`owner`, `admin`, `member`, `viewer`) are combined by `rbac.perms_for()`.
- Organization viewers are stripped of every `:write`, `:manage` and `:import` permission, even if their platform role would otherwise grant it.
- Admin routes require `admin:access` or more specific permissions; super-admin-only configuration and role changes are separated.
- Plan entitlements (module tiers, report formats, custom attacks, AI analysis, members, concurrent assessments, monthly assessments, request budgets) are enforced in handlers, never trusted from the client.
- Every finding, execution, report and model query is tenant-scoped. Report downloads check ownership and org membership.

## Input and injection controls

- All request bodies are typed Pydantic models with length limits, enums and patterns.
- Search terms are escaped before use in regular expressions; filters and sorts are enum-validated.
- MongoDB operators in user input are rejected by strict typing; no raw query strings are constructed from user input.
- Report HTML is output-escaped. CSV cells are guarded against formula injection. CSV/JSON report downloads use explicit content types and attachment filenames.
- Custom attack regexes are ReDoS-guarded and restricted to supported rule types.
- Avatar uploads are validated, size-limited and served with explicit content types.

## SSRF and target validation

`backend/app/core/ssrf.py` enforces:

- allow-listed schemes (`https`, and `http` only when explicitly enabled);
- resolution and validation of every address (loopback, private ranges, link-local, metadata, CGNAT, multicast, reserved, decimal/hex/octal IPv4, IPv4-mapped IPv6, credentials-in-URL, bad ports);
- cloud metadata endpoints always blocked, even when private targets are enabled;
- single-resolution pinned connection: connect to the validated IP with the original Host header and TLS SNI, preventing DNS rebinding;
- no redirects, no environment proxies, response-size cap and timeout;
- the same validation when saving a model or credential, not only when running a test.

`LLMGUARD_ALLOW_PRIVATE_TARGETS=true` is intended only for single-tenant/self-hosted deployments. Never enable it on a multi-tenant SaaS.

## Secret handling

- Provider API keys and TOTP secrets are encrypted with Fernet using a rotatable `MultiFernet` key list.
- Credentials are masked in API responses and never written to logs.
- Redaction runs before evidence is persisted and again when reports are built. It covers provider key patterns, bearer tokens, private keys, emails/phone-like values in synthetic PII contexts, and high-entropy secrets. Redaction can over-match benign values; this is documented in reports.
- `.env` files are excluded from version control. Use a secret manager in production and back up encryption keys; without them stored credentials cannot be decrypted.
- Database and Redis should be private, authenticated and encrypted in transit where the provider supports it.

## Assessment safety

- Every assessment requires `authorization.confirmed=true` and a statement of at least 20 characters, recorded with timestamp and IP.
- Request and token budgets are enforced per assessment. Concurrency is bounded per plan.
- Modules use synthetic canaries and policy strings. They do not request harmful content, real credentials, malware or destructive actions.
- The harness provides no tool executor. Tool-call modules observe proposals only; no downstream action is performed.
- DoS modules use bounded inputs and measure latency/timeouts. They are not sustained load tests and cannot establish availability impact.
- Targets are SSRF-validated; private targets are opt-in.
- Provider pacing (`LLMGUARD_PROVIDER_MIN_INTERVAL`) prevents accidental quota exhaustion.
- Pause, resume and cancel are checked by the runner; executions are idempotent.

## Evidence and report integrity

- Findings store the redacted request/response transcript, detector rule, confidence, method, expected/actual behaviour and classification metadata.
- Classification separates model behaviour from application impact. CVSS is published only for confirmed findings with a valid vector, confidence >= 0.70, deterministic detection and no unproven service-impact claim.
- Tool calls are marked proposed, not executed, unless execution evidence exists. Generated HTML/JS/SQL/shell is marked unrendered/unexecuted.
- Each finding carries an evidence SHA-256; the report carries a content hash and report-control metadata.
- HTML reports set a restrictive CSP (no scripts, no framing) and are self-contained. PDFs embed the supplied logo and no remote assets.
- Stored report narrative is sanitised so legacy product names do not leak into customer-facing output.

## Audit and monitoring

- Security-relevant actions are written to an append-only, hash-chained audit log (registration, login failures, lockouts, password changes, role changes, admin actions, assessment lifecycle, report generation).
- `GET /api/admin/audit/verify` recomputes the chain and reports the first broken sequence.
- Request logs include method, path, status, duration and request ID, but not credentials or evidence bodies.
- Admin health exposes service status; production deployments should add external uptime and error monitoring.

## Residual risks

1. **No independent penetration test or load/soak test.** The controls follow OWASP ASVS-style practice but have not been independently reviewed.
2. **Rate limiting fails open if Redis is down.** Login brute force remains bounded by per-account lockout in MongoDB, but other limits degrade.
3. **CSP allows `'unsafe-inline'` scripts** because Next.js is served without nonce middleware. Tighten before a high-assurance deployment.
4. **Frontend route protection is client-side.** It is UX only; the API is authoritative.
5. **Assessment results are non-deterministic.** A passed test is absence of an indicator in one run, not proof of security.
6. **RAG, tool execution and downstream sinks are outside the assessed boundary.** Findings that depend on them are labelled potential/unsafe, not confirmed.
7. **Provider quotas and cost are outside the platform's control.** Pacing reduces but does not eliminate 429s; budgets bound requests/tokens, not currency.
8. **SMTP delivery and payment checkout are not production-configured by default.** See `SCOPE.md`.
9. **Stale-job recovery is manual.** There is no Celery beat sweeper.

## Reporting a vulnerability

Do not open a public issue for a security defect. Send a private report to the operator's security contact with:

- affected version/commit;
- reproduction steps and impact;
- whether customer data or credentials may be involved;
- a safe contact and disclosure preference.

The operator should acknowledge, triage, preserve logs and rotate affected secrets. This document does not define a legal SLA.
