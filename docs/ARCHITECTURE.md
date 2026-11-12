# Architecture

## System overview

```text
Browser ──▶ nginx ──▶ Next.js (web) ──/api rewrite──▶ FastAPI (api) ──▶ MongoDB
                    │                                  │  └▶ Redis (rate limits, Celery broker)
                    │                                  └──enqueue──▶ Celery worker
                    │                                                    │
                    └────────────────────────────────────────────────────┴──▶ target LLM
                                                                              (SSRF-pinned) or
                                                                              hosted provider API
```

The application is a multi-tenant SaaS. Next.js provides the UI; FastAPI owns authentication, authorisation, entitlements, the assessment engine, findings, reporting and administration. MongoDB is the system of record. Redis provides distributed rate limits and the Celery broker. Celery workers execute assessments out of process; `LLMGUARD_TASK_BACKEND=inline` runs them inside the API process for local development and tests only.

## Backend

### Routers (`backend/app/routers/`)

| Router | Responsibility |
|---|---|
| `auth.py` | Registration, verification, login, refresh rotation, logout, password reset/change, TOTP MFA, session list/revoke, login history |
| `orgs.py` | Current organization, rename, switch, members, invitations, roles |
| `users.py` | Profile, preferences, avatar, encrypted provider credentials, provider catalog, model configurations, connection test |
| `assessments.py` | Create/list/get/delete assessments, start/pause/resume/cancel, progress, executions, retry, logs, export, suggestions |
| `attacks.py` | Attack catalog, categories, custom attack CRUD, import/export, version history |
| `vulns.py` | Finding list/stats/detail, status workflow, triage, retest |
| `reports.py` | Generate report versions, preview, list, download, delete |
| `dashboard.py` | Aggregated dashboard metrics |
| `notifications.py` | In-app notifications |
| `billing.py` | Plan catalog, subscription state, signed webhooks; checkout adapter intentionally returns 501 until configured |
| `admin.py` | Platform stats, analytics, health, users, plans, settings, announcements, audit log, audit-chain verification |

All user-owned queries pass through `deps.scope()`, which filters by `org_id` and, unless the caller has `org:manage`, by `owner_id`. A foreign resource returns the same 404 as a missing one. Role permissions are defined in `app/rbac.py`; organization viewers cannot write even if their platform role is higher.

### Authentication and sessions

- Passwords: Argon2id (t=3, m=64 MiB, p=4).
- Access token: HTTP-only `lg_access` cookie, 15 minutes, signed JWT.
- Refresh token: HTTP-only `lg_refresh` cookie scoped to `/api/auth`, rotating on every use, with reuse detection that revokes the session.
- CSRF: `lg_csrf` double-submit cookie plus `X-CSRF-Token`; Origin is checked on unsafe cookie-authenticated requests.
- MFA: TOTP with replay protection; the secret is encrypted at rest.
- Bearer tokens are accepted for automation where explicitly supported.
- Account lockout and per-IP/per-account Redis limits apply uniformly to existing and unknown accounts.

### Engine (`backend/app/engine/`)

```text
templating → runner → provider → detectors → optional AI analysis → classification → scoring → findings → reports
```

1. **Templating** (`templating.py`) renders the selected module with a fresh canary context, optional harness context (protected secret, synthetic PII, approval/tool instructions) and the conversation turns. The harness never provides a real tool executor.
2. **Runner** (`runner.py`) enforces request and token budgets, per-intensity concurrency/delay, retries, pause/resume/cancel, heartbeat and per-execution persistence. `provider_min_interval` adds process-wide pacing across all assessments for a hosted provider quota.
3. **Providers** (`providers.py`) implement Anthropic, OpenAI, Gemini, Hugging Face Inference Providers, OpenAI-compatible and custom endpoints. User-supplied URLs use `core/ssrf.py`; hosted provider calls use fixed TLS endpoints. The provider response records text, tool calls, usage, latency, truncation and error status.
4. **Detectors** (`detectors.py`) evaluate canaries, protected values, policy markers, tool calls and arguments, structured output, refusal/leak patterns and behavioural checks. Deterministic rules carry higher confidence than heuristics.
5. **AI analysis** (`analysis.py`) is optional. A schema-validated judge can add context but may not override a strong deterministic hit; invalid or malicious judge output is discarded.
6. **Classification** (`classification.py`) turns execution evidence into one of six conclusions and computes confidence, validation method, impact scope, tool/output/service state and CVSS eligibility.
7. **Scoring** (`scoring.py`) recalculates the assessment score from executions plus enriched findings. Skipped/errored/inconclusive tests never count as secure.
8. **Findings** persist redacted evidence, detector metadata, remediation and classification. `redact.py` runs before storage; report generation re-redacts persisted transcripts before publication.
9. **Reports** (`reporting/model.py`) build one canonical report object consumed by the HTML, PDF, JSON and CSV renderers. The report recalculates scoring from enriched findings and records a reconciliation note if the stored score differs.

### Attack library (`backend/app/attacks/`)

`builtin.py` contains 84 validated definitions (57 basic, 27 advanced) across ten categories. Each definition has a stable `LG-*` ID, procedure turns, severity, tier, expected secure/vulnerable behaviour, detector rules, mappings (OWASP LLM Top 10 2025, CWE, MITRE ATLAS), remediation and an optional CVSS candidate vector. The library is seeded idempotently into `attack_modules` at startup. Tenants can add private custom attacks with restricted rule types, ReDoS-guarded regexes, import/export and version history. Advanced modules are plan-gated on the server.

### Data (`backend/app/db.py`)

22 collections with unique, compound, partial/sparse and TTL indexes created at startup. The audit log is append-only and hash-chained; `/api/admin/audit/verify` recomputes the chain. See [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md).

### Jobs

`jobs.dispatch` enqueues `llmguard.run_assessment` through Celery (or runs inline in development). Executions are unique per `(assessment_id, attack_id)` and idempotent, so pause/resume and retries do not duplicate work. Running assessments update `heartbeat_at`; stale jobs can be resumed manually. There is no Celery beat sweeper.

### Reporting

The canonical model contains:

- metadata and report control (report ID, version, generated timestamp, tenant, assessment ID);
- scope, system under test, authorisation statement and out-of-scope boundaries;
- executive summary, score reconciliation and posture;
- per-test inventory with status and evidence;
- per-finding procedure, redacted request/response, expected vs actual, detection rule, confidence, validation status, impact scope, tool/output/service states, limitations and remediation;
- coverage, category posture, prioritised actions and sign-off;
- integrity hashes, glossary and methodology.

HTML embeds the supplied `logo.jpg` as a data URI and is print-optimised. PDF is rendered from the same model and embeds the same logo. JSON and CSV expose the same finding set and classification metadata. Report downloads are tenant-scoped and versioned.

## Frontend

App Router groups:

- `(public)`: home, features, pricing, docs, privacy, terms.
- `(auth)`: login, register, verify, forgot/reset password, accept invite.
- `(app)`: dashboard, assessments (list/new/detail), attacks, models, vulnerabilities, reports, organization, notifications, settings.
- `(admin)`: overview, analytics, assessments, audit, config, health, users.

`lib/api.ts` attaches the CSRF header, performs silent refresh on 401, and redirects to login when the session is gone. Route protection is a UX convenience only; every authorisation decision is enforced by the API. The UI is responsive from 320 px upward, uses a shared shell and accessible primitives, and renders the ZeroDay logo from `/logo.jpg`.

## Trust boundaries

| Boundary | Assumption |
|---|---|
| Browser ↔ API | Untrusted input; TLS in production; cookies + CSRF; all authorisation server-side |
| API ↔ MongoDB | Trusted network with least-privilege DB user; credentials encrypted with Fernet |
| API ↔ Redis | Trusted network; rate limits fail open if Redis is unavailable (logged) |
| Worker ↔ target LLM | Untrusted response content; SSRF-pinned connections; bounded budgets; no tool executor |
| Report consumer | Reports contain synthetic canaries, not production secrets; redaction is applied twice |
| Platform operator | Super-admin can change platform settings and plans; all actions audited |

## Scaling and failure behaviour

- API and web are stateless; scale horizontally behind nginx.
- Celery workers scale independently (`--scale worker=N`). Per-plan concurrency and per-assessment request/token budgets bound load.
- Provider pacing is process-local; with multiple worker processes, divide the provider quota across workers or use a shared limiter.
- Redis loss affects rate limits (fail open) and queued jobs; MongoDB remains the source of truth.
- If a worker dies, executions remain persisted. Resume is manual; the heartbeat and stale-job check surface the condition.
- Report generation is synchronous and bounded; very large assessments are supported by the reporting tests.

## Design trade-offs

- Detection is indicator-based. A passed test means no indicator was observed in that run, not proof of security.
- Model output is non-deterministic. Repeat counts increase confidence but do not make a single observation universal.
- RAG tests supply retrieved text directly; the platform does not connect to the customer's vector store, so retrieval ACLs are out of scope.
- Tool-call tests observe proposals only; the harness has no executor.
- DoS tests observe latency, timeouts and errors under bounded inputs; they are not load tests.
- CSP currently allows `'unsafe-inline'` for Next.js compatibility; nonce-based tightening is recommended.
