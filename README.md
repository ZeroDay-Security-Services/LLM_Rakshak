# ZeroDay's LLM Rakshak

**Expose AI vulnerabilities before attackers do.**

ZeroDay's LLM Rakshak is a multi-tenant AI security assessment platform. It runs bounded, authorised red-team modules against LLM applications, evaluates the responses with evidence-aware detectors, and publishes findings that distinguish model behaviour from application impact.

**Backend:** FastAPI · MongoDB · Redis · Celery  
**Frontend:** Next.js 16 · React 19 · TypeScript · Tailwind CSS · Recharts

> Read [`docs/SCOPE.md`](docs/SCOPE.md) before relying on any security claim. It records what has actually been executed and verified, and what has not.

## What it does

- **84 built-in attack modules** across 10 categories: prompt injection (13), jailbreak (13), sensitive disclosure (7), insecure output (10), excessive agency (6), RAG security (7), model DoS (5), hallucination (7), system prompt (8) and tool calling (8). 57 are basic, 27 are advanced. Every module records its procedure, secure/vulnerable expectations, detector rules, OWASP LLM Top 10 (2025) / CWE / MITRE ATLAS mappings, CVSS candidate vector and remediation.
- **Evidence-aware conclusions.** Each finding is classified as a confirmed vulnerability, likely vulnerability, unsafe behaviour, potential vulnerability, inconclusive or false positive. A tool call emitted by a model is not treated as an executed action. Generated HTML, SQL, shell text or Markdown is not treated as XSS, SQL injection, command execution or exfiltration without downstream evidence.
- **Deterministic-first detection.** Per-run canary tokens, protected values, policy markers, tool-call inspection and structured checks are evaluated before heuristic patterns and optional AI review. Confidence is bounded by the detection method and validation state.
- **Defensible scoring.** The 0-100 score is recalculated from enriched findings, weights severity by classification, caps only confirmed/likely critical or high findings, and never counts skipped, errored or inconclusive tests as secure. Coverage below 60% is marked provisional.
- **Client-ready reporting.** HTML, PDF, JSON and CSV exports share one canonical report model: scope, system under test, methodology, per-test evidence, expected vs actual behaviour, detection rule, confidence, validation state, tool/service/output states, limitations, prioritised actions and integrity hashes.
- **Real provider coverage.** Anthropic, OpenAI, Google Gemini and Hugging Face Inference Providers are native adapters. OpenAI-compatible and custom self-hosted endpoints cover vLLM, Ollama, TGI and private gateways. Credentials are encrypted at rest; user-supplied URLs pass through the SSRF-safe client.
- **Multi-tenant operation.** Cookie sessions with rotating refresh tokens, Argon2id passwords, TOTP MFA, CSRF protection, tenant + owner scoping, organization roles, hash-chained audit logs, admin controls and backend-enforced plan entitlements.

## Status

- Backend suite: **76 tests passing** against real MongoDB and Redis (`backend/tests`, see [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md)).
- Real-provider validation: Gemini assessment exercised through the real Google API; Anthropic/OpenAI adapters are implemented but require your own keys. See [`docs/SCOPE.md`](docs/SCOPE.md).
- Browser validation: public and authenticated pages exercised in a real browser at desktop and mobile widths.
- Payments: webhook verification is implemented and tested; checkout/session creation returns `501` until a payment provider is configured.

## Quick start (local)

Prerequisites: Python 3.11+, Node.js 20+, MongoDB 7+, Redis 7+.

```bash
# 1. Backend
cd backend
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt     # Windows
# source .venv/bin/activate && pip install -r requirements-dev.txt  # macOS/Linux
cp ../.env.example .env
# Set LLMGUARD_JWT_SECRET (>=32 chars), LLMGUARD_ENCRYPTION_KEYS (Fernet),
# LLMGUARD_MONGODB_URI, LLMGUARD_REDIS_URL and LLMGUARD_FRONTEND_ORIGIN.
.venv/Scripts/python -m uvicorn app.main:app --reload --port 8000

# 2. Frontend (second terminal)
cd frontend
npm ci
BACKEND_URL=http://127.0.0.1:8000 npm run dev
```

Open <http://localhost:3000>. Create the first administrator with:

```bash
cd backend
.venv/Scripts/python -m app.cli create-admin --email you@example.com
```

The CLI prompts for a password, marks the account verified and grants the super-admin role. Without SMTP configured, verification, reset and invitation emails are only written to the development log.

For hosted providers, add a credential under **Models & credentials**, then create a model configuration. Set `LLMGUARD_PROVIDER_MIN_INTERVAL` to `60 / requests-per-minute` when your provider quota requires pacing (for example `4.2` for 15 RPM).

## Docker

```bash
cp .env.example .env
# Fill the mandatory secrets and MongoDB URI.
docker compose up --build -d
docker compose exec api python -m app.cli create-admin --email you@example.com
```

`nginx` exposes the web app on port 80 and proxies `/api` to FastAPI. MongoDB is external (Atlas or your own cluster); Redis runs as a compose service. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Tests

```bash
cd backend
.venv/Scripts/python -m pytest -q
```

The suite uses real MongoDB and Redis (no database mocks), a local OpenAI-compatible target for end-to-end engine tests, and a mocked provider for AI-analysis merge tests. Configure the test database/Redis in `backend/tests/conftest.py` or through the same `LLMGUARD_*` variables.

```bash
# Optional real-process checks
python scripts/smoke_celery.py
python scripts/smoke_stack.py
```

## Layout

```text
backend/app/core          configuration, security primitives, SSRF client, rate limits, mail
backend/app/routers       auth, orgs, models, assessments, attacks, findings, reports, admin, billing
backend/app/engine        runner, providers, detectors, classification, CVSS, scoring, redaction, templating
backend/app/attacks       84 built-in definitions + custom attack validation
backend/app/reporting     canonical report model + HTML/PDF renderers
backend/tests             76 unit, integration and end-to-end tests
frontend/app              public, auth, application and admin routes
frontend/components       UI kit, application shell, charts
deploy/nginx.conf         TLS/reverse-proxy entry point
docs/                     architecture, security, API, schema, methodology, operations
```

## Documentation

| Document | Purpose |
|---|---|
| [SCOPE](docs/SCOPE.md) | Verified vs unverified capabilities |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Components, trust boundaries and data flow |
| [SECURITY](docs/SECURITY.md) | Threat model and implemented controls |
| [SCANNING_METHODOLOGY](docs/SCANNING_METHODOLOGY.md) | How tests are executed and judged |
| [REPORTING_METHODOLOGY](docs/REPORTING_METHODOLOGY.md) | Evidence model, classification, CVSS and exports |
| [SCORING](docs/SCORING.md) | Score calculation and caps |
| [ATTACK_LIBRARY](docs/ATTACK_LIBRARY.md) | All 84 modules |
| [API_DOCUMENTATION](docs/API_DOCUMENTATION.md) | Endpoints, auth, permissions and examples |
| [DATABASE_SCHEMA](docs/DATABASE_SCHEMA.md) | Collections, indexes and retention |
| [ENVIRONMENT_SETUP](docs/ENVIRONMENT_SETUP.md) | Local setup and configuration |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | Production deployment and operations |
| [USER_GUIDE](docs/USER_GUIDE.md) | End-user workflow |
| [ADMIN_GUIDE](docs/ADMIN_GUIDE.md) | Platform administration |
| [HUGGINGFACE_INTEGRATION](docs/HUGGINGFACE_INTEGRATION.md) | Hugging Face and self-hosted model setup |
| [TEST_REPORT](docs/TEST_REPORT.md) | Executed verification record |
| [COMMERCIAL_READINESS](docs/COMMERCIAL_READINESS.md) | Packaging, gaps and launch checklist |
| [PRODUCTION_READINESS](docs/PRODUCTION_READINESS.md) | Operational readiness |
| [CHANGELOG](docs/CHANGELOG.md) | Release history |

## Legal and ethics

Only assess systems you own or are explicitly authorised to test. Every assessment requires a recorded authorisation statement. Modules use harmless canary values and policy strings; they do not request harmful content, real credentials or destructive actions. Targets are SSRF-validated and request/token budgets are enforced server-side.

The bundled Privacy Policy and Terms are templates. Have them reviewed by counsel before commercial launch.
