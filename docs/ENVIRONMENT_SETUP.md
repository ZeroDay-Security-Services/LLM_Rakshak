# Environment setup

## Prerequisites

| Component | Version | Notes |
|---|---|---|
| Python | 3.11+ | Backend and tests |
| Node.js | 20+ | Next.js 16 |
| MongoDB | 7+ (8.x tested) | Local, Docker or Atlas |
| Redis | 7+ | Rate limits and Celery broker |
| Docker | Optional | Compose deployment |
| Browser | Current Edge/Chrome/Firefox | Frontend and report verification |

## 1. Clone and configure

```bash
cp .env.example .env
```

Generate the mandatory secrets:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"          # JWT secret
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # encryption key
```

## Environment variables

All backend variables use the `LLMGUARD_` prefix for compatibility. User-visible branding is ZeroDay.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `LLMGUARD_ENV` | yes | `development` | `development`, `test` or `production`; production disables docs and enforces secure cookies/HSTS |
| `LLMGUARD_MONGODB_URI` | yes | localhost | MongoDB connection string |
| `LLMGUARD_MONGODB_DB` | yes | `llmguard` | Database name |
| `LLMGUARD_REDIS_URL` | yes | localhost | Redis URL |
| `LLMGUARD_JWT_SECRET` | yes | — | >= 32 characters; signs access/session tokens |
| `LLMGUARD_ENCRYPTION_KEYS` | yes | — | Comma-separated Fernet keys; first encrypts, all decrypt |
| `LLMGUARD_FRONTEND_ORIGIN` | yes | `http://localhost:3000` | CORS/Origin allow-list and email links |
| `LLMGUARD_COOKIE_SECURE` | prod | `true` | Set `false` only for local HTTP |
| `LLMGUARD_COOKIE_DOMAIN` | no | — | Cookie domain for subdomains |
| `LLMGUARD_TRUST_PROXY` | no | `false` | Only behind the bundled nginx that overwrites `X-Forwarded-For` |
| `LLMGUARD_ACCESS_TTL_MINUTES` | no | `15` | Access-token lifetime |
| `LLMGUARD_REFRESH_TTL_DAYS` | no | `14` | Refresh-token lifetime |
| `LLMGUARD_REFRESH_ABS_TTL_DAYS` | no | `30` | Absolute session lifetime |
| `LLMGUARD_TASK_BACKEND` | yes | `celery` | `celery` or `inline` (development/tests only) |
| `LLMGUARD_ALLOW_PRIVATE_TARGETS` | no | `false` | Permit private LLM endpoints; metadata IPs remain blocked |
| `LLMGUARD_ALLOW_HTTP_TARGETS` | no | `false` | Permit plain HTTP targets |
| `LLMGUARD_PROVIDER_MIN_INTERVAL` | no | `0` | Process-wide seconds between calls to a hosted provider; use `60 / RPM` |
| `LLMGUARD_MAX_DOS_PAYLOAD_CHARS` | no | `64000` | Upper bound for DoS input construction |
| `LLMGUARD_SMTP_HOST/PORT/USER/PASSWORD/FROM` | no | — | Verification/reset/invite email |
| `LLMGUARD_ANALYSIS_API_KEY` | no | — | Platform Anthropic key for optional AI analysis |
| `LLMGUARD_ANALYSIS_MODEL` | no | `claude-sonnet-5-5` | Analysis model |
| `LLMGUARD_PAYMENTS_ENABLED` | no | `false` | Enables the payment architecture hook |
| `LLMGUARD_STRIPE_WEBHOOK_SECRET` | no | — | Stripe signature verification |
| `LLMGUARD_RAZORPAY_WEBHOOK_SECRET` | no | — | Razorpay signature verification |

Frontend:

| Variable | Purpose |
|---|---|
| `BACKEND_URL` | Server-side API origin used by Next.js rewrites. Required at **build** time for production. |
| `NEXT_PUBLIC_API_URL` | Optional browser API base if not using the `/api` rewrite. |

## 2. Start MongoDB and Redis

Local services:

```bash
mongod --dbpath ./data/db --port 27017
redis-server --port 6379
```

Docker equivalents:

```bash
docker run -d --name zeroday-mongo -p 27017:27017 mongo:8
docker run -d --name zeroday-redis -p 6379:6379 redis:7-alpine
```

If you use non-default ports (for example 27018/6380), update `LLMGUARD_MONGODB_URI` and `LLMGUARD_REDIS_URL`.

## 3. Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt        # Windows
# source .venv/bin/activate && pip install -r requirements-dev.txt  # macOS/Linux
.venv/Scripts/python -m uvicorn app.main:app --reload --port 8000
```

Check:

```bash
curl http://127.0.0.1:8000/api/health
```

Create the first administrator:

```bash
.venv/Scripts/python -m app.cli create-admin --email you@example.com
```

The CLI reads `LLMGUARD_ADMIN_PASSWORD` if set, otherwise prompts. It creates a verified super-admin and organization. Do not use the CLI in a container that shares shell history.

## 4. Frontend

```bash
cd frontend
npm ci
BACKEND_URL=http://127.0.0.1:8000 npm run dev
```

Open <http://localhost:3000>. If you use a different host/port, set `LLMGUARD_FRONTEND_ORIGIN` to the exact browser origin (scheme + host + port) or CSRF/Origin checks will reject writes.

## 5. Provider credentials

1. Sign in and open **Models & credentials**.
2. Add the provider credential (API key; endpoint only where required).
3. Create a model configuration with the exact model ID.
4. Use **Test connection** to verify reachability and auth.
5. Start a small assessment (Quick preset) before running the full library.

Provider notes:

- **Gemini:** use a model ID available to your API key. Free-tier quotas are low; set `LLMGUARD_PROVIDER_MIN_INTERVAL=4.2` for 15 RPM or higher for stricter tiers.
- **Hugging Face:** use an HF token with Inference Providers permission. The default route is the HF router; set an endpoint for a dedicated Inference Endpoint. See [`HUGGINGFACE_INTEGRATION.md`](HUGGINGFACE_INTEGRATION.md).
- **OpenAI-compatible/custom:** endpoint must include the base path; `/chat/completions` is appended if absent. Private targets require `LLMGUARD_ALLOW_PRIVATE_TARGETS=true`.
- **Anthropic/OpenAI:** model IDs and token parameters must match what your account exposes.

## 6. Tests

Tests use a separate database and Redis DB number. Check `backend/tests/conftest.py`; it defaults to `llmguard_test` and Redis DB 15. Never point tests at production.

```bash
cd backend
.venv/Scripts/python -m pytest -q
```

Expected current result: **76 passed**. See [`TEST_REPORT.md`](TEST_REPORT.md).

## 7. Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `LLMGUARD_JWT_SECRET must be at least 32 characters` | Short/blank secret | Generate a new secret |
| `database not initialised` | App started without lifespan/DB | Start through uvicorn/Celery, not an ad-hoc import |
| 403 CSRF on writes | Missing header or wrong Origin | Send `X-CSRF-Token`; set `LLMGUARD_FRONTEND_ORIGIN` exactly |
| Login 403 "Email address not verified" | No SMTP and no verification | Use the CLI admin or mark the account verified in development |
| 429 from a provider | Quota exhausted | Set provider pacing, reduce concurrency/intensity, wait for the quota window |
| `Future attached to a different loop` in tests | Old pytest-asyncio | Use `pytest-asyncio==1.4.1.post1` or newer |
| Frontend rewrites hit the wrong API | `BACKEND_URL` baked at build time | Rebuild with the correct `BACKEND_URL` |
| PDF export unavailable | Plan or missing dependency | Use Researcher/Enterprise; ensure the PDF renderer is installed |
| 501 on billing checkout | Payment adapter intentionally disabled | Configure a provider; webhooks alone do not create checkout sessions |

## 8. Security checklist for local use

- Keep `.env` out of version control.
- Do not reuse production provider keys in test workspaces.
- Set `LLMGUARD_ALLOW_PRIVATE_TARGETS=false` unless you are testing a private endpoint you own.
- Do not expose development servers (`--host 0.0.0.0`) to untrusted networks.
- Delete test assessments and rotate test credentials when finished.
