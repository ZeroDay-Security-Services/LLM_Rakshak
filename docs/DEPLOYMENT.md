# Deployment

This guide covers a production-style deployment behind TLS. Read [`SECURITY.md`](SECURITY.md), [`COMMERCIAL_READINESS.md`](COMMERCIAL_READINESS.md) and [`SCOPE.md`](SCOPE.md) first.

## Topology

```text
Internet ──TLS──▶ load balancer / nginx ──▶ Next.js (web)
                                      └──▶ FastAPI (api) ──▶ MongoDB Atlas
                                                         └▶ Redis
                                                         └▶ Celery worker(s) ──▶ LLM providers
```

The bundled `docker-compose.yml` runs nginx, web, api, worker and Redis. MongoDB is external (Atlas or a managed cluster). For production, run web/api/worker as separate services so they can scale and restart independently.

## 1. MongoDB

1. Create a dedicated cluster and database (`llmguard` or your chosen name).
2. Restrict network access to the application's egress addresses.
3. Create a least-privilege user:
   - `readWrite` on the application database;
   - **no** update/remove on `audit_logs` (custom role with `insert` + `find` only);
   - no cluster-admin rights.
4. Enable TLS and provider backups. Test a restore before launch.
5. Size for the audit log and report blobs. Reports are stored in `assessment_reports.content`; monitor collection growth and set a retention policy.

## 2. Secrets

Generate:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store in a secret manager, not in `.env` on disk. Back up encryption keys separately from MongoDB. Rotate by prepending a new Fernet key: new writes use the first key, old keys remain for decryption. Re-save credentials before removing an old key.

## 3. Configuration

Set at minimum:

```dotenv
LLMGUARD_ENV=production
LLMGUARD_MONGODB_URI=mongodb+srv://...
LLMGUARD_MONGODB_DB=llmguard
LLMGUARD_REDIS_URL=redis://...
LLMGUARD_JWT_SECRET=...
LLMGUARD_ENCRYPTION_KEYS=...
LLMGUARD_FRONTEND_ORIGIN=https://app.example.com
LLMGUARD_COOKIE_SECURE=true
LLMGUARD_COOKIE_DOMAIN=
LLMGUARD_TRUST_PROXY=true
LLMGUARD_TASK_BACKEND=celery
LLMGUARD_ALLOW_PRIVATE_TARGETS=false
LLMGUARD_ALLOW_HTTP_TARGETS=false
LLMGUARD_PROVIDER_MIN_INTERVAL=0
```

Set `LLMGUARD_PROVIDER_MIN_INTERVAL` to `60 / provider_RPM` per deployment. It is process-wide, so when running multiple worker processes, divide the quota accordingly or use a shared limiter.

## 4. TLS and proxy

- Terminate TLS at a load balancer or use certbot with nginx.
- Keep `LLMGUARD_TRUST_PROXY=true` **only** behind the bundled nginx, which overwrites `X-Forwarded-For`.
- Do not expose MongoDB or Redis publicly.
- Set HSTS at the edge (the app also emits it in production).
- Restrict `/api/docs` exposure; it is disabled when `LLMGUARD_ENV=production`.

## 5. Build and start

```bash
cp .env.example .env    # fill values
docker compose up --build -d
docker compose exec api python -m app.cli create-admin --email admin@example.com
```

Or without Docker:

```bash
cd backend
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
.venv/Scripts/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

celery -A app.worker.celery_app worker -l info --concurrency=4

cd ../frontend
npm ci
BACKEND_URL=https://api.example.com npm run build
npm start
```

Next.js bakes rewrites at **build** time. Rebuild the frontend whenever `BACKEND_URL` changes.

## 6. Scale

- Web/API: stateless, scale horizontally. Use sticky sessions only if your load balancer cannot route cookie requests consistently; the API itself is stateless.
- Workers: `docker compose up -d --scale worker=3`. Plan concurrency and `LLMGUARD_PROVIDER_MIN_INTERVAL` together.
- MongoDB: monitor connections, index usage and report collection size.
- Redis: use persistence/HA if queued jobs must survive restarts. Rate limits degrade to fail-open if Redis is unavailable.

## 7. Email

Configure SMTP (`LLMGUARD_SMTP_*`) before onboarding external users. Without it, verification, reset and invitation emails are only logged. Use a verified sender domain with SPF/DKIM/DMARC.

## 8. Backups and retention

- Back up MongoDB daily and before upgrades; verify restores quarterly.
- Back up Fernet keys in a separate secret store. A database backup without the keys cannot decrypt credentials.
- Define retention for assessments, findings, reports, login history and audit logs.
- Export customer reports before deleting a workspace; deletion is not a backup.

## 9. Monitoring

Minimum:

- uptime check on `/api/health`;
- HTTP 5xx rate and latency;
- worker queue depth and failed tasks;
- provider 429/5xx rates;
- assessment heartbeat age and stale jobs;
- disk/database growth;
- audit-chain verification (daily job);
- authentication failure/lockout spikes.

The admin health page is a convenience, not a substitute for external monitoring.

## 10. Upgrades

1. Read `CHANGELOG.md`.
2. Back up MongoDB and keys.
3. Build new images with the correct `BACKEND_URL`.
4. Run the test suite in staging against real MongoDB/Redis.
5. Apply changes during a maintenance window if indexes are large.
6. Roll web/api/worker together; the schema is additive and the report layer tolerates legacy findings.
7. Verify `/api/health`, login, a small assessment, report export and audit verification.

## 11. Incident response

- Rotate JWT and Fernet keys if compromise is suspected; revoke all sessions.
- Disable affected users/orgs and preserve audit logs.
- Check provider usage for unexpected spend.
- If report integrity is questioned, compare stored report SHA-256 and manifest hash with the downloaded file.
- If a worker is compromised, isolate it, revoke provider keys, and review assessment targets and outbound connections.

## 12. Known production gaps

- Payment checkout returns `501`; only webhook verification is implemented.
- SMTP is not configured by default.
- No Celery beat sweeper; stale jobs require manual resume.
- CSP allows inline scripts; tighten with nonces.
- No independent penetration test, load test or soak test has been performed.
- MongoDB Atlas-specific behaviour has not been exercised in the build environment.

See [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) for the go-live checklist.
