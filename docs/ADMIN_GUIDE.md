# Administrator guide

Administration is split into platform roles and organization roles. Platform admins operate the service; organization owners/admins manage their own workspace. The API enforces both.

## Roles and permissions

| Platform role | Capabilities |
|---|---|
| `viewer` | Read-only workspace access |
| `user` | Assessments, findings, reports, credentials/models, org read |
| `researcher` | User + custom attacks, imports |
| `admin` | Researcher + admin panel, user administration, audit read |
| `super_admin` | Admin + platform config, role changes, billing administration |

Organization roles (`owner`, `admin`, `member`, `viewer`) are separate. `org:manage` is granted to owners/admins. Organization viewers lose every write/manage/import permission.

## Admin panel

The `(admin)` routes are visible to users with `admin:access`. Hiding a route in the UI is not a security control; the API returns 403 without the permission.

### Overview and analytics

- **Overview** (`/admin`): platform counts, recent activity, plan distribution.
- **Analytics** (`/admin/analytics`): assessment/finding trends, severity and category breakdowns.
- **Assessments** (`/admin/assessments`): cross-tenant view for support and abuse investigation.
- **Health** (`/admin/health`): MongoDB, Redis, worker/service status and configuration checks.

Health is a diagnostic aid. Use external uptime and error monitoring in production.

### Users

`/admin/users` supports search, detail, activation/suspension and role changes. `PUT /api/admin/users/{uid}/plan` changes the organization plan.

Guidelines:

- Verify identity before changing a role.
- Prefer suspension over deletion during an incident; preserve audit context.
- Role changes and password resets revoke sessions.
- Never share provider keys or evidence between tenants.
- Use a named admin account, not a shared login.

### Platform settings

`/admin/config` controls:

- registration open/closed;
- maintenance mode (unauthenticated paths: health, auth, admin, docs, billing webhooks);
- announcements;
- supported provider configuration exposed to users.

Changes are audited. Maintenance mode returns `503` with `Retry-After` for non-exempt API paths.

### Audit log

`/admin/audit` is an append-only, hash-chained record. `GET /api/admin/audit/verify` recomputes the chain and reports the first invalid sequence.

Investigation checklist:

1. Filter by actor, action and time.
2. Correlate with request IDs in application logs.
3. Verify the chain before presenting the log as evidence.
4. Preserve a copy before any retention purge.
5. Do not edit audit documents directly.

### Notifications and announcements

Admins can publish an announcement. It appears as an in-app notification. Use it for maintenance, incidents and policy changes; do not include secrets or customer data.

## Plans and entitlements

| Plan | Assessments/month | Max requests | Tiers | Reports | Members | Concurrent | AI analysis | Custom attacks |
|---|---|---|---|---|---|---|---|---|
| Free | 5 | 120 | Basic | HTML/JSON | 1 | 1 | No | No |
| Researcher | 60 | 1,000 | Basic/Advanced | HTML/PDF/JSON/CSV | 1 | 3 | Yes | Yes |
| Enterprise | 1,000 | 5,000 | Basic/Advanced | HTML/PDF/JSON/CSV | 200 | 10 | Yes | Yes |

Entitlements are enforced by the backend. Changing a plan in the database without the admin workflow is unsupported and may leave inconsistent usage records.

## Provider operations

- Credentials are Fernet-encrypted. Back up keys; losing them makes credentials unrecoverable.
- Hugging Face uses the HF router or a dedicated endpoint. See [`HUGGINGFACE_INTEGRATION.md`](HUGGINGFACE_INTEGRATION.md).
- Set `LLMGUARD_PROVIDER_MIN_INTERVAL` to protect shared quotas. It is process-local.
- Monitor provider 429/5xx rates; a burst of errors usually means quota exhaustion, not a target vulnerability.
- Rotate a provider key by saving a new value, verifying a connection test, then revoking the old key upstream.

## Assessment operations

- Stale jobs: check `heartbeat_at` and worker health, then resume from the assessment page. There is no automatic sweeper.
- Queue backlog: add workers, but keep provider quotas and per-plan concurrency in mind.
- Cancelled/failed assessments can still produce reports with the evidence recorded before the stop.
- Deleting an assessment removes its findings/executions; export the report first.
- Never run an assessment against a target without a recorded authorisation. Suspicious targets should be blocked and investigated.

## Incident response

1. **Contain**: suspend the account, revoke sessions, disable the organization if necessary.
2. **Preserve**: export audit logs, request IDs and affected reports.
3. **Rotate**: JWT secret, Fernet keys (with re-encryption), provider credentials.
4. **Assess**: determine whether evidence, credentials or reports were exposed.
5. **Notify**: follow legal/contractual obligations.
6. **Recover**: restore from a verified backup if integrity is in doubt.
7. **Review**: document root cause and add a regression test.

## Backup and restore

- Back up MongoDB and Fernet keys separately.
- Test restores on a non-production database.
- After restore, verify `GET /api/admin/audit/verify`, login, model connection test and report download.
- Report content hashes are stored in `assessment_reports`; compare them with downloaded artifacts during integrity checks.

## Operational checklist

- [ ] TLS and HSTS enabled; HTTP redirects to HTTPS.
- [ ] MongoDB/Redis private and authenticated.
- [ ] Least-privilege database user; audit collection append-only.
- [ ] Secrets in a manager; encryption keys backed up.
- [ ] SMTP configured and sender domain aligned.
- [ ] External uptime, error and queue monitoring.
- [ ] Audit-chain verification scheduled daily.
- [ ] Retention and deletion policy documented.
- [ ] Provider quotas and pacing configured.
- [ ] Admin accounts use MFA and are individually named.
- [ ] Backup restore tested.
- [ ] Incident contact and escalation path published.
