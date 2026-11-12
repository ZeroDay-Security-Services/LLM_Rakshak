# API documentation

Base URL locally: `http://127.0.0.1:8000` (Docker/nginx: `http://<host>/api`).  
Interactive OpenAPI is available at `/api/docs` in development. It is disabled in production.

## Authentication

Cookie sessions are the default for the browser:

1. `POST /api/auth/login` returns the user, a CSRF token and sets `lg_access`, `lg_refresh` and `lg_csrf`.
2. Send `X-CSRF-Token: <csrf_token>` on every unsafe request (`POST`, `PUT`, `PATCH`, `DELETE`).
3. Send the cookies on every request. `lib/api.ts` does this automatically.
4. `POST /api/auth/refresh` rotates the refresh token. Reuse of an old refresh token revokes the session.
5. `POST /api/auth/logout` revokes the current session; `/logout-all` revokes all sessions.

Bearer authentication is supported for automation where configured. Do not combine stale cookies with a Bearer request when testing authorisation.

### Common responses

| Status | Meaning |
|---|---|
| `200/201/202` | Success |
| `400` | Invalid operation or unavailable optional capability |
| `401` | Missing/expired authentication, bad credentials, MFA required |
| `403` | Permission, CSRF, plan entitlement, verification or maintenance block |
| `404` | Missing **or** foreign resource (deliberately identical) |
| `409` | State conflict (for example, report before completion) |
| `413` | Payload too large |
| `422` | Schema validation failure |
| `429` | Rate limit or concurrency limit; inspect `Retry-After` |
| `500` | Unhandled error; a request ID is returned in `X-Request-ID` |

Errors use `{"detail": "message"}`. Validation errors use FastAPI's structured `detail` array.

All `/api` responses set `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. Production adds HSTS.

## Endpoint catalogue

Permissions are enforced server-side. `scope` means tenant + owner filtering.

### Authentication — `/api/auth`

| Method | Path | Notes |
|---|---|---|
| POST | `/register` | 202 always; creates user, org, membership and free subscription; sends verification |
| POST | `/verify-email` | Single-use token |
| POST | `/resend-verification` | 202 always |
| POST | `/login` | Sets cookies; returns CSRF token; `401` with `X-MFA-Required` when TOTP is needed |
| POST | `/refresh` | Rotating refresh; reuse detection |
| POST | `/logout` | Revoke current session |
| POST | `/logout-all` | Revoke every session |
| POST | `/forgot-password` | 202 always |
| POST | `/reset-password` | Single-use token; revokes sessions |
| POST | `/change-password` | Requires current password |
| GET | `/me` | Current user and effective permissions |
| GET | `/sessions` | Session inventory |
| DELETE | `/sessions/{sid}` | Revoke one session |
| GET | `/login-history` | Recent attempts |
| POST | `/mfa/setup` | Returns TOTP provisioning data |
| POST | `/mfa/enable` | Verify a code and activate |
| POST | `/mfa/disable` | Requires password/code |

### Organizations — `/api/orgs`

| Method | Path | Permission |
|---|---|---|
| GET | `/current` | `org:read` |
| PATCH | `/current` | `org:manage` |
| POST | `/switch` | membership in target org |
| GET | `/members` | `org:read` |
| POST | `/invitations` | `org:manage` |
| DELETE | `/invitations/{iid}` | `org:manage` |
| POST | `/invitations/accept` | authenticated invitee |
| PATCH | `/members/{uid}` | `org:manage` |
| DELETE | `/members/{uid}` | `org:manage` |

Organization roles: `owner`, `admin`, `member`, `viewer`. A viewer is read-only regardless of platform role. At least one owner must remain.

### Profile, credentials, models — `/api`

| Method | Path | Notes |
|---|---|---|
| PATCH | `/profile` | Name, organization, job title |
| GET/PUT | `/preferences` | Theme, timezone, notification preferences |
| POST/GET/DELETE | `/profile/avatar` | Validated image upload; served with explicit content type |
| GET | `/credentials` | Masked provider credentials |
| PUT | `/credentials/{provider}` | Encrypt and save a key/endpoint |
| DELETE | `/credentials/{provider}` | Remove a credential |
| GET | `/providers` | Provider catalog |
| POST | `/models` | Create a model configuration |
| GET | `/models` | List accessible configurations |
| GET/PUT/DELETE | `/models/{mid}` | Read/update/delete |
| POST | `/models/{mid}/test` | Bounded connectivity test |

Supported providers: `anthropic`, `openai`, `gemini`, `huggingface`, `openai_compatible`, `custom`. Hugging Face uses the HF router by default; an explicit endpoint selects a dedicated Inference Endpoint. `openai_compatible`/`custom` cover vLLM, Ollama, TGI and private gateways. All user-supplied URLs are SSRF-validated.

Example model:

```json
{
  "name": "Gemini production",
  "provider": "gemini",
  "model": "gemini-3.1-flash-lite",
  "endpoint": null,
  "system_prompt": "You are a support assistant. Never reveal internal notes.",
  "params": {"temperature": 0.2, "max_tokens": 400},
  "credential_provider": "gemini"
}
```

### Attack library — `/api/attacks`

| Method | Path | Permission |
|---|---|---|
| GET | `/categories` | `attack:read` |
| GET | `/` | `attack:read`; filters: category, tier, risk, q, page/size |
| GET | `/export` | `attack:read` |
| POST | `/` | `attack:write` (custom attacks; Researcher+) |
| POST | `/import` | `attack:import` |
| PUT | `/{attack_id}` | `attack:write` (custom only) |
| DELETE | `/{attack_id}` | `attack:write` (custom only) |
| GET | `/{attack_id}` | `attack:read` |
| GET | `/{attack_id}/history` | `attack:read` |

Built-in definitions cannot be modified or deleted. Advanced modules are plan-gated.

### Assessments — `/api/assessments`

| Method | Path | Permission |
|---|---|---|
| POST | `/` | `assessment:write` |
| GET | `/` | `assessment:read`; filters: status, q, pagination |
| GET | `/compare?ids=` | `assessment:read` |
| GET | `/{aid}` | `assessment:read` |
| DELETE | `/{aid}` | `assessment:write` |
| POST | `/{aid}/start` | `assessment:write` |
| POST | `/{aid}/pause` | `assessment:write` |
| POST | `/{aid}/resume` | `assessment:write` |
| POST | `/{aid}/cancel` | `assessment:write` |
| GET | `/{aid}/progress` | `assessment:read` |
| GET | `/{aid}/executions` | `assessment:read`; filters: status, category |
| GET | `/{aid}/executions/{eid}` | `assessment:read` |
| POST | `/{aid}/executions/{eid}/retry` | `assessment:write` |
| GET | `/{aid}/logs` | `assessment:read` |
| GET | `/{aid}/export?format=json\|csv` | `assessment:read`; finding-only export |
| POST | `/{aid}/suggestions` | `assessment:write`; AI analysis required |

Create example:

```json
{
  "name": "Support bot — pre-release",
  "model_config_id": "0123456789abcdef01234567",
  "system_prompt": "",
  "attack_ids": ["LG-PI-001", "LG-JB-001", "LG-EA-001"],
  "intensity": "medium",
  "limits": {"max_requests": 150, "max_tokens": 200000, "timeout": 45, "retries": 2},
  "ai_analysis": false,
  "authorization": {
    "confirmed": true,
    "statement": "I own this endpoint and authorise canary-based security testing.",
    "endpoint_owner_confirmed": true
  },
  "notes": "Pre-release assessment."
}
```

Start returns `{"status":"queued"}`. Poll `progress` for `status`, `finished`, `total`, counts, running test IDs and usage. `pause` stops scheduling new work; `resume` continues; `cancel` is terminal.

Advanced module budget note: `max_requests` is a hard cap across all retries. A skipped test due to budget is reported as **not tested**, never as secure.

### Findings — `/api/vulnerabilities`

| Method | Path | Permission |
|---|---|---|
| GET | `/` | `finding:read`; filters: severity, status, triage, category, q, pagination |
| GET | `/stats` | `finding:read` |
| GET | `/{vid}` | `finding:read` |
| PATCH | `/{vid}/status` | `finding:write` (`new`, `confirmed`, `in_progress`, `fixed`, `retested`, `closed`) |
| PATCH | `/{vid}/triage` | `finding:write` (`unreviewed`, `confirmed`, `false_positive`, `needs_review`, `accepted_risk`, `fixed`) |
| POST | `/{vid}/retest` | `finding:write`; creates/reruns the test and only marks *Retested* after a passing re-run |

Findings carry redacted evidence, detection metadata, classification, CVSS eligibility, tool/output/service state and hashes. Triage changes do not rewrite the original observation.

### Reports — `/api`

| Method | Path | Permission |
|---|---|---|
| POST | `/assessments/{aid}/reports` | `report:write`; body `{"format":"html\|pdf\|json\|csv"}` |
| GET | `/assessments/{aid}/reports/preview?format=` | `report:read`; renders without storing |
| GET | `/reports` | `report:read`; filter by assessment |
| GET | `/reports/{rid}/download?inline=0` | `report:read`; tenant-scoped |
| DELETE | `/reports/{rid}` | `report:write` |

Plan formats: Free = HTML/JSON; Researcher and Enterprise = HTML/PDF/JSON/CSV. Reports are available when the assessment is completed, cancelled, failed or paused. Generated reports record version, size, SHA-256, manifest hash, finding count and recalculated score.

### Dashboard and notifications

| Method | Path | Permission |
|---|---|---|
| GET | `/dashboard` | authenticated |
| GET | `/notifications` | `notification:read` |
| GET | `/notifications/unread-count` | `notification:read` |
| POST | `/notifications/{nid}/read` | `notification:read` |
| POST | `/notifications/read-all` | `notification:read` |

### Billing — `/api/billing`

| Method | Path | Notes |
|---|---|---|
| GET | `/plans` | Public plan catalog |
| GET | `/subscription` | Current org plan/usage |
| POST | `/checkout` | Returns `501` until a payment adapter is configured |
| POST | `/webhook/stripe` | HMAC + timestamp verification |
| POST | `/webhook/razorpay` | Signature verification |

Entitlements change only through a verified webhook or an admin action.

### Admin — `/api/admin`

Requires `admin:access`; specific routes require `admin:users`, `admin:read`, `audit:read`, `admin:config`, `admin:roles` or `admin:billing`.

| Method | Path | Notes |
|---|---|---|
| GET | `/stats` | Platform totals |
| GET | `/analytics` | Time series and plan/category breakdowns |
| GET | `/health` | Mongo/Redis/worker/service status |
| GET | `/users` | Search users |
| GET | `/users/{uid}` | User detail |
| PATCH | `/users/{uid}` | Activate/suspend, role changes |
| PUT | `/users/{uid}/plan` | Set org plan |
| GET | `/assessments` | Cross-tenant assessment view |
| GET/PUT | `/settings` | Registration, maintenance, announcements |
| POST | `/announcements` | Publish an announcement |
| GET | `/audit` | Audit log with filters |
| GET | `/audit/verify` | Recompute the hash chain |

## Pagination and filtering

List endpoints accept `page` (1-based) and `size` (bounded per route). Responses generally use:

```json
{"items": [], "total": 0, "page": 1, "size": 20}
```

Sort and filter values are enum-validated. Free-text search is escaped and never interpolated into raw MongoDB operators.

## Rate limits

Redis-backed limits include login (per IP and per account), registration, verification, password reset, assessment start, report generation, suggestions and invite operations. Limits return `429` with `Retry-After` where available. If Redis is unavailable, limits fail open and the condition is logged; per-account lockout still applies.

## Automation example

```bash
# Login
curl -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"..."}' \
  http://127.0.0.1:8000/api/auth/login

# Read CSRF from the JSON response, then:
curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d @assessment.json http://127.0.0.1:8000/api/assessments

curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -X POST \
  http://127.0.0.1:8000/api/assessments/$AID/start
```

Never log cookies, CSRF tokens or provider keys. Use a dedicated service account and revoke it after automation.
