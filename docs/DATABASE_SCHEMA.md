# Database schema

MongoDB is the system of record. `backend/app/db.py` creates the 22 collections and their indexes idempotently at startup, then records `platform_settings._id="schema"` with `version=1`. There is no migration framework; changes are applied as idempotent index/field updates.

All timestamps are stored as UTC `datetime` values. Object references are `ObjectId`. Tenant-owned documents carry `org_id`; user-owned documents also carry `owner_id`.

## Collections

### `users`

| Field | Notes |
|---|---|
| `_id` | ObjectId |
| `email` | Lowercase, unique |
| `name`, `organization`, `job_title` | Profile |
| `password_hash` | Argon2id |
| `role` | `super_admin`, `admin`, `researcher`, `user`, `viewer` |
| `is_active`, `email_verified`, `mfa_enabled` | Account state |
| `totp_secret_enc`, `totp_pending_enc`, `last_totp_step` | MFA, encrypted |
| `failed_attempts`, `locked_until` | Lockout |
| `preferences` | Theme, timezone, notification preferences |
| `active_org_id` | Current organization |
| `avatar`, `avatar_ct` | Avatar bytes and content type |
| `created_at`, `last_login_at` | Timestamps |

Indexes: unique `email`; `(role, is_active)`; `created_at` descending.

### `organizations`

`name`, `slug` (unique), `owner_id`, `created_at`. Indexes: unique `slug`; `owner_id`.

### `organization_members`

`org_id`, `user_id`, `role` (`owner`, `admin`, `member`, `viewer`), `created_at`. Unique `(org_id, user_id)`; `user_id`.

### `sessions`

`user_id`, `token_hash`, `prev_hash`, `revoked`, `created_at`, `last_used_at`, `expires_at`, `abs_expires_at`, `ip`, `ua`. Indexes: `token_hash`; sparse `prev_hash`; `(user_id, revoked)`; TTL on `abs_expires_at`.

### `email_verifications`, `password_resets`

`user_id`, `token_hash` (unique), `expires_at`. TTL on `expires_at`.

### `invitations`

`org_id`, `email`, `role`, `token_hash` (unique), `invited_by`, `expires_at`, `created_at`. Indexes: unique token; `(org_id, email)`; TTL on `expires_at`.

### `api_credentials`

One document per user/provider. `owner_id`, `org_id`, `provider`, `encrypted` (Fernet token), `preview` (masked), `auth_header`, `endpoint`, `created_at`, `updated_at`. Unique `(owner_id, provider)`.

Never store plaintext keys here. The `encrypted` value is decrypted only inside the provider call path.

### `llm_providers`

Seed/catalog metadata for supported providers: `key` (unique), `label`, `needs_endpoint`, `default_model`, timestamps.

### `model_configurations`

`name`, `provider`, `model`, `endpoint`, `system_prompt`, `params`, `credential_provider`, `org_id`, `owner_id`, `created_at`, `updated_at`. Index: `(org_id, owner_id, created_at)`.

### `assessments`

| Field | Notes |
|---|---|
| `name`, `org_id`, `owner_id` | Identity |
| `model_config_id`, `model_name`, `provider`, `endpoint`, `system_prompt`, `params` | Snapshot of the system under test |
| `attack_ids` | Selected module IDs |
| `intensity` | `low`, `medium`, `high` |
| `limits` | `max_requests`, `max_tokens`, `timeout`, `retries` |
| `ai_analysis` | Optional judge |
| `authorization` | `confirmed`, `statement`, `endpoint_owner_confirmed`, `confirmed_at`, `ip` |
| `status` | `draft`, `queued`, `running`, `pausing`, `paused`, `cancelling`, `cancelled`, `completed`, `failed` |
| `control` | Pause/cancel signal |
| `usage` | Requests and tokens consumed |
| `progress` | `total`, `done` |
| `score` | Stored score snapshot and evidence-aware fields |
| `summary` | Generated narrative |
| `queued_at`, `started_at`, `heartbeat_at`, `finished_at`, `validated_at` | Lifecycle timestamps |
| `error` | Failure detail |

Indexes: `(org_id, owner_id, created_at)`; `(status, heartbeat_at)`; `(org_id, status)`.

### `assessment_jobs`

`assessment_id`, `status`, `created_at`, `started_at`, `finished_at`, `error`, `worker`. Indexes: `(assessment_id, created_at)`; `status`.

### `attack_modules`

Built-in and custom definitions. `attack_id` (unique), `name`, `category`, `risk`, `tier`, `description`, `turns`, `detect`, `harness`, `tools`, `repeat`, `dos`, `applies_to`, `expected_secure`, `expected_vulnerable`, `remediation`, `owasp`, `cwe`, `atlas`, `cvss_vector`, `org_id` (custom only), `builtin`, `version`, `created_at`, `updated_at`. Indexes: unique `attack_id`; `(category, tier)`; sparse `org_id`; text index on `name`/`description`.

### `attack_executions`

One document per `(assessment_id, attack_id)`. `org_id`, `owner_id`, `assessment_id`, `attack_id`, `attack_name`, `category`, `severity`, `status` (`queued`, `running`, `passed`, `failed`, `inconclusive`, `error`, `skipped`), `confidence`, `method`, `detected`, `response`, `detector`, `repeat_count`, `attempts`, `started_at`, `finished_at`, `duration_ms`, `error`. Unique `(assessment_id, attack_id)`; `(org_id, attack_id, finished_at)`; `(assessment_id, status)`.

### `vulnerabilities`

Findings. `org_id`, `owner_id`, `assessment_id`, `attack_id`, `finding_id` (unique), `title`, `description`, `severity`, `status`, `triage`, `category`, `owasp`, `cwe`, `atlas`, `evidence`, `detection`, `remediation`, `cvss`, `classification`, `evidence_sha256`, `detected_at`, `updated_at`. Indexes: `(org_id, owner_id, severity, detected_at)`; unique `(assessment_id, attack_id)`; unique `finding_id`; text index on `title`/`description`.

### `assessment_reports`

`assessment_id`, `org_id`, `owner_id`, `format`, `version`, `status`, `model` (canonical report snapshot or reference), `content_hash`, `size`, `created_at`. Indexes: `(assessment_id, created_at)`; `owner_id`.

### `notifications`

`user_id`, `type`, `title`, `body`, `read`, `created_at`, `expires_at`, `link`. Indexes: `(user_id, read, created_at)`; TTL on `expires_at`.

### `subscriptions`

One per organization. `org_id` (unique), `plan`, `status`, `provider`, `current_period_end`, `created_at`, `updated_at`.

### `usage_records`

`org_id`, `assessment_id`, `kind`, `quantity`, `created_at`. Indexes: `(org_id, created_at)`; `assessment_id`.

### `audit_logs`

Append-only, hash-chained. `seq` (unique), `ts`, `action`, `actor_id`, `actor_email`, `ip`, `target`, `meta`, `prev_hash`, `hash`. Indexes: unique `seq`; `(action, ts)`; `(actor_id, ts)`.

Application users should not have update/remove permission on this collection.

### `platform_settings`

Key/value documents. `_id="schema"` stores the schema version. `_id="config"` stores registration, maintenance, announcement and feature flags. Indexes: none.

### `login_history`

`user_id`, `email`, `ip`, `ua`, `success`, `reason`, `ts`, `expires_at`. Indexes: `(user_id, ts)`; TTL on `expires_at` (180 days).

## Retention

| Data | Retention |
|---|---|
| Sessions | TTL at absolute expiry |
| Email verification / reset / invite tokens | TTL at expiry |
| Login history | 180 days (TTL) |
| Notifications | TTL where an expiry is set |
| Assessments, findings, reports | Customer-controlled; deleted with the assessment/tenant workflow |
| Audit logs | Retained; immutable by application policy |

Deleting an assessment should remove its executions and findings through the API. For regulated customers, define a documented retention schedule and a verified backup/restore procedure.

## Index and migration notes

- Index creation is idempotent and runs on startup. Large production collections may need a maintenance window or background index builds.
- `SCHEMA_VERSION` is informational. Additive fields are backward-compatible; the reporting layer reconstructs missing classification metadata for legacy findings.
- Do not edit `audit_logs` directly. Tamper detection is based on the chain.
- Back up the Fernet keys separately from the database. A database restore without the matching keys leaves credentials undecryptable.
