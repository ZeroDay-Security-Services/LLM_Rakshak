# Production readiness

**Current decision: conditionally ready for a controlled pilot; not ready for unattended paid production traffic.**

This assessment reflects the code and verification recorded in `TEST_REPORT.md` (2026-11-11). It must be revisited after infrastructure, payment and legal work.

## Readiness matrix

| Area | Status | Evidence / gap |
|---|---|---|
| Core assessment engine | Ready | 76 backend tests; real Gemini run across 84 modules |
| Evidence-aware reporting | Ready | HTML/PDF/JSON/CSV consistency, classification, CVSS gating, reconciliation, hashes |
| Multi-tenancy and RBAC | Ready | Isolation and role tests; identical 404s; org viewer stripped of writes |
| Authentication and sessions | Ready | Argon2id, refresh rotation/reuse detection, CSRF, MFA, lockout |
| SSRF protection | Ready | Unit coverage for private/metadata/rebinding forms; pinned connection |
| Admin and audit | Ready | Admin tests; hash-chain verification |
| Real provider coverage | Partial | Gemini verified live; Anthropic/OpenAI/HF require per-account verification |
| Frontend responsiveness | Ready | Desktop/mobile browser checks; public and authenticated pages |
| Email delivery | Not ready | SMTP not configured; templates exist |
| Payments | Not ready | Checkout returns 501; webhook verification only |
| MongoDB Atlas | Unverified | Local MongoDB exercised; Atlas-specific operations untested |
| Independent security review | Not done | No external penetration test |
| Load/soak testing | Not done | Concurrency and capacity unmeasured |
| Observability | Partial | Health endpoint/admin page; no external APM/alerting bundled |
| Backups/restore | Process only | Must be configured and restore-tested per deployment |
| Legal/privacy | Template | Counsel review required |
| SSO/SCIM | Not implemented | Enterprise procurement may block |
| Data residency | Not implemented | Single deployment region |
| Stale-job recovery | Manual | No Celery beat sweeper |
| CSP hardening | Partial | `'unsafe-inline'` scripts allowed for Next.js |

## Go-live gates

### Must have

- [ ] Production MongoDB (Atlas or managed) with least-privilege user, TLS, backups and a tested restore.
- [ ] Redis with persistence/HA appropriate to queue-loss tolerance.
- [ ] TLS, HSTS, secure cookies and an exact `FRONTEND_ORIGIN`.
- [ ] Secrets in a manager; Fernet keys backed up separately.
- [ ] SMTP configured and deliverability verified (SPF/DKIM/DMARC).
- [ ] External uptime, error, queue and provider-429 monitoring.
- [ ] Audit-chain verification scheduled.
- [ ] Retention/deletion policy and customer export process.
- [ ] Incident response runbook and on-call contact.
- [ ] External penetration test with critical/high findings remediated.
- [ ] Load test at expected concurrency and report generation size.
- [ ] Counsel-reviewed Terms, Privacy, DPA and subprocessor list.
- [ ] Support/SLA process and status page.

### Should have

- [ ] Payment checkout, invoicing, tax and dunning.
- [ ] SSO (OIDC/SAML) and SCIM, or a documented enterprise exception.
- [ ] Per-tenant usage/cost reporting.
- [ ] Nonce-based CSP.
- [ ] Automated stale-job sweep and worker autoscaling.
- [ ] Synthetic monitoring that runs a small assessment end to end.
- [ ] Report retention/archival to object storage.
- [ ] Provider-specific rate limiter shared across workers.

### Nice to have

- [ ] Data-region choice.
- [ ] Customer-managed encryption keys.
- [ ] Integration harness for tool/RAG execution evidence.
- [ ] Benchmark of detector precision/recall on a labelled corpus.
- [ ] White-label reports for MSSPs.
- [ ] Public status/trust center.

## Capacity assumptions

These are starting points, not measured limits:

- API: stateless; scale horizontally. Report generation is CPU/memory heavy for large assessments.
- Worker: one assessment can issue hundreds of provider calls. Size workers by provider quota, not CPU alone.
- Provider pacing is process-local. With N workers, effective interval per process must be multiplied by N or replaced with a shared limiter.
- MongoDB growth is dominated by execution transcripts and stored report blobs. Monitor and set retention.
- Celery/Redis loss can drop queued work; executions already persisted can be resumed.

## Security operations

- Patch Python/Node dependencies and rebuild images on a schedule.
- Rotate JWT/Fernet/provider secrets on compromise and on a defined schedule.
- Review admin accounts and MFA quarterly.
- Verify audit-chain integrity daily and before exporting evidence.
- Monitor authentication failures, lockouts, 403/404 spikes, provider abuse and unusual egress.
- Restrict database/Redis access to application networks.
- Keep `ALLOW_PRIVATE_TARGETS=false` on multi-tenant deployments.

## Reliability and recovery

| Scenario | Expected behaviour | Action |
|---|---|---|
| Provider 429 | Bounded retries; execution may error | Pacing, lower intensity, wait |
| Provider outage | Errors, not false passes | Retry/resume after recovery |
| Worker crash | Heartbeat stale; executions persisted | Restart worker, resume |
| Redis loss | Limits fail open; queued jobs may be lost | Restore Redis, re-run |
| MongoDB loss | Service unavailable | Restore backup, verify audit/report hashes |
| Report generation failure | No stored report | Retry; check size/dependencies |
| Suspected key compromise | Sessions/credentials at risk | Rotate keys, revoke sessions, investigate audit |

## Launch recommendation

**Controlled pilot:** acceptable with design-partner agreements, synthetic data, manual onboarding/billing, a named support contact and a documented scope. Do not represent the platform as a substitute for a penetration test or as proof of application security.

**Paid self-serve production:** not yet. Close the must-have gates, especially payments, email, Atlas validation, external testing, legal review and monitoring.

## Sign-off

| Role | Name | Date | Decision |
|---|---|---|---|
| Engineering | | | |
| Security | | | |
| Operations | | | |
| Legal/Privacy | | | |
| Product | | | |

Record the decision, accepted risks and expiry date. Reassess after any material change to providers, scoring, reporting or infrastructure.
