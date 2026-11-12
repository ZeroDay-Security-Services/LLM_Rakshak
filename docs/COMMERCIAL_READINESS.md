# Commercial readiness

This document is an honest assessment of what can be sold today, what is still a template, and what must be completed before a commercial launch. It is not a substitute for legal, finance or independent security review.

## Product position

**ZeroDay's LLM Rakshak** is a multi-tenant LLM security assessment platform for teams deploying chatbots, RAG assistants, agents and tool-calling applications. It differentiates on evidence-aware reporting: it distinguishes confirmed model/API findings from unsafe behaviour and from potential vulnerabilities that depend on an untested integration.

Target buyers:

- AI product and platform teams preparing for launch or procurement review;
- security teams that need repeatable LLM testing without building a harness;
- consultancies/MSSPs that need branded, client-ready evidence and reports;
- regulated teams that need a documented scope, methodology and limitations.

## What is ready

| Capability | Status |
|---|---|
| 84-module attack library across 10 categories | Implemented and seeded |
| Real Gemini provider execution | Verified against the live Google API |
| Anthropic/OpenAI/Hugging Face adapters | Implemented; require customer keys and verification per account |
| OpenAI-compatible/self-hosted targets | Implemented and exercised in end-to-end tests |
| Evidence-aware classification, confidence and CVSS gating | Implemented with regression tests |
| HTML/PDF/JSON/CSV reports with logo, evidence, hashes and reconciliation | Implemented and visually checked |
| Multi-tenancy, RBAC, sessions, MFA, CSRF, SSRF controls | Implemented and tested |
| Plans/entitlements and usage quotas | Implemented and enforced server-side |
| Admin panel, audit chain, health, announcements | Implemented |
| Billing webhook verification | Implemented and tested |
| Public marketing site, auth pages, app shell, responsive layouts | Implemented and browser-verified |

## What is not ready for a paid launch

| Gap | Impact | Required action |
|---|---|---|
| Payment checkout returns `501` | Customers cannot self-serve payment | Integrate Stripe/Razorpay checkout/session creation, test end to end, reconcile webhooks and refunds |
| SMTP not configured by default | Users cannot verify/reset without admin help | Configure a transactional provider, sender domain, SPF/DKIM/DMARC, bounce handling |
| MongoDB Atlas not exercised | Production database behaviour unverified | Staging run on Atlas, network/role/TLS/backup tests |
| No independent penetration test | Security claims are self-assessed | Commission an external test; remediate and publish a summary |
| No load/soak test | Capacity and cost limits unknown | Load test API, workers, provider pacing and report generation |
| PDF/HTML report legal review | Client deliverable may over/under-claim | Counsel review of wording, scope, limitations and liability |
| Privacy/Terms are templates | Legal exposure | Counsel review, DPA, subprocessor list, retention policy |
| No SLA/support process | Commercial commitments undefined | Define support tiers, response times, escalation and status page |
| No native SSO/SCIM | Enterprise procurement blocker for some buyers | Add OIDC/SAML and SCIM, or document a roadmap |
| No billing self-service/invoices | Finance operations manual | Add invoices, tax handling, dunning, plan changes |
| No data-region choice | Residency requirements | Offer region-pinned deployment or document constraints |
| No agentic integration testing | Tool/RAG findings remain potential | Build customer-side integration harness or professional services |
| Provider cost model not exposed | Customers cannot forecast spend | Add token/request usage reporting and optional cost estimates |
| No independent model-quality benchmark | Detection efficacy varies | Publish methodology and measured precision/recall on a labelled corpus |

## Packaging recommendation

| Package | Contents | Notes |
|---|---|---|
| Free | 5 assessments/month, 120 requests, basic modules, HTML/JSON | Acquisition and evaluation |
| Researcher ($29/month) | 60 assessments, advanced modules, 1,000 requests, all report formats, custom attacks, AI analysis | Individual consultants |
| Enterprise (quote) | 1,000 assessments, 5,000 requests, 200 members, 10 concurrent, admin/audit, support | Team/agency deployment |

Do not advertise "unlimited" testing. Provider costs and quotas are real. Keep request/token budgets and provider pacing visible.

## Launch checklist

### Product

- [x] Branding, logo and user-visible copy
- [x] 84-module library and plan gating
- [x] Evidence-aware findings and reports
- [x] Tenant isolation, RBAC, sessions, MFA
- [x] Admin and audit
- [ ] Payment checkout and reconciliation
- [ ] Email delivery and deliverability
- [ ] SSO/SCIM decision (build or document)
- [ ] Retention/deletion automation
- [ ] Status page and support tooling

### Security and legal

- [ ] External penetration test and remediation
- [ ] Load/soak test
- [ ] Privacy Policy, Terms, DPA, subprocessor list reviewed by counsel
- [ ] Incident response runbook and contact
- [ ] Vulnerability disclosure policy
- [ ] Data-processing and cross-border transfer review
- [ ] Insurance/contractual limitation review

### Go-to-market

- [ ] Pricing page matches enforced entitlements
- [ ] Demo workspace with synthetic targets
- [ ] Sample report approved for external use
- [ ] Sales deck and security questionnaire answers
- [ ] Onboarding guide and support macros
- [ ] Reference customers/pilots
- [ ] Clear claims: model/API boundary, no exploit/execution proof

## Claims guidance

Safe to say:

- "84 canary-based modules across 10 LLM risk categories."
- "Evidence-aware findings distinguish confirmed model/API behaviour from unsafe output and integration-dependent potential."
- "Reports include redacted evidence, confidence, validation state and limitations."
- "Only authorised targets; bounded requests; no tool executor."

Do not say without additional evidence:

- "Proves your application is secure."
- "Detects all prompt injection/jailbreaks."
- "Confirms XSS, SQL injection, command execution or data exfiltration."
- "Tests your RAG authorization, tool execution or production infrastructure."
- "Replaces a penetration test."
- "Zero false positives/negatives."

## Commercial risks

1. **Detection efficacy is not benchmarked.** A customer may over-trust a pass. Keep limitations prominent.
2. **Provider dependence.** Quotas, safety filters and model changes affect results and cost.
3. **Non-determinism.** Repeatability requires re-runs and clear methodology.
4. **Legal exposure from reports.** Scope and limitations must be reviewed.
5. **Support burden.** Integration questions (tools, RAG, private endpoints) will dominate early support.
6. **Competition.** Differentiate on evidence quality and report defensibility, not module count alone.

## Minimum viable paid launch

A defensible paid launch requires:

1. working checkout and invoicing;
2. reliable transactional email;
3. a staging deployment on Atlas with backups;
4. an external penetration test and load test;
5. counsel-reviewed terms/privacy/DPA;
6. a published support/SLA process;
7. sample report and claims review;
8. an incident response runbook.

Until then, use design-partner agreements with explicit scope, synthetic data and manual billing.
