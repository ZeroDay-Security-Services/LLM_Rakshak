# User guide

ZeroDay's LLM Rakshak helps you test an LLM application you own or are authorised to assess. It does not prove that an application is secure; it records observed behaviour and the evidence behind each conclusion.

## 1. Create an account

1. Open the web app and choose **Start free**.
2. Register with your work email and a strong password.
3. Verify your email. If SMTP is not configured, the verification link is written to the server log or an administrator can verify the account.
4. Sign in. The first user of a workspace is its owner.

Use **Settings** to change your name, password, theme, timezone and notification preferences. Enable TOTP MFA before inviting others.

## 2. Set up your organization

The **Organization** page shows members and invitations.

Roles:

| Role | Can do |
|---|---|
| Owner | Manage members, billing/plan, all workspace data |
| Admin | Manage members and workspace data |
| Member | Create and run assessments, manage own resources |
| Viewer | Read-only |

Owners/admins can invite by email and change roles. A viewer cannot write, even if their platform account has a higher role. Every user-owned resource is scoped to the organization and owner; foreign IDs return 404.

## 3. Connect a model

1. Open **Models & credentials**.
2. Add a credential:
   - Anthropic, OpenAI, Gemini or Hugging Face: API key;
   - OpenAI-compatible or custom: endpoint, optional key, optional auth header/scheme.
3. Create a model configuration:
   - name;
   - provider;
   - exact model ID;
   - optional system prompt and parameters (temperature, max output tokens);
   - credential.
4. Use **Test connection**. A failure usually means a wrong model ID, missing key, quota, or a blocked private address.

Credentials are encrypted and masked. They are never shown again in full.

For self-hosted targets, an administrator must enable private targets on the server. Cloud metadata addresses remain blocked.

## 4. Create an assessment

1. Open **Assessments → New assessment**.
2. Choose the model configuration.
3. Choose the scope:
   - **Quick / Standard / Full** preset, or
   - select categories or individual modules (basic and advanced).
4. Choose intensity:
   - **Low**: one request at a time, slower, gentler on quotas;
   - **Medium**: moderate concurrency;
   - **High**: more concurrency and larger DoS inputs.
5. Set request/token budgets. These are hard caps across retries.
6. Optionally enable AI analysis (requires a platform or BYOK Anthropic key and an eligible plan).
7. Read and complete the authorisation statement. You must confirm you own or are authorised to test the target.
8. Create and start the assessment.

You can pause, resume or cancel while it runs. Progress shows completed/failed/passed counts and the currently running test IDs. If the budget is exhausted, remaining tests are **not tested**, not passed.

## 5. Understand results

Each test ends in one of these states:

| State | Meaning |
|---|---|
| Passed | No indicator of the tested weakness was observed |
| Failed | The detector observed an indicator; see the finding |
| Inconclusive | Evidence is insufficient (empty/timeout/ambiguous) |
| Error | The provider or network failed before a judgment could be made |
| Skipped | Budget exhausted, not applicable or cancelled |

A finding adds a six-state conclusion:

| Classification | Meaning |
|---|---|
| Confirmed vulnerability | Deterministic evidence directly demonstrates the weakness at the assessed model/API boundary |
| Likely vulnerability | Behaviour is consistent with the weakness but detection is heuristic; needs review/reproduction |
| Unsafe behaviour | The model generated unsafe or unreliable content, but no downstream renderer/executor/sink was exercised |
| Potential vulnerability | Exploitability depends on an integration (tool authorization, output sink, retrieval ACL) that was not tested |
| Inconclusive | Evidence cannot support or exclude the weakness |
| False positive | Analyst triage determined the indicator is not a real weakness |

Key boundaries:

- A tool call emitted by the model is **not** an executed action. Check the tool state: proposed, authorized, executed.
- Generated HTML/JS/SQL/shell is captured as text. It is **not** proof of XSS, SQL injection, command execution or exfiltration.
- RAG tests supply retrieved text directly; retrieval ACLs and tenant isolation are not exercised.
- DoS tests observe bounded latency/timeouts, not sustained availability.
- CVSS is shown only for confirmed findings with valid, deterministic evidence. Otherwise the report explains why it is suppressed.

Open a finding to see the procedure, redacted request/response, expected vs actual behaviour, detection rule, confidence, validation state, impact scope, remediation and limitations.

## 6. Triage and retest

On **Vulnerabilities** you can:

- change workflow status (`new`, `confirmed`, `in_progress`, `fixed`, `retested`, `closed`);
- triage (`unreviewed`, `confirmed`, `false_positive`, `needs_review`, `accepted_risk`, `fixed`);
- add a note;
- request a retest.

A retest re-runs the test. A finding becomes **Retested** only after a passing re-run. Triage does not alter the original evidence.

Marking a false positive excludes it from risk and scoring but keeps the audit record.

## 7. Reports

Open **Reports** (or an assessment) and generate:

- **HTML** — self-contained, print-friendly, logo embedded;
- **PDF** — client-ready;
- **JSON** — canonical machine-readable model;
- **CSV** — spreadsheet-friendly sections and findings.

Reports include scope, system under test, authorisation, methodology, score reconciliation, every selected test, per-finding evidence, limitations, prioritised actions and integrity hashes. The report recalculates the score from persisted, evidence-aware findings; if the stored score differs, a reconciliation note explains which value is authoritative.

Free plans include HTML/JSON; Researcher and Enterprise include PDF/CSV. Downloads are scoped to your organization.

## 8. Dashboard and notifications

The dashboard summarises recent assessments, findings and posture. Notifications cover completed assessments, failures and platform announcements. Unread counts are shown in the shell.

## 9. Practical guidance

- Start with a Quick/Standard run, review findings, then expand to the full library.
- Use low intensity and provider pacing for free/low-quota API keys.
- Test a staging endpoint with synthetic data, not production customer data.
- Record a clear authorisation statement and keep it with the report.
- Treat a single pass as evidence from one run, not a guarantee. Re-run after model, prompt or integration changes.
- Re-test after remediation and attach the new report to the change record.
- Never upload real secrets. The harness uses synthetic canaries, but your system prompt and endpoint are still sensitive.

## 10. Limitations you should communicate

- Results depend on the model, prompt, parameters and provider behaviour at the time of the run.
- The harness does not execute tools or render output.
- Retrieval stores, application logic, authentication, infrastructure and downstream sinks are outside the assessed boundary unless explicitly integration-tested by your team.
- Heuristic checks (hallucination, SQL/command indicators) require human review.
- A score of 100 means no indicator was recorded by the executed tests; it does not prove absence of vulnerabilities.
