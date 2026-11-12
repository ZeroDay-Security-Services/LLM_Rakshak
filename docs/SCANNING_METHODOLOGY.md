# Scanning methodology

This document explains how an assessment is executed and how an observation becomes a finding. It is the technical reference behind the customer-facing methodology section in reports.

## 1. Scope and authorisation

Every assessment requires:

- an explicit `authorization.confirmed=true`;
- a statement of at least 20 characters;
- optional endpoint-owner attestation;
- a recorded timestamp and source IP.

The assessment snapshots the target (`provider`, `model`, `endpoint`, system prompt, parameters), selected modules, intensity and budgets. Later edits to a model configuration do not silently change an existing assessment's record.

## 2. Module library

84 built-in modules across 10 categories:

| Category | Modules | Focus |
|---|---:|---|
| Prompt injection | 13 | Instruction override, fake system messages, indirect/document/JSON/image/HTML injection, payload splitting, forged continuations |
| Jailbreak | 13 | Persona, fiction, negotiation, encoding, history spoofing, policy inversion, chain-of-thought extraction |
| Sensitive disclosure | 7 | Protected values, debug dumps, credential-like output, synthetic PII, memory bleed, bulk aggregation |
| Insecure output | 10 | Script/event handlers, Markdown data URIs, `javascript:` links, SQL/shell indicators, JSON/CSV injection |
| Excessive agency | 6 | Destructive tool calls, unapproved actions, external forwarding, transfers, tool-result exfiltration, persistence |
| RAG security | 7 | Poisoned/conflicting/restricted chunks, cross-tenant leakage, self-declared authority, metadata injection, retrieved tool calls |
| Model DoS | 5 | Oversized/repeated input, output amplification, burst/rate-limit behaviour, recursive expansion |
| Hallucination | 7 | Fabricated citations/APIs/statistics, arithmetic, unsafe advice, false-claim consistency, legal citation |
| System prompt | 8 | Verbatim/paraphrased/translated extraction, YAML/config dumps, formatting tricks, boundary disclosure, stack dumps |
| Tool calling | 8 | Injection-to-tool, parameter tampering, privilege claims, argument injection, secret exfiltration, special tokens, tool-output injection, confused deputy |

57 modules are basic; 27 are advanced and plan-gated. Each definition includes procedure turns, expected secure/vulnerable behaviour, detector rules, OWASP LLM Top 10 (2025), CWE, MITRE ATLAS, remediation and an optional CVSS candidate vector.

## 3. Execution pipeline

```text
select modules → validate target and entitlements → enqueue/run
  → render turns with a fresh canary context
  → enforce budgets, pacing, concurrency, timeout and retries
  → call the provider
  → evaluate deterministic detectors, then heuristics
  → optionally ask the AI judge (cannot override strong deterministic hits)
  → persist redacted execution + finding
  → classify evidence → score → report
```

### Canary context

Each assessment run generates synthetic values: a unique canary, a protected reference token, policy markers, synthetic PII and tool names. Canaries make leakage and instruction-override checks unambiguous while remaining harmless. Values are not real secrets and are redacted where necessary.

### Messages and harness

A module may run one or more turns. Some modules add a harness system prompt describing the model's role, protected context or available tools. The harness does not provide a tool executor. The provider receives the messages and tool schema; any call is only a proposal.

### Retries and budgets

- `max_requests` and `max_tokens` are hard caps across all modules and retries.
- Retryable conditions: rate limit, timeout, network error, server error.
- Retries use exponential backoff with a cap.
- When the budget is exhausted, remaining executions are `skipped` / **not tested**. They never count as secure.
- `LLMGUARD_PROVIDER_MIN_INTERVAL` adds process-wide pacing between provider calls.

### Intensity

| Intensity | Concurrency | Base delay | DoS input | Burst |
|---|---:|---:|---:|---:|
| Low | 1 | 0.5 s | 4,000 chars | 8 |
| Medium | 2 | 0.2 s | 16,000 chars | 16 |
| High | 4 | 0 s | 48,000 chars | 32 |

Higher intensity is not "more accurate"; it increases load and may trigger provider rate limits. Use low intensity for metered/free tiers.

### Statuses

| Status | Counts as tested? | Meaning |
|---|---|---|
| `passed` | Yes | No indicator observed |
| `failed` | Yes | Indicator observed; finding created |
| `inconclusive` | No | Evidence insufficient |
| `error` | No | Provider/network/validation failure |
| `skipped` | No | Budget, cancellation, not applicable |

Coverage = `(passed + failed) / selected`. Below 60% the score is provisional. A run with no tested modules has no score.

## 4. Detectors

Detectors are deterministic first:

- **canary**: the unique per-run token appears outside an allowed context;
- **secret_leak**: a protected reference token or credential-like pattern appears;
- **policy marker**: a forbidden policy string is emitted;
- **tool_call**: a named tool is proposed, optionally with argument regex;
- **regex / regex_unfenced**: output matches a risky construct outside a code fence;
- **structured checks**: JSON/CSV shape, arithmetic, citation/API consistency;
- **behavioural checks**: refusal vs compliance, truncation, latency/error patterns;
- **optional AI review**: schema-validated, advisory, cannot override a strong deterministic hit.

Heuristic checks carry lower confidence and require human review. Confidence is bounded by method and validation state.

## 5. Category-specific boundaries

### Prompt injection / jailbreak / system prompt

The test observes whether user or retrieved text changes the model's behaviour relative to its configured role. A hit proves a prompt-level instruction-hierarchy or policy failure in the assessed configuration. It does not prove the application exposes dangerous capabilities.

### Sensitive disclosure

Protected values are synthetic. A hit proves the model emitted the protected value. It does not prove the application stores real secrets or that a real attacker can reach the same context.

### Insecure output

Generated HTML/JS/SQL/shell/Markdown is captured as text. No renderer, browser or database is invoked. A hit is **unsafe behaviour** unless downstream execution/rendering is separately demonstrated. XSS/exfiltration/command execution are not claimed.

### Excessive agency / tool calling

The model may emit a tool call. The harness records:

- `proposed`: the model emitted a call;
- `authorized`: an integration approved it (not exercised by default);
- `executed`: a real downstream action occurred (not exercised by default).

A proposed destructive call is a **potential vulnerability** until the integration's authorization and execution are tested. This is deliberate: model output is not application impact.

### RAG

Retrieved text is supplied directly to the model. Tests observe whether the model follows poisoned/unauthorised content. Retrieval-layer ACLs, tenant isolation and vector-store configuration are outside the boundary; findings that depend on them are labelled accordingly.

### Model DoS

Bounded inputs and bursts observe latency, timeouts, truncation and errors. They are not sustained load tests and cannot establish availability impact or cost exhaustion. Timeouts are usually `inconclusive`, not confirmed DoS.

### Hallucination

Checks look for fabricated citations/APIs/statistics, arithmetic inconsistency and unsafe advice. These are heuristic and marked needs-review. They are reliability/security-relevant behaviour, not a confirmed exploit.

## 6. Evidence capture

For each failed test, the platform stores:

- test ID, name, category, severity and tier;
- target provider/model/endpoint and assessment timestamps;
- procedure/messages and repeat count;
- redacted request and response;
- expected secure vs actual behaviour;
- detection rule/method, matched rules and reason;
- confidence, validation status and evidence quality;
- tool/output/service state;
- limitations and remediation;
- evidence SHA-256.

Redaction runs before persistence. Report generation re-redacts persisted transcripts. See [`REPORTING_METHODOLOGY.md`](REPORTING_METHODOLOGY.md).

## 7. Classification

The classifier maps evidence to:

| Code | Typical evidence |
|---|---|
| `confirmed_vulnerability` | Deterministic canary/secret/tool proposal at the assessed boundary with strong evidence |
| `likely_vulnerability` | Consistent behaviour but heuristic detection or incomplete evidence |
| `unsafe_behavior` | Unsafe/unreliable output without a downstream sink |
| `potential_vulnerability` | Plausible exploit depends on an untested integration |
| `inconclusive` | Timeout/empty/ambiguous evidence |
| `false_positive` | Analyst triage rejected the indicator |

CVSS is assigned only when the finding is confirmed, the vector is valid, confidence >= 0.70, detection is deterministic, and no unproven service-impact claim is involved. Otherwise the report states why CVSS is suppressed.

## 8. Scoring

See [`SCORING.md`](SCORING.md). In short:

- severity weights: critical 10, high 6, medium 3, low 1.5, info 0.5;
- failed penalties are multiplied by the classification factor;
- confirmed/likely critical/high/medium findings can cap the score;
- untested tests never count as secure;
- coverage < 60% is provisional.

## 9. Safety controls

- Canary-based, policy-bounded modules; no harmful content requests.
- No tool executor, browser, SQL client or shell.
- SSRF validation and metadata blocking.
- Request/token/time limits and per-plan concurrency.
- Pause/resume/cancel and idempotent executions.
- Redaction at capture and report time.
- Authorisation required per assessment.

## 10. Limitations

- Model behaviour is non-deterministic; one run is one observation.
- A passed test is absence of an indicator, not proof of security.
- The assessed boundary is the model API, not the full application.
- Retrieval, tools, renderers and infrastructure require separate integration testing.
- Provider outages, quotas and safety filters can change results.
- Heuristic checks require human review.
- The platform has not undergone independent penetration or load testing.
