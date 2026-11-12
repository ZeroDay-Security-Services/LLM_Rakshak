# Documentation index

ZeroDay's LLM Rakshak — documentation for operators, users, reviewers and developers.

## Start here

| Document | Audience | Summary |
|---|---|---|
| [SCOPE](SCOPE.md) | Everyone | What is verified, what is not, and known limitations |
| [ARCHITECTURE](ARCHITECTURE.md) | Engineering | Components, data flow, trust boundaries and scaling |
| [SECURITY](SECURITY.md) | Security/ops | Threat model and implemented controls |
| [TEST_REPORT](TEST_REPORT.md) | Reviewers | Executed verification record |
| [CHANGELOG](CHANGELOG.md) | Everyone | Release history |

## Product and methodology

| Document | Summary |
|---|---|
| [ATTACK_LIBRARY](ATTACK_LIBRARY.md) | All 84 modules with severity and tier |
| [SCANNING_METHODOLOGY](SCANNING_METHODOLOGY.md) | Execution, detectors, statuses, classification and safety |
| [REPORTING_METHODOLOGY](REPORTING_METHODOLOGY.md) | Evidence model, CVSS policy, exports and integrity |
| [SCORING](SCORING.md) | Score formula, caps, coverage and reconciliation |
| [HUGGINGFACE_INTEGRATION](HUGGINGFACE_INTEGRATION.md) | HF router, dedicated endpoints, vLLM/Ollama/TGI |

## Setup and operations

| Document | Summary |
|---|---|
| [ENVIRONMENT_SETUP](ENVIRONMENT_SETUP.md) | Local setup, environment variables and troubleshooting |
| [DEPLOYMENT](DEPLOYMENT.md) | Production topology, TLS, scaling, backups and incidents |
| [DATABASE_SCHEMA](DATABASE_SCHEMA.md) | 22 collections, indexes and retention |
| [API_DOCUMENTATION](API_DOCUMENTATION.md) | Endpoints, auth, permissions and examples |
| [USER_GUIDE](USER_GUIDE.md) | End-to-end customer workflow |
| [ADMIN_GUIDE](ADMIN_GUIDE.md) | Platform administration and incident response |
| [PRODUCTION_READINESS](PRODUCTION_READINESS.md) | Go-live gates and readiness matrix |
| [COMMERCIAL_READINESS](COMMERCIAL_READINESS.md) | Packaging, gaps and launch checklist |

## Conventions

- **Test ID** is the stable `LG-*` identifier for an attack module. Findings also carry an internal `FND-*` finding ID.
- **Confirmed** means deterministic evidence at the assessed model/API boundary, not proven downstream application exploitability.
- **Not tested** means the test did not run to a judgment (skipped/error/budget/cancel) and is never counted as secure.
- All timestamps are UTC unless a UI preference says otherwise.
- Provider credentials are encrypted; reports contain redacted synthetic evidence.
