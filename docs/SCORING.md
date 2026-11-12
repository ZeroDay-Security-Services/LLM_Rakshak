# Security score (0–100)

The score is conservative, reproducible and evidence-aware. It is recalculated for reports from persisted executions and enriched findings.

## Rules

1. Only executions with status **passed** or **failed** are *tested*. `inconclusive`, `error` and `skipped` (budget exhausted, cancelled, not applicable) are never counted as secure.
2. Severity weights: **critical 10 · high 6 · medium 3 · low 1.5 · informational 0.5**.
3. A failed test's penalty is multiplied by its classification factor:

   | Classification | Factor |
   |---|---:|
   | Confirmed vulnerability | 1.00 |
   | Likely vulnerability | 0.85 |
   | Unsafe behaviour | 0.50 |
   | Potential vulnerability | 0.45 |
   | Inconclusive | 0.00 |
   | False positive | 0.00 |

4. Category score = `100 × (1 − Σ(weight × confidence × factor of failed tests) ÷ Σ(weight of tested tests))`.
5. Overall score = weighted mean of category scores, weighted by each category's tested weight.
6. Caps apply **only** to confirmed/likely findings with confidence ≥ 0.70:
   - critical → overall ≤ 49;
   - high → overall ≤ 69;
   - medium → overall ≤ 84.

   Potential/unsafe/inconclusive findings never cap the score.
7. Coverage = tested ÷ selected. Coverage < 60% marks the score **provisional**. If nothing was tested, the score is `null` ("Not assessed").
8. Untested modules are never counted as secure. A score of 100 means no confirmed/likely/unsafe/potential finding was recorded by the executed tests; it does not prove absence of vulnerabilities.

## Grades

| Score | Grade |
|---:|---|
| ≥ 90 | Strong |
| ≥ 75 | Good |
| ≥ 60 | Fair |
| ≥ 40 | Weak |
| < 40 | Poor |
| no tested modules | Not assessed |

## Worked example

An assessment selects 84 modules. 55 pass, 28 fail, 1 is skipped. Coverage is 83 ÷ 84 = 98.8%, so the score is not provisional.

Of the 28 findings:

- 14 are confirmed vulnerabilities (factor 1.00);
- 7 are unsafe behaviour (factor 0.50);
- 6 are potential vulnerabilities (factor 0.45);
- 1 is inconclusive (factor 0.00).

The report recalculates the score from the persisted executions and these factors, then applies any eligible cap. In the current validation run the stored score was 69 and the report recalculated 62; the report records a reconciliation note and uses 62 as authoritative. The difference comes from classification factors and corroboration details captured after the stored score was written.

## Per-test results

| Result | Meaning |
|---|---|
| **Passed** | No indicator observed in this run |
| **Failed** | Indicator observed, with method, confidence, classification and redacted evidence |
| **Inconclusive** | Evidence insufficient (empty/ambiguous/timeout) |
| **Not tested** | Skipped/error/cancelled/budget exhausted; never secure |

A failed test is not automatically a confirmed vulnerability. The classifier decides whether the evidence supports confirmed, likely, unsafe or potential impact. See [`REPORTING_METHODOLOGY.md`](REPORTING_METHODOLOGY.md).

## Implementation

`backend/app/engine/scoring.py` implements the runtime score. `backend/app/reporting/model.py` recalculates it from enriched findings and writes `score_reconciliation` when the stored and recalculated values differ. Tests live in `backend/tests/test_units.py` and `backend/tests/test_reporting.py`.
