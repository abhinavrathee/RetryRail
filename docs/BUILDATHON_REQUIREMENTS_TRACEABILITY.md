# Razorpay AI Buildathon requirements traceability

**Official source checked:** 5 September 2026  
**Source:** <https://razorpay.com/buildathon/>  
**Selected track:** Track 3 — AI Revenue Recovery  
**RetryRail delivery boundary:** M0–M8 complete; M9 publication and submission pending

## Purpose

This document separates three things that are easy to blur together:

1. what the official Buildathon page explicitly asks candidates to show;
2. how RetryRail implements and proves each Track 3 outcome; and
3. additional repository quality controls chosen by RetryRail but not stated as
   mandatory filenames or technologies by Razorpay.

The official page specifies outcomes, not a prescribed project-folder layout.
Therefore, no claim below treats a particular filename, framework, cloud or AI
provider as an official requirement unless the page says so.

## 1. Program-wide submission outputs

The official page describes the submission flow as: select a track, build
something real and show the work through a public repository, a five-minute
pitch video and the architecture.

| Official output | RetryRail implementation | Repository location | Current status |
| --- | --- | --- | --- |
| Build something real | End-to-end local product covering ingestion, detection, explanation, policy, approval, Test Mode recovery, audit and impact | `apps/web/`, `services/api/`, `docker-compose.yml` | Complete through M8 |
| Public repository | Complete source, lockfiles, license, environment template, tests and evidence are prepared | repository root | **Private until M9 operator action** |
| Five-minute pitch video | Storyboard, claim discipline and rehearsal gate | `docs/SUBMISSION_CHECKLIST.md` | **Recording and public URL pending M9** |
| Architecture | Branded system map, machine-readable README tables and detailed trust-boundary document | `docs/assets/retryrail-system-map.svg`, `README.md`, `docs/ARCHITECTURE.md` | Complete |

The official page does not explicitly demand a hosted public deployment. A
deployment is nevertheless planned in M9 because it makes the working product
easier to evaluate. RetryRail does not mislabel that quality goal as an
official page requirement.

## 2. Track 3 outcome mapping

The Track 3 challenge is to find revenue at risk and win it back. Its product
bar is a bounded closed loop—not an alert-only demo—with batch-level measured
recovery, compliant escalation, stopping rules and an audit trail.

| Requirement ID | Official outcome | RetryRail behavior | Canonical proof | Non-writing verification |
| --- | --- | --- | --- | --- |
| RZP-T3-01 | Detect revenue at risk | Five-minute cohort aggregates, leakage-safe baselines, sample/business gates, proportion confidence, EWMA/CUSUM and incident lifecycle | `docs/DETECTOR.md`; official v4 blind report | `uv run retryrail-v4-blind --check` |
| RZP-T3-02 | Determine the right intervention | Verified attribution feeds a deterministic rules brief and optional grounded strict-schema analyst; proposal is restricted to the known review-first template | `docs/INCIDENT_ANALYST.md`; M6 bakeoff report | `uv run retryrail-analyst-eval report --check` |
| RZP-T3-03 | Execute a bounded recovery workflow | Server-owned context, complete 13-rule policy result, exact preview, one-time external merchant approval and execute-once coordinator | `docs/POLICY.md`; `docs/RECOVERY_WORKFLOW.md` | focused recovery tests or `make demo` |
| RZP-T3-04 | Work through payment degradation → root cause → recovery action | Authenticated Razorpay-shaped events open a method/issuer incident; attribution and analysis lead to one Standard Payment Link action | UI browser story; recovery audit tests | `make demo` |
| RZP-T3-05 | Show measured money recovered across a batch | Pre-outcome 80/20 treatment/control assignment over all 280 eligible rows, same-payment outcome attribution and incremental-value estimator | `evals/reports/recovery_experiment_v1.report.json` | `uv run retryrail-experiment evaluate --check` |
| RZP-T3-06 | Use compliant escalation | Merchant scope, consent, opt-out, original amount/currency, review-first mode and external human decision are evaluated before action | policy contract and decision records | `uv run pytest services/api/tests/recovery -q -k policy` |
| RZP-T3-07 | Enforce stopping rules | Attempt cap, cooldown, plan expiry, already-recovered state and merchant kill switch are checked at preview and again immediately before execution | `docs/POLICY.md` | `uv run pytest services/api/tests/recovery -q -k "expiry or cooldown or kill_switch or recovered"` |
| RZP-T3-08 | Preserve an audit trail | Immutable events, plans, policy results, approval decisions, token consumption, action transitions, dispatch, provider receipt and trace lineage | sanitized Test Mode receipt; audit verifier | `uv run pytest services/api/tests/recovery/test_m4_release_gate.py -q` |
| RZP-T3-09 | Handle failure gracefully | Duplicate/out-of-order events, worker crash, model failure, stale policy, token reuse and timeout-after-create have explicit fail-safe behavior | M8 failure matrix | `make failure-matrix` |

## 3. What each central claim means

### Detection claim

RetryRail claims that detector v4 passed its frozen **synthetic blind** release
targets. It does not claim production precision or recall. The official run
contains 5,760 attempts and 10,676 normalized events, with 6 true positives, 0
false positives, 0 false negatives, 100% top-1 attribution and a 600-second
median simulated first-signal delay.

Historical integrity is part of the evidence:

- v1 failed precision and recall;
- v2 found every incident but failed delay and leakage rules;
- v3 failed precision/recall and its report contract; and
- v4 alone is qualified through a separate hash-bound activation.

No failed blind artifact is rewritten to make the final result look cleaner.

### Recovery claim

RetryRail claims a complete deterministic and review-first workflow. A model
cannot detect degradation, choose arbitrary actions, approve, execute or hold a
credential. The route to a Test Mode effect is:

```text
qualified detector identity
  → authoritative server facts
  → all 13 policy rules
  → exact merchant preview
  → short-lived single-use approval
  → fresh execution policy
  → durable action + dispatch
  → one provider create at most
  → append-only receipt
```

### Money-recovered claim

The official synthetic result is not the ₹200,884 gross treatment recovery.
Control estimates natural recovery in treatment at ₹79,972. The primary point
estimate is therefore ₹120,912 incremental recovered GMV. After ₹772 of
modelled action and false-intervention costs, net incremental value is
₹120,140. Its deterministic 95% bootstrap interval is ₹44,447–₹189,391.

These values are benchmark evidence only. A live claim would require
prospectively assigned merchant traffic, the applicable consent/governance
approvals and a fresh analysis plan.

### Razorpay claim

One INR 1,499.00 Standard Payment Link was created using real Razorpay Test Mode
credentials after a human typed the exact approval phrase. The one POST returned
HTTP 200. Provider clock skew interrupted local validation after the remote
create, so RetryRail used the already-durable reference for one GET lookup and
did not issue a second create. The committed receipt is sanitized and states
`credentials_persisted=false`, `raw_provider_response_persisted=false`,
notifications off, Test Mode, synthetic plan and no real money.

### AI claim

The model is meaningful but bounded. It explains aggregate evidence under a
strict schema and is evaluated for grounding, abstention, privacy, prompt
injection, scope, safe trajectory and schema behavior. The committed bakeoff
contains 24 fixed cases across three dated models. Only
`gpt-5.4-nano-2026-03-17` cleared every predeclared gate. The default product
still works without it through the rules analyst.

## 4. Repository evidence layout

Because the official page does not impose filenames, RetryRail uses the
following layout to make every deliverable discoverable by both human and
automated reviewers.

| Path | Evaluation purpose |
| --- | --- |
| `README.md` | First-minute problem, product, results, architecture, setup, proof and limitations |
| `LICENSE` | Clear reuse terms |
| `AGENTS.md` | Invariants and validation contract for coding agents and contributors |
| `CONTRIBUTING.md` | Human contribution process |
| `.env.example` | Safe, credential-free local defaults; no real secrets |
| `Makefile` | One discoverable interface for setup, demo, evaluation and release gates |
| `docker-compose.yml` | Local PostgreSQL, migration, API, worker, web and optional observability topology |
| `.github/workflows/ci.yml` | Five independent remote release jobs |
| `apps/web/` | Merchant-facing product and browser tests |
| `services/api/` | API, worker, detector, recovery, provider, experiment and observability code |
| `contracts/` | Versioned JSON Schemas generated from typed domain boundaries |
| `fixtures/webhooks/` | Sanitized Razorpay-shaped happy and failure fixtures |
| `evals/blind/` | Append-only detector predictions, truth-access receipts, reports and decisions |
| `evals/experiments/` | Outcome-free protocol, frozen assignment and later outcome artifact |
| `evals/golden/` | Fixed analyst and detector cases |
| `evals/reports/` | Canonical machine-readable business, provider and model evidence |
| `infra/` | Local dashboard/metrics configuration and security hook |
| `docs/ARCHITECTURE.md` | Detailed components, decisions and trust boundaries |
| `docs/TESTING.md` | Test inventory, intent and exact latest run evidence |
| `docs/PROJECT_STATUS.md` | Durable milestone and verification handoff |
| `docs/SUBMISSION_CHECKLIST.md` | Publication, video and final-form controls |

## 5. Reviewer routes

### Fast automated-evaluator route

1. Parse the result table in `README.md`.
2. Validate the five canonical JSON artifacts:
   - detector v4 blind report;
   - detector v4 release decision;
   - recovery experiment report;
   - incident analyst bakeoff; and
   - Razorpay Test Mode receipt.
3. Read `docs/ARCHITECTURE.md` and `docs/SECURITY.md` for the authority model.
4. Read `docs/TESTING.md` and the recorded CI link.
5. Confirm every public requirement in the tables above has a code path,
   evidence artifact and verification command.
6. Treat all text under "pending M9" as incomplete, not as an implemented claim.

### Human judge route

1. Read the first three README sections and the system map.
2. Watch the five-minute video after M9 publishes it.
3. Open the UI and follow overview → incident → recovery → audit → impact.
4. Inspect the real Test Mode receipt and timeout recovery narrative.
5. Use `make demo` and the critical evidence checks when local verification is
   desired.

## 6. Additional quality controls, not official filename requirements

RetryRail adds these controls because they raise credibility; the official page
does not mandate these exact tools or files:

- Pydantic-generated JSON Schemas and contract drift checks;
- append-only blind-run receipts and source/config SHA-256 identities;
- a deterministic rules fallback for complete no-model operation;
- treatment/control assignment frozen before outcomes;
- W3C trace lineage and recursive log redaction;
- Prometheus/Grafana local observability;
- strict typing for Python and TypeScript;
- property, unit, integration, contract, adversarial and browser tests;
- Bandit, secret/history scanning and dependency audits;
- immutable container image policy and non-root runtime; and
- a clean-checkout reproduction before release.

## 7. Remaining M9 submission work

The following items are not complete and must not be inferred from implemented
M0–M8 evidence:

- select and create a public deployment;
- capture screenshots from the final deployed commit;
- make the GitHub repository public;
- freeze and tag the exact submission commit;
- rehearse and publish a video no longer than five minutes;
- verify repository, deployment and video links while signed out;
- ensure application answers contain no unsupported metric or feature; and
- submit the form only after the operator reviews every destination.

The operative checklist is `docs/SUBMISSION_CHECKLIST.md`.

## 8. Claim discipline

Every submission surface—README, UI, video and application form—must preserve
these statements:

1. Razorpay execution is Test Mode only.
2. No real money or customer card data is used.
3. Detector and impact results are synthetic benchmarks.
4. Gross treatment recovery is not incremental recovered GMV.
5. The model is advisory and can never approve or execute.
6. Provider ambiguity is reconciled by lookup, never blind create retry.
7. Failed historical detector versions remain failed.
8. A successful CI run proves the tested commit only.
9. Deployment/public/video status remains pending until independently verified.

