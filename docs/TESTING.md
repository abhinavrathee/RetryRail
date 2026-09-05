# RetryRail testing and verification dossier

**Latest remote release evidence:** 5 September 2026  
**CI run:** <https://github.com/abhinavrathee/RetryRail/actions/runs/33976562151>  
**Implementation commit:** `791cf4162f60e8d2815c9b18e1a852c180c6fe60`  
**Evidence commit:** `30a2694cf00f406048152f0c62cf3d9ff9134a9d`

## Purpose

This document explains what RetryRail tests, why each suite exists, what the
latest release actually passed and how a reviewer can reproduce the evidence.
It distinguishes executable tests from synthetic evaluation cases, external
Test Mode evidence and historical milestone snapshots.

No test count is a feature claim by itself. The important property is that
critical authority, money, time, failure and idempotency boundaries have both
positive and negative executable evidence.

## Latest verified snapshot

| Layer | Exact recorded result |
| --- | --- |
| Python release suite | 514 pytest nodes passed on PostgreSQL in 31:42 |
| Backend coverage | 85.48% branch-aware coverage |
| Frontend unit/component | 13 Vitest tests passed |
| Frontend coverage | 90.05% statements, 77.69% branches, 93.69% functions, 92.40% lines |
| Browser | 3 Chromium scenarios passed |
| M8 focused evidence | 17-case failure matrix and 11-case readiness/migration/trace/dashboard/audit set passed |
| Static analysis | Ruff and strict mypy over 142 source files passed |
| Security | Bandit reported zero findings; repository/history secret scans, `pip-audit` and fail-closed pnpm high-severity audit passed |
| Contracts/evaluations | 23-schema drift gate and every frozen detector, experiment and model-report integrity check passed |
| Containers | Digest policy, API/worker/web builds, non-root runtime and local observability configuration passed |
| Clean checkout | Locked install took 67.82 seconds; the focused clean M8 gate took 49.13 seconds; checkout remained byte-clean |

### Reviewer-deployment candidate rehearsal

Before publishing the public service, the exact `infra/render/Dockerfile` image
and `render.yaml` topology were rehearsed locally against PostgreSQL 16:

| Check | Observed result |
| --- | --- |
| Blueprint contract | `render.yaml` validates against Render's published Blueprint JSON Schema |
| Immutable build | Locked Node and Python stages completed and produced the combined API/UI image |
| Database lifecycle | Alembic upgraded an empty PostgreSQL database through `0008_m8_trace_lineage` |
| Public surface | `/health/ready`, `/`, a nested incident route and a fingerprinted asset returned HTTP 200 |
| Fail-closed surface | `/docs`, `/openapi.json`, `/.env` and a missing asset returned HTTP 404 in `review` mode |
| Browser caching/security | Fingerprinted assets emitted immutable caching; CSP and HSTS were present |
| Initial data hook | 2,722 synthetic inputs selected; 2,717 accepted, 3 deduplicated, 2 rejected as designed and 0 expectation mismatches |
| Worker convergence | The dedicated worker projected the batch through `2026-09-01T23:59:59Z` and reproduced 2 resolved synthetic incidents |
| Focused regression | 30 configuration, health, SPA-hosting and security-header tests passed; Ruff and strict mypy passed |

This is pre-deployment evidence for the current working tree, not proof that a
public Render hostname exists. The public URL, Render health state, UptimeRobot
monitor and signed-out browser pass remain operator-owned M9 evidence.

The authoritative narrative is
`docs/PROJECT_STATUS.md#verified-m8-completion-snapshot`. Historical sections in
that file intentionally retain smaller test counts from earlier milestones and
must not be added together.

## How to enumerate every individual test

The source-controlled test names are the executable inventory. These commands
list every collected test without running it:

```bash
uv run pytest --collect-only -q
pnpm --filter @retryrail/web exec vitest list
pnpm --filter @retryrail/web exec playwright test --list
```

At the latest collection point, pytest produces 514 nodes. Parameterized tests
produce more nodes than function definitions; the per-file counts below are
collected nodes, not a manual function count.

## Verification layers

| Layer | Question answered |
| --- | --- |
| Unit | Does one parser, validator, policy rule, estimator or redactor behave at its exact boundaries? |
| Property | Do time, amount, attempt and cooldown invariants hold across generated values rather than a few examples? |
| Contract | Do typed models, JSON Schemas, enum/nullability rules and frozen fingerprints agree byte-for-byte? |
| Integration | Do database transactions, migrations, locks, webhook/outbox flow and authenticated routes work together? |
| Adversarial | Does the system fail closed under forgery, rebinding, injection, stale state, concurrency and ambiguous I/O? |
| Evaluation | Does a frozen detector/model/experiment report reproduce and satisfy a predeclared selection rule? |
| Browser E2E | Can a merchant complete or reject the full workflow using the real UI and keyboard? |
| Security/release | Can the exact checkout build, scan, migrate, start and remain free of unexplained High/Critical findings? |
| External evidence | Did the real Razorpay Test Mode boundary behave as claimed without exposing a credential? |

## Backend inventory — all 514 collected pytest nodes

### Contracts and deterministic data — 69

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 7 | `contracts/test_contracts.py` | Generated schema catalogue, exporter behavior and drift rejection |
| 10 | `contracts/test_domain_models.py` | Strict event/incident/plan/action model boundaries and money/time types |
| 37 | `contracts/test_recovery_contracts.py` | Recovery template, policy, approval and action invariants, typed failures and canonical ordering |
| 11 | `contracts/test_synthetic_dataset.py` | Seed determinism, manifest identity, split isolation and truth reconciliation |
| 4 | `contracts/test_webhook_fixtures.py` | Sanitized Razorpay-shaped fixtures and expected signature/body behavior |

### Detector and blind-release machinery — 200

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 9 | `detection/test_engine.py` | Aggregate windows, sample/impact/statistical gates, lifecycle and hard-negative safety |
| 4 | `detection/test_evaluation.py` | Matching, precision/recall, delay, attribution and release arithmetic |
| 4 | `detection/test_runtime_activation.py` | Exact v4 hash-bound eligibility and rejection of failed/forged identities |
| 4 | `detection/test_v2_blind_reproduction.py` | Nonce-derived v2 input and artifact reproduction |
| 7 | `detection/test_v2_blind.py` | Append-only v2 stages, truth-access order and blocked release |
| 10 | `detection/test_v2_candidate.py` | Frozen candidate behavior and development report |
| 6 | `detection/test_v2_dataset.py` | Development/blind separation, manifests and deterministic generation |
| 26 | `detection/test_v3_blind_postrun.py` | Post-run reconstruction and preserved v3 procedural/report failures |
| 9 | `detection/test_v3_blind.py` | V3 receipt state machine and create-only run boundary |
| 10 | `detection/test_v3_candidate.py` | Guarded-baseline candidate and development partitions |
| 16 | `detection/test_v3_cli.py` | Bounded CLI errors, stage ordering and overwrite refusal |
| 12 | `detection/test_v3_freeze.py` | Candidate/config/matcher/evaluator freeze identities |
| 15 | `detection/test_v3_protocol.py` | Precommitment, source identity and report contract |
| 12 | `detection/test_v4_blind.py` | Prediction-before-truth run, strict report read-back and qualified decision |
| 18 | `detection/test_v4_candidate.py` | Canonical cohort hierarchy, overlap/lifecycle resolution and all development partitions |
| 11 | `detection/test_v4_freeze.py` | Complete nonce-free candidate and append-only runner freeze |
| 27 | `detection/test_v4_protocol.py` | Failure-specific remediation boundary, nullable report output, adversarial evidence and digests |

### Recovery experiment — 8

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 2 | `experiments/test_api.py` | Merchant authentication and exact packaged-report digest validation |
| 6 | `experiments/test_evaluation.py` | Eligibility, frozen allocation, same-payment attribution, value arithmetic and bootstrap integrity |

### Cross-component integration — 23

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 3 | `integration/test_detection_service.py` | Projection-to-aggregate-to-incident lifecycle and evidence persistence |
| 6 | `integration/test_outbox_projection.py` | Worker leases, crash recovery, poison handling and out-of-order monotonic state |
| 6 | `integration/test_replay_and_migrations.py` | Protected replay, bounded demo, schema equivalence, migration round trips and M8 backfill |
| 8 | `integration/test_webhook_ingestion.py` | Raw-body authentication, malformed input, triple delivery, identity conflict and atomic outbox |

### Observability — 5

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 5 | `observability/test_m8_observability.py` | Valid/invalid W3C context, immutable trace lineage, recursive redaction, metrics families and six-section dashboard provisioning |

### Deterministic policy — 25

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 25 | `policy/test_policy_engine.py` | Paired allow/deny evidence for all 13 rules, complete non-short-circuit results, exact time boundaries, multi-denial and property tests |

### Recovery, provider and AI boundary — 92

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 1 | `recovery/test_m4_release_gate.py` | Literal qualified-v4 detect → no-model brief → plan → approve → execute → complete audit path |
| 18 | `recovery/test_m6_incident_analyst.py` | Snapshot allowlist, prompt injection exclusion, strict schema, repair limit, timeout/refusal/error fallback, grounding and provenance |
| 19 | `recovery/test_razorpay_adapter.py` | Test-key-only request, notification suppression, redirect/clock/HTTP/transport behavior and exact-reference lookup |
| 10 | `recovery/test_test_mode_demo.py` | Human-gated prepare/execute/reconcile command, credential CSV boundary and sanitized receipt |
| 44 | `recovery/test_workflow.py` | Authoritative preview, idempotency, approval/rejection, token races, fresh policy, fake/Test Mode execution, ambiguity and audit APIs |

Critical individual recovery cases include:

- complete immutable and idempotent authoritative preview;
- idempotency-key rebinding rejection;
- denied preview cannot be approved;
- bearer returned once and only a keyed digest persisted;
- rejection is token-free, terminal and idempotent;
- approval binding, exact expiry and atomic single-use;
- concurrent preview/approval/execute races with one durable winner;
- missing migration, inconsistent evidence and forged detector identity fail
  closed;
- model-unavailable rules path completes through an audited receipt;
- execution revalidates already-recovered, attempt, cooldown, expiry and kill
  switch facts before a provider call;
- known provider failure produces a typed terminal receipt;
- timeout after upstream creation reconciles without a second create; and
- action audit reconstruction is read-only and detects missing evidence.

### Security — 30

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 16 | `security/test_dependency_audit.py` | Python/web audit command behavior, severity thresholds and fail-closed parsing |
| 6 | `security/test_pre_push.py` | Authenticated history scan, hook installation and bounded failure modes |
| 8 | `security/test_repository_scan.py` | Credential/PII patterns, narrow reviewed exclusions and immutable image policy |

### API, configuration and operational foundation — 62

| Nodes | Test file | Primary coverage |
| ---: | --- | --- |
| 15 | `test_config.py` | Environment parsing, secret masking, Test-vs-Live rejection and production fail-closed rules |
| 7 | `test_event_contract.py` | Normalized event parsing, allowlist and cross-field invariants |
| 6 | `test_health.py` | Live/readiness state, migration head, W3C/security headers and resource disposal |
| 21 | `test_operational_clis.py` | Seed/replay/detect/worker entry points, bounded error text and exit codes |
| 11 | `test_webhook_signatures.py` | Exact-byte HMAC, malformed headers, modified bodies and constant-time validation |
| 2 | `test_worker.py` | Worker configuration, redacted metrics and graceful shutdown |

## Frontend inventory — all 13 Vitest tests

| Test | What it verifies |
| --- | --- |
| `shows the honest empty overview and healthy API state` | Real empty state, synthetic label and readiness identity |
| `shows a useful failure state when the local API is unavailable` | No stale metric is shown as current; bounded retry is visible |
| `preserves a typed server reason without exposing response details` | Safe typed API error mapping |
| `falls back to the HTTP status when an error body is untrusted` | Malformed/untrusted response content is not rendered |
| `performs lookup-only reconciliation with encoded identifiers and no approval token` | Correct safe request shape for ambiguity |
| `creates collision-resistant operation keys without retaining secrets` | Client idempotency helper does not persist authority |
| `completes evidence, fallback, approval, execution, impact and demo views` | Complete successful product story |
| `closes and clears a merchant session without persisting secrets` | Browser-memory-only authorization boundary |
| `fails closed when authoritative policy denies a Razorpay Test Mode preview` | Denied policy blocks approval/execution UI |
| `supports a keyboard rejection without issuing an execution token` | Accessible rejection and absence of execute authority |
| `invalidates the in-memory approval bearer when the merchant locks the session` | One-time bearer does not survive lock |
| `reconciles an ambiguous provider timeout by lookup only` | No create retry is offered or sent |
| `retains ordinary theme keys while dropping prototype override keys` | Razorpay Blade compatibility adapter resists unsafe merge keys |

## Browser inventory — all 3 Chromium scenarios

| Scenario | What it verifies |
| --- | --- |
| Foundation shell while API is offline | Application remains accessible, synthetic scope remains visible and offline state is honest |
| Primary evidence-to-impact story | Overview → incident → fallback brief → preview → 13 rules → keyboard approval → fake execution → audit → impact → demo |
| Keyboard rejection story | Merchant can reject with Enter and no execute request is emitted |

The browser suite uses deterministic synthetic API interception for repeatable
UI state coverage. It is not presented as proof of the backend; backend
integration and provider behavior have independent tests and receipts.

## Mandatory failure matrix

`make failure-matrix` verifies the committed analyst report and 12 selected
pytest cases covering 17 required failure conditions. Some parameterized or
multi-condition tests cover more than one matrix row.

| Failure | Required outcome |
| --- | --- |
| Invalid webhook signature | Rejected before persistence |
| Duplicate event ID | One event/outbox chain |
| Out-of-order events | Projection cannot regress |
| Worker crash | Expired lease is safely reclaimed |
| Detector low sample / hard negative | No action eligibility |
| Conflicting root-cause evidence | Abstain with bounded uncertainty |
| Unknown/ungrounded model evidence | Reject provider result |
| Model timeout or refusal | Rules fallback; no raw body retained |
| Malformed model output | One bounded repair, then fallback |
| Policy changes after preview | Fresh deny and zero provider calls |
| Already-recovered payment | Stop before provider call |
| Approval token reused | One atomic consumption winner |
| Plan/approval expires | Replayable typed terminal result; no provider call |
| Kill switch enabled | Full policy denial and no mutation |
| Payment Link timeout after success | GET by reference; no second POST |
| Duplicate execute | Same durable action; one provider call |
| Incomplete audit | Verifier reports the exact missing evidence |

The source mapping is in `docs/M8_RELEASE_HARDENING.md` and the executable
selection is in the `failure-matrix` Make target.

## Evaluation evidence is not counted as pytest

| Evaluation | Cases / rows | Purpose |
| --- | ---: | --- |
| Detector v4 official blind | 5,760 attempts; 10,676 normalized events | Frozen unseen-batch precision, recall, delay, attribution and safety |
| Detector v4 adversarial | 15 cases | Hierarchy, overlap, lifecycle and strict report edge cases |
| Recovery experiment | 280 eligible payments | Treatment/control value and recovery-rate impact with uncertainty |
| M6 analyst bakeoff | 24 cases × 3 models = 72 evaluations | Grounding, abstention, privacy, injection, scope, trajectory and schema |

These artifacts are checked for source identity, arithmetic, schema and
selection-rule integrity by `make eval`. They are not multiplied into the 514
pytest count.

## Real external evidence is not a test-count multiplier

The one human-approved Razorpay Test Mode Payment Link is recorded in
`evals/reports/razorpay_test_mode_receipt.v1.json`. It verifies that the real
API boundary authenticated, accepted one create and safely recovered an
ambiguous local completion state through one GET by the stable reference.

It is one deliberately bounded external integration proof—not 224 real
actions, live money, a load test or merchant-performance evidence.

## Commands

```bash
make lint                  # Ruff + ESLint
make typecheck             # strict mypy + TypeScript
make test                  # backend and frontend coverage
make test-contract         # schemas, fixtures and deterministic identities
make test-e2e              # all Chromium stories
make build                 # production web build + bundle budgets
make eval                  # every frozen detector/experiment/model check
make security-check        # static, secret and dependency checks
make observability-check   # trace, redaction, metrics and dashboards
make failure-matrix        # selected mandatory failure cases
make m8-check              # M8 consolidated gate
make check                 # every implemented release gate
```

`make check` is intentionally comprehensive and takes materially longer than a
smoke test. The exact subcommands are visible in the root `Makefile`. On a
Windows host without GNU Make, those `uv` and `pnpm` commands can be run
directly; availability of individual commands must be reported honestly.

## Evidence interpretation rules

1. A passing local test proves the tested working tree, not the remote branch.
2. A passing CI run proves only its exact commit.
3. A synthetic evaluation proves performance only on that versioned benchmark.
4. Test Mode proves integration behavior without live money.
5. Historical milestone counts are snapshots, not totals to add together.
6. Parameterized pytest nodes are counted as collected cases; frontend test
   counts come from the relevant runner.
7. No skipped, unimplemented or pretend command is described as passing.
8. A changed README/UI still requires its relevant lint, type, unit, build and
   browser checks before the new commit can be called release-ready.
