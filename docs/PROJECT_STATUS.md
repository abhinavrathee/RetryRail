# RetryRail project status and next-chat handoff

**Last verified:** September 5, 2026

**Current delivery boundary:** M4 complete; M5 code and synthetic measurement complete; one human-approved Test Mode receipt remains

**Runtime recovery:** deterministic fake or human-approved Razorpay Test Mode for exact qualified synthetic v4 incidents; Razorpay Live Mode rejected

This file is the durable handoff for a new project chat. Read `AGENTS.md`,
`docs/PRODUCT_REQUIREMENTS.md`, `docs/BUILD_PLAN.md`, and then this file before
changing the repository. The requirements and build plan remain authoritative;
this document records the verified implementation boundary.

## What is complete

| Milestone | Verified outcome |
| --- | --- |
| M0 | Repository skeleton, locked Python/web environments, Compose stack, health endpoints, Blade shell and five-job CI |
| M1 | Versioned event/domain contracts, sanitized fixtures, deterministic synthetic truth data and manifest checks |
| M2 | Raw-body webhook authentication, immutable event log, merchant/event deduplication, transactional outbox, bounded worker retry/dead-letter behavior, monotonic projection, replay and metrics |
| M3 | Rolling detector aggregates, guarded baselines, business/statistical gates, incident lifecycle, evidence reconciliation, attribution and frozen evaluation; detector v1 honestly failed release targets |
| M3R / detector v2 | Append-only blind procedure completed; 6 TP / 0 FP / 0 FN, but blocked by 900-second median delay and two baseline-leakage violations |
| M3R.4 / detector v3 | Separate guarded-baseline candidate and blind run preserved; 5 TP / 1 FP / 1 FN and a required-nullable report defect make the result blocked and procedurally invalid |
| R5.1 | V4 failure analysis, evidence boundary, allowed change class, unchanged targets and strict report contract precommitted |
| R5.2 | `detector_v4_0_0` passes all three revealed development partitions independently and reproduces nullable reports byte-for-byte |
| R5.3 | Fifteen adversarial cases pass; candidate, configuration, matcher, evaluator, contracts and append-only runner are frozen |
| R5.4 | Official synthetic blind run `detector_v4_official_blind_5497598109b06d21c625` records 6 TP / 0 FP / 0 FN and passes every unchanged target |
| R5.5 | Append-only preservation, full local and remote-clone suites, security scans, immutable container builds, runtime smoke checks and five remote CI jobs pass |
| M4.1 | Recovery template, policy result, approval record and recovery action contracts are frozen with explicit side effects, actor authority, pre-/post-approval expiry paths, lifecycle invariants and a documented threat boundary; a fail-closed fingerprint gate preserves both frozen M1 recovery schemas byte-for-byte |
| M4.2 | Pure `deterministic_policy_v1_0_0` evaluator implements all 13 rules with complete machine-readable reasons, fail-closed version/time boundaries and content-addressed result identity; it adds no I/O or mutation authority |
| M4.3 | Authenticated, server-owned plan preview and merchant approve/reject workflow persists canonical source evidence, plans and policy decisions append-only; approval bearers are short-lived, single-use, returned once and stored only as a keyed digest; this milestone intentionally introduced no execute route |
| M4.4 | Fresh execution-stage policy, atomic approval consumption, immutable execute-once actions/transitions, exact replay, lookup-only ambiguity reconciliation and a typed synthetic-only fake Payment Link adapter |
| M4.5 | Verified-citation rules brief, no-model plan fallback, complete action-audit verifier and exact hash-bound activation of the qualified v4 detector without altering frozen evidence |
| M5 provider edge | Test-key-only Standard Payment Link adapter, immutable pre-network dispatch and sanitized provider receipts, no-create replay, lookup-only crash/timeout reconciliation and an exact interactive human gate for the one reviewer action |
| M5 measurement | Remotely frozen 224/56 stratified assignment over all 280 eligible blind-batch rows, same-payment outcome attribution, gross/natural/incremental/net value separation, deterministic 10,000-replicate uncertainty and an authenticated hash-bound report API |

The v4 figures are synthetic benchmark evidence, not production-performance
claims. Detector v2 and v3 artifacts are immutable historical failures and must
not be repaired or represented as blind again.

## Verified R5.5 snapshot

The release-gate implementation commit is
`2dd6cc0bb5f58bedd1fa48eee7bef163d81ea5a3`. It pins Python 3.12.11, Node
22.23.2 and PostgreSQL 16.15 container manifests by SHA-256 and makes the local
security scanner reject mutable external images.

- Hardened working-tree `make check`: 327 Python tests, 85.66% branch-aware
  coverage, three web tests, 31 contract tests, production build/budget,
  Chromium smoke, every frozen evaluation, and all security audits passed.
- Fresh clone of the exact remote commit: `make bootstrap` and `make check`
  passed with 327 Python tests and 85.63% coverage. V2 and v4 each reconstructed
  two absent ignored inputs; v3 derived two absent inputs in memory.
- Isolated Compose runtime: PostgreSQL became healthy, migration
  `0002_m3_detection_incidents` applied, API live/readiness and web checks
  returned HTTP 200, worker metrics returned HTTP 200, and application
  containers ran as UID 10001.
- GitGuardian workspace/API was healthy. Full history and outgoing-commit scans
  found no secret. Only the two exact previously reviewed synthetic receipt
  values are narrowly ignored; no new exclusion exists.
- [GitHub Actions run 30](https://github.com/abhinavrathee/RetryRail/actions/runs/33869599558)
  passed Python, web, Chromium, security and container jobs on the exact commit.

See `docs/DETECTOR_V4_PROTOCOL.md` for the full R5.5 evidence narrative.

## Verified M4.1 snapshot

- Four additive JSON Schemas bring the generated contract catalog to 14; the
  existing M1 `recovery_plan.v1` and `action_receipt.v1` schemas are unchanged,
  and the exporter now rejects any future in-place source drift against their
  pinned canonical SHA-256 values.
- Thirty-seven focused M4.1 cases cover allow/deny completeness, canonical
  policy ordering, approval lifecycle misuse, actor authority, both safe expiry
  paths, side-effect consistency, typed failures and ambiguous-result retry
  safety. The new recovery-contract module has 100% statement/branch coverage.
- The complete backend suite passes with 365 tests and 86.18% branch-aware
  coverage. All 69 contract tests, Python/web lint and type checks, contract and
  data reproducibility checks, frontend tests, production build/budget,
  Chromium smoke, frozen evaluations, Bandit, dependency audits and the
  repository secret scanner pass.
- GNU Make is unavailable on the current Windows host, so the individual
  commands behind the implemented Make targets were run directly; no Make
  wrapper is represented as having passed.
- ADR-0007 records the contract-only boundary, exact policy-rule set, state
  transitions, threat analysis and deferred runtime responsibilities.

## Verified M4.2 snapshot

- All 13 policy rules have paired allow/deny evidence, and evaluation continues
  after a denial so the result always carries the complete reason set.
- Exact cooldown/expiry boundaries, required-contact consent, multi-denial,
  preview/execution identity, unknown-version and non-UTC rejection are tested.
- Property tests cover integer-subunit equality, attempt-cap arithmetic and
  cooldown arithmetic across generated inputs.
- Twenty-five focused cases pass with 100% statement/branch coverage for the
  policy package. `docs/POLICY.md` records the executable truth table and trust
  boundary.
- The exact working tree passes 390 backend tests with 86.26% branch-aware
  coverage, including all 94 contract-plus-policy tests. Python/web lint and
  type checks, deterministic data checks, frontend tests and production bundle,
  Chromium smoke, every frozen evaluation, Bandit, Python/web dependency audits
  and the repository secret scanner all pass.

## Verified M4.3 snapshot

- Four authenticated routes accept only incident, payment and idempotency
  identities from the caller. Merchant, actor, money, policy, consent,
  eligibility, retry and kill-switch facts are assembled from locked
  server-owned records and configuration; attempted client fact injection is
  rejected.
- Migration `0003_m4_preview_approval` creates recovery controls plus immutable
  plan, preview-policy, approval-decision and token-consumption evidence. Exact
  request and document digests detect idempotency rebinding and stored-content
  drift.
- Approval bearers contain 256 random bits, expire no later than both the
  configured 15-minute cap and plan expiry, are returned only on the first
  response, and persist only as HMAC-SHA-256 under a separate key. Atomic
  consumption has one database-enforced winner and does not have an HTTP route
  until it can be coupled to M4.4 action receipts.
- Twenty-two focused recovery workflow cases cover authentication, complete
  provenance, every material fail-closed path, immutable evidence, replay and
  rebinding, token non-disclosure, malformed/unknown/mismatched/expired/reused
  tokens, exact expiry, concurrent preview/decision/consumption, stale-read
  idempotency races and the absence of an execute route.
- The exact working tree passes 415 backend tests with 86.53% branch-aware
  coverage and 69 contract tests. Python/web lint and type checks, three web
  tests, the production bundle budget, Chromium smoke, all deterministic data
  and frozen evaluation checks, Bandit, dependency audits and the repository
  secret scan pass.
- An isolated PostgreSQL 16.15 instance passes full migration upgrade,
  metadata schema comparison, downgrade to base, re-upgrade to
  `0003_m4_preview_approval`, and inspection of all five M4.3 tables and four
  immutable-evidence triggers. Alembic now selects a Psycopg-compatible event
  loop on Windows, so the normal migration CLI performs that verification.
  Three focused workflow race cases also pass against PostgreSQL.
- At the M4.3 verification point, GNU Make and Docker Compose were unavailable
  on the Windows host, so the individual commands behind every implemented Make
  gate and an isolated PostgreSQL service were used; neither unavailable wrapper
  was represented as having passed in that historical snapshot.

## Verified M4.4–M4.5 snapshot

- Seven authenticated recovery routes now cover grounded rules analysis, plan
  creation/read-back, approve/reject, execute and lookup-only reconciliation.
  Strict request models accept identities and idempotency keys only; all money,
  detector, policy, consent, notification and provider facts remain server-owned.
- Migration `0004_m4_action_execution` adds execution policy, actions,
  transitions and reconciliation receipts. Migration
  `0005_m4_rules_fallback` adds content-addressed rules briefs. PostgreSQL
  upgrade, schema comparison, full downgrade/re-upgrade and all four new
  immutable-trigger inspections pass at head `0005_m4_rules_fallback`.
- The additive activation gate verifies the exact qualified v4 candidate,
  official blind report and release digests. The frozen v4 artifacts and both
  frozen M1 recovery schemas remain byte-for-byte unchanged; failed historical
  detector identities and forged v4 hashes are denied.
- The deterministic fake covers success, typed provider failures, timeout before
  creation, timeout after creation, exact replay, rebinding, expiry and
  lookup-only reconciliation. Approval consumption, action creation, initial
  transitions and attempt-control advancement are atomic.
- Forty-two focused recovery cases pass, including the literal qualified-v4
  detect -> no-model analyze -> plan -> approve -> fake execute -> receipt ->
  complete-audit path. Three lock/idempotency races also pass against PostgreSQL
  on Windows after selecting Psycopg's compatible selector event loop.
- The complete backend regression passes 440 tests with 86.27% branch-aware
  coverage. Ruff, mypy over 124 source files, 69 contract tests, 14-schema drift,
  truth-data reproducibility, every frozen detector/evaluation gate, Bandit,
  repository secret scanning and Python/web dependency audits pass.
- The web passes lint, strict type checking, three unit tests, production build
  and bundle budgets (145,621-byte entry, 750,224-byte Blade chunk, 895,845-byte
  total JavaScript), plus the Chromium smoke test.
- A clean wheel extracted outside the checkout loads the packaged qualified-v4
  activation and detector configuration. An isolated Compose build starts the
  API, worker, PostgreSQL and web successfully as UID 10001; migration reaches
  `0005`, all health/metrics/web probes return HTTP 200, and the packaged
  activation loads inside the API container. Only the isolated containers,
  network and disposable volume were removed afterward.
- GNU Make is unavailable on this Windows host, so every implemented command
  behind `make check` was run directly. Standalone Docker Compose v5.1.3 was
  available for the isolated runtime verification.

## M5 implementation checkpoint

- M4 was reviewed and secured in commit `d16e802`; the full local release gate
  passed before that commit was pushed to `origin/main`.
- Commit `191ec3f` was then pushed with the real Test Mode adapter, migration
  `0006_m5_provider_dispatch`, crash-safe execution coordinator, provider tests,
  protocol and complete assignment freeze. It contains no outcome artifact and
  records `outcomes_observed=false`.
- The later official synthetic stage covers all 280 eligible failed incident
  payments: 224 treatment and 56 control. It records 116 versus 7 recoveries,
  39.29 percentage points of recovery-rate uplift, ₹120,912 incremental recovered
  GMV and ₹120,140 net value after modeled costs.
- The 95% deterministic-bootstrap interval for incremental recovered GMV is
  ₹44,447–₹189,391, so the precommitted conclusion is statistically positive.
  These are synthetic benchmark results, not live merchant performance or
  Razorpay pricing.
- The result API validates the exact report SHA-256 before startup and exposes
  the typed report only behind merchant authentication. Gross treatment recovery
  (₹200,884) remains a different field from incremental recovery.
- The supplied Test Mode credential pair authenticated with a read-only Razorpay
  list request. Its values remain only in the downloaded CSV outside Git and
  were never printed, logged or copied into repository configuration.
- The final POST is deliberately not model-authorized. A prepared disposable
  database and exact terminal phrase must be reviewed by the human merchant
  operator; until that happens, no Test Mode Payment Link or external receipt is
  claimed.
- The exact backend release command passes 475 tests with 85.24% branch-aware
  coverage. Ruff, mypy over 135 source files, 69 contract tests, all 19 schema
  drift checks, the M1/v2/v3/v4 data and evaluation gates, both M5 experiment
  stages, Bandit, repository secret scanning and both dependency audits pass.
- The web passes lint, strict type checking, three covered unit tests, production
  build/budget (145,621-byte entry, 750,224-byte Blade chunk, 895,845-byte total)
  and Chromium end-to-end.
- A clean wheel contains and loads the exact activated M5 report outside the
  source checkout. An isolated Compose build reaches migration
  `0006_m5_provider_dispatch`, creates both provider tables and all four
  update/delete protection triggers, and runs API/worker as UID 10001. API,
  worker and web health pass; anonymous experiment access returns 401 and the
  authenticated packaged endpoint returns the expected 280-row synthetic
  report. The isolated containers, network and disposable volume were removed.

## Safety boundary that must remain true

- Frozen detector artifacts retain their historical
  `runtime_action_eligible=false` values. Only the separate activation gate for
  the exact qualified v4 release can make an open synthetic runtime incident
  action-eligible; v1–v3 and forged v4 identities remain blocked.
- M4 execution targets only the injected deterministic fake. It accepts no
  contact data or Razorpay credential, forces notifications off and labels the
  outcome `simulated_external_mutation`.
- M5 can replace that provider edge only with a Test-key-only adapter after the
  same fresh policy and single-use approval chain. The dispatch commits before
  network I/O; credentials and raw responses are never persistent fields.
- M4.1 contracts describe the full boundary but grant no provider authority.
- M4.2 evaluates supplied internal facts but performs no I/O and cannot approve,
  persist or execute an action.
- M4.4 must re-evaluate policy immediately before every fake mutation, consume
  approval once with an immutable action receipt and reconcile ambiguity by
  reference lookup only—never blind create retry.
- M4.5 rules analysis can explain verified evidence and propose only the frozen
  review-first template; it cannot detect, approve or execute.
- No LLM may decide whether degradation occurred or cross a mutation boundary.
- No v4 threshold, candidate, blind artifact, receipt or decision may be tuned
  or rewritten after the nonce reveal.
- No credential is needed for M4. Razorpay Test Mode credentials first become
  relevant in M5 and must stay outside Git, logs, prompts, fixtures and media.
- The GitHub repository is currently private. Public visibility and signed-out
  verification are deliberate M9 submission actions, not assumptions.

## Start here next: close the M5 external gate

The provider and measurement work is implemented. Prepare one fresh disposable
demo database, show its exact synthetic amount/reference/expiry to the merchant
operator, and let that human type the plan-specific approval phrase in an
interactive terminal. Commit only the generated sanitized receipt after its
provider lookup, complete audit, schema, security scan and full release gates
pass. Never retry the create; an interruption resumes through `reconcile`.

## What remains after the M5 implementation checkpoint

- M5: one human-approved Razorpay Test Mode link, committed sanitized receipt,
  and final full-gate verification of that external evidence.
- M6: bounded AI analyst, redacted inputs, deterministic fallback and agent
  golden/adversarial evaluations.
- M7: merchant UI and complete browser story.
- M8: observability, security and final release hardening.
- M9: public repository, tag, video, signed-out link checks and submission.
