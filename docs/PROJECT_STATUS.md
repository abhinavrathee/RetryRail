# RetryRail project status and next-chat handoff

**Last verified:** September 4, 2026

**Current delivery boundary:** M3R.5 / R5.5 complete; M4 is next

**Runtime recovery:** disabled

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

## Safety boundary that must remain true

- Every detector output remains `runtime_action_eligible=false`.
- There is no Razorpay action adapter, approval token or recovery endpoint yet.
- No LLM may decide whether degradation occurred or cross a mutation boundary.
- No v4 threshold, candidate, blind artifact, receipt or decision may be tuned
  or rewritten after the nonce reveal.
- No credential is needed for M4. Razorpay Test Mode credentials first become
  relevant in M5 and must stay outside Git, logs, prompts, fixtures and media.
- The GitHub repository is currently private. Public visibility and signed-out
  verification are deliberate M9 submission actions, not assumptions.

## Start here next: M4

M4 is the deterministic policy engine and safe recovery path. Implement it in
small sequential review gates; do not start M5 until all M4 exit criteria pass:

1. **M4.1:** freeze typed recovery-template, plan, policy-result, approval and
   action contracts plus their side effects and threat model.
2. **M4.2:** implement `ANALYZE_ONLY` and `REVIEW_FIRST` policy evaluation with
   amount, currency, consent, opt-out, attempt, cooldown, expiry and kill-switch
   gates.
3. **M4.3:** implement plan preview and hashed, short-lived, single-use approval
   tokens; approval must occur outside the model.
4. **M4.4:** implement the append-only action state machine, idempotency
   receipts and a deterministic fake Razorpay adapter for integration/failure
   testing.
5. **M4.5:** add the rules-based incident brief/plan fallback and run the
   complete M4 allow/deny, misuse, retry, expiry, concurrency and audit matrix.

M4 exits only when detect -> plan -> approve -> execute -> receipt passes with
the model unavailable, every policy rule has allow and deny tests, approval
token misuse is rejected, and API tests prove zero unapproved mutations.

## What remains after M4

- M5: Razorpay Test Mode adapter, timeout reconciliation, treatment/control and
  incremental recovered-GMV measurement.
- M6: bounded AI analyst, redacted inputs, deterministic fallback and agent
  golden/adversarial evaluations.
- M7: merchant UI and complete browser story.
- M8: observability, security and final release hardening.
- M9: public repository, tag, video, signed-out link checks and submission.
