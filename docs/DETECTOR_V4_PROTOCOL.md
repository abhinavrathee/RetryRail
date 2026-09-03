# Detector v4 hierarchy and report-contract remediation protocol

## Current status

M3R.5 phases R5.1 through R5.3 are complete. The failure analysis, development
evidence boundary, allowed change class, unchanged targets, report contract and
fresh-run procedure were precommitted before the separately versioned v4
candidate was implemented. That candidate now passes every unchanged target
on all three allowed development partitions and passes the strict open-report
round-trip preflight. Fifteen adversarial cases pass, and the candidate plus
append-only runner are frozen. It is not release-qualified, and no fresh
official nonce or blind run exists. Detector v2 and v3 remain immutable failed
predecessors, M4 remains blocked, and every output remains action-ineligible.

The machine-readable boundary is
`evals/protocols/detector_v4.protocol.json`. The
`retryrail-v4-protocol --check` command reconstructs it from hash-bound v2 and
v3 evidence and fails on drift.

## Why v4 exists

Detector v3 passed all unchanged targets on its two development partitions,
then failed its one official synthetic blind run in two independent ways:

| Measure | Required | V3 observed | Result |
| --- | ---: | ---: | --- |
| Precision | >= 900,000 ppm | 833,333 ppm | Fail |
| Recall | >= 850,000 ppm | 833,333 ppm | Fail |
| Report strict reload | Valid | Missing required nullable field | Fail |

The metric result was 5 true positives, 1 false positive and 1 false negative.
The frozen writer also omitted `incidents[5].resolved_at` for an open incident.
That field is nullable but required by the frozen report model. The append-only
run is therefore both release-blocked and procedurally invalid; it cannot be
edited, repaired or rerun.

## Reproduced hierarchy failure

The false negative and false positive are two outcomes of the same hierarchy
lifecycle defect, not two threshold misses that may be tuned independently:

- The missed truth case was a netbanking / `issuer_synthetic_gamma`
  degradation with 29 attempts and 20 failures between 08:00 and 10:50 UTC.
- Evaluating that exact child cohort under the frozen v3 gates produced nine
  independent passing steps from 08:15 through 09:10 UTC.
- V3 keyed active candidate state and cooldown only by payment method. At
  08:15 it selected a broad netbanking parent candidate instead of retaining
  the passing child in parallel. The parent was suppressed at 08:25 and its
  method-wide cooldown continued to block the child while it was passing.
- A later broad netbanking candidate opened at 10:30, confirmed at 11:00, and
  became unmatched incident `inc_01ebb86d73b3f7d17df502a3`. The exact matcher
  correctly refused to count a method-wide prediction as an issuer-specific
  match.
- The official report's missed-case gate reason reflects its endpoint
  diagnostic. It does not erase the earlier passing child evaluations exposed
  by deterministic replay.

The replay used the committed public v3 nonce, unchanged generator, frozen v3
configuration and label-free normalized events. Scenario truth was used only
after prediction to identify the missed cohort and cannot enter v4 runtime
selection.

## Frozen development boundary

Only these three already-revealed synthetic partitions may influence v4:

1. `detector_v2_development_v1`;
2. `detector_v2_official_blind_ef49a16703b1612ef774`, now development evidence;
3. `detector_v3_official_blind_1a1852634945b54e300a`, now blocked/invalid
   development evidence.

Each partition is bound to exact manifests, predictions, reports, decisions,
receipts or public-reveal digests in the machine protocol. None is blind again.
Development reports derived from these partitions are not additional
independent datasets.

The benchmark remains `detector_v2_generator_v1_0_0` with bundle SHA-256
`a91e12e9945dd9cab9252dbd6f345e99fd52229505baf10a9aafc5dae511a9b9`.
Its distribution is not changed after either failed run. R5.2 must pass every
target on all three partitions separately; an aggregate pass cannot conceal a
partition failure.

## Allowed candidate change class

R5.2 may make one structural hierarchy-lifecycle correction within these
boundaries:

- Candidate state is keyed by the canonical cohort, not only payment method.
- A method parent and each eligible method/issuer child are observed
  independently. Parent state, resolution and cooldown cannot starve a child.
- Scope arbitration is deterministic and label-free. It may use only the same
  event-time evidence available to the detector, including confirmed breadth
  and attribution across sibling cohorts.
- One overlapping method episode emits at most one incident. Every other
  passing candidate receives an explicit, durable audit disposition.
- The existing minimum-sample, provider-actionability, rate-drop, confidence,
  excess-failure, business-impact and confirmation gates remain. Lowering a
  core gate requires a new protocol rather than being hidden inside R5.2.
- The guarded frozen baseline, non-overlap rule, hard-negative suppression and
  evidence reconciliation remain mandatory.
- Matcher semantics stay exact. A broad method prediction cannot be relabelled
  as an issuer-specific true positive to improve a score.
- Runtime prediction cannot receive scenario labels, truth membership or an
  LLM decision. Every output remains `runtime_action_eligible=false`.

This boundary deliberately precommits the safety properties rather than a
scenario-specific formula. The final deterministic arbitration formula and
configuration must be developed only on the three allowed partitions and then
frozen before any fresh nonce is created.

## Report-contract remediation

The v4 report path must prove all of the following before it is eligible for a
runner freeze:

1. required nullable fields are emitted even when their value is `null`;
2. an open-incident fixture exercises `resolved_at=null`;
3. written bytes strictly reload into the report model;
4. canonicalizing the reloaded model reproduces the exact written bytes;
5. this preflight runs before nonce creation and again in the blind runner;
6. no v3 artifact is changed to make the historical failure disappear.

A serialization failure after nonce creation consumes that run slot and forces
a blocked decision, even if its in-memory metrics would otherwise pass.

## Staged delivery

| Phase | Work | Status |
| --- | --- | --- |
| R5.1 | Bind failure analysis, evidence, change envelope, report contract and release rules | Complete |
| R5.2 | Implement and tune one separately versioned candidate on all three partitions | Complete |
| R5.3 | Add adversarial cases and freeze candidate, matcher, evaluator, contracts and runner | Complete |
| R5.4 | Create one fresh public nonce; persist/replay predictions; authorize truth once | Pending |
| R5.5 | Preserve the result and run all repository, security and remote release gates | Pending |

Development and adversarial success are not release claims. R5.3 creates no
nonce. R5.4 gets one append-only official slot only after the complete freeze
is committed, pushed and remotely verified.

## R5.2 development result

Detector `detector_v4_0_0` uses canonical-cohort state and deterministic
confirmed-child-breadth arbitration. The original v2 development partition,
revealed v2 official partition and revealed v3 official partition each record
6 true positives, 0 false positives, 0 false negatives and 1,000,000 ppm
top-1 attribution. Their median first-signal delays are 600, 600 and 450
seconds. Every partition has zero hard-negative incidents, baseline-leakage
violations and evidence-reconciliation violations.

The third report contains one open incident with an explicit
`resolved_at=null`; every prediction and report strictly reloads and
canonicalizes to its exact bytes. These are revealed synthetic development
results only. The candidate remains unfrozen and action-ineligible. See
`DETECTOR_V4_CANDIDATE.md` and `evals/reports/detector_v4.development.json`.

## R5.3 adversarial and freeze result

`evals/reports/detector_v4.adversarial.json` contains 15 deterministic passing
cases. They cover the guarded/frozen baseline, invalid time and configuration
inputs, out-of-order events, canonical child lifecycle isolation, both scope
arbitration branches, overlap uniqueness, arbitration reconciliation, hard
negatives, evidence reconciliation, label isolation, strict nullable report
serialization and the pre-nonce action boundary.

`evals/golden/detector_v4.freeze.json` binds the exact protocol, generator,
configuration, candidate/matcher/evaluator/contract sources, all seven
development artifacts and the adversarial report. The separate
`evals/golden/detector_v4.blind_procedure.freeze.json` binds that candidate
freeze to the append-only runner and its strict evidence contracts. Runner
tests cover create-only paths, exclusive stages, replay refusal, known-nonce
rejection, byte tampering, prediction/truth isolation, redacted terminal
failure and report-contract failure after truth authorization. A completion
receipt is impossible unless persisted report bytes strictly reload and
canonicalize identically. Once a completed run publishes its nonce, the frozen
reproducer can restore only the two git-ignored deterministic input artifacts,
verify their receipt-bound bytes and refuse any mismatched existing file.

## Fresh-run rules

The future v4 blind procedure must:

1. accept one new 16–256 character public, non-secret nonce only after freeze;
2. reject both consumed official nonces and all committed v2/v3 test nonces;
3. expose no nonce CLI argument and persist only its digest before generation;
4. generate label-free normalized events without loading truth;
5. persist and re-read canonical prediction bytes;
6. independently reproduce those exact bytes before truth authorization;
7. durably authorize truth access, then load truth exactly once;
8. validate strict report reload and byte round-trip before completion;
9. use create-only, repository-confined, append-only evidence paths;
10. keep every failed or invalid result permanently action-ineligible.

The R5.1 protocol and R5.3 freeze explicitly record that no fresh v4 nonce
digest or run identity exists. R5.2 and R5.3 create neither.

## Unchanged release targets

- precision at least 900,000 ppm;
- recall at least 850,000 ppm;
- top-1 attribution at least 800,000 ppm;
- median simulated first-signal delay at most 600 seconds;
- zero action-eligible hard-negative incidents;
- zero baseline-leakage violations;
- zero evidence-reconciliation violations.

These are synthetic benchmark targets, not production-performance claims. A
qualified v4 result would still require M4 deterministic policy and external
merchant approval before any recovery action.

## R5.1 through R5.3 verification

```bash
uv run retryrail-v4-protocol --check
uv run retryrail-v4-candidate --check
uv run retryrail-v4-adversarial --check
uv run retryrail-v4-freeze --check
uv run retryrail-v4-blind-reproduce
uv run retryrail-v4-blind --check
uv run pytest services/api/tests/detection/test_v4_protocol.py
uv run pytest services/api/tests/detection/test_v4_candidate.py
uv run pytest services/api/tests/detection/test_v4_freeze.py
uv run pytest services/api/tests/detection/test_v4_blind.py
make v4-protocol-check
make v4-candidate-check
make v4-adversarial-check
make v4-freeze-check
make v4-blind-check
```

The protocol tests cover artifact drift, exact v3 metrics and case identities,
hierarchy shape and timeline, development-role isolation, unchanged targets,
matcher and gate constraints, consumed/test nonce denylisting and absence of
fresh v4 nonce state. Candidate tests cover independent cohort lifecycle,
overlap dispositions, all three partition scores, label-free prediction,
required-nullable output, strict reload, canonical byte reproduction, artifact
drift and fail-closed writes. R5.3 tests add hierarchy/overlap evidence,
candidate and runner source freezes, nonce absence, path confinement,
prediction-first ordering, tamper and concurrency handling, append-only
terminal states and report-contract failure behavior.
