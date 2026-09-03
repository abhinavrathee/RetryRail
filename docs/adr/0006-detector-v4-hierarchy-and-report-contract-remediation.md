# ADR 0006: Remediate hierarchy starvation and report serialization in v4

- Status: Accepted; R5.1–R5.3 complete, candidate and runner frozen
- Date: 2026-09-03

## Context

Detector v3's one official synthetic blind run failed precision and recall at
833,333 ppm each and produced report bytes that its frozen strict contract
cannot reload. The exact expected issuer cohort passed the v3 statistical and
business gates during deterministic replay, but v3 kept only one active state
and cooldown per payment method. A broad netbanking parent occupied that slot,
the child was not retained, and a later broad parent became the unmatched
false-positive incident. Separately, the report writer omitted a required
nullable field for an open incident.

Editing v3, accepting a parent prediction as an issuer match, weakening a gate,
or repairing and rerunning the consumed evidence would make the result look
better without demonstrating a safer detector.

## Decision

M3R.5 creates a separately versioned detector-v4 candidate. V2 and v3 remain
immutable. V4 may use exactly three revealed development partitions: the
original v2 development batch and the consumed v2 and v3 official batches.
All must pass the unchanged targets independently before freeze.

V4 candidate state includes the canonical cohort identity. Parent and child
candidates are observed independently. Confirmed same-method time intervals
form connected components; two or more confirmed child scopes select the
parent when present, otherwise the strongest child is selected using a stable
evidence-only ordering. At most one incident is emitted per component. A
parent state or cooldown cannot suppress child observation, and non-selected
passing candidates remain auditable. Core evidence gates, the guarded baseline
and exact matcher semantics are retained.

The report contract must also pass an open-incident required-nullable fixture,
strict reload and canonical byte round-trip before runner freeze. Only after
candidate, configuration, matcher, evaluator, contracts and runner are
committed and pushed may one fresh public, non-secret nonce be created.

## Consequences

The change addresses the observed state-machine failure without redefining
ground truth or making the benchmark easier. Parallel cohort observation costs
more deterministic computation and requires explicit overlap arbitration, but
it prevents one hierarchy level from silently starving another. Required
audit dispositions make deduplication decisions reviewable.

The third development partition is no longer blind and may overfit the known
failure, so it cannot qualify v4. Qualification still depends on a fresh
nonce-derived partition generated only after the complete freeze. Any metric,
contract or procedure failure consumes that run slot and remains append-only.
M4 stays blocked until a valid v4 release decision passes every target.

R5.2 demonstrates the decision on all three allowed revealed development
partitions and passes each unchanged target independently. It also proves the
null-preserving report reload and exact-byte round-trip with an actual open
incident. R5.3 then records 15 passing adversarial cases and binds candidate,
configuration, matcher, evaluator, contracts, development evidence and the
append-only runner into two nonce-free freezes. The runner boundary includes a
receipt-bound clean-checkout reproducer for git-ignored inputs after public
nonce reveal. This does not qualify the detector; one fresh R5.4 blind run is
still required.
