# Detector v4 development candidate

## Status and boundary

M3R.5 R5.2 through R5.4 are complete. Detector `detector_v4_0_0` passes all
unchanged release targets on each of the three development partitions allowed
by the precommitted v4 protocol. Those revealed synthetic development results
are not blind evidence. Its separately generated official synthetic blind run
also passes every unchanged target and is release-qualified for M4 integration
review.

The candidate, exact matcher/evaluator/contracts and append-only blind runner
were frozen before the official nonce existed. Fifteen deterministic
adversarial cases pass. Run
`detector_v4_official_blind_5497598109b06d21c625` is terminally complete and
append-only. The qualified decision does not authorize runtime recovery:
R5.5 remains pending and every output stays action-ineligible until M4's
deterministic policy and external approval boundaries exist.

## Lifecycle correction

V4 preserves the v3 statistical, business, confirmation, guarded-baseline,
resolution and diagnosis rules. It changes only hierarchy lifecycle and
overlap handling:

1. Every method and method/issuer candidate uses its complete canonical cohort
   as the state and cooldown key.
2. Parent and child cohorts are evaluated independently at each event-time
   step. A parent candidate, incident, resolution or cooldown cannot prevent a
   child from collecting evidence.
3. Every candidate freezes its own guarded, non-overlapping opening baseline.
4. Confirmed candidates are grouped into deterministic connected components
   when their same-method event-time intervals overlap.
5. A component with a confirmed parent and at least two distinct confirmed
   issuer children selects the parent as evidence of breadth. A component with
   one confirmed child selects that child. Otherwise, the strongest eligible
   scope is selected lexicographically by excess failures, at-risk GMV, unique
   confirmation evidence, confidence, opening time and canonical cohort key.
6. Exactly one incident is emitted per overlap component. Every confirmed
   loser receives a typed `V4ScopeArbitration` record; every unconfirmed
   passing candidate retains the existing typed suppression record.

The formula consumes only normalized events and candidate evidence available
at prediction time. Scenario identities, truth membership and LLM output are
not accepted by the runtime prediction boundary. Matcher version
`detector_v2_matcher_v1_0_0` remains unchanged.

## Development evidence

All targets are evaluated separately, so an aggregate score cannot hide a
failed partition.

| Development evidence | TP / FP / FN | Precision | Recall | Top-1 | Median first signal | Leakage / reconciliation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original v2 development batch | 6 / 0 / 0 | 1,000,000 ppm | 1,000,000 ppm | 1,000,000 ppm | 600 s | 0 / 0 |
| Revealed blocked v2 official batch | 6 / 0 / 0 | 1,000,000 ppm | 1,000,000 ppm | 1,000,000 ppm | 600 s | 0 / 0 |
| Revealed blocked/invalid v3 official batch | 6 / 0 / 0 | 1,000,000 ppm | 1,000,000 ppm | 1,000,000 ppm | 450 s | 0 / 0 |

Every partition also records zero hard-negative incidents. The previously
missed `netbanking / issuer_synthetic_gamma` case opens at 08:15 UTC, 900
seconds after its simulated onset. Its early broad parent remains visible as a
suppressed candidate, and the later broad parent that v3 emitted as a false
positive is now an explicit non-selected arbitration record pointing to the
child incident.

V4 records 9, 12 and 11 confirmed losing candidates respectively. Those
counts are audit evidence, not additional predicted incidents.

## Report-contract remediation

The v4 canonical writer does not omit `None` values. Before any development
artifact is accepted it:

- emits `resolved_at` for every incident summary, including an explicit
  `null` for open incidents;
- strictly reloads prediction, partition-report and suite bytes into their
  immutable Pydantic contracts;
- canonicalizes each reloaded model and requires byte-for-byte equality;
- checks that typed open-incident identities equal the JSON objects carrying
  `status="open"` and `resolved_at=null`.

The revealed v3 development partition supplies one real open incident for this
preflight. Removing its required nullable field makes model validation fail.
Historical v3 bytes remain unchanged.

## Committed evidence

- `evals/golden/detector_v4.candidate.json`
- `evals/golden/detector_v4.freeze.json`
- `evals/golden/detector_v4.blind_procedure.freeze.json`
- `evals/reports/detector_v4.development.json`
- `evals/reports/detector_v4.adversarial.json`
- `evals/reports/detector_v4.prior_development.predictions.json`
- `evals/reports/detector_v4.prior_development.report.json`
- `evals/reports/detector_v4.revealed_v2_predecessor.predictions.json`
- `evals/reports/detector_v4.revealed_v2_predecessor.report.json`
- `evals/reports/detector_v4.revealed_v3_predecessor.predictions.json`
- `evals/reports/detector_v4.revealed_v3_predecessor.report.json`

Prediction artifacts are label-free. Reports load truth only after all three
prediction byte sequences exist. Each artifact is canonical and digest-bound.
The historical R5.2 suite correctly retains `candidate_frozen=false` and null
official nonce/run fields because it predates the freeze and official run; the
R5.3 freeze is the authoritative frozen identity. The later R5.4 append-only
receipts, not those historical development artifacts, carry the official run
identity and release decision.

## R5.3 adversarial and runner freeze

The committed adversarial report passes 15 cases spanning guarded/frozen time
windows, invalid timestamps and gate changes, event ordering, the reproduced
v3 hierarchy starvation, both breadth arbitration branches, overlap and audit
reconciliation, hard negatives, label isolation, required-nullable report
serialization and the pre-nonce action boundary.

`detector_v4.freeze.json` binds the protocol, generator, candidate config,
candidate source bundle, exact matcher, all seven development artifacts and
the adversarial report. `detector_v4.blind_procedure.freeze.json` separately
binds the candidate freeze to the runner, evidence-contract and clean-checkout
reproducer sources. The runner accepts no nonce argument, writes a digest
commitment before generation, uses
repository-confined create-only paths and exclusive stage locks, reproduces
persisted predictions before authorizing truth, and writes only redacted
terminal failures. It must strictly reload and byte-reproduce its report before
writing a completion receipt. Its separately frozen reproduction entry point
can recreate only the two git-ignored inputs for a completed run, verifies them
against the append-only receipt chain and refuses to overwrite mismatched bytes.

## R5.4 official blind qualification

The prediction-only commit `19398fc` precedes truth access in Git history. It
contains the commitment, canonical label-free prediction artifact and its
receipt. The subsequent result commit `b9c3efd` records the one truth-access
receipt and terminal digest chain for
`detector_v4_official_blind_5497598109b06d21c625`.

The synthetic blind report covers 5,760 attempts and 10,676 normalized events.
It records 6 TP / 0 FP / 0 FN, 1,000,000 ppm precision, recall and top-1
attribution, a 600-second median simulated first-signal delay, and zero
hard-negative action-eligible incidents, baseline leakage or evidence
reconciliation violations. Required nullable fields, strict reload and exact
canonical byte reproduction all pass. The decision is qualified for M4
integration review, while `runtime_action_eligible` remains false throughout.

Official evidence is rooted at:

- `evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/nonce.commitment.json`
- `evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/blind.predictions.v1.json`
- `evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/blind.report.v1.json`
- `evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/blind.release.v1.json`
- `evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/completion.receipt.json`

## Verification

```bash
uv run retryrail-v4-protocol --check
uv run retryrail-v4-candidate --check
uv run retryrail-v4-adversarial --check
uv run retryrail-v4-freeze --check
uv run retryrail-v4-blind-reproduce
uv run retryrail-v4-blind --check
uv run pytest services/api/tests/detection/test_v4_candidate.py
uv run pytest services/api/tests/detection/test_v4_freeze.py
uv run pytest services/api/tests/detection/test_v4_blind.py
make v4-candidate-check
make v4-adversarial-check
make v4-freeze-check
make v4-blind-check
```

R5.4 created its one fresh public, non-sensitive nonce only after the complete
freeze was committed, pushed and remotely verified. That run is now consumed
and append-only. R5.5 preservation and release verification remain next.
