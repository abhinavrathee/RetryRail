# Detector v3 guarded-baseline remediation protocol

## Current status

M3R.4 phases R4.1 through R4.4 are complete. The one official detector-v3
synthetic blind slot was consumed after the candidate and runner freeze. Its
release decision is blocked on precision and recall, and its persisted report
is invalid under the frozen report contract because the canonical writer
omitted one unresolved incident's null `resolved_at` field. The run is not a
qualification attempt that may be repaired or repeated. Detector v2 and v3
remain immutable failed predecessors and every detector output remains runtime
action-ineligible. R4.5 preservation and release-gate verification are in
progress.

The machine-readable process contract is
`evals/protocols/detector_v3.protocol.json`. It is regenerated from and bound
to the exact predecessor artifacts by `retryrail-v3-protocol --check`.

## Why v3 exists

The official v2 synthetic blind result passed precision, recall, top-1
attribution, hard-negative and evidence-reconciliation targets. It failed two
release targets:

| Target | Required | V2 observed | Failure |
| --- | ---: | ---: | --- |
| Median first-signal delay | <= 600 seconds | 900 seconds | Two early cases opened too slowly |
| Baseline leakage | 0 | 2 | Baselines ended 20 minutes after degradation onset |

V2 chose a baseline ending at the start of whichever 15, 30 or 60-minute
current window first had enough samples. Before the first passing signal, that
boundary continued to roll. A signal delayed beyond its selected current
window could therefore compare degraded traffic with partly degraded traffic.
This both contaminates evidence and can delay the signal further.

## Frozen development boundary

Only these already-revealed synthetic partitions may influence v3:

1. `detector_v2_development_v1`, bound by its manifest and report digests;
2. `detector_v2_official_blind_ef49a16703b1612ef774`, now explicitly labelled
   `revealed_blocked_blind` and bound by its manifest, predictions, report,
   release decision and nonce-reveal digests.

The second partition must never be called blind again. No future v3 blind
events, labels, nonce, or derived metrics may enter candidate development.

The benchmark stays `detector_v2_generator_v1_0_0` with bundle SHA-256
`a91e12e9945dd9cab9252dbd6f345e99fd52229505baf10a9aafc5dae511a9b9`.
Keeping the generator and distribution unchanged after observing the failure
prevents the remediation from making its next benchmark easier.

## Candidate invariants

R4.2 may tune a new candidate only within these precommitted boundaries:

- The deterministic detector alone decides degradation; labels and an LLM are
  absent from runtime prediction.
- The baseline guard is explicit configuration and is at least the maximum
  current-window length.
- Baseline and current windows never overlap. A gap is allowed.
- The first passing signal freezes that cohort's baseline for the episode.
- First-signal time and later confirmation time remain separate evidence.
- Provider-actionability, minimum samples, business impact, confirmation,
  hard-negative suppression and evidence reconciliation remain mandatory.
- Candidate outputs remain `runtime_action_eligible=false` before a qualifying
  blind release and later M4 policy integration.

The guard is label-free. At evaluation time `t`, with configured guard `g`,
an unopened candidate's baseline must end no later than `t - g`; it is not
anchored to a known scenario start.

## Staged delivery

| Phase | Work | Status |
| --- | --- | --- |
| R4.1 | Bind failure analysis, allowed evidence, unchanged benchmark and release rules | Complete |
| R4.2 | Implement and tune one separately versioned guarded-baseline candidate | Complete |
| R4.3 | Run adversarial checks; freeze candidate, matcher, evaluator and runner | Complete |
| R4.4 | Create one fresh nonce, persist predictions, reproduce, authorize truth once | Complete — blocked and procedurally invalid |
| R4.5 | Preserve the decision and run all repository/security/CI gates | In progress |

R4.2 cannot claim release success. It must pass every unchanged target on each
approved development partition independently before R4.3.

## R4.2 candidate and development result

`detector_v3_0_0` retains v2's deterministic statistical, business-impact,
actionability, confirmation and diagnosis evidence contracts. Three bounded
changes address observed lifecycle failures:

1. a 60-minute baseline guard covers the maximum current window, leaving a
   label-free gap before shorter current windows;
2. a method candidate may survive statistical misses for at most 30 minutes,
   while still requiring four passing signals, three fresh-evidence steps,
   four unique provider failures and fresh evidence in its latest confirming
   step;
3. issuer attribution must explain at least 80% of method excess failures
   before replacing a passing method-level candidate, reducing unstable sparse
   slice selection.

The ten-minute provider burst still fails confirmation, customer failures stay
non-actionable, and low-volume evidence still fails the sample gate. The exact
configuration is `evals/golden/detector_v3.candidate.json`; development
predictions contain no scenario identities or expected outcomes.

Both approved synthetic partitions independently record six true positives,
zero false positives, zero false negatives, 1,000,000 ppm precision, recall and
top-1 attribution, a 600-second median first-signal delay, zero hard-negative
incidents, zero baseline leakage and zero evidence-reconciliation violations.
The revealed predecessor delays are `[300, 300, 300, 900, 900, 2100]` seconds;
the 2,100-second maximum is retained rather than hidden by the median.

These are development results only. The suite report forces
`candidate_frozen=false`, `official_blind_evaluated=false`,
`release_qualified=false` and `runtime_action_eligible=false`.

## Executed blind boundary

After candidate and runner freeze, the official procedure was required to:

1. create exactly one fresh 16–256 character public, non-secret nonce;
2. reject the v2 official nonce and all committed v2/v3 test nonces by digest;
3. persist only the nonce commitment before generation;
4. generate normalized events without loading scenario labels;
5. persist canonical prediction bytes and their digest;
6. independently reproduce those exact prediction bytes;
7. durably authorize truth access, then load labels exactly once;
8. write an append-only report, decision, completion receipt and public reveal;
9. keep a failed result permanently action-ineligible.

The prediction/truth ordering and create-only receipt chain completed, but the
persisted report failed its own frozen reload contract. Any algorithm,
configuration, matcher, evaluator, contract or runner change after nonce
creation invalidates that run for release. Previous evidence is never
overwritten.

## Unchanged release targets

- precision at least 900,000 ppm;
- recall at least 850,000 ppm;
- top-1 attribution at least 800,000 ppm;
- median simulated first-signal delay at most 600 seconds;
- zero action-eligible hard-negative incidents;
- zero baseline-leakage violations;
- zero evidence-reconciliation violations.

These are synthetic benchmark targets, not production performance claims.

## R4.1 verification

```bash
uv run retryrail-v3-protocol --check
uv run pytest services/api/tests/detection/test_v3_protocol.py
make v3-protocol-check
```

The check fails if any bound v2 artifact, the frozen generator bundle, nonce
denylist, target, or canonical protocol byte changes.

## R4.2 verification

```bash
uv run retryrail-v3-candidate --check
uv run pytest services/api/tests/detection/test_v3_candidate.py
make v3-candidate-check
```

The tests cover both development partitions, exact target comparisons,
baseline gaps and freeze behavior, bounded method confirmation, hierarchy
selection, every hard-negative family, label-free prediction bytes, evidence
reconciliation, fail-closed action eligibility and cross-platform bundle
identity.

## R4.3 candidate and runner freeze

`evals/golden/detector_v3.freeze.json` binds the protocol and unchanged
generator to the candidate configuration, twelve ordered source files, both
development prediction/report pairs, the suite decision and the adversarial
report. It contains no nonce digest or blind run identifier.

The adversarial report records ten passing cases: guard coverage across all
windows, opening-baseline freeze, guard-weakening rejection, timezone
validation, out-of-order input invariance, bounded method confirmation, all
eight hard negatives across the two development partitions, leakage and
evidence reconciliation, label-free prediction artifacts, and continued
disclosure of the 2,100-second slow case.

The candidate freeze alone does not authorize nonce creation. The separate
`evals/golden/detector_v3.blind_procedure.freeze.json` now binds the candidate
and generator identities to the exact blind runner and evidence-contract
sources. Its runner bundle SHA-256 is
`8ff1a614412278ca4de471dc4e8cdb46315ca67ec9071acdb30555dc2148f5e6`.

The runner uses create-only durable writes and repository-confined paths. It
persists label-free events and canonical v3 predictions first, reads those
bytes back, and requires an exact independent detector replay before writing a
truth-access receipt. Truth is then loaded through the separate loader exactly
once. Completion links every artifact digest; failure is terminal, redacted,
and permanently consumes the candidate's one official run slot. Stage locks
reject concurrent prediction or scoring, and no CLI argument can carry the
nonce into the process list.

Nine isolation and integrity tests cover truth-loader exclusion during
prediction, v3 artifact identity, exact replay-before-truth ordering, terminal
replay refusal, byte tampering, prior/test/malformed nonce rejection,
single-run failure semantics, concurrent stage locks, raw-nonce absence and
cross-platform runner hashing.

```bash
uv run retryrail-v3-adversarial --check
uv run retryrail-v3-freeze --check
uv run retryrail-v3-blind --check
uv run pytest services/api/tests/detection/test_v3_freeze.py \
  services/api/tests/detection/test_v3_blind.py
```

Only after this freeze is committed and pushed may R4.4 create its one fresh
public, non-sensitive nonce.

## R4.4 official result

The committed pre-truth prediction evidence was pushed before truth access.
The same public nonce then completed exactly one scoring stage under run
`detector_v3_official_blind_1a1852634945b54e300a`. The raw outcome is:

| Measure | Result | Target | Decision |
| --- | ---: | ---: | --- |
| Payment attempts | 5,760 | fixed batch | informational |
| True / false positives / false negatives | 5 / 1 / 1 | — | informational |
| Precision | 833,333 ppm | >= 900,000 ppm | fail |
| Recall | 833,333 ppm | >= 850,000 ppm | fail |
| Top-1 attribution | 1,000,000 ppm | >= 800,000 ppm | pass |
| Median first-signal delay | 300 seconds | <= 600 seconds | pass |
| Maximum first-signal delay | 2,100 seconds | — | disclosed |
| Hard-negative action-eligible incidents | 0 | 0 | pass |
| Baseline leakage violations | 0 | 0 | pass |
| Evidence reconciliation violations | 0 | 0 | pass |

The false negative is blind scenario 02. The false positive is one unmatched
background incident. Both target misses are retained; no threshold or evidence
was changed after reveal. The release decision is `blocked`, M4 approval is
false and runtime action eligibility remains false everywhere.

### Frozen report-contract defect

The final predicted incident remained open, so its in-memory `resolved_at` was
`None`. The frozen canonical writer used `exclude_none=true` and omitted that
field. `V2IncidentEvaluationSummary` declares `resolved_at` nullable but
required, so `retryrail-v3-blind --check` now rejects the persisted report at
`incidents[5].resolved_at`. The report content validates only after adding that
single `None` in memory; canonicalizing the hydrated model reproduces the exact
original bytes. No official file is modified.

This is a procedure failure in addition to the metric failures. The separate
`postrun.audit.v1.json` binds the completion, report and decision digests and
records `preserved_blocked_invalid`. `retryrail-v3-blind-postrun` verifies the
known defect exactly, the complete digest and identity chain, the blocked
flags, the public-nonce reproduction of both ignored inputs, and any existing
derived bytes. Any additional or different schema failure is rejected.

```bash
uv run retryrail-v3-blind-postrun
uv run pytest services/api/tests/detection/test_v3_blind_postrun.py
make v3-blind-check
```

The frozen `retryrail-v3-blind --check` command is intentionally not replaced
or changed: its exact one-field failure is historical evidence of the defect.
The post-run command verifies preservation of a failed run; a zero exit status
does not qualify detector v3.
