# Detector v2 remediation and blind-evaluation protocol

## Current status

R1 and R2 are complete, and the pre-nonce portion of R3 is complete. The
development dataset, blind generator, v2 candidate configuration, detector
source, matcher, evaluator and append-only blind runner are frozen. No
official blind nonce or blind result exists yet. Development success is not a
release qualification: detector v1 remains release-blocked and is still the
only runtime detector.

The protocol identity is `detector_v2_protocol_v1`. Its machine-readable source
is `evals/protocols/detector_v2.protocol.json`.

## Why v2 exists

V1 missed the sparse issuer-specific held-out incident, produced two background
UPI customer-cancellation incidents, and missed the ten-minute median detection
target. Those failures motivate three transparent design hypotheses for R2:

1. evaluate method and method/issuer candidates hierarchically instead of
   diluting every issuer change into a method-only rate;
2. distinguish provider-actionable excess failures from customer-behavior
   failures before an incident can become action-eligible;
3. require persistence/confirmation so a short provider burst is visible as
   evidence but cannot become an action incident.

These are hypotheses, not claimed results. R2 may tune them only on approved
development data.

## Staged delivery

| Gate | Work | Status |
| --- | --- | --- |
| R1 | Freeze protocol, development data and nonce-derived blind generator | Complete |
| R2 | Implement and tune one v2 candidate using development data only | Complete |
| R3 | Freeze runner, obtain fresh nonce, predict, then load blind truth once | In progress — runner frozen; nonce pending |
| R4 | Integrate v2 only if its generated release decision qualifies it | Not started |

M4 recovery execution remains behind R4. A model, policy rule or merchant
approval cannot override a blocked detector release decision.

## Frozen R2 candidate

`detector_v2_0_0` is a deterministic hierarchical detector. Its exact
configuration is `evals/golden/detector_v2.candidate.json`, and
`evals/golden/detector_v2.freeze.json` binds that configuration to the detector,
matcher, evaluator, shared contract sources, R1 protocol and development
prediction/report bytes.

The candidate applies these rules without an LLM:

1. evaluate method and method/issuer cohorts using 15, 30 and 60-minute current
   windows against a non-overlapping four-hour baseline;
2. count only the allowlisted `bank`, `gateway` and `wallet` sources in
   provider-degradation statistics, while retaining customer failures as
   visible but non-actionable evidence;
3. choose at most one hierarchical candidate per method and retain the exact
   cohort, counts, thresholds, event identifiers and inferred/verified
   separation;
4. confirm method candidates only after four passing observations, three fresh
   evidence steps, four unique provider failures and fresh evidence in the
   latest step;
5. allow sparse issuer candidates to be visible early, but require three
   passing observations, two fresh evidence steps, two unique provider
   failures and at least five subsequent cohort attempts within a bounded
   60-minute confirmation period;
6. retain unconfirmed bursts and low-volume candidates as suppressed audit
   evidence, never as action incidents.

The first signal is the detection timestamp. The later confirmation timestamp
is recorded separately. Even confirmed candidate incidents have
`runtime_action_eligible=false` until a blind-qualified release decision is
integrated in R4.

### Development-only result

The frozen development report records six true positives, zero false
positives, zero false negatives, 1,000,000 ppm precision/recall/top-1
attribution and a 600-second median first-signal delay. The two customer spikes
stop at the non-actionable-source gate, the low-volume wallet case stops at the
sample gate, and the ten-minute provider burst stops at confirmation. Baseline
leakage and evidence reconciliation violations are both zero.

Those are synthetic development results, not blind results or production
claims. Median confirmation delay is separately reported as 2,100 seconds;
confirmation latency is not hidden inside the faster first-signal metric.

## Versioned development batch

`retryrail_detector_v2_development_v1` contains 5,760 attempts at one attempt
every 30 seconds over 48 simulated hours. Normalized events and attempt truth
are physically separate artifacts. The committed manifest SHA-256 is
`09ea61ca4ae08b8bcef7771358478f20896133d4a1e88bde7b06450c5dd9de37`.

The ten non-overlapping scenarios contain six true incidents and four hard
negatives:

| Family | Count | Expected behavior |
| --- | ---: | --- |
| Method provider degradation | 3 | Detect |
| Issuer provider degradation | 3 | Detect |
| Customer-behavior spike | 2 | Do not make action-eligible |
| Low-volume spike | 1 | Block on sample evidence |
| Ten-minute provider burst | 1 | Block on confirmation |

V1 tuning, consumed V1 held-out data and this new development batch are the
only datasets permitted during R2. The consumed V1 partition is development
evidence now; it cannot be represented as blind again.

## Official blind procedure

The official blind batch uses the same volume and precommitted family counts,
but its family ordering, methods, issuers, outcomes, amounts and background
traffic are derived from a fresh nonce. The R3 CLI accepts no raw nonce command
line argument; `--predict` and `--score` read it from a hidden interactive
prompt so it is not exposed through process arguments.

`evals/golden/detector_v2.blind_procedure.freeze.json` binds the runner and its
evidence contracts to the existing candidate, configuration, matcher,
generator and protocol hashes before a nonce is supplied. The runner uses
exclusive stage locks, create-only durable writes and a terminal redacted
failure receipt. Historical evidence is never overwritten.

R3 must execute in this order:

1. freeze the detector implementation, configuration, matcher and evaluation
   code with recorded hashes;
2. obtain a new nonce of at least 16 characters from the user;
3. reject either committed test nonce and record only the nonce SHA-256 before
   generation;
4. generate normalized blind events through `build_blind_runtime`;
5. run the frozen detector and persist prediction bytes plus their SHA-256;
6. only then call `load_blind_truth` and join it to the matching nonce
   commitment;
7. score all incidents and hard negatives and generate a release decision;
8. commit every result, including a failure.

The two explicit irreversible stages are:

```bash
uv run retryrail-v2-blind --predict
uv run retryrail-v2-blind --score
```

`--predict` stops after a canonical prediction receipt whose models force
`labels_loaded=false`. `--score` independently reproduces those exact bytes,
writes a truth-access authorization receipt, and only then invokes the truth
loader. The nonce is published in a separate reproducibility artifact only
after the report and release decision have been durably written.

Any threshold, algorithm or matching change after nonce reveal invalidates the
run and requires a different nonce and run identifier. The previous output
remains historical evidence; it is never overwritten.

## Release targets

The protocol copies the P0 product requirements without adjustment:

- precision at least 900,000 ppm;
- recall at least 850,000 ppm;
- top-1 attribution at least 800,000 ppm;
- median simulated detection delay at most 600 seconds;
- zero hard-negative action-eligible incidents;
- zero baseline leakage or evidence reconciliation violations.

Six blind incidents make recall granular: at least six of six are required to
clear 0.85. With six true positives, any false positive also misses 0.90
precision. The small synthetic set is deliberately strict but is not a
production performance claim.

## Integrity and limitations

- Runtime event JSON contains no dataset role, split, scenario identifier,
  expected membership or root-cause label.
- The raw nonce is absent from generated events and manifests; only its digest
  is stored until the post-evaluation reveal needed for reproducibility.
- Generator source and its consumed schemas are bound by one bundle SHA-256.
  Drift makes `retryrail-v2-data --check` fail.
- Candidate, matcher and evaluator sources are independently bound by the R2
  freeze. Drift makes `retryrail-v2-candidate --check` fail before a nonce is
  requested.
- The blind runner and evidence contracts are independently bound by the R3
  procedure freeze. Drift, partial state, digest-chain disagreement or a stale
  stage lock makes `retryrail-v2-blind --check` fail closed.
- This is a nonce-unpredictable synthetic holdout, not a double-blind external
  benchmark. Scenario families and distributions are intentionally public.
- No cloud service, Razorpay credential or model provider is used.

## R1 verification

```bash
uv run retryrail-v2-data --check
uv run pytest services/api/tests/detection/test_v2_dataset.py
make v2-data-check
```

The tests cover deterministic generation, nonce variation, official test-nonce
rejection, label-free runtime events, separate truth loading, non-overlapping
scenarios and exact family/count reconciliation.

## R2 verification

```bash
uv run retryrail-v2-candidate --check
uv run pytest services/api/tests/detection/test_v2_candidate.py
make v2-candidate-check
```

The prediction artifact contains no scenario identifiers, expected outcomes or
truth membership. Tests cover hierarchy, provider/customer source separation,
sparse issuer confirmation, low-volume and transient suppression, development
metrics, evidence reconciliation, fail-closed runtime eligibility and the
absence of any blind identity from the freeze.

## R3 pre-nonce verification

```bash
uv run retryrail-v2-blind --check
uv run pytest services/api/tests/detection/test_v2_blind.py
make v2-blind-check
```

The workflow tests use only the already-approved development dataset behind
mocked blind boundaries; they never evaluate the candidate on a nonce-derived
test batch. They cover durable prediction-first ordering, label isolation,
byte-for-byte detector replay before truth access, append-only release
evidence, tamper rejection, concurrent-stage exclusion, replay refusal,
test-nonce rejection and the M4 activation boundary.
