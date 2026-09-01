# Detector v3 guarded-baseline remediation protocol

## Current status

M3R.4 phase R4.1 is precommitted. No detector-v3 candidate, candidate freeze,
blind runner, blind nonce or release claim exists yet. Detector v2 remains the
immutable failed predecessor and every detector output remains runtime
action-ineligible.

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
| R4.2 | Implement and tune one separately versioned guarded-baseline candidate | Not started |
| R4.3 | Run adversarial checks; freeze candidate, matcher, evaluator and runner | Not started |
| R4.4 | Create one fresh nonce, persist predictions, reproduce, authorize truth once | Not started |
| R4.5 | Commit release decision and run all repository/security/CI gates | Not started |

R4.2 cannot claim release success. It must pass every unchanged target on each
approved development partition independently before R4.3.

## Future blind boundary

After candidate and runner freeze, the future procedure must:

1. create exactly one fresh 16–256 character public, non-secret nonce;
2. reject the v2 official nonce and all committed v2/v3 test nonces by digest;
3. persist only the nonce commitment before generation;
4. generate normalized events without loading scenario labels;
5. persist canonical prediction bytes and their digest;
6. independently reproduce those exact prediction bytes;
7. durably authorize truth access, then load labels exactly once;
8. write an append-only report, decision, completion receipt and public reveal;
9. keep a failed result permanently action-ineligible.

Any algorithm, configuration, matcher, evaluator or runner change after nonce
creation invalidates that run for release and requires a different nonce and
run identity. Previous evidence is never overwritten.

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
