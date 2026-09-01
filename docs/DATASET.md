# RetryRail deterministic truth set

## Release boundary

This document describes the implemented M1 synthetic batch. It is evaluation
data, not merchant traffic, and every runtime event and truth record carries a
synthetic label. M2 consumes these contracts through the protected replay path.
M3 has now consumed the held-out partition; its failed blind decision remains
committed and the split cannot qualify later detector changes.

## Stable identity

| Field | Value |
| --- | --- |
| Dataset | `retryrail_default_v1` |
| Generator | `generator_v1_0_0` |
| Seed | `retryrail_m1_seed_v1` |
| Attempts | 2,880 |
| Normalized events | 5,463 |
| Currency | INR, integer subunits |
| Manifest SHA-256 | `24cc716b0d144fd14ee68ae8cd3dce821fbc7acff3fb38b95bf17c6571ff8934` |

The committed manifest is `fixtures/manifests/default.v1.json`; its digest is
stored beside it. Large generated JSONL files are intentionally ignored by Git
and are recreated from the committed generator and seed.

## Leakage-safe partitions

| Split | Window (UTC) | Attempts | Events | Purpose |
| --- | --- | ---: | ---: | --- |
| Tuning | 2026-09-01 00:00–24:00 | 1,440 | 2,717 | Detector development and threshold selection |
| Held-out | 2026-09-08 00:00–24:00 | 1,440 | Final detector and attribution evaluation only |

Runtime normalized events do not contain `split`, `scenario_id`, expected
incident membership, severity or root-cause labels. Those fields exist only in
physically separate `attempt_truth` artifacts. Tests reject label leakage and
overlapping payment/event identifiers between partitions.

Detector v1 loads normalized events first, produces incidents, and only then
loads scenario definitions for matching. Its thresholds were frozen at the
synthetic event-time boundary `2026-09-02T00:00:00Z`, before the held-out
partition begins on September 8.

## Frozen ground truth

| Scenario | Split | Window (UTC) | Cohort | Seeded failure rate | Actual failures / attempts | Expected decision |
| --- | --- | --- | --- | ---: | ---: | --- |
| `incident_tuning_card_issuer_alpha` | Tuning | 04:00–07:00 | card + synthetic issuer alpha | 58% | 20 / 34 | Open incident; bank / authorization / issuer unavailable |
| `incident_tuning_upi_gateway` | Tuning | 10:00–13:00 | UPI | 49% | 35 / 68 | Open incident; gateway / processing / timeout |
| `incident_heldout_netbanking_beta` | Held-out | 04:00–10:00 | netbanking + synthetic issuer beta | 62% | 10 / 23 | Open incident; bank / authentication / issuer unavailable |
| `hard_negative_heldout_wallet_low_volume` | Held-out | 13:00–14:00 | wallet | 90% | 2 / 2 | Do not open; minimum-sample gate |

Normal traffic surrounds every episode. The hard negative deliberately has a
dramatic percentage change but insufficient evidence, ensuring later detectors
cannot equate a high failure percentage with an actionable incident.

## Reliability schedule

Business-event truth is separate from webhook delivery behavior. The delivery
artifact contains one stable sequence with:

- one event delivered four times, expecting one acceptance and three duplicate
  no-ops;
- one event delayed by two hours;
- a captured event delivered before its authorized event;
- invalid-signature, missing-signature and modified-after-signing attempts,
  each rejected before a later valid delivery.

No test signature or secret is stored in the schedule. M2 turns each typed
condition into raw-body replay behavior using a local-only test secret.

## Precommitted experiment design

The manifest freezes the future M5 experiment before any recovery result is
generated:

- eligibility is frozen before assignment;
- only failed members of true incidents are eligible;
- assignment uses a SHA-256 hash of stable payment identity;
- treatment/control allocation is 80/20;
- method, issuer and amount band are strata;
- assignment and outcome draws use independent namespaces;
- simulated control and treatment recovery rates are 15% and 45%;
- attribution closes after 24 hours;
- an interval crossing zero must be reported as inconclusive.

These are simulated outcome assumptions, not measured business results. M1
does not calculate or claim recovered GMV.

## Reproduction and verification

```bash
make seed
uv run retryrail-seed --check
uv run retryrail-contracts --check
uv run pytest services/api/tests/contracts
uv run retryrail-eval --check
```

On Windows without GNU Make, use `uv run retryrail-seed`. Generation uses
SHA-256-derived integer buckets, fixed timestamps, canonical key ordering and
newline-normalized JSON. It does not depend on wall-clock time, mutable random
state, locale or filesystem enumeration order.

## Privacy rules

The fixtures use invented merchant, issuer, payment and event identifiers.
They contain no customer names, contact details, VPA, notes, tokens, account
keys or card objects. The repository security scan parses JSON and JSONL
fixtures structurally and blocks prohibited keys.

## Consumed held-out result

Detector v1 achieved 2/2 true incidents with no false positives on tuning, but
0 true positives, 2 background false positives and 1 false negative on
held-out. The wallet hard negative correctly remained blocked by the sample
gate. This partition is now consumed and may not be used to tune a replacement
while still being called blind. See `docs/DETECTOR.md` and the committed files
under `evals/reports/`.

A post-evaluation no-traffic lifecycle correction required regenerating the
current-code reports. Only synthetic resolution timestamps changed; all
classification, attribution and release metrics remained identical. This was
not treated as a second qualification attempt, and v1 remains blocked.

## Detector-v2 pre-blind development data

The separate `retryrail_detector_v2_development_v1` batch contains 5,760
attempts and ten scenarios over 48 simulated hours. Its normalized events and
evaluation truth use separate paths, and its committed manifest SHA-256 is
`09ea61ca4ae08b8bcef7771358478f20896133d4a1e88bde7b06450c5dd9de37`.

R2 consumed this batch as development evidence and committed a label-free
prediction followed by a separate scored report. It cannot be represented as
held-out evidence. The later v2 official batch is revealed, release-blocked
development evidence for v3 and must never be called blind for another
candidate. V3's fresh official batch is also now consumed: its release failed
precision and recall and its report failed the frozen reload contract. Neither
batch may be reused as held-out evidence. See `DETECTOR_V2_PROTOCOL.md` and
`DETECTOR_V3_PROTOCOL.md`.
