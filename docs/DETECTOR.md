# M3 deterministic detector and incident lifecycle

## Release decision

The M3 implementation is complete, reproducible and **not approved as the P0
release detector**. Detector v1 passed its tuning cases but failed the frozen
held-out precision and recall targets. The failed result is committed rather
than tuned away.

This distinction matters:

- the aggregate, detector, diagnosis, lifecycle, persistence and API machinery
  is implemented and tested;
- the hard negative is correctly blocked and every persisted incident is
  evidence-reconcilable;
- detector v1 does not generalize well enough to justify recovery actions on
  the held-out batch;
- the generated `evals/reports/detector_v1.release.json` decision is bundled
  with the runtime and forces every v1 incident's `action_eligible` flag to
  `false`;
- M4 recovery policy must not treat this version as release-qualified until a
  new detector is evaluated on a fresh blind set.

## Decision boundary

No model is involved. The detector consumes only authenticated normalized
events whose projection outbox receipt is complete. It never receives
`split`, `scenario_id`, incident-membership or expected-cause labels.

```text
completed normalized events
  -> duplicate/out-of-order-safe terminal attempts
  -> exact five-minute method and method/issuer aggregates
  -> adaptive 30/60/120-minute method windows
  -> frozen four-hour pre-window baseline
  -> sample + confidence + EWMA + CUSUM + business-impact gates
  -> one merged incident per active method cohort
  -> issuer/error attribution from excess-failure contribution
  -> resolve after 90 consecutive sample-eligible, rate-recovered minutes
```

Authorized-only payments are pending and are not counted as successful.
Captured dominates an earlier failure or authorization for the same payment,
and immutable money/method identity conflicts fail closed.
An authorization may precede its terminal event across window boundaries;
reconstructed terminal-attempt time, not terminal-webhook time, defines the
detector partition. Low or absent traffic never counts as healthy resolution
evidence.

## Frozen v1 thresholds

The exact artifact is
`evals/golden/detector_v1.freeze.json`, SHA-256
`d7182d843cd15adbca972d562b72f6fffe9d31cfcf12fa30a56b1045d6ab77d6`.
Its `frozen_at` value is an event-time marker after the synthetic tuning day
and before the synthetic held-out day, not a production wall-clock claim.

The separate release decision is derived from the held-out report by
`retryrail-eval`; it is not a caller-controlled setting. Runtime startup rejects
a decision whose detector version or configuration hash does not match the
frozen threshold artifact. A missing, invalid or mismatched artifact therefore
fails closed.

| Gate | Frozen value |
| --- | ---: |
| Detector step | 5 minutes |
| Adaptive current windows | 30, 60, 120 minutes |
| Baseline lookback | 240 minutes before the current window |
| Minimum current / baseline attempts | 12 / 20 |
| Minimum current failures | 2 |
| Minimum success-rate drop | 1,000 bps |
| One-sided proportion confidence | 987,500 ppm |
| EWMA alpha / minimum EWMA drop | 300,000 ppm / 1,000 bps |
| CUSUM allowance / threshold | 500 bps / 1,500 milli |
| Minimum excess failures | 4 |
| Minimum at-risk GMV | 250,000 subunits |
| Healthy resolution window | 90 minutes |

The confidence threshold applies a four-method Bonferroni correction to a 5%
family error budget. The selected window is the narrowest configured window
that clears both sample gates. Once an incident opens, its baseline interval is
frozen; later observations cannot absorb incident-period data.

## Transparent calculations

The one-sided pooled two-proportion test compares current and baseline failure
rates. EWMA starts at the measured baseline rate. CUSUM accumulates failures
above baseline plus the configured allowance.

```text
excess failures = observed current failures
                - current attempts * baseline failure rate

at-risk GMV = observed failed GMV
            - current GMV * baseline failure rate
```

Both values are floored at zero and persisted with the counts, intervals,
thresholds, confidence, EWMA and CUSUM inputs. No opaque score is sufficient to
open an incident.

## Attribution and claim safety

The detector opens at method level so a sparse issuer slice cannot independently
clear the sample gate. Diagnosis ranks method, issuer, error source, error step
and error reason by positive excess-failure contribution. A dominant issuer is
added to the affected cohort only when it owns at least 700,000 ppm of issuer
contribution.

Incident output separates:

- `verified_observation`: counts, expected failures, contribution, confidence
  and source event identifiers;
- `inferred_hypothesis`: merchant-local wording such as “consistent with”;
- `unknown`: external provider state and causality, which payment events cannot
  verify.

The system never turns merchant-local evidence into an unsupported statement
that a bank or ecosystem is down.

## Persistence and APIs

Alembic revision `0002_m3_detection_incidents` adds:

- `aggregate_windows`, upserted from terminal attempt facts;
- `incidents`, with a partial unique constraint allowing one open episode per
  merchant/detector cohort;
- `incident_observations`, protected by update/delete rejection triggers;
- `detection_runs`, an append-only idempotent receipt keyed by merchant,
  config hash and source-event snapshot.

The worker refreshes detection after completed projection work. A one-shot
operator command is also available:

```bash
uv run retryrail-detect
```

Merchant-scoped read boundaries are:

```text
GET /api/v1/overview
GET /api/v1/incidents
GET /api/v1/incidents/{incident_id}
```

The P0 API uses one configured merchant and accepts no caller-supplied merchant
scope. Unknown or cross-scope identities return the same not-found response.

## Evaluation protocol and results

Detection runs before the evaluator loads scenario definitions. Predictions
are matched afterward; unmatched predictions count as background false
positives. Every later `make eval` run only checks deterministic drift against
the already frozen config and committed result.

During the final post-evaluation implementation audit, lifecycle handling was
hardened so that a period with no sample-eligible traffic cannot resolve an
incident. Regenerating the current-code reports changed only the four synthetic
`resolved_at` timestamps; incident classifications, attribution, precision,
recall and detection delays were unchanged. Because the blind labels had
already been consumed, this rerun cannot qualify v1 and the release decision
remains blocked. A future candidate still requires a new blind set.

| Metric | Tuning | Held-out | P0 held-out target |
| --- | ---: | ---: | ---: |
| True / false-positive / false-negative incidents | 2 / 0 / 0 | 0 / 2 / 1 | — |
| Precision | 1.00 | 0.00 | >= 0.90 |
| Recall | 1.00 | 0.00 | >= 0.85 |
| Top-1 / top-3 attribution | 1.00 / 1.00 | 0.00 / 0.00 | top-1 >= 0.80 |
| Median simulated detection delay | 17.5 min | unavailable | <= 10 min |
| Hard-negative action-eligible incidents | n/a | 0 | 0 |
| Baseline leakage violations | 0 | 0 | 0 |
| Evidence reconciliation violations | 0 | 0 | 0 |

The tuning latency target also missed: card opened after 15 minutes and UPI
after 20 minutes.

### Held-out failure analysis

1. The true held-out episode affected only 23 netbanking/issuer-beta attempts
   across six hours. Method-level aggregation diluted that issuer-specific
   change, and the confidence gate blocked it.
2. Two unrelated UPI customer-cancellation clusters in held-out background
   traffic cleared all frozen gates. They became two false-positive incidents.
3. The two-attempt wallet hard negative remained below the current-sample gate
   and correctly opened no incident.
4. Thresholds were not changed after this result. Correct remediation requires
   a principled detector revision and a newly frozen blind dataset; the consumed
   held-out partition cannot honestly validate that revision.

That remediation has a precommitted protocol, a frozen R2 development candidate
and a completed official synthetic blind run in
`docs/DETECTOR_V2_PROTOCOL.md`. The candidate passed blind precision, recall
and attribution targets but failed median detection delay and baseline leakage.
Its release decision is blocked; it is not integrated or runtime-authorized.

Committed evidence:

- `evals/reports/tuning.detector_report.v1.json`
- `evals/reports/heldout.detector_report.v1.json`
- `evals/reports/heldout.detector_evaluation.v1.json`
- `evals/reports/detector_v1.release.json`
- `evals/blind/detector_v2/runs/detector_v2_official_blind_ef49a16703b1612ef774/blind.report.v1.json`
- `evals/blind/detector_v2/runs/detector_v2_official_blind_ef49a16703b1612ef774/blind.release.v1.json`

## Verification

```bash
uv run pytest services/api/tests/detection
uv run pytest services/api/tests/integration/test_detection_service.py
uv run retryrail-eval --check
make eval
```

The integration test exercises partial traffic, incident opening, completed
traffic, healthy resolution, repeat-safe refresh, exact aggregate
reconciliation, immutable evidence and all three read APIs.
