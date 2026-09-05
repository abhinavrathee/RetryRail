# M5 recovery experiment protocol

Status: official synthetic outcome batch and report generated

Scope: synthetic batch only; not live merchant performance
Protocol: `recovery_experiment_protocol_v1`

The outcome-free protocol and all 280 assignments were committed and pushed in
`191ec3f` before the outcome stage was run. The assignment artifact records
`outcomes_observed=false`; the later evaluator refuses any source-derived
assignment drift.

## Frozen source and eligibility

The experiment verifies and scans the complete qualified detector-v4 blind
truth artifact:

- source rows scanned: 5,760
- eligible failed incident members: 280
- eligible GMV: 50,022,000 INR subunits (₹500,220.00)
- selection: blind + synthetic + INR + incident member + failed
- assignment unit: payment ID
- attribution window: 86,400 seconds

The source manifest, truth artifact and qualified detector release are each
SHA-256-bound in the machine-readable protocol. Treatment and control share the
same frozen eligibility snapshot.

## Assignment

The embedded M1 design fixes 80% treatment and 20% control. SHA-256 ranks are
independent of the outcome namespace. Hamilton apportionment fixes the global
holdout total while minimizing rounding imbalance across the 20 observed
method × issuer × amount-band strata.

- treatment: 224
- control: 56
- assignment freeze declares `outcomes_observed=false`
- every payment, assignment rank, stratum, amount and arm is retained

## Predeclared measurement

Outcomes must recover the same payment inside 24 hours. The primary estimator
is the treatment/control difference in recovered value per eligible payment,
scaled to the treatment population. Recovery-rate uplift is secondary.

Uncertainty uses a deterministic 10,000-replicate independent-arm
nonparametric percentile bootstrap at 95% confidence. The conclusion is
inconclusive when the primary interval includes zero. Gross treatment recovery,
estimated natural recovery, incremental recovery, action cost,
false-intervention cost and net value are separate fields.

All generated outcomes and every report metric are structurally labelled
`synthetic_batch_not_live_merchant_performance`.

## Official synthetic result

The evaluator consumed every frozen assignment and wrote the outcome batch and
report once. Gross recovery is shown separately and is not presented as causal
impact.

| Measure | Official result |
| --- | ---: |
| Eligible failed incident payments | 280 |
| Treatment / control | 224 / 56 |
| Treatment recovered | 116 (51.7857%) |
| Control recovered | 7 (12.5000%) |
| Absolute recovery-rate uplift | 39.29 percentage points |
| Gross treatment recovered GMV | ₹200,884 |
| Estimated natural recovery in treatment | ₹79,972 |
| **Incremental recovered GMV** | **₹120,912** |
| Action + false-intervention costs | ₹772 |
| **Net incremental value** | **₹120,140** |
| 95% incremental-GMV interval | ₹44,447 to ₹189,391 |
| 95% recovery-rate uplift interval | 28.13 to 49.55 percentage points |

The precommitted conclusion rule therefore records
`statistically_positive_synthetic_incremental_value`. The committed report file
has SHA-256
`165dbed8d4116aae353a4df85d6dbd1906f5e8bf9e14c25880b08c5996762ec6`;
the outcome file has SHA-256
`4e692fd2f41c91bcad7a4de346ff675131768d83de0c1952b3cd7ae6a4613e85`.

## Interpretation limits

- These are deterministic simulated outcomes using the recovery-rate and cost
  assumptions frozen in the M1 experiment design. They are not transactions
  observed from a merchant, Razorpay pricing or a forecast of live performance.
- The synthetic source batch's October 2026 timestamps are its simulation
  clock. They are not wall-clock claims about when repository work ran.
- The sample supports this versioned benchmark only. A production claim would
  require prospectively assigned merchant traffic, consent and a fresh analysis
  plan appropriate to that population.
- The control arm estimates natural recovery; subtracting it is why ₹200,884 of
  gross treatment recovery becomes ₹120,912 of estimated incremental recovery.

Reproduce without writing:

```bash
uv run retryrail-experiment freeze --check
uv run retryrail-experiment evaluate --check
```
