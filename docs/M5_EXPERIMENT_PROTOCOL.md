# M5 recovery experiment protocol

Status: assignment frozen; official outcome artifact not yet produced

Scope: synthetic batch only; not live merchant performance
Protocol: `recovery_experiment_protocol_v1`

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
