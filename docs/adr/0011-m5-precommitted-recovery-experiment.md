# ADR-0011: Freeze recovery assignment before synthetic outcomes

- Status: Accepted
- Date: 2026-09-05
- Decision owners: RetryRail maintainers
- Milestone: M5

## Context

Gross treatment recovery is not incremental value. A credible M5 report needs
the counterfactual natural-recovery rate from an untreated holdout, identical
pre-assignment eligibility, a predeclared attribution window and uncertainty.
Choosing individual successes or changing the allocation after seeing outcomes
would invalidate the claim.

M1 already froze `experiment_design_v1`: payment-level SHA-256 assignment,
80/20 treatment/control allocation, method/issuer/amount-band strata, a 24-hour
attribution window, independent assignment/outcome namespaces, synthetic
control/treatment recovery rates of 15%/45%, and an inconclusive result when an
interval includes zero.

## Decision

M5 inherits the M1 design unchanged and binds it to the qualified detector-v4
blind source by exact manifest, truth and release SHA-256 identities.

Eligibility scans all 5,760 truth rows and selects every row that is synthetic,
blind, INR, an expected incident member and finally failed. This is one rule for
both arms and yields 280 eligible payments. No outcome field participates in
selection or assignment.

Amounts are pre-banded as `< ₹1,000`, `₹1,000–₹2,499.99`, and `≥ ₹2,500`.
The cross-product of method, issuer and amount band yields 20 observed strata.
The exact global holdout count is apportioned across strata with the Hamilton
largest-remainder method, then the lowest independent SHA-256 ranks in each
stratum enter control. This produces 224 treatment and 56 control assignments
without mutable randomness.

The protocol and complete assignment freeze are generated and committed before
the official outcome/report artifacts. The freeze records the full-source scan,
eligibility digest, every assignment rank, arm totals, GMV and per-stratum
balance. Its `outcomes_observed` field is structurally false.

Synthetic outcomes use the independent M1 outcome namespace and the frozen arm
rates. Recovery must be attributed to the same payment within 24 hours. The
cost model is also fixed before outcomes: ₹2 per treatment action and ₹3 for an
unrecovered treatment intervention. These are explicit simulation assumptions,
not Razorpay pricing claims.

The primary estimator is the product-required difference in recovered value
per eligible payment, multiplied by treatment size. The report keeps these
quantities separate:

```text
gross treatment recovered GMV
- estimated natural recovery among treatment
= incremental recovered GMV
- action cost
- false-intervention cost
= net recovered value
```

Recovery-rate uplift is a companion measure. A deterministic 10,000-replicate,
independent-arm nonparametric percentile bootstrap gives 95% intervals for both
incremental GMV and rate uplift. If the primary interval contains zero, the
result is labelled inconclusive; a wholly negative interval is labelled
negative rather than positive.

## Consequences

The report is reproducible from versioned source bytes and cannot silently
reassign a payment, omit a failed eligible member or call gross recovery
incremental. All results remain prominently labelled
`synthetic_batch_not_live_merchant_performance`.

This design estimates impact only for the synthetic evaluation population. It
does not establish live merchant lift, and its cost assumptions must not be
presented as actual provider fees.

## Rejected alternatives

- **Report every treatment success as incremental.** Rejected because some
  payments recover naturally.
- **Use the entire blind batch as eligible.** Rejected because healthy and
  non-incident attempts do not share the recovery policy population.
- **Assign by an outcome-correlated hash or mutable random seed.** Rejected to
  preserve independence and byte reproducibility.
- **Report only a point estimate.** Rejected because sample sizes and
  uncertainty are P0 requirements.
- **Set intervention costs to zero.** Rejected because false-intervention cost
  is a required component of net value.
