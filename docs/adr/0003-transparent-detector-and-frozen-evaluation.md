# ADR 0003: Transparent method detector with frozen blind evaluation

- Status: Accepted for M3 implementation; release qualification blocked
- Date: 2026-09-01

## Context

RetryRail needs an explainable detector that works without an LLM, resists
low-volume noise, merges repeated alerts and preserves enough evidence for a
reviewer to reproduce every decision. Threshold selection and final evaluation
must not share labels.

Testing every method/issuer pair independently increased multiple-testing
noise and let sparse slices appear dramatic. Detecting only a global payment
rate hid actionable cohort changes. An opaque learned model would make the
small synthetic set look more sophisticated without making the result more
trustworthy.

## Decision

The P0 v1 detector:

1. reconstructs terminal attempts from normalized events;
2. materializes five-minute method and method/issuer facts;
3. opens at method level using adaptive windows, a pre-window baseline,
   sample gates, a one-sided proportion test, EWMA, CUSUM and business impact;
4. freezes the opening baseline for the complete incident;
5. uses issuer and structured error slices for transparent attribution;
6. persists every passing observation and an idempotent detector-run receipt;
7. resolves only after a configured interval of sample-eligible observations
   whose measured rate drop is below the frozen degradation threshold; absent
   traffic is not recovery evidence;
8. loads scenario labels only after prediction generation.

Thresholds are a committed immutable-by-process JSON artifact. Held-out
results are committed even when they fail. Evaluation also generates a
machine-readable release decision bound to the detector version, threshold
hash and held-out manifest. Only a fully passing decision can set
`action_eligible`; missing, contradictory or mismatched artifacts fail closed.

## Consequences

The design is deterministic, model-independent, tenant-scoped, auditable and
easy to reproduce. The same source snapshot/config pair cannot create a second
run receipt, and one active method episode cannot create alert spam.

The v1 method-level choice failed the sparse issuer-specific held-out episode
and produced two background UPI false positives. Its held-out precision and
recall are both zero. This is a release blocker, not a reason to rewrite the
result. A v2 detector may use hierarchical evidence or confirmation logic, but
it requires a newly frozen blind partition because the original held-out labels
have now been consumed. V1 incidents remain available for review and at-risk
visibility, but the runtime persists them with `action_eligible=false`.

No LLM, recovery policy or external action may override this detector decision.

A final generic lifecycle audit found that absence of traffic had been counted
as a healthy interval. The correction changed only synthetic resolution
timestamps in the regenerated reports, not any classification, attribution or
release metric. The consumed held-out set cannot qualify that correction; the
blocked decision is intentionally unchanged.
