# RetryRail deterministic recovery policy

## Current boundary

M4.2 implements a pure, version-pinned policy evaluator. It accepts only a
validated `PolicyContextSnapshot`, evaluates every frozen rule, and returns a
complete `PolicyResultContract`. The evaluator itself still performs no I/O,
persistence, token issuance, provider request or external mutation.

M4.3 now owns the separate runtime boundary: it accepts no policy facts from the
caller, assembles the context from the configured merchant, locked incident,
payment projection, immutable source event, explicit recovery-control record and
server configuration, then persists the plan, provenance and complete preview
result. A policy allow permits an authenticated merchant decision; it is not an
execution authorization by itself. M4.4 must rebuild current facts and record a
fresh execution-stage allow in the same bounded execution workflow.

The implemented policy version is `deterministic_policy_v1_0_0`. Unknown
versions and non-UTC policy timestamps fail before evaluation. The result
identifier is the SHA-256 of the canonical complete context with a `policy_`
prefix, making identical inputs idempotent and making preview/execution
snapshots independently identifiable. A committed golden-vector test prevents
the identifier algorithm from drifting silently.

The exact runtime sources, fail-closed non-synthetic control behavior and token
boundary are documented in `RECOVERY_WORKFLOW.md` and ADR-0008.

## Rule truth table

All rules are evaluated in this exact order. Evaluation never stops at the
first denial, so the merchant and audit trail receive complete reasons.

| Rule | Pass condition | Deny boundary |
| --- | --- | --- |
| Merchant scope | Request merchant equals the resource merchant | Any mismatch |
| Incident eligibility | Qualified detector evidence marks the incident action-eligible | Ineligible or unqualified incident |
| Operating mode | `REVIEW_FIRST` | `ANALYZE_ONLY` |
| Template enablement | Known template is enabled by current merchant policy | Disabled template |
| Original amount | Proposed integer subunits equal the verified source amount | Any difference |
| Currency | Proposed currency equals verified source currency | Any difference |
| Contact consent | Contact is unnecessary, or required contact has verified consent | Contact required without consent |
| Customer opt-out | Customer is not opted out | Opted out |
| Attempt cap | Prior attempts are strictly below the configured maximum | Attempts equal or exceed maximum |
| Cooldown | No prior action, or elapsed time is greater than or equal to cooldown | Elapsed time below cooldown |
| Plan expiry | Evaluation is strictly before expiry | Evaluation at or after expiry |
| Kill switch | Merchant kill switch is off | Kill switch on |
| Already recovered | Payment is not already recovered | Payment already recovered |

An aggregate result is `allow` only when all 13 rules pass. Every rule has one
allowlisted pass reason and one allowlisted denial reason.

## Trust and time boundary

The policy context is an internal input contract, not a client authorization
request. A future route must construct it from authenticated merchant scope,
qualified incident evidence, the immutable plan, current policy settings and
current payment/action state. In particular, the client or model must never
supply `evaluated_at`, eligibility, amount, consent, attempts, kill-switch or
already-recovered facts.

Execution must build a new context and evaluate it immediately before any
provider call. A stored preview result cannot authorize execution. Server time
must be UTC; exact expiry is denied, while exact cooldown completion is allowed.

## Verification evidence

`services/api/tests/policy/test_policy_engine.py` contains paired allow/deny evidence
for every rule, multi-denial/no-short-circuit behavior, exact temporal
boundaries, consent behavior, version rejection, deterministic replay and
distinct preview/execution identities.
