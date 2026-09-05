# M4–M5 deterministic recovery workflow

## Implemented boundary

M4 completes a model-independent, review-first recovery loop for explicitly
synthetic data. The qualified detector-v4 runtime can create an incident; a
deterministic analyst can explain its verified evidence; the server can preview
one standard Payment Link plan; an authenticated merchant can approve it; and a
deterministic fake adapter can produce an append-only action receipt.

M5 preserves that authority chain and adds the real Razorpay Test Mode edge.
No live-mode target, customer contact field or production mutation exists. The
fake adapter records a
`simulated_external_mutation`, always disables notifications and accepts only
synthetic plans. The Test Mode adapter accepts only `rzp_test_` credentials,
performs at most one Standard Payment Link POST after a durable dispatch, and
stores only an allowlisted receipt.

The detector, policy engine and merchant each retain separate authority:

- detector-v4 alone decides whether degradation occurred;
- the rules analyst explains persisted evidence but cannot detect, approve or
  execute;
- the deterministic policy evaluates all 13 rules at preview and again at
  execution;
- only the authenticated merchant route can issue approval authority; and
- the execution service can call only its configured fake or Test Mode provider
  after a fresh allow decision and atomic approval consumption; and
- the reviewer Test Mode CLI additionally requires an exact plan-specific phrase
  from an interactive human terminal.

## Qualified detector activation

The additive M4 activation gate reads the exact qualified release
`detector_v4_official_blind_5497598109b06d21c625`, verifies the release and
source-report byte digests, the frozen candidate digest, qualification,
integration approval and the absence of failed targets, and then binds runtime
eligibility to `detector_v4_0_0` plus that exact configuration SHA-256.

| Independently pinned artifact | SHA-256 |
| --- | --- |
| Frozen v4 candidate | `c94c10e257599ec59e323bfbc9ba9a1084bf0607c18d0ebdcdfba5a602f9527b` |
| Official blind report | `b39d1e389920b2c2c03ba7dc0ec1feb4694788a03c38bac2e025f125c1552e4d` |
| Qualified release decision | `da633356f34e358327be73bf733165b9993fdbb4d159bf7ace9fa512813a0faa` |

The frozen candidate, report and release files are not edited. Their historical
`runtime_action_eligible=false` fields remain truthful: they were produced before
M4 existed. Runtime activation is a separate M4 fact. Recovery policy sees an
incident as eligible only when its stored flag is true, it is open and synthetic,
and its detector version and configuration digest exactly match the activated
artifacts. Known-failed v1, v2 and v3 identities and forged v4 digests fail
closed.

The API process, worker and one-shot detector command now select this activated
v4 runtime explicitly. The legacy v1 service path remains available only for
historical regression tests. Wheel and container builds package exact copies of
the three required v4 artifacts so startup does not depend on a source checkout.

## Authenticated HTTP surface

Every route is scoped to the single configured P0 merchant and requires
`X-RetryRail-Merchant-Authorization`, compared in constant time against a
server-only value. The actor in an approval record is the configured merchant
operator, never a caller-supplied identity.

| Route | Effect | Replay rule |
| --- | --- | --- |
| `POST /api/v1/incidents/{incident_id}/analyze` | Appends a content-addressed rules brief for the current incident snapshot | Exact snapshot returns the same brief |
| `POST /api/v1/incidents/{incident_id}/plans` | Appends one plan and complete preview policy | Merchant plus caller key; rebinding returns `409` |
| `POST /api/v1/plans/{plan_id}/preview` | Revalidates and returns immutable preview evidence | Read only |
| `POST /api/v1/plans/{plan_id}/approve` | Appends a merchant approval and returns one short-lived bearer once | Replay never repeats the bearer |
| `POST /api/v1/plans/{plan_id}/reject` | Appends a terminal token-free rejection | A plan can be decided once |
| `POST /api/v1/plans/{plan_id}/execute` | Revalidates policy, consumes approval, commits dispatch and invokes the configured provider once | Same plan/key returns the identical receipt; rebinding returns `409` |
| `POST /api/v1/actions/{action_id}/reconcile` | Looks up an ambiguous provider result by stable reference | One lookup receipt; never creates or retries an action |

Plan creation accepts only `payment_id` and `idempotency_key`. Execution accepts
only an idempotency key in the body and the raw approval bearer in
`X-RetryRail-Approval-Token`. Amount, currency, mode, consent, eligibility,
provider target, notifications and policy decisions are server-owned. Extra
caller fields are rejected by strict request models.

## Authoritative preview and approval

Within one transaction, preview creation locks the incident, payment projection
and recovery controls; reloads the immutable normalized source event; checks
merchant, payment, method, issuer, amount, currency, status, synthetic label and
incident-cohort membership; then creates the plan and complete policy context.

Recovery-control defaults are created only for explicitly synthetic projections
and are labelled `synthetic_fixture_default`. A non-synthetic payment without a
first-party control record fails closed. One plan covers exactly one failed
payment, preserving the source amount and currency.

An approval bearer contains 256 random bits. Its lifetime is the earlier of the
configured limit, capped at fifteen minutes, and plan expiry; the exact expiry
instant is invalid. Persistence stores only
`HMAC-SHA-256(approval_token_hmac_key, bearer)`. The separate HMAC key must be
distinct from merchant and webhook secrets in production. The decision binds
merchant, incident, plan, preview-policy identity and both canonical document
digests. A unique append-only consumption row gives concurrent callers one
winner.

Missing, malformed, unknown, cross-plan and cross-merchant bearers share the
non-oracular `APPROVAL_TOKEN_INVALID` response. Expired and already-used tokens
have separate bounded reasons needed by the merchant UI and audit trail.

## Execute-once state machine

Execution reloads the plan and approval under lock, checks exact replay before
expiry, reconstructs current policy facts and persists a new execution-stage
decision. A deny records complete rule evidence but creates no action, consumes
no token and calls no provider. Clearing a stop condition requires a new plan
and approval; a prior execution decision is immutable.

On allow, token consumption, the immutable action row, initial transitions,
recovery-attempt control and sanitized provider dispatch advance in the same
database transaction. That transaction commits before any network I/O. The
provider receives only amount, currency, stable reference, expiry, synthetic
label and `external_notifications_enabled=false`. The state chain is:

```text
previewed -> awaiting_approval -> approved -> executing
                                              |-> succeeded
                                              |-> failed
                                              `-> reconciliation_required
                                                   |-> succeeded
                                                   `-> failed
```

Approval or plan expiry before execution produces a replayable `expired`
receipt without consuming the bearer or calling the provider. A known provider
failure produces a typed terminal error. A timeout before or after creation is
ambiguous and produces `reconciliation_required`; the only permitted next
operation is provider lookup by the stable reference. Reconciliation never calls
create and is itself idempotent.

The provider call always occurs after the pre-network transaction, including for
the deterministic fake. A process failure after dispatch leaves an `executing`
action with enough immutable evidence to permit only reference lookup; execute
replay returns the stored action and cannot re-POST. A successful allowlisted
create or lookup response is recorded in a second transaction as a provider
receipt bound to the dispatch/request digest.

## Model-unavailable analysis

The rules analyst imports no model provider. It validates v1 or v4 statistical
evidence, diagnosis structure, cohort predicates and every cited event against
verified merchant-scoped event records. The persisted brief separates:

- verified observations with exact event citations;
- bounded merchant-local hypotheses;
- explicit unknowns;
- observed at-risk opportunity, labelled as neither forecast nor recovered or
  incremental GMV;
- customer risk and the fact that no notification is sent; and
- the full stop-condition set.

The fallback recommends only the standard Payment Link template, requires
external merchant approval and reports plan availability through the same exact
detector-activation gate used by preview and execution.

## Durable evidence and audit completeness

Migration `0003_m4_preview_approval` creates recovery controls, plans, preview
policy results, approval decisions and token consumptions. Migration
`0004_m4_action_execution` adds execution policy support plus actions,
transitions and reconciliation receipts. Migration
`0005_m4_rules_fallback` adds content-addressed rules briefs. Migration
`0006_m5_provider_dispatch` adds immutable provider dispatches and sanitized
provider receipts and admits only the fake and Razorpay Test Mode targets.

Plan, policy, approval, consumption, action, transition, reconciliation, brief,
dispatch and provider-receipt records reject update and delete in PostgreSQL and
the SQLite test adapter.
Composite foreign keys preserve merchant/incident/plan scope. Unique plan,
approval, reference and idempotency constraints make duplicate logical actions
database-invalid even if process-local coalescing is bypassed.

The audit verifier reconstructs an action contract and checks the correlated
source event, incident, pre-action rules brief, plan, both policy stages,
merchant approval, token consumption, terminal provider transition, recovery
control attempt, provider dispatch, successful provider receipt and, when
needed, reconciliation receipt. It reports the exact missing-fact set and cannot
mark an incomplete chain complete.

## Verification matrix

Focused recovery coverage includes success, known failure, timeout before
create, timeout after create, reconciliation, exact replay, idempotency
rebinding, plan/token expiry, malformed and cross-plan tokens, concurrent use,
kill-switch and mutable control drift, resolved incidents, forged detector
identity, append-only enforcement, raw-token non-persistence, missing audit
evidence and the literal qualified-detector-to-audited-receipt path with no model
provider. Test Mode coverage adds credential/live-key rejection, exact bounded
request and response parsing, redirects, 4xx/5xx classification, oversized and
malformed responses, bounded provider-clock skew, pre-network durability and
process-crash replay. The completed external proof also demonstrates a 200
create followed by crash-equivalent local parsing failure and GET-only recovery
of the same reference. All 13 policy rules retain paired allow/deny and property
coverage.

The complete release-gate command results are recorded in
`docs/PROJECT_STATUS.md`; commands are listed only as passing when they were
actually run.

## Deliberate limits after M5 implementation

- The API is a single-merchant demo boundary using a shared authorization
  secret; per-user IAM, roles, revocation, rate limiting and database row-level
  security are production work.
- The fake provider is process-local and stores no durable external object; it
  is deterministic test evidence, not a Razorpay integration claim.
- The real adapter is deliberately Test Mode-only. One human-approved external
  link and its sanitized complete-audit receipt close the M5 exit gate; neither
  is evidence of live money or production recovery performance.
- The committed impact report uses deterministic synthetic outcomes and must not
  be generalized to live merchant performance.
- The reviewer-facing incident, approval and audit UI begins in M7.
