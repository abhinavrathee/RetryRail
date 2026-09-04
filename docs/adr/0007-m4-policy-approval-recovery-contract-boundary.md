# ADR-0007: Freeze the M4 policy, approval and recovery contract boundary

- Status: accepted; M4.1 contract boundary frozen
- Date: 2026-09-04

## Context

Detector v4 has qualified for integration, but qualification is evidence, not
mutation authority. Runtime recovery remains disabled until deterministic
policy, merchant approval and execute-once persistence are implemented and
tested. The model must never be able to convert an incident or proposal into an
external action by itself.

M1 intentionally froze proposal-only `recovery_plan.v1` and evidence-only
`action_receipt.v1` schemas before recovery behavior existed. Those schemas are
public, versioned artifacts and cannot be silently edited. They also do not
represent the complete M4 boundary: policy inputs and results, approval-token
lifecycle, the deterministic fake provider, typed execution errors and
actor-authorized action transitions were not yet present.

M4.1 must define those semantics before a mutating route, database migration,
token issuer, policy implementation or provider adapter can be introduced.

## Decision

Preserve the M1 schemas byte-for-byte and add four separately named M4 schemas:

| Contract | Authority and purpose |
| --- | --- |
| `recovery_template.v1` | Defines the sole pre-authorized P0 effect and its non-negotiable safety properties |
| `policy_result.v1` | Records the complete PII-free policy context, every rule outcome and the derived allow/deny decision |
| `approval_record.v1` | Records an authenticated merchant decision and only the hash and lifecycle of an approval credential |
| `recovery_action.v1` | Joins plan, payment, policy, approval, target, money, idempotency, transitions and typed provider outcome evidence |

The existing `recovery_plan.v1` remains the immutable proposal contract used by
M4. It never carries execution authority. The existing `action_receipt.v1`
remains valid M1 evidence; `recovery_action.v1` adds the M4 actor, provider and
authority bindings without changing its meaning.

The schema exporter pins the canonical SHA-256 of both M1 recovery schemas and
fails before writing if either source model would alter the published v1 bytes.
Future intentional changes require a separately named schema version.

### Recovery template boundary

P0 admits one template: `standard_payment_link_v1`. It may describe only the
creation of a Standard Payment Link. It must preserve the verified source
amount, keep external notifications disabled, require external merchant
approval and reject production execution. The only contract-level targets are:

- `deterministic_fake`, used by M4 integration and failure tests; and
- `razorpay_test_mode`, reserved for the M5 adapter and explicit sandbox proof.

No live-mode target exists in the enum. Adding another effect, target or
notification behavior requires a new contract version and security review.

### Deterministic policy boundary

Policy evaluates a PII-free snapshot at `preview` and again at `execution`.
Every result must contain all rules exactly once in canonical order:

1. merchant scope;
2. detector incident action eligibility;
3. operating mode;
4. template enablement;
5. original amount equality;
6. currency equality;
7. contact consent when contact is required;
8. customer opt-out;
9. attempt cap;
10. cooldown;
11. plan expiry;
12. merchant kill switch; and
13. already-recovered status.

Each rule has an allowlisted pass and deny reason. The aggregate result is
`allow` only when every rule passes; the contract rejects a missing, duplicate,
reordered or hidden denial. A policy result records an authorization decision,
but it is not an approval credential and cannot call an adapter.

Unknown recovery-template names fail schema validation before policy. A valid
known template can still be denied when it is disabled in the current merchant
policy.

### Approval boundary

Only an authenticated merchant actor outside the model may approve or reject a
plan. An approved credential is bound to merchant, incident, plan, policy
result, and canonical plan and policy-result digests. The server may return the
opaque bearer value once in M4.3, but persistence, logs, audits, schemas and
receipts may contain only a server-keyed token hash. Database compromise must
not reveal a usable approval bearer.

Approval credentials are single-use and valid for no more than fifteen minutes.
Their valid states are `issued`, `consumed`, `expired` and `rejected`. Rejected
decisions contain no token lifecycle fields. Consumed credentials require a
consumption timestamp after issuance and strictly before expiry. M4.3 must use
an atomic compare-and-consume operation so concurrent requests cannot both
succeed.

### Action boundary and state graph

Every recovery action binds one merchant, incident, plan, payment, verified
amount and currency, plan digest, stable provider `reference_id`, idempotency
key, preview policy result and execution target. Approval becomes mandatory at
`approved`; a fresh execution policy result becomes mandatory at `executing`.
No customer contact field exists and notifications remain a literal `false`.

```text
none -> previewed -> awaiting_approval
                       |-> approved -> executing -> succeeded
                       |           |             |-> failed
                       |           |             `-> reconciliation_required
                       |           |                          |-> succeeded
                       |           |                          `-> failed
                       |           `-> expired
                       |-> rejected
                       `-> expired
```

The contract binds security-sensitive transitions to actors:

- policy engine: initial successful preview;
- system: awaiting-approval and pre- or post-approval expiry transitions;
- merchant: approve or reject;
- worker: begin execution and drive reconciliation; and
- the selected fake or Test Mode provider: record the immediate provider
  outcome.

An actor for one target cannot attest an outcome for the other target. Success
requires a provider action identity and verification time. Known failures use
typed categories: invalid input, unauthorized, rate limited or upstream
failure. An ambiguous outcome is `reconciliation_required`, explicitly forbids
blind retry and must be reconciled before another create attempt.

### Side-effect classification

| Operation | Side effect | Idempotency/authority rule in later gates |
| --- | --- | --- |
| Read incident evidence | None | Merchant scope; no model or mutation authority |
| Create recovery plan | Durable internal write | Stable plan idempotency key; qualified incident only |
| Evaluate/preview policy | None during evaluation | Persisted result is a separate idempotent internal write |
| Approve or reject | Durable internal write | Authenticated merchant; plan/result digest binding |
| Execute with deterministic fake | Simulated external mutation | Single-use approval, fresh policy allow and stable action key |
| Execute with Razorpay Test Mode | Test Mode external mutation | M5 only; same gates plus reconciliation by stable reference |
| Reconcile | Provider read plus durable internal write | Never creates a second provider action |

No operation permits a production mutation. M4.1 adds no route and performs no
runtime write or provider call.

## Threat analysis

| Threat | Frozen boundary response | Required implementation evidence |
| --- | --- | --- |
| Model self-approves or executes | Policy result is not a credential; approval actor is literal `merchant`; model has no action adapter | M4.3/M4.5 misuse and model-unavailable tests |
| Cross-merchant plan or token use | Policy compares request and resource merchant; approval and action bind merchant and plan | Allow/deny and API not-found tests |
| Amount discount or currency substitution | Context carries source and proposed values; explicit equality rules; action carries integer subunits and currency | M4.2 amount/currency deny tests |
| Detector result bypass | Incident action eligibility is a mandatory policy rule | Blocked detector and forged-plan tests |
| Preview becomes stale | Execution requires a newly persisted execution-stage policy result | Policy-change-before-execute test |
| Approval replay, expiry or concurrent use | Hashed, short-lived, single-use credential and distinct pre-/post-approval expiry paths | Reuse, both expiry paths and concurrent-consume tests |
| Database hash used as bearer | Raw bearer is never persisted; M4.3 uses a server-keyed hash | Storage/log redaction tests |
| Kill switch races execution | Kill switch is re-read by the execution-stage policy evaluation | Toggle-before-execute test |
| Timeout after provider success duplicates action | Stable reference and idempotency keys; ambiguous result forbids retry | M4.4 timeout/reconcile test |
| Fake evidence presented as real | Fake target requires `synthetic=true` and has a distinct actor/side-effect class | Contract and UI-label tests |
| Live-mode call | No production target exists; credentials remain absent in M4 | Configuration and adapter-boundary tests |
| Customer contacted unintentionally | Template and action fix external notifications to `false`; no contact data crosses the contract | Schema and provider-request tests |

## Alternatives considered

- Edit the M1 schemas in place: rejected because they are already published and
  frozen; silent changes would erase evidence and violate the contract policy.
- Let the model emit a generic tool name or provider request: rejected because
  it would cross both the template allowlist and mutation boundaries.
- Use a signed self-contained token without durable state: rejected because
  expiry alone cannot guarantee single-use consumption under concurrency.
- Enable the real Test Mode adapter in M4: rejected because M4 must first prove
  policy, approval and idempotency deterministically without credentials.

## Consequences

The M4.2 policy implementation has a closed, testable input and output surface.
M4.3 can implement token issuance without deciding token semantics during
endpoint work. M4.4 can persist an action state machine and fake-provider
receipt without changing the security contract. The extra explicit fields and
canonical rule order add validation work, but they prevent partial policy
evaluation, ambiguous authority and unauditable retries.

M4.1 does not enable recovery. Runtime action eligibility remains gated, there
is no mutating API, and no Razorpay credential is required. M4.2 now implements
the deterministic evaluator with paired allow/deny evidence for every frozen
rule; `docs/POLICY.md` records its exact truth and time boundaries. The next
gate is M4.3 context assembly, preview persistence and external merchant
approval.
