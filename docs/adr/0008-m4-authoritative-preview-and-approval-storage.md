# ADR-0008: Authoritative preview and append-only approval storage

- **Status:** Accepted
- **Date:** 2026-09-04
- **Milestone:** M4.3

## Context

M4.2 evaluates a typed policy context but deliberately does not decide where its
facts came from. Passing client or model-provided amount, merchant, consent,
opt-out, attempt or kill-switch values into that evaluator would make an
otherwise deterministic policy unsafe. M4.3 must also issue a short-lived
approval credential without turning a database read into a usable bearer and
must resolve concurrent consumption safely on PostgreSQL and the local SQLite
adapter.

The current product serves one configured merchant and has no production user
identity provider. Runtime detector-v1 incidents remain action-ineligible even
though the separately frozen v4 evaluation qualified for integration review.

## Decision

### Context ownership

The create-plan boundary accepts only a payment identifier and idempotency key;
the incident is in the URL. The server reconstructs all policy facts from the
configured tenant, locked incident/payment/control rows, the immutable source
event and fixed template/configuration. It verifies failed state, tenant,
identity, money, synthetic label and every affected-cohort predicate before
evaluation. The resulting preview includes versioned source provenance and
canonical digests.

M4.3 initializes control records only for explicitly synthetic payment
projections. Missing controls for a non-synthetic payment deny plan creation.
This avoids inventing first-party consent or opt-out claims while keeping the
fully synthetic reviewer demo reproducible.

### Persistence and idempotency

One P0 plan targets one failed payment. The plan ID is deterministic from the
merchant-scoped idempotency key, while a canonical request digest detects key
rebinding. The policy result retains its M4.2 content-addressed identity. Exact
retries return the original immutable documents and timestamps.

Plan, preview-policy, approval-decision and token-consumption facts are
append-only and protected by database update/delete triggers. Unique constraints
enforce one preview stage per plan, one merchant decision per plan, one logical
write per merchant/idempotency key and one consumption per approval. Current
approval status is derived from the immutable decision, optional consumption
fact and current time rather than by rewriting history.

### Merchant boundary

The four M4.3 routes require a server-configured shared merchant authorization
secret, checked in constant time. The recorded actor ID is also server
configuration. This is a bounded single-merchant demo mechanism, not a claim of
per-user production IAM. The model receives neither value and has no approve or
reject tool.

### Bearer design

Approval uses a 256-bit random opaque bearer. Only a keyed HMAC-SHA-256 digest is
stored. The raw value is returned once and is never repeated on idempotent API
replay. Merchant authorization and token-HMAC secrets are independently
configured, production-required and distinct.

The token expires at the earlier of its configured lifetime, capped at fifteen
minutes, and plan expiry. Consumption verifies the merchant, incident, plan,
policy-result identity and both canonical digests, rejects exact expiry, locks
the decision and appends a unique consumption fact. A uniqueness conflict is a
used-token result, never permission to continue.

### Deferred authority

M4.3 adds no execute endpoint, recovery action row, fake/provider adapter,
Razorpay credential or notification. Token consumption is an internal primitive
for M4.4, where it must share the action-receipt transaction with a fresh
execution-stage policy evaluation.

## Consequences

- A caller or model cannot alter policy facts through the HTTP body.
- A database snapshot cannot reveal a usable approval bearer without the
  separately managed HMAC key.
- History remains inspectable because approval expiry/consumption does not
  overwrite the original decision.
- Response loss after first bearer delivery requires an explicit future
  invalidation/reissue flow; silently reconstructing or storing the bearer is
  forbidden.
- Real Test Mode payments remain blocked until a first-party recovery-control
  source is implemented and versioned.
- Per-user authentication, authorization roles, revocation, WAF rate limits and
  row-level security remain production work and must not be implied by this ADR.
