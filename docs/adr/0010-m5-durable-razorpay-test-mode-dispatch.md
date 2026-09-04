# ADR-0010: Put Razorpay Test Mode behind a durable create-once dispatch boundary

- Status: Accepted
- Date: 2026-09-05
- Decision owners: RetryRail maintainers
- Milestone: M5
- Supersedes: ADR-0009's fake-only in-transaction provider call

## Context

M4 proves policy, external merchant approval and action-state safety with a
process-local fake. Its provider call could not lose external state because the
fake had no network side effect. A Razorpay HTTP request is different: the
remote create may succeed even when the client times out or the RetryRail
process exits before storing the response. Rolling back the local transaction
and retrying POST would risk two Payment Links.

The M5 adapter must use Razorpay Test Mode only, send no customer contact, keep
notifications off and retain enough sanitized evidence for a reviewer to verify
one real test action. Credentials and raw provider error bodies must remain
outside persisted facts and logs.

## Decision

Execution is split into two database transactions around one network call.

1. Revalidate the plan, source evidence, stopping rules and execution policy.
2. Consume the merchant approval token.
3. Append the `executing` action and increment its attempt control.
4. Append an immutable provider-dispatch record containing the stable
   reference, canonical request digest and PII-free request document.
5. Commit all four facts before permitting network access.
6. Perform exactly one create POST.
7. In a new transaction, append either a sanitized provider receipt, a typed
   known failure, or `reconciliation_required`.

If the process stops after step 5, the durable action remains `executing`.
Replaying execute returns that original action and cannot call create again.
The only recovery operation is a GET lookup by the stable `reference_id`.
Lookup may be repeated when unavailable, but it never calls a mutating endpoint.

Both the fake and Test Mode targets use this boundary so the tested state
machine matches the external path. Database uniqueness binds one dispatch and
one sanitized provider receipt to one action. Update/delete triggers preserve
both as audit facts.

## Razorpay boundary

- Configuration admits only a complete credential pair whose key ID starts
  with `rzp_test_`; a live key is rejected even when the fake target is active.
- Basic Authentication is constructed only inside the HTTP client. Secret
  values are Pydantic `SecretStr` instances and never enter action documents.
- The base URL is fixed to `https://api.razorpay.com`, redirects are disabled,
  response bodies are size-bounded, and connect/read/write/pool timeouts are
  finite.
- Create accepts only an integer amount, three-letter currency, stable
  reference and expiry. `accept_partial=false`, SMS/email notification are
  false, reminders are false, and no customer object is sent.
- Only provider ID, reference, status, amount, currency, HTTPS short URL and
  timestamps are admitted into the sanitized receipt.
- Determinate 4xx failures are typed. Transport errors, 5xx responses and an
  invalid successful response are ambiguous and require lookup rather than
  POST retry.

## Consequences

RetryRail provides at-most-one local dispatch authority and one logical action
under duplicate requests, timeouts and post-create crashes. No distributed
system can claim exactly-once remote execution without provider idempotency;
the stable reference plus lookup-only recovery is the explicit safety strategy.

The real Test Mode link still requires the normal non-model merchant approval.
Test Mode is not production and its receipt is not evidence of live revenue.
The current single-merchant shared-secret authorization remains a bounded demo
control rather than production IAM.

## Rejected alternatives

- **Retry POST after a timeout.** Rejected because the original create may have
  succeeded remotely.
- **Store dispatch and response in one transaction after the HTTP call.**
  Rejected because a crash can erase the only local evidence of an accepted
  request.
- **Send a customer phone number or email for the demo.** Rejected because the
  Test Mode proof needs no PII or external message.
- **Accept a live-mode key and rely on operator care.** Rejected because the
  safety boundary must fail closed in configuration and in the adapter.
