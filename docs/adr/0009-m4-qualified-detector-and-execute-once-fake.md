# ADR-0009: Activate the qualified detector through an execute-once fake boundary

- Status: Accepted
- Date: 2026-09-05
- Decision owners: RetryRail maintainers
- Milestones: M4.4 and M4.5

## Context

Detector-v4 completed one append-only blind evaluation and qualified for M4
integration. Its frozen artifacts correctly retain
`runtime_action_eligible=false` because no policy, merchant approval or action
receipt boundary existed when they were produced. Editing those artifacts after
the nonce reveal would invalidate the evidence.

M4 must prove a complete recovery loop with no model provider while preserving
four independent controls: exact detector identity, deterministic policy,
external merchant approval and at-most-once action execution. It must also make
provider ambiguity visible instead of turning a timeout into a duplicate create.
No real Razorpay credential or network mutation is authorized until M5.

## Decision

### Additive detector activation

An additive runtime gate verifies the exact v4 candidate, report and release
bytes and requires a qualified release, M4 integration approval and zero failed
targets. It emits a separate versioned activation identity. It does not alter
the frozen candidate models or artifacts.

An incident can satisfy recovery policy only if all of these remain true:

1. the runtime activation is enabled;
2. the incident's stored eligibility flag is true;
3. its detector version and configuration SHA-256 exactly match the activation;
4. it is open; and
5. it is explicitly synthetic.

The API, worker and detector CLI select activated v4 explicitly. Historical v1
execution remains available for regression tests and stays action-blocked.

### Execute-once fake action

M4 supports one action template and one target:
`standard_payment_link_v1` through `deterministic_fake`. The request contains
only integer amount subunits, currency, a stable reference, the synthetic flag
and `external_notifications_enabled=false`.

Execution must:

1. authenticate the configured merchant;
2. validate the raw approval bearer without persisting or logging it;
3. lock and revalidate the plan, approval and current authoritative facts;
4. persist a complete execution-stage policy decision;
5. stop without mutation on any denial;
6. atomically consume approval and persist the action/initial transitions;
7. increment the bounded attempt control; and
8. call the injected fake exactly once and append its typed outcome.

Action, plan, approval, merchant reference and idempotency uniqueness are also
enforced by the database. Exact replay returns the original receipt. Rebinding a
key or plan returns a conflict.

### Ambiguous outcomes

A known failure is terminal. A timeout before or after fake creation is
`reconciliation_required`. Execution does not retry create. The sole follow-up
looks up the stable reference, appends one reconciliation receipt and ends in
verified success or definite failure. Reconciliation has its own idempotency and
one-receipt constraints.

### Rules fallback and audit gate

When no model provider exists, a deterministic analyst validates the incident's
statistics, diagnosis, cohort and verified event citations. It stores a
content-addressed brief that keeps observations, hypotheses, unknowns,
opportunity value, customer risk and stopping conditions distinct. It can only
recommend the existing review-first template.

The M4 release test starts with the activated detector over normalized synthetic
events and ends with a complete audit report for a fake receipt. The audit gate
requires the source event, incident, pre-action brief, plan, both policy stages,
merchant approval, token consumption, terminal transition, attempt control and
any required reconciliation receipt.

## Transaction boundary

The M4 provider call is permitted inside the database transaction only because
the adapter is deterministic, local and side-effect-free outside process memory.
This choice makes approval consumption and the fake receipt indivisible for the
release proof. It is not an approved design for Razorpay HTTP calls.

M5 must introduce a durable dispatch/reconciliation boundary before using Test
Mode. A network timeout must never roll back the only evidence that an external
create may have happened.

## Rejected alternatives

- **Rewrite the frozen v4 release to set its flag true.** Rejected because it
  would falsify the pre-M4 evidence and break append-only reproducibility.
- **Let the rules analyst or an LLM approve.** Rejected because explanation is
  not authority and would violate the merchant-approval invariant.
- **Retry create after a timeout.** Rejected because an after-create timeout can
  produce duplicate recovery actions.
- **Use a Razorpay Test Mode credential in M4.** Rejected because M4's purpose is
  to prove policy and lifecycle safety before external integration.
- **Treat at-risk GMV as recovered value.** Rejected because exposure is not a
  causal outcome; incremental recovered GMV requires M5's held-out experiment.

## Consequences

M4 can demonstrate the complete safe control loop without model availability or
external credentials. Frozen detector evidence remains untouched, and forged or
historically failed detector identities cannot reach execution. Duplicate,
expired, denied, ambiguous and concurrent paths all have deterministic receipts
or bounded errors.

The fake adapter is intentionally not horizontally durable, the API remains a
single-merchant shared-secret boundary, and no recovery metric is a production
or incremental-GMV claim. Those limits must remain prominent in reviewer-facing
documentation and demonstrations.
