# RetryRail repository instructions

This file is the operating contract for humans and coding agents working on
RetryRail. Read it before changing the repository.

## Mission

Build a reviewer-ready Razorpay AI Buildathon Track 3 submission that detects
payment degradation, performs evidence-backed diagnosis, executes bounded
recovery through Razorpay Test Mode, and measures incremental recovered GMV.

The product requirements in `docs/PRODUCT_REQUIREMENTS.md` are authoritative.
The sequencing and release gates in `docs/BUILD_PLAN.md` are authoritative for
delivery.

## Product invariants

1. The detector, not an LLM, decides whether degradation occurred.
2. The LLM may explain evidence and propose only pre-authorized interventions.
3. A deterministic policy gate validates every mutating action.
4. Consequential actions default to review-first and require approval outside
   the model.
5. Webhook signature validation uses the unmodified raw request body.
6. `x-razorpay-event-id` and merchant scope are used for event deduplication.
7. Processing must tolerate duplicate and out-of-order events.
8. Every write has an idempotency key and a durable action receipt.
9. No API keys, secrets, real card data, or unnecessary PII enter source
   control, logs, prompts, fixtures, screenshots, or videos.
10. No claimed metric may come from a cherry-picked transaction. Business and
    model results must come from a versioned batch and held-out evaluation.
11. Simulated outcomes must be prominently labelled as simulated.
12. The demo must still complete if the LLM is unavailable.

## Scope discipline

Implement P0 requirements before P1 or P2 work. Do not introduce Kafka,
Kubernetes, a vector database, a multi-agent swarm, custom model training,
voice calling, WhatsApp messaging, or a second backend language until all P0
release gates pass.

When a simpler implementation satisfies the acceptance criterion, prefer it.
Production compatibility should be expressed through typed interfaces and
contracts rather than infrastructure theatre.

## Planned structure

```text
apps/web/                  React + TypeScript merchant interface
services/api/              FastAPI modular monolith and worker
contracts/events/          Versioned event schemas
contracts/tools/           Versioned agent-tool schemas
fixtures/webhooks/         Sanitized Razorpay-shaped fixtures
evals/golden/              Deterministic held-out evaluation cases
evals/adversarial/         Safety and reliability cases
docs/                      Product, architecture and delivery evidence
infra/                     Local containers and later deployment definitions
```

Do not create additional top-level directories without documenting the reason
in an architecture decision record.

## Engineering standards

- Python: typed public boundaries, Pydantic validation, `ruff`, static type
  checking and pytest.
- TypeScript: strict mode, accessible Blade components, ESLint and Playwright.
- Database changes: Alembic migrations only; preserve append-only audit facts.
- APIs and tools: typed inputs, typed outputs, typed errors and documented side
  effects.
- Time and money: store timestamps in UTC and money as integer currency
  subunits with an explicit currency.
- Logs: structured, redacted and correlated by merchant, event, incident,
  recovery plan and action identifiers.
- Tests: include negative and failure-path cases, not only happy paths.
- Documentation: update the requirement or decision record when behavior or
  scope changes.

## Required verification before declaring work complete

Run the narrowest relevant checks while developing. Before a milestone is
declared complete, the repository must pass the implemented equivalent of:

```bash
make lint
make typecheck
make test
make test-contract
make test-e2e
make eval
make security-check
```

Never state that a command passed unless it was actually run. If a planned
command is not implemented yet, state that plainly.

## Definition of a reviewer-ready change

- Acceptance criteria are linked to tests or recorded evidence.
- Failure behavior and retry behavior are explicit.
- Security and privacy effects are considered.
- UI includes empty, loading, success, failure, approval and recovery states.
- Metrics and audit fields are emitted where applicable.
- No unrelated cleanup is bundled with the change.

