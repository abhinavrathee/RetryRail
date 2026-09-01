# RetryRail architecture

## Current release boundary

This document describes the implemented M0–M2 foundation, contract/data and
authenticated-event boundary, not the complete target system. The authoritative
product behavior remains in `PRODUCT_REQUIREMENTS.md`; sequencing remains in
`BUILD_PLAN.md`.

```mermaid
flowchart LR
    Browser[Merchant browser] --> Web[React + Blade shell]
    Web -->|typed readiness request| API[FastAPI process]
    Truth[M1 synthetic generator] --> Contracts[Versioned schemas + manifest]
    Contracts -->|protected raw-body replay| API
    Razorpay[Razorpay payment webhook] -->|exact bytes + HMAC| API
    API -->|one transaction| Events[(Immutable events)]
    API -->|same transaction| Outbox[(Transactional outbox)]
    Outbox -->|lease + bounded retry| Worker[Projection worker]
    Worker --> Projection[(Monotonic payment state)]
    Razorpay -. M5 outbound action .-> API
```

Solid arrows are implemented and tested. The only dashed arrow is the explicit
future outbound-action boundary. No M2 component can call Razorpay or mutate a
customer-facing payment action.

## Decisions implemented in M0–M2

- Python 3.12-compatible FastAPI modular monolith with typed Pydantic
  boundaries.
- React 18, TypeScript strict mode, Vite and Razorpay Blade for the merchant
  shell.
- Alembic-managed PostgreSQL 16 event, outbox and projection tables; SQLite is
  a hermetic local-test adapter and is rejected in production.
- One backend image reused by API and worker processes.
- Committed uv and pnpm lockfiles, pinned CI actions and explicit dependency
  build-script allowlisting.
- A versioned normalized payment-event schema generated from its Pydantic model.
- Strict contracts for incidents, recovery plans, action receipts, detector
  evaluation, delivery instructions and experiment design.
- A SHA-256-derived 2,880-attempt truth set with physically separated tuning
  and held-out labels, plus a committed manifest identity.
- Exact-body verification before parsing, bounded request allocation,
  duplicate-key rejection and allowlist-only durable storage.
- Merchant/event uniqueness plus database-level event immutability.
- Lease-based `SKIP LOCKED` outbox processing with capped retry, explicit
  dead-letter state and monotonic payment projection.
- Protected, production-disabled replay plus redacted low-cardinality metrics
  and database/migration readiness.

## Trust boundaries

1. Webhook bytes remain untrusted until raw-body HMAC succeeds. The HTTP route
   reads a bounded exact byte stream and does not decode JSON before
   constant-time signature verification.
2. Normalization uses an allowlist. Contact, email, VPA, notes, card and token
   fields cannot enter the normalized event contract.
3. Production configuration refuses placeholder webhook secrets, non-Postgres
   stores, enabled replay and localhost CORS origins.
4. The browser receives no credential-bearing environment variable. Only
   values prefixed `VITE_` may enter its build.
5. Detector truth labels live outside normalized runtime events, preventing
   threshold code from receiving held-out labels through the event contract.
6. Event rows reject update and delete in the database. Outbox and projection
   rows are merchant-scoped, and every processing intent has a stable
   idempotency key and durable terminal receipt.
7. The future model boundary and external mutation boundary remain absent; M2
   cannot perform any payment or customer action.

## Dependency boundary

Razorpay Blade publishes one universal package with web and React Native peers.
RetryRail imports its conditional web export and intentionally ignores the
native-only peers. TypeScript remains strict for first-party code while
`skipLibCheck` isolates upstream declaration conflicts. Production build and a
real Chromium test verify the web integration.

The Blade provider is lazy-loaded: the initial JavaScript entry is capped at
200 kB, the isolated design-system chunk at 800 kB and total JavaScript at
1 MB. The production build fails if any budget is exceeded.

Blade 12.121.0 pins `ts-deepmerge` 6.2.0, affected by GHSA-87mf-gv2c-c62c.
The workspace overrides it to 8.0.0 and redirects Blade's removed default
export through a four-line compatibility module. An unsafe-key regression test,
production build and Chromium test are release gates for that adapter.

## Next architecture increment

M3 may read normalized events and projections to add deterministic rolling
aggregates, detection, attribution and incident lifecycle. It may not weaken
the M2 authentication, immutability, tenant scope, replay separation or
monotonic-state rules, and detector decisions remain outside the LLM.
