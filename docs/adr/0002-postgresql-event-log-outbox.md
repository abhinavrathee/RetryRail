# ADR-0002: Use a PostgreSQL event log and transactional outbox

- Status: accepted
- Date: 2026-09-01

## Context

RetryRail must acknowledge a webhook only after its authenticated event is
durable, then continue processing after process crashes without duplicating a
logical event. Adding a broker before this product loop is proven would create
another consistency boundary and an additional service for reviewers to run.

## Decision

Store the sanitized and normalized event in an immutable PostgreSQL table. In
the same transaction, insert one idempotent projection message into an outbox.
A dedicated worker claims available rows with `FOR UPDATE SKIP LOCKED`, a
finite lease and a worker identity. It completes projection and the outbox
receipt in one transaction. Expired claims are reclaimable; transient failures
use capped exponential retry; terminal or exhausted work is retained as a
dead-letter row.

Use SQLAlchemy's async engine with psycopg 3 for application, worker and
Alembic connections. This differs from the early `asyncpg` preference in the
build plan: one supported driver now covers async runtime and migration paths,
reducing driver-specific behavior without changing the database contract.

SQLite is allowed only as a hermetic compatibility adapter for local tests.
It enables foreign keys and equivalent immutability triggers. Production
configuration rejects every non-PostgreSQL URL, and CI runs the same integration
suite against PostgreSQL 16.

## Alternatives considered

- Kafka or Kinesis first: rejected because it cannot make the database event
  and broker publish one transaction without another coordination mechanism.
- In-memory background tasks: rejected because an API crash after acknowledgement
  would lose work.
- Updating payment state in the webhook request: rejected because downstream
  failure would increase acknowledgement latency and complicate retries.
- `asyncpg` plus a second synchronous migration driver: rejected for this
  milestone because it adds dependencies without an acceptance benefit.

## Consequences

- Acknowledged events and their processing intent commit atomically.
- Duplicate merchant/event identities converge on one event and one outbox row.
- Database load, lease duration and dead-letter operations must be monitored.
- The event table is append-only; corrections require a new versioned event.
- SQLite passing is useful local evidence but is not a substitute for the
  PostgreSQL CI run.

## Revisit when

Revisit only when measured outbox throughput, retention or organizational
ownership requires a broker. Preserve event identity, ordering rules,
idempotency keys and durable receipts during any migration.
