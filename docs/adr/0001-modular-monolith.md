# ADR-0001: Use a modular monolith for the Buildathon

- Status: accepted
- Date: 2026-09-01

## Context

RetryRail must demonstrate authenticated ingestion, statistical detection,
bounded recovery, measurement and audit within a short Buildathon schedule.
Splitting those domains across deployable services before their contracts are
proven would add network failure modes, duplicated configuration and release
overhead without improving the P0 evidence.

## Decision

Use one Python package and container image with separate API and worker process
entry points. Keep domain modules and typed protocols independent so later
service extraction does not change domain behavior. Use PostgreSQL and a
transactional outbox as the first durable event boundary.

## Alternatives considered

- Independent webhook, detector, agent and action microservices: rejected for
  P0 because operational surface exceeds the evidence it adds.
- Kafka-first event platform: rejected until PostgreSQL outbox throughput or
  integration requirements demonstrate a real need.
- Serverless functions for every stage: rejected because local replay,
  transactions and reviewer reproducibility are clearer in one runtime.

## Consequences

- Transactions, tests and local startup remain simple.
- API and worker failures can still be isolated as separate processes.
- Module boundaries require discipline because the compiler cannot enforce
  network separation.
- A later split must preserve event schemas, idempotency keys and audit facts.

## Revisit when

Revisit only after P0 gates pass and measured load, team ownership or an
external platform contract requires independent scaling or deployment.

