# M2 authenticated event pipeline

## Release boundary

M2 turns the frozen synthetic contracts into an authenticated, durable and
replayable event path. It does not detect incidents, call a model, execute a
Razorpay action or claim recovered GMV.

```text
exact request bytes
  -> bounded body reader
  -> HMAC-SHA256 verification
  -> duplicate-key-safe JSON decode
  -> allowlist sanitization + v1 normalization
  -> one transaction: immutable event + outbox intent
  -> lease-based worker
  -> monotonic payment projection + completed receipt
```

The webhook returns 2xx only after the event/outbox transaction commits. A
duplicate returns the original internal event identity and does not create a
second processing chain.

## HTTP contract

```text
POST /v1/merchants/{merchant_id}/webhooks/razorpay
Content-Type: application/json
X-Razorpay-Event-Id: <merchant-scoped event identity>
X-Razorpay-Signature: <HMAC-SHA256 over the exact body bytes>
```

Successful responses are `202` with `accepted` or `duplicate`. Failures expose
only bounded reason codes:

| Condition | Status | Reason code |
| --- | ---: | --- |
| Missing or invalid signature, including post-signing mutation | 401 | `WEBHOOK_SIGNATURE_MISSING` or `WEBHOOK_SIGNATURE_INVALID` |
| Unsupported content type | 415 | `CONTENT_TYPE_UNSUPPORTED` |
| Invalid length or body above the configured limit | 400/413 | `CONTENT_LENGTH_INVALID` or `WEBHOOK_BODY_TOO_LARGE` |
| Invalid JSON, duplicate object key or invalid event schema | 422 | `WEBHOOK_PAYLOAD_INVALID` |
| Same merchant/event identity with changed allowlisted content | 409 | `WEBHOOK_EVENT_IDENTITY_CONFLICT` |
| Event/outbox transaction unavailable | 503 | `WEBHOOK_PERSISTENCE_UNAVAILABLE` |

Unknown fields are discarded before storage. Customer contact, email, VPA,
card, note and token values cannot enter the sanitized or normalized records.
The payload hash is calculated from canonical sanitized content, not from
sensitive discarded fields.

## Durable records

`payment_events` has a unique `(merchant_id, razorpay_event_id)` identity and
database triggers that reject update and delete. It stores UTC times, integer
currency subunits, the allowlisted Razorpay-shaped document and the normalized
v1 event. Check constraints require schema `1.0.0`, a verified signature status
and one of the three allowlisted payment event types.

`outbox_messages` has a unique event/topic pair and idempotency key. Its states
are:

```text
pending -> processing -> completed
                 |  \
                 |   -> dead_letter (terminal or attempts exhausted)
                 -> retry -> processing

processing -- expired lease --> processing by another worker
```

Each claim increments `attempts`. Retry delay is deterministic exponential
backoff capped at five minutes. Error storage is a low-cardinality reason code;
driver messages and event content are not persisted as error text. Terminal
and successful receipts retain the final claimant, attempt count and most
recent bounded error so a recovered retry remains auditable.

`payment_projections` is keyed by merchant and payment. State rank is
`failed < authorized < captured`. A lower or equal event is processed and its
outbox receipt completes, but it cannot regress the payment state. Amount,
currency, method, non-null issuer and synthetic/real classification are
immutable for a payment identity; a conflict is dead-lettered for review.

## Replay

Synthetic replay uses the committed M1 manifest and raw-body serializer. It
applies the exact valid, invalid, missing-signature, modified-body, duplicate,
delayed and out-of-order delivery instructions through the same ingestion
service.

Replay is disabled by default, cannot be enabled in production, and the HTTP
boundary requires a constant-time-checked local replay token.

```bash
uv run retryrail-db upgrade
RETRYRAIL_REPLAY_ENABLED=true uv run retryrail-replay --mode required_cases
```

The protected local API is `POST /v1/demo/replay`; responses are aggregate,
prominently marked synthetic and contain no incident or held-out truth labels.
It accepts only the required reliability-case mode, so held-out partitions
cannot be injected through an HTTP demo call. Repeated replay is safe: an
earlier accepted event becomes a duplicate, not a mismatch or a second chain.

## Operations

- `/health/live` checks only the API process.
- `/health/ready` checks database connectivity and the exact Alembic head.
- `/metrics` exposes API-process ingestion, signature, duplicate and latency
  metrics without merchant/event labels.
- The worker serves its own private-network Prometheus registry on port 9101,
  including processing lag, claim/completion, retry, dead-letter and projection
  decisions.
- API, replay and worker application logs are structured and correlate only
  bounded merchant, event, outbox and reason identifiers; bodies, secrets and
  driver exception text are excluded.
- Compose runs a finite migration service before API or worker startup; neither
  process silently changes schema.
- `retryrail-db schema-check` fails when ORM metadata would require an
  uncommitted migration.

## Acceptance evidence

| Required behavior | Executable evidence |
| --- | --- |
| Invalid signature and modified signed body rejected before persistence | `services/api/tests/integration/test_webhook_ingestion.py` |
| Three deliveries converge on one logical event/outbox chain | `services/api/tests/integration/test_webhook_ingestion.py` |
| Crash after event commit is recovered through an expired lease | `services/api/tests/integration/test_outbox_projection.py` |
| Captured-before-authorized remains captured | `services/api/tests/integration/test_outbox_projection.py` |
| Poison work dead-letters without blocking healthy work | `services/api/tests/integration/test_outbox_projection.py` |
| Migrations round-trip and events reject update/delete | `services/api/tests/integration/test_replay_and_migrations.py` |
| Required replay reconciles projections with persisted events | `services/api/tests/integration/test_replay_and_migrations.py` |
