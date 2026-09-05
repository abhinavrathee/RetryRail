# ADR-0014: Preserve bounded trace lineage and provision local release observability

**Status:** Accepted
**Date:** 2026-09-05
**Milestone:** M8

## Context

RetryRail already emitted low-cardinality metrics and durable identifiers, but
the asynchronous event, detector and recovery stages did not share a durable
trace lineage. Logs also depended on every call site remembering not to render
a credential. M8 requires reviewer-visible observability without weakening the
frozen detector, policy, approval, provider or experiment evidence boundaries.

The original M3–M7 tables include immutable facts whose canonical documents and
digests are release evidence. Adding operational fields to those documents
would create unnecessary drift and would blur audit evidence with telemetry.

## Decision

1. Every HTTP response carries a valid W3C `traceparent` and `X-Trace-Id`.
   A valid inbound version-00 trace ID is continued with a fresh server span;
   malformed or all-zero input is ignored and replaced.
2. A new append-only `trace_links` ledger records only merchant scope, bounded
   entity type, opaque entity ID, trace ID, span ID, parent span ID and UTC
   creation time. It contains no payload, contact data, token or credential.
3. Event and outbox links are committed in the same transaction as ingestion.
   Detection links an incident to one verified evidence event. Plan and action
   creation then copy the same trace ID and parent the next deterministic span.
   Idempotent replay returns the existing lineage rather than rebinding it.
4. Migration `0008_m8_trace_lineage` backfills existing event, outbox, incident,
   plan and action rows deterministically, then installs update/delete rejection
   triggers. It does not alter any frozen evidence document.
5. Structured logging applies recursive, key- and value-aware redaction after
   context binding and before JSON rendering. Bounded reason codes, versions and
   aggregate measurements remain visible. A failed model attempt records its
   bounded outcome and elapsed time in metrics and an incident-correlated log;
   unavailable cost remains explicit rather than invented.
6. Prometheus and Grafana run only through the optional local
   `observability` Compose profile. Patched Prometheus 3.5 LTS and Grafana 13.2
   images are immutable digest pins. Grafana update/plugin checks and mutable
   plugin installation are disabled; it is provisioned read-only with panels
   for ingestion, detector, policy, action, experiment and advisory-model
   signals.
7. Metric labels remain finite enums or allowlisted reason codes. Customer
   contact data, payment IDs, incident IDs and free-form provider errors are
   prohibited as labels.
8. Payment and experiment correlation stays in the authoritative business
   evidence: event/action records share `payment_id`, while the frozen M5
   assignment and outcome artifacts bind `payment_id`, `experiment_id` and
   `assignment_id`. The trace ledger does not copy or mutate those facts.

## Consequences

- Reviewers can prove one event → incident → plan → action lineage across the
  HTTP/worker boundary without searching payload text.
- Existing evidence contracts and content hashes remain unchanged.
- Trace rows are operational correlation evidence, not authorization and not a
  substitute for the recovery audit verifier.
- The local dashboard is credible release evidence but is not a hosted
  production monitoring service. Production exporters, retention, alert routing
  and access control remain deployment work.
- Deterministic trace/span IDs are used only when no live request context exists
  or when backfilling legacy rows. They are opaque SHA-256 prefixes and carry no
  secret material.

## Rejected alternatives

- **Put trace fields into every frozen domain document:** rejected because it
  would rewrite evidence whose meaning is already hash-bound.
- **Use business identifiers as Prometheus labels:** rejected due to cardinality
  and privacy risk.
- **Treat logs as the source of lineage:** rejected because logs can be sampled,
  rotated or unavailable after a crash.
- **Make Grafana part of the required product runtime:** rejected because loss
  of a dashboard must not stop ingestion or recovery safety controls.

## Verification

- `test_m4_model_unavailable_detect_to_audited_receipt_release_gate` proves the
  complete event → incident → plan → action parent chain and the independent
  complete recovery audit.
- `test_m8_upgrade_backfills_event_to_outbox_trace_lineage` proves a populated
  pre-M8 database upgrades with preserved lineage.
- Migration round-trip tests prove safe downgrade/re-upgrade and trace-row
  immutability.
- `test_m8_observability.py` verifies trace parsing, recursive redaction,
  required metric families, two scrape targets, six dashboard sections and
  immutable image pins.
