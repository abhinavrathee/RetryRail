# M8 observability, security and release hardening

## Scope and safety boundary

M8 makes the implemented M0–M7 product reviewable and release-ready. It does
not deploy RetryRail, enable Razorpay Live Mode, change detector thresholds,
grant an LLM action authority or rewrite any frozen evaluation artifact.

## Implemented release controls

- W3C-compatible request context with a fresh server span and response headers.
- Immutable `trace_links` lineage across event, outbox, incident, plan and
  action, including deterministic legacy backfill.
- Recursive structured-log redaction for authorization, credentials, secrets,
  tokens, signatures, customer/contact fields, credential-bearing URLs and
  recognized OpenAI/Razorpay key shapes.
- Low-cardinality Prometheus series for ingestion, detector, policy, action,
  treatment/control recovered GMV, incremental value and advisory-model
  outcome/latency/cost/fallback signals. Failed provider attempts still emit a
  latency observation and an incident-correlated structured log with an
  explicit unavailable cost estimate.
- A digest-pinned, optional local Prometheus 3.5.5 LTS/Grafana 13.2.0 Compose
  profile with a provisioned six-section dashboard, outbound update/plugin
  checks disabled and no mutable plugin installation at startup.
- Database readiness against the exact Alembic head, graceful API resource
  disposal and worker SIGINT/SIGTERM shutdown with metrics-server cleanup.
- Ruff, strict mypy, Bandit, GitGuardian-compatible repository scanning,
  Python dependency audit and fail-closed pnpm audit in the release gates.

## Trace lineage

| Stage | Durable entity | Parent | Mutation behavior |
| --- | --- | --- | --- |
| Ingestion | `event` | root | Event and trace link commit together |
| Outbox | `outbox` | event span | Link commits with the same ingestion transaction |
| Detection | `incident` | verified evidence-event span | Existing incident lineage cannot be rebound |
| Recovery preview | `plan` | incident span | Link commits with immutable plan evidence |
| Execution | `action` | plan span | Link commits before provider network I/O |

The trace ledger stores opaque identifiers only. Authorization still comes
solely from server-owned policy facts plus merchant approval; complete audit is
still decided by `RecoveryAuditVerifier`.

The wider FR-AUD-003 correlation does not duplicate business identifiers into
telemetry. `payment_events.payment_id` and the action receipt bridge the durable
trace to the payment; the hash-bound assignment and outcome artifacts use that
same payment identifier together with `experiment_id` and `assignment_id`.
Thus payment and experiment evidence remain searchable without turning any of
those identifiers into Prometheus labels or rewriting frozen M5 artifacts.

## Mandatory failure matrix

`make failure-matrix` executes the deterministic cases below. The model rows do
not require a network key; the committed 24-case bakeoff is checked separately
for arithmetic and selection integrity.

| Required failure | Executable evidence | Expected result |
| --- | --- | --- |
| Invalid webhook signature | `test_invalid_or_modified_signature_is_rejected_before_persistence` | Reject before persistence |
| Duplicate event ID | `test_triple_delivery_creates_one_event_and_one_outbox_chain` | One event/outbox; stable domain trace |
| Out-of-order payment events | `test_captured_before_authorized_never_regresses_projection` | Final projection never regresses |
| Worker crash | `test_expired_worker_claim_is_recovered_without_event_loss` | Expired lease is safely reclaimed |
| Detector low sample | `test_heldout_hard_negative_never_becomes_action_eligible` | Observe only; no action eligibility |
| Conflicting root-cause evidence | M6 report case `scope_conflicting_signal` | Abstain with bounded uncertainty |
| Model timeout | `test_openai_adapter_maps_refusal_and_timeout_without_body` | Deterministic fallback; no raw body retained |
| Malformed model output | `test_openai_adapter_fails_closed_after_repair_limit` | Bounded repair then fallback |
| Policy changes after preview | `test_execution_revalidates_mutable_stop_conditions_without_provider_call` | Fresh deny; zero provider calls |
| Approval token reused | `test_token_binding_and_atomic_single_use` | One consumption winner |
| Payment Link timeout after success | `test_test_mode_dispatch_survives_crash_and_reconciles_without_second_create` | GET by stable reference; no second POST |
| Customer already recovered | `test_execution_revalidates_mutable_stop_conditions_without_provider_call` (`already_recovered`) | Stop before provider call |
| Merchant kill switch | `test_execution_revalidates_kill_switch_and_records_complete_denial` | Complete policy denial; no mutation |

## Commands

```bash
make observability-check
make failure-matrix
make m8-check
make check
```

To view the local dashboard after the normal stack is healthy:

```bash
docker compose --profile observability up --build -d
```

Grafana is then available only on <http://127.0.0.1:3000>; Prometheus is on
<http://127.0.0.1:9090>. Anonymous Grafana Viewer access is intentionally
limited to loopback and local demo use.

## Clean-checkout release protocol

1. Clone the exact pushed commit into a new directory with no ignored files.
2. Run `make bootstrap` and record elapsed wall time.
3. Run `make check` and record elapsed wall time and test summaries. The test
   target first reconstructs the ignored, deterministic detector-v4 derived
   inputs from their committed reveal receipts; it never assumes local cache.
4. Run `docker compose --profile observability config --quiet`, build the API,
   worker and web images, then start the isolated stack.
5. Verify migration head, API live/readiness, worker metrics, Grafana health,
   dashboard provisioning, non-root application users and the complete demo
   action audit.
6. Run repository/history secret scans and both dependency audits; any
   unexplained High/Critical result blocks release.

The final observed commit, timings and CI URL are recorded in
`PROJECT_STATUS.md` only after those commands actually pass.

## Known production gaps

- No public deployment, external TLS/WAF, production DNS or hosted monitoring
  is included in M8.
- Grafana anonymous access is a loopback-only demo setting, not production IAM.
- W3C context and durable lineage are implemented; a vendor-neutral remote
  trace exporter, sampling backend and alert routing are not.
- RetryRail remains single-merchant at runtime and lacks production RBAC,
  row-level security, secret-manager rotation and multi-region operations.
- The M5 value report and M6 model bakeoff are synthetic evaluation evidence,
  not live merchant performance.
- Dead letters are observable but intentionally have no operator requeue API.
