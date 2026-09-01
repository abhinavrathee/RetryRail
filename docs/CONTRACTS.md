# RetryRail M1 contract catalog

M1 freezes boundaries, not product behavior. Every model is immutable,
rejects undeclared fields and exports a Draft 2020-12 JSON Schema. Later
milestones may add new schema versions but may not silently change v1 meaning.

| Contract | Meaning | Side effects |
| --- | --- | --- |
| Normalized payment event | PII-free, versioned payment fact after successful webhook authentication | None |
| Sanitized Razorpay webhook | Allowlisted Razorpay-shaped fixture form | None |
| Webhook delivery instruction | Replay timing, signature/body condition and expected ingress disposition | None in M1 |
| Incident | Detector-owned degradation record with cohort, evidence counts, confidence and GMV at risk | None in M1 |
| Recovery plan | Pre-authorized template, eligibility, expiry and stopping rules | Proposal only |
| Action receipt | Idempotency identity and legally chained action-state history | Evidence only |
| Detector evaluation | Held-out confusion counts and top-1/top-3 attribution results | None |
| Attempt ground truth | Evaluation-only payment label, physically separated from runtime events | None |
| Experiment design | Eligibility, allocation, strata and outcome assumptions frozen before results | None |
| Synthetic manifest | Complete batch identity, scenario truth and artifact digests | None |

## Contract invariants

- Event type and payment status must agree.
- Failed events require structured error evidence; non-failed events reject it.
- Money is positive integer currency subunits and currency is explicit.
- Timestamps are timezone-aware and generated data uses UTC.
- Runtime events never contain detector split or scenario labels.
- Incidents cannot contain impossible success/attempt counts or invalid lifecycle
  timestamps.
- Plans always require external approval, preserve the verified source amount
  and carry expiry, cooldown, attempt-cap and kill-switch controls.
- Action histories must begin at `previewed`, follow the allowed state graph and
  represent ambiguous upstream outcomes as `reconciliation_required`.
- Successful actions require both an external reference and a verification
  timestamp.
- Experiment assignment and simulated outcome draws use independent namespaces.
- Unknown fields fail validation at domain boundaries.

## Schema locations

Event and delivery schemas live in `contracts/events/`. Incident, recovery,
action, evaluation and truth schemas live in `contracts/domain/`. They are
generated only from Pydantic source models:

```bash
uv run retryrail-contracts
uv run retryrail-contracts --check
```

The check mode compares every committed schema byte-for-byte and fails on a
missing or stale file. Schema changes require a model change, regenerated
artifacts, tests and documentation; hand-edited generated schema files are not
accepted.
