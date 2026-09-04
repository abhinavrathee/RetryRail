# RetryRail versioned contract catalog

M1 and M4.1 freeze boundaries, not endpoint behavior. Every model is immutable,
rejects undeclared fields and exports a Draft 2020-12 JSON Schema. Later
milestones may add new schema versions but may not silently change a published
schema's meaning.

| Contract | Meaning | Side effects |
| --- | --- | --- |
| Normalized payment event | PII-free, versioned payment fact after successful webhook authentication | None |
| Sanitized Razorpay webhook | Allowlisted Razorpay-shaped fixture form | None |
| Webhook delivery instruction | Replay timing, signature/body condition and expected ingress disposition | None in M1 |
| Incident | Detector-owned degradation record with cohort, evidence counts, confidence and GMV at risk | None in M1 |
| Recovery plan | Pre-authorized template, eligibility, expiry and stopping rules | Proposal only |
| Action receipt (M1) | Idempotency identity and legally chained action-state history | Evidence only |
| Recovery template (M4.1) | Sole P0 effect, allowed non-production targets and fixed safety properties | None |
| Policy result (M4.1–M4.4) | PII-free input snapshot, complete rule results and derived decision | Evaluation has none; preview and execution stages are immutable internal evidence |
| Approval record (M4.1/M4.3–M4.4) | Merchant decision, plan/policy digest binding and hashed single-use token lifecycle | Append-only decision/consumption writes; consumption is atomic with fake action creation |
| Recovery action (M4.1/M4.4) | Payment-bound request, authority bindings, target-specific state history and typed outcome | Explicitly synthetic fake mutation in M4; Razorpay Test Mode mutation in M5 |
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
- The sole M4 template preserves the verified amount, disables external
  notifications, forbids production targets and requires merchant approval.
- A policy result contains all 13 P0 rules in canonical order. Any denial forces
  the aggregate decision to `deny`; a result cannot grant merchant approval.
- M4.2 evaluates every rule without short-circuiting. `ANALYZE_ONLY`, exact
  expiry, amount/currency changes, missing consent, exhausted attempts, active
  cooldown, opt-out, kill switch and already-recovered state all fail closed.
- Approval records never contain the bearer token. Approved credentials are
  hash-bound to the plan and policy result, expire within fifteen minutes and
  may be consumed once.
- M4.3 rejects caller-supplied policy facts, binds each preview to exact event,
  projection, recovery-control and detector provenance, and preserves plan,
  policy, decision and consumption facts as update/delete-protected records.
- Exact idempotent approval replay never repeats the bearer. Only a separate-key
  HMAC digest is persisted, and a unique append-only consumption row makes
  concurrent use single-winner.
- Recovery actions bind merchant, incident, plan, payment, amount, currency,
  plan digest, stable reference, idempotency key, both policy stages and the
  approval record as their lifecycle advances.
- Execution revalidates current facts, and any denied rule prevents approval
  consumption, action creation and provider access. Exact replay returns the
  original receipt; ambiguous create outcomes permit lookup-only reconciliation.
- A deterministic-fake provider cannot attest a Razorpay Test Mode transition,
  and every fake action is explicitly synthetic.
- The M4.5 rules brief is content-addressed internal audit evidence rather than
  model authority. Every incident citation must resolve to a verified,
  merchant-scoped event before the brief is persisted.
- Experiment assignment and simulated outcome draws use independent namespaces.
- Unknown fields fail validation at domain boundaries.

## Schema locations

Event and delivery schemas live in `contracts/events/`. Incident, recovery,
policy, approval, action, evaluation and truth schemas live in
`contracts/domain/`. They are generated only from Pydantic source models:

```bash
uv run retryrail-contracts
uv run retryrail-contracts --check
```

The check mode compares every committed schema byte-for-byte and fails on a
missing or stale file. Schema changes require a model change, regenerated
artifacts, tests and documentation; hand-edited generated schema files are not
accepted.

The M1 `recovery_plan.v1` and `action_receipt.v1` schemas remain byte-for-byte
unchanged. M4.1 adds named contracts around them instead of retroactively
changing their semantics. Their canonical SHA-256 values are pinned in the
exporter, which fails before writing if either source model would change its v1
schema. An intentional evolution must use a new versioned schema path. The
complete threat and side-effect boundary is in ADR-0007.

The executable truth table and time boundaries are documented in
`docs/POLICY.md`; the complete authoritative-source, approval, execute-once,
fallback and audit boundary is documented in `docs/RECOVERY_WORKFLOW.md`,
ADR-0008 and ADR-0009.
