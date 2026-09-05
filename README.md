# RetryRail

> AI-powered payment reliability and revenue recovery.

**Detect. Diagnose. Recover.**

RetryRail is a Track 3 — AI Revenue Recovery project for the Razorpay AI
Buildathon. It detects merchant-specific payment degradation, identifies the
affected payment cohort and likely cause, proposes a policy-safe recovery plan,
executes only approved actions through Razorpay Test Mode, and measures the
incremental GMV recovered against a holdout group.

## Product promise

Given a replayable batch of payment events, RetryRail must prove the complete
loop:

1. Detect revenue at risk.
2. Diagnose the affected cohort with evidence.
3. Select a bounded intervention.
4. Obtain the required merchant approval.
5. Execute the action idempotently.
6. Verify the outcome.
7. Report measured incremental recovered GMV.
8. Preserve a complete audit trail, including failures and refusals.

## Source-of-truth documents

- [Product requirements](docs/PRODUCT_REQUIREMENTS.md)
- [Architecture and build plan](docs/BUILD_PLAN.md)
- [M1 contract catalog](docs/CONTRACTS.md)
- [Deterministic truth set](docs/DATASET.md)
- [Authenticated event pipeline](docs/EVENT_PIPELINE.md)
- [Deterministic detector and honest evaluation](docs/DETECTOR.md)
- [Detector-v4 remediation boundary](docs/DETECTOR_V4_PROTOCOL.md)
- [Detector-v4 development candidate](docs/DETECTOR_V4_CANDIDATE.md)
- [M5 recovery experiment and official synthetic result](docs/M5_EXPERIMENT_PROTOCOL.md)
- [Razorpay Test Mode safety and one-link workflow](docs/RAZORPAY_TEST_MODE.md)
- [M6 bounded incident analyst and evaluation](docs/INCIDENT_ANALYST.md)
- [M7 merchant control room](docs/MERCHANT_UI.md)
- [Sanitized Razorpay Test Mode evidence receipt](evals/reports/razorpay_test_mode_receipt.v1.json)
- [Razorpay submission checklist](docs/SUBMISSION_CHECKLIST.md)
- [Repository instructions](AGENTS.md)

## Foundation stack

- React 18, TypeScript, Vite and Razorpay Blade
- Python 3.12, FastAPI, Pydantic, SQLAlchemy and Alembic
- PostgreSQL with a transactional outbox
- Explainable statistical detection, with a bounded LLM analyst
- Razorpay Test Mode webhooks and Standard Payment Links
- OpenTelemetry, Prometheus and Grafana
- pytest, Playwright, golden-set evaluations and GitHub Actions

The repository/release foundation (M0), deterministic contract/truth-data
slice (M1), authenticated event pipeline (M2), and M3 detector/lifecycle
machinery are implemented. Detector v1 deliberately remains release-blocked:
it passed tuning but scored 0 precision and 0 recall on the frozen held-out
batch. A generated, hash-bound release decision keeps every v1 incident
action-ineligible. M4 proves the full model-independent fake execution path. M5
adds the real Test Mode provider edge, a frozen synthetic impact report and one
human-approved external Test Mode receipt recovered safely by reference lookup.
M5 is complete; Test Mode evidence is not live-money or merchant-performance
evidence.

Detector-v2 remediation completed its one-time, nonce-derived synthetic blind
run with byte-reproducible, append-only evidence. The frozen candidate found
all six incidents with zero false positives or false negatives and perfect
top-1 attribution, but the generated release decision is still blocked: its
900-second median first-signal delay missed the 600-second target, and two
incident baselines crossed their scenario start when the target was zero.
Detector v2 therefore has no runtime authority and did not unblock M4; see the
[protocol and complete result](docs/DETECTOR_V2_PROTOCOL.md).

Detector v3 later passed both approved development partitions but its only
official synthetic blind run recorded 5 true positives, 1 false positive and
1 false negative, missing both precision and recall targets at 833,333 ppm.
Its frozen writer also omitted one required nullable report field. The exact
run is preserved as blocked and procedurally invalid. M3R.5 R5.1 precommitted
a detector-v4 hierarchy-lifecycle and report-contract remediation. R5.2
implements that separately versioned candidate and passes all unchanged
targets independently on all three revealed synthetic development partitions,
including strict open-report byte reproduction. R5.3 adds 15 passing
adversarial cases and freezes the candidate plus the append-only blind runner.
R5.4 then consumes one fresh public-nonce official synthetic blind run after
the freeze passed all five remote jobs. The report records 6 TP / 0 FP / 0 FN,
perfect precision, recall and top-1 attribution, a 600-second median simulated
delay, and zero safety or reconciliation violations. Its detector decision is
qualified for M4 integration review. R5.5 subsequently passed working-tree,
clean-checkout, security, container and all five remote CI gates. M3R.5 is now
complete. M4.1 freezes the recovery-template, complete policy-result, hashed
approval-record and provider-bound action contracts plus their threat model.
M4.2 now implements the pure, version-pinned 13-rule policy evaluator with
complete allow/deny evidence. M4.3 now assembles those facts from authoritative
server records, persists hash-bound preview evidence and implements
authenticated, idempotent approve/reject with hash-only, short-lived,
single-use bearers. M4.4 adds fresh pre-execution policy, atomic approval
consumption, append-only action transitions, execute-once replay and a
deterministic fake provider with lookup-only timeout reconciliation. M4.5 adds a
grounded rules analyst, model-unavailable fallback, complete audit verifier and
an additive activation gate for only the exact qualified detector-v4 identity.
The frozen v4 release remains unchanged. M5 adds an immutable pre-network
dispatch, a no-create-retry Test Mode adapter, reference-only reconciliation,
and a remotely frozen 224/56 treatment/control experiment. Its official full-
batch synthetic report estimates ₹120,912 incremental recovered GMV with a 95%
interval of ₹44,447–₹189,391; this is not a live merchant-performance claim.
The sole approved Test Mode POST returned 200; when provider clock skew stopped
local response validation, the durable action was completed with one GET by its
stable reference and no repeated create.
M6 adds a redacted, strict-schema advisory analyst, append-only provenance,
deterministic grounding and outage fallback, plus a fixed 24-case safety
evaluation. Its create-only three-model report selected
`gpt-5.4-nano-2026-03-17`, the only candidate to clear every frozen gate, with
95.83% grounding and zero unsafe actions. M7 adds the responsive merchant
control room and complete keyboard-tested browser story. Provider credentials
never enter the browser, and neither milestone changes detector, policy,
approval or execution authority.
See the [v4 protocol](docs/DETECTOR_V4_PROTOCOL.md) and
[v4 candidate](docs/DETECTOR_V4_CANDIDATE.md), plus the
[M4 recovery-boundary decision](docs/adr/0007-m4-policy-approval-recovery-contract-boundary.md)
and [M4.3 storage decision](docs/adr/0008-m4-authoritative-preview-and-approval-storage.md),
plus the [M4 execution and activation decision](docs/adr/0009-m4-qualified-detector-and-execute-once-fake.md),
the [M5 provider decision](docs/adr/0010-m5-durable-razorpay-test-mode-dispatch.md),
the [M5 experiment decision](docs/adr/0011-m5-precommitted-recovery-experiment.md),
the [M6 analyst decision](docs/adr/0012-m6-redacted-bounded-incident-analyst.md),
the [M7 control-room decision](docs/adr/0013-m7-merchant-control-room.md),
plus the [deterministic policy](docs/POLICY.md) and
[complete recovery workflow](docs/RECOVERY_WORKFLOW.md).

## Run locally

Required tools are Python 3.12 or 3.13, `uv`, Node.js 22, pnpm 11, GNU Make
and Docker with Compose.
The default local path uses the deterministic fake provider and rules analyst,
so it needs no cloud credential. Razorpay Test Mode credentials are used only by
the protected M5 workflow. An OpenAI Platform key is used only for the explicit
M6 live bakeoff or an opted-in server analyst.

```bash
cp .env.example .env
uv sync --all-groups --frozen
pnpm install --frozen-lockfile
pnpm --filter @retryrail/web exec playwright install chromium
uv run retryrail-seed
docker compose up --build
```

PowerShell users can replace the first command with:

```powershell
Copy-Item .env.example .env
```

Compose migrates PostgreSQL before starting the API and worker. The local shell
is at <http://127.0.0.1:5173>, readiness is at
<http://127.0.0.1:8000/health/ready>, metrics are at
<http://127.0.0.1:8000/metrics>, and development-only API documentation is at
<http://127.0.0.1:8000/docs>.

## Developer contract

The completed repository should support:

```bash
make bootstrap  # install locked dependencies and the test browser
make install-security-hook # activate authenticated offline + GitGuardian pre-push checks
make dev        # start the complete local stack
make migrate    # upgrade the configured database explicitly
make replay     # replay the M2 reliability cases when locally enabled
make detect     # refresh deterministic aggregates and incidents
make eval       # verify reports and the generated detector release decision
make v2-data-check # verify the pre-blind v2 protocol and development identity
make v2-candidate-check # verify the frozen v2 candidate and development report
make v2-blind-check # verify the frozen blind runner and append-only run state
make v3-blind-check # verify the preserved blocked/invalid v3 run
make v4-protocol-check # verify the pre-candidate v4 remediation boundary
make v4-candidate-check # verify all three v4 development partitions
make v4-adversarial-check # verify v4 hierarchy, overlap and contract edge cases
make v4-freeze-check # verify the complete nonce-free v4 candidate freeze
make v4-blind-check # reproduce revealed inputs, then verify append-only v4 evidence
make analyst-corpus-check # verify the fixed 24-case M6 corpus
make analyst-report-check # verify the committed key-backed model report
make demo       # run the M7 backend replay and browser-story gates
make check      # run every implemented release gate
```

`make seed` recreates the M1 truth artifacts and their stable manifest. Runtime
replay requires `RETRYRAIL_REPLAY_ENABLED=true` and the configured local token.
`make demo` runs the bounded demo API integration and both M7 Playwright paths;
it does not contact Razorpay or OpenAI. On Windows without GNU Make, run the
underlying `uv` and `pnpm` commands shown in the Makefile.

M0–M7 verification includes Python and TypeScript lint/typecheck, backend and
web unit tests, schema and truth-manifest drift, production web build, a
Chromium smoke test, Bandit, credential/fixture scanning and Python/web
dependency audits. Pipeline integration tests run hermetically on SQLite
locally and against PostgreSQL 16 in the Python CI job. The M4 workflow adds
SQLite/PostgreSQL migration coverage, adversarial approval/action races and a
literal model-unavailable detector-to-audit release test. M6 adds strict
redaction, provider-failure and grounding cases; M7 adds API-boundary,
responsive workflow and keyboard-only approval/rejection coverage.

## Official context

- [Razorpay AI Buildathon](https://razorpay.com/buildathon/)
- [Razorpay webhook validation and testing](https://razorpay.com/docs/webhooks/validate-test/)
- [Razorpay Standard Payment Link API](https://razorpay.com/docs/api/payments/payment-links/create-standard/)
- [Razorpay Blade](https://github.com/razorpay/blade)
- [Razorpay AI Playbook](https://github.com/razorpay/ai-playbook)

## Status

M0–M3, M3R.1–R.5 and M4.1–M4.5 are implemented. M3R.4 is complete only
as preservation of detector v3's blocked and procedurally invalid official
result. M3R.5 R5.1 binds the exact hierarchy failure, three revealed
development partitions, unchanged release targets, strict report round-trip
requirements and a fresh-run procedure. R5.2 implements the canonical-cohort
candidate, records every overlap decision, passes each development partition
and fixes required-nullable canonical report output. R5.3 records 15 passing
adversarial cases, freezes all candidate identities and freezes an append-only,
prediction-first runner with strict report read-back and receipt-bound
clean-checkout reproduction after the public nonce is revealed. R5.4 consumes
the one official synthetic blind slot only after that freeze was remotely
verified. The committed prediction bytes precede truth access, reproduce
exactly and lead to a qualified decision that passes every unchanged target.

The v4 detector is qualified and R5.5 closed the repository, security,
clean-checkout, container and remote release gates. M4.1 preserves the M1 plan
and receipt schemas byte-for-byte while adding the explicit recovery boundary;
M4.2 implements all 13 deterministic rules; and M4.3 adds server-owned preview
and merchant approval. M4.4 adds fake-only execute/reconcile with immutable
receipts and at-most-once authority. M4.5 adds grounded no-model analysis,
audit-completeness verification and a separate hash-bound activation for exact
qualified v4 incidents. Failed historical detectors remain blocked, no frozen
release artifact is rewritten, and no M4 route can reach Razorpay or notify a
customer. M5 preserves those controls while adding a Test-key-only provider
edge, durable dispatch/receipt evidence and holdout-based incremental recovered-
GMV measurement. Its single interactive merchant-approved Test Mode link and
sanitized complete-audit receipt are committed. M6 implements the redacted
single-provider boundary, deterministic fallback and fixed 24-case evaluation;
its create-only report freezes `gpt-5.4-nano-2026-03-17` as the only candidate
that passed every gate. M7 implements the merchant control room and primary
browser story. See the current
[project status and next-chat handoff](docs/PROJECT_STATUS.md),
[v3 result](docs/DETECTOR_V3_PROTOCOL.md),
[v4 protocol](docs/DETECTOR_V4_PROTOCOL.md),
[v4 candidate](docs/DETECTOR_V4_CANDIDATE.md),
[event pipeline](docs/EVENT_PIPELINE.md),
[detector](docs/DETECTOR.md), [policy](docs/POLICY.md),
[recovery workflow](docs/RECOVERY_WORKFLOW.md), [incident analyst](docs/INCIDENT_ANALYST.md),
[merchant UI](docs/MERCHANT_UI.md),
[architecture](docs/ARCHITECTURE.md),
[dataset](docs/DATASET.md), [security](docs/SECURITY.md) and the
[authoritative build plan](docs/BUILD_PLAN.md).
