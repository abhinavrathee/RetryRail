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
action-ineligible. Recovery execution and impact reporting remain behind later
milestones.

Detector-v2 remediation completed its one-time, nonce-derived synthetic blind
run with byte-reproducible, append-only evidence. The frozen candidate found
all six incidents with zero false positives or false negatives and perfect
top-1 attribution, but the generated release decision is still blocked: its
900-second median first-signal delay missed the 600-second target, and two
incident baselines crossed their scenario start when the target was zero.
Detector v2 therefore has no runtime authority and M4 remains blocked; see the
[protocol and complete result](docs/DETECTOR_V2_PROTOCOL.md).

Detector v3 later passed both approved development partitions but its only
official synthetic blind run recorded 5 true positives, 1 false positive and
1 false negative, missing both precision and recall targets at 833,333 ppm.
Its frozen writer also omitted one required nullable report field. The exact
run is preserved as blocked and procedurally invalid. M3R.5 R5.1 precommitted
a detector-v4 hierarchy-lifecycle and report-contract remediation. R5.2 now
implements that separately versioned candidate and passes all unchanged
targets independently on all three revealed synthetic development partitions,
including strict open-report byte reproduction. This is development evidence,
not release qualification. See the [v4 protocol](docs/DETECTOR_V4_PROTOCOL.md)
and [v4 candidate](docs/DETECTOR_V4_CANDIDATE.md).

## Run through Part 4 locally

Required tools are Python 3.12 or 3.13, `uv`, Node.js 22, pnpm 11 and Docker.
No cloud account or Razorpay credential is needed for M0–M3.

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
make check      # run every implemented release gate
```

`make seed` recreates the M1 truth artifacts and their stable manifest. Replay
requires `RETRYRAIL_REPLAY_ENABLED=true` and the configured local token. `make
demo` deliberately exits with an explanatory error until M7. `make eval` now
checks detector artifacts; agent evaluation will be added in M6. This prevents
event processing from being mistaken for a working recovery product. On
Windows without GNU Make, run the underlying `uv`
and `pnpm` commands shown in the Makefile.

M0–M3 verification includes Python and TypeScript lint/typecheck, backend and
web unit tests, schema and truth-manifest drift, production web build, a
Chromium smoke test, Bandit, credential/fixture scanning and Python/web
dependency audits. Pipeline integration tests run hermetically on SQLite
locally and against PostgreSQL 16 in the Python CI job.

## Official context

- [Razorpay AI Buildathon](https://razorpay.com/buildathon/)
- [Razorpay webhook validation and testing](https://razorpay.com/docs/webhooks/validate-test/)
- [Razorpay Standard Payment Link API](https://razorpay.com/docs/api/payments/payment-links/create-standard/)
- [Razorpay Blade](https://github.com/razorpay/blade)
- [Razorpay AI Playbook](https://github.com/razorpay/ai-playbook)

## Status

Parts 1–4 / M0–M3, M3R.1–R.3 and M3R.4 are implemented. M3R.4 is complete only
as preservation of detector v3's blocked and procedurally invalid official
result. M3R.5 R5.1 binds the exact hierarchy failure, three revealed
development partitions, unchanged release targets, strict report round-trip
requirements and a fresh-run procedure. R5.2 implements the canonical-cohort
candidate, records every overlap decision, passes each development partition
and fixes required-nullable canonical report output.

The v4 candidate is not frozen or release-qualified, no v4 nonce exists, every
output is action-ineligible, and M4 remains blocked. R5.3 adversarial coverage
and freeze is next. GitHub Actions includes PostgreSQL 16 integration and all
implemented detector integrity gates. See
[v3 result](docs/DETECTOR_V3_PROTOCOL.md),
[v4 protocol](docs/DETECTOR_V4_PROTOCOL.md),
[v4 candidate](docs/DETECTOR_V4_CANDIDATE.md),
[event pipeline](docs/EVENT_PIPELINE.md),
[detector](docs/DETECTOR.md), [architecture](docs/ARCHITECTURE.md),
[dataset](docs/DATASET.md), [security](docs/SECURITY.md) and the
[authoritative build plan](docs/BUILD_PLAN.md).
