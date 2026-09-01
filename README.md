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
slice (M1) and authenticated event pipeline (M2) are implemented. Detection,
recovery execution and impact reporting remain behind later milestone gates and
are not represented as working features.

## Run through Part 3 locally

Required tools are Python 3.12 or 3.13, `uv`, Node.js 22, pnpm 11 and Docker.
No cloud account or Razorpay credential is needed for M0–M2.

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
make dev        # start the complete local stack
make migrate    # upgrade the configured database explicitly
make replay     # replay the M2 reliability cases when locally enabled
make check      # run every implemented release gate
```

`make seed` recreates the M1 truth artifacts and their stable manifest. Replay
requires `RETRYRAIL_REPLAY_ENABLED=true` and the configured local token. `make
demo` and `make eval` deliberately exit with an explanatory error until M7 and
M3/M6 respectively. This prevents event processing from being mistaken for a
working recovery product. On Windows without GNU Make, run the underlying `uv`
and `pnpm` commands shown in the Makefile.

M0–M2 verification includes Python and TypeScript lint/typecheck, backend and
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

Parts 1–3 / M0–M2 are implemented. The GitHub Actions workflow includes a
PostgreSQL 16 integration run but cannot be observed until the repository is
pushed; no commit or push is performed automatically. See
[event pipeline](docs/EVENT_PIPELINE.md), [architecture](docs/ARCHITECTURE.md),
[dataset](docs/DATASET.md), [security](docs/SECURITY.md) and the
[authoritative build plan](docs/BUILD_PLAN.md) before beginning M3.
