# Contributing to RetryRail

RetryRail is built in release-gated P0 slices. Read `AGENTS.md`,
`docs/PRODUCT_REQUIREMENTS.md` and `docs/BUILD_PLAN.md` before changing product
behavior.

## Local setup

1. Install Python 3.12 or 3.13, `uv`, Node.js 22, pnpm 11 and Docker.
2. Copy `.env.example` to `.env`; keep all real credentials outside Git.
3. Run `uv sync --all-groups` and `pnpm install --frozen-lockfile`.
4. Run `make check` on Unix, or the equivalent commands documented in the
   root `package.json` on Windows.

## Change requirements

- Keep changes inside the active milestone and link behavior to a requirement.
- Add negative and retry-path tests with each boundary or mutation.
- Use Alembic for every database schema change.
- Store timestamps in UTC and money in integer currency subunits.
- Do not add real customer data, card data, credentials or personal contact
  data to fixtures, logs, prompts, screenshots or videos.
- State which commands were actually run. Never describe a planned check as
  passing.

Pull requests should explain the acceptance criterion, failure behavior,
security/privacy impact, verification evidence and any known gap.
