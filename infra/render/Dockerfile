FROM node:22.23.2-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS web-build

ENV COREPACK_HOME="/home/retryrail/.cache/node/corepack" \
    VITE_API_BASE_URL=""

WORKDIR /app

RUN corepack enable \
    && useradd --create-home --uid 10001 --user-group retryrail \
    && chown retryrail:retryrail /app

COPY --chown=retryrail:retryrail package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY --chown=retryrail:retryrail apps/web/package.json ./apps/web/package.json

USER retryrail

RUN pnpm install --frozen-lockfile

COPY --chown=retryrail:retryrail apps/web ./apps/web

RUN pnpm --filter @retryrail/web build


FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PATH="/app/.venv/bin:${PATH}" \
    RETRYRAIL_SERVE_WEB=true \
    RETRYRAIL_WEB_DIST_PATH=/app/apps/web/dist

WORKDIR /app

RUN pip install --no-cache-dir uv==0.11.32 \
    && useradd --create-home --uid 10001 --user-group retryrail \
    && chown retryrail:retryrail /app

COPY --chown=retryrail:retryrail pyproject.toml uv.lock README.md LICENSE ./
COPY --chown=retryrail:retryrail services/api/app ./services/api/app
COPY --chown=retryrail:retryrail services/api/alembic.ini ./services/api/alembic.ini
COPY --chown=retryrail:retryrail services/api/migrations ./services/api/migrations
COPY --chown=retryrail:retryrail evals/golden/detector_v1.freeze.json ./evals/golden/detector_v1.freeze.json
COPY --chown=retryrail:retryrail evals/reports/detector_v1.release.json ./evals/reports/detector_v1.release.json
COPY --chown=retryrail:retryrail evals/reports/recovery_experiment_v1.report.json ./evals/reports/recovery_experiment_v1.report.json
COPY --chown=retryrail:retryrail evals/golden/incident_analyst_v1.cases.json ./evals/golden/incident_analyst_v1.cases.json
COPY --chown=retryrail:retryrail evals/reports/incident_analyst_bakeoff.v1.json ./evals/reports/incident_analyst_bakeoff.v1.json
COPY --chown=retryrail:retryrail evals/golden/detector_v4.candidate.json ./evals/golden/detector_v4.candidate.json
COPY --chown=retryrail:retryrail evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/blind.release.v1.json ./evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/blind.release.v1.json
COPY --chown=retryrail:retryrail evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/blind.report.v1.json ./evals/blind/detector_v4/runs/detector_v4_official_blind_5497598109b06d21c625/blind.report.v1.json
COPY --from=web-build --chown=retryrail:retryrail /app/apps/web/dist ./apps/web/dist

USER retryrail

RUN uv sync --frozen --no-dev

EXPOSE 10000

CMD ["uvicorn", "retryrail.main:app", "--host", "0.0.0.0", "--port", "10000"]
