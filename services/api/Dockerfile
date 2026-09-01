FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

RUN pip install --no-cache-dir uv==0.11.32 \
    && useradd --create-home --uid 10001 --user-group retryrail \
    && chown retryrail:retryrail /app

COPY --chown=retryrail:retryrail pyproject.toml uv.lock README.md LICENSE ./
COPY --chown=retryrail:retryrail services/api/app ./services/api/app
COPY --chown=retryrail:retryrail services/api/alembic.ini ./services/api/alembic.ini
COPY --chown=retryrail:retryrail services/api/migrations ./services/api/migrations

USER retryrail

RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000

CMD ["uvicorn", "retryrail.main:app", "--host", "0.0.0.0", "--port", "8000"]
