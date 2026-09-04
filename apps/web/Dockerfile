FROM node:22.23.2-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS runtime

ENV COREPACK_HOME="/home/retryrail/.cache/node/corepack"

WORKDIR /app

RUN corepack enable \
    && useradd --create-home --uid 10001 --user-group retryrail \
    && chown retryrail:retryrail /app

COPY --chown=retryrail:retryrail package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY --chown=retryrail:retryrail apps/web/package.json ./apps/web/package.json

USER retryrail

RUN pnpm install --frozen-lockfile

COPY --chown=retryrail:retryrail apps/web ./apps/web

EXPOSE 5173

CMD ["pnpm", "--filter", "@retryrail/web", "dev", "--host", "0.0.0.0"]
