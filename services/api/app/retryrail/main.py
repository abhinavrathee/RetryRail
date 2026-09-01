"""FastAPI application factory and process-owned resource lifecycle."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from retryrail import __version__
from retryrail.api.health import router as health_router
from retryrail.api.replay import router as replay_router
from retryrail.api.webhooks import router as webhook_router
from retryrail.config import Settings, get_settings
from retryrail.db.session import Database
from retryrail.events.ingestion import EventIngestionService
from retryrail.observability.logging import configure_logging
from retryrail.observability.metrics import PipelineMetrics
from retryrail.observability.metrics import router as metrics_router

RequestHandler = Callable[[Request], Awaitable[Response]]


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    metrics: PipelineMetrics | None = None,
) -> FastAPI:
    """Create the API with validated settings and security response headers."""

    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.log_level)
    resolved_database = database or Database(resolved_settings.database_dsn())
    resolved_metrics = metrics or PipelineMetrics()
    owns_database = database is None
    expose_docs = resolved_settings.environment != "production"

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.settings = resolved_settings
        application.state.database = resolved_database
        application.state.metrics = resolved_metrics
        application.state.ingestion_service = EventIngestionService(
            resolved_database,
            resolved_settings.webhook_secret,
            resolved_metrics,
            outbox_max_attempts=resolved_settings.outbox_max_attempts,
        )
        try:
            yield
        finally:
            if owns_database:
                await resolved_database.dispose()

    application = FastAPI(
        title="RetryRail API",
        summary="Payment reliability and bounded revenue recovery",
        version=__version__,
        docs_url="/docs" if expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if expose_docs else None,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin).rstrip("/") for origin in resolved_settings.cors_origins],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=[
            "Content-Type",
            "X-Razorpay-Event-Id",
            "X-Razorpay-Signature",
            "X-RetryRail-Replay-Token",
        ],
    )

    @application.middleware("http")
    async def add_security_headers(request: Request, call_next: RequestHandler) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    application.include_router(health_router)
    application.include_router(webhook_router)
    application.include_router(replay_router)
    application.include_router(metrics_router)
    return application


app = create_app()


def run() -> None:
    """Run the local API process."""

    uvicorn.run("retryrail.main:app", host="127.0.0.1", port=8000, reload=False)
