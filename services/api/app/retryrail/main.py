"""FastAPI application factory and process-owned resource lifecycle."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from retryrail import __version__
from retryrail.api.experiments import router as experiments_router
from retryrail.api.health import router as health_router
from retryrail.api.incidents import router as incidents_router
from retryrail.api.recovery import router as recovery_router
from retryrail.api.replay import router as replay_router
from retryrail.api.webhooks import router as webhook_router
from retryrail.config import Environment, Settings, get_settings
from retryrail.db.session import Database
from retryrail.detection.service import DetectionService
from retryrail.events.ingestion import EventIngestionService
from retryrail.experiments.service import ExperimentReportService
from retryrail.observability.logging import configure_logging
from retryrail.observability.metrics import PipelineMetrics
from retryrail.observability.metrics import router as metrics_router
from retryrail.observability.tracing import (
    TraceContext,
    bind_trace_context,
    request_trace_context,
)
from retryrail.recovery.adapter import (
    DeterministicFakeRazorpayAdapter,
    RazorpayTestModeAdapter,
    RecoveryProvider,
)
from retryrail.recovery.analysis import RulesBasedIncidentAnalyst
from retryrail.recovery.analyst_evaluation import check_report as check_analyst_report
from retryrail.recovery.audit import RecoveryAuditVerifier
from retryrail.recovery.execution import RecoveryExecutionService
from retryrail.recovery.incident_analyst import IncidentAnalyst
from retryrail.recovery.openai_analyst import (
    IncidentAnalystProvider,
    OpenAIIncidentAnalystProvider,
)
from retryrail.recovery.workflow import RecoveryWorkflowService
from retryrail.web import install_compiled_web

RequestHandler = Callable[[Request], Awaitable[Response]]


def _initialize_experiment_metrics(
    metrics: PipelineMetrics,
    service: ExperimentReportService,
) -> None:
    """Expose only frozen aggregate synthetic experiment evidence."""

    metrics.experiment_eligible_payments.set(service.report.eligible_count)
    metrics.experiment_incremental_recovered_gmv.set(
        service.report.value.incremental_recovered_gmv_subunits
    )
    metrics.recovered_gmv.labels(arm="treatment").set(
        service.report.treatment.recovered_gmv_subunits
    )
    metrics.recovered_gmv.labels(arm="control").set(
        service.report.control.recovered_gmv_subunits
    )
    metrics.experiment_net_recovered_value.set(
        service.report.value.net_recovered_value_subunits
    )


def _harden_response(
    response: Response,
    trace: TraceContext,
    settings: Settings,
) -> None:
    """Apply security and W3C correlation headers to every API response."""

    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; connect-src 'self'; "
        "font-src 'self' data:; frame-ancestors 'none'; img-src 'self' data:; "
        "object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Traceparent"] = trace.traceparent
    response.headers["X-Trace-Id"] = trace.trace_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if settings.environment.value in {"production", "review"}:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    metrics: PipelineMetrics | None = None,
    recovery_provider: RecoveryProvider | None = None,
    incident_analyst_provider: IncidentAnalystProvider | None = None,
) -> FastAPI:
    """Create the API with validated settings and security response headers."""

    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.log_level)
    resolved_database = database or Database(resolved_settings.database_dsn())
    resolved_metrics = metrics or PipelineMetrics()
    owns_database = database is None

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
        application.state.detection_service = DetectionService(
            resolved_database,
            resolved_metrics,
            runtime_version="v4",
        )
        workflow = RecoveryWorkflowService(
            resolved_database,
            resolved_settings,
            resolved_metrics,
        )
        provider = recovery_provider or _configured_recovery_provider(resolved_settings)
        application.state.recovery_workflow_service = workflow
        application.state.recovery_provider = provider
        execution = RecoveryExecutionService(
            resolved_database,
            resolved_settings,
            resolved_metrics,
            workflow,
            provider,
        )
        application.state.recovery_execution_service = execution
        analyst_provider = _install_incident_analyst(
            application,
            resolved_database,
            resolved_settings,
            resolved_metrics,
            incident_analyst_provider,
        )
        application.state.recovery_audit_verifier = RecoveryAuditVerifier(
            resolved_database,
            resolved_settings,
            execution,
        )
        experiment_service = ExperimentReportService()
        application.state.experiment_report_service = experiment_service
        _initialize_experiment_metrics(resolved_metrics, experiment_service)
        try:
            yield
        finally:
            if recovery_provider is None and isinstance(provider, RazorpayTestModeAdapter):
                await provider.aclose()
            if incident_analyst_provider is None and isinstance(
                analyst_provider, OpenAIIncidentAnalystProvider
            ):
                await analyst_provider.aclose()
            if owns_database:
                await resolved_database.dispose()

    interactive_docs = resolved_settings.environment in {
        Environment.DEVELOPMENT,
        Environment.TEST,
    }
    application = FastAPI(
        title="RetryRail API",
        summary="Payment reliability and bounded revenue recovery",
        version=__version__,
        docs_url="/docs" if interactive_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if interactive_docs else None,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin).rstrip("/") for origin in resolved_settings.cors_origins],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=[
            "Content-Type",
            "Traceparent",
            "X-Razorpay-Event-Id",
            "X-Razorpay-Signature",
            "X-RetryRail-Replay-Token",
            "X-RetryRail-Merchant-Authorization",
            "X-RetryRail-Approval-Token",
        ],
        expose_headers=[
            "Traceparent",
            "X-Trace-Id",
            "X-RetryRail-Domain-Trace-Id",
        ],
    )

    @application.middleware("http")
    async def add_security_headers(request: Request, call_next: RequestHandler) -> Response:
        trace = request_trace_context(request.headers.get("traceparent"))
        with bind_trace_context(trace):
            response = await call_next(request)
        _harden_response(response, trace, resolved_settings)
        return response

    application.include_router(health_router)
    application.include_router(incidents_router)
    application.include_router(webhook_router)
    application.include_router(replay_router)
    application.include_router(recovery_router)
    application.include_router(experiments_router)
    application.include_router(metrics_router)
    if resolved_settings.serve_web:
        install_compiled_web(application, resolved_settings.web_dist_path)
    return application


app = create_app()


def _configured_recovery_provider(settings: Settings) -> RecoveryProvider:
    """Construct only the provider explicitly enabled by validated settings."""

    if settings.recovery_execution_target == "deterministic_fake":
        return DeterministicFakeRazorpayAdapter()
    if settings.razorpay_key_id is None or settings.razorpay_key_secret is None:
        msg = "validated Razorpay Test Mode settings are incomplete"
        raise RuntimeError(msg)
    return RazorpayTestModeAdapter(
        key_id=settings.razorpay_key_id,
        key_secret=settings.razorpay_key_secret,
        connect_timeout_seconds=settings.razorpay_connect_timeout_seconds,
        read_timeout_seconds=settings.razorpay_read_timeout_seconds,
    )


def _configured_incident_analyst_provider(
    settings: Settings,
) -> IncidentAnalystProvider | None:
    """Construct the single external analyst only after settings validation."""

    if settings.incident_analyst_target == "deterministic_rules":
        return None
    if settings.openai_api_key is None:
        msg = "validated OpenAI incident-analysis settings are incomplete"
        raise RuntimeError(msg)
    report = check_analyst_report()
    if report.status != "passed" or report.selected_model != settings.openai_incident_model:
        msg = "OpenAI incident analyst must match the passing frozen M6 selection"
        raise RuntimeError(msg)
    return OpenAIIncidentAnalystProvider(
        api_key=settings.openai_api_key,
        model=settings.openai_incident_model,
        prompt_version=settings.incident_analyst_prompt_version,
        evaluator_version=settings.incident_analyst_evaluator_version,
        timeout_seconds=settings.openai_timeout_seconds,
        max_output_tokens=settings.openai_max_output_tokens,
        max_schema_repairs=settings.openai_max_schema_repairs,
    )


def _install_incident_analyst(
    application: FastAPI,
    database: Database,
    settings: Settings,
    metrics: PipelineMetrics,
    provider_override: IncidentAnalystProvider | None,
) -> IncidentAnalystProvider | None:
    """Install one advisory analyst and its always-available rules fallback."""

    provider = provider_override or _configured_incident_analyst_provider(settings)
    fallback = RulesBasedIncidentAnalyst(database, settings, metrics)
    application.state.incident_analyst_provider = provider
    application.state.rules_based_incident_analyst = fallback
    application.state.incident_analyst = IncidentAnalyst(
        database,
        settings,
        metrics,
        fallback,
        provider,
    )
    return provider


def run() -> None:
    """Run the local API process."""

    uvicorn.run("retryrail.main:app", host="127.0.0.1", port=8000, reload=False)
