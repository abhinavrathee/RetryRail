"""Protected synthetic replay HTTP boundary for the local reviewer demo."""

import hmac
import uuid
from dataclasses import asdict
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from retryrail.config import Environment, Settings
from retryrail.db.session import Database
from retryrail.detection.service import DetectionRefreshResult, DetectionService
from retryrail.events.ingestion import (
    EventIdentityConflictError,
    EventIngestionService,
    EventPersistenceError,
)
from retryrail.events.outbox import OutboxWorker
from retryrail.observability.metrics import PipelineMetrics
from retryrail.replay import ReplayMode, ReplayRunner

router = APIRouter(prefix="/v1/demo", tags=["demo"])


class ReplayRequest(BaseModel):
    """Bound one replay invocation to a known partition and finite size."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["required_cases", "tuning"] = "required_cases"
    limit: int | None = Field(default=None, ge=1, le=10_000)


class ReplayResponse(BaseModel):
    """Aggregate replay result without detector or evaluation labels."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    synthetic: Literal[True] = True
    dataset_sha256: str
    selected_deliveries: int
    accepted: int
    duplicates: int
    rejected_signatures: int
    expectation_mismatches: int


class DemoRunResponse(BaseModel):
    """Bounded local replay, projection and deterministic-detection result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    synthetic: Literal[True] = True
    replay: ReplayResponse
    projected: int = Field(ge=0)
    retried: int = Field(ge=0)
    dead_lettered: int = Field(ge=0)
    detector_run_id: str | None
    detector_reused: bool
    source_events: int = Field(ge=0)
    attempts: int = Field(ge=0)
    aggregates: int = Field(ge=0)
    incidents: int = Field(ge=0)
    active_incidents: int = Field(ge=0)
    at_risk_gmv_subunits: int = Field(ge=0)


@router.post("/replay", summary="Replay synthetic webhooks")
async def replay(
    body: ReplayRequest,
    request: Request,
    replay_token: Annotated[
        str | None,
        Header(alias="X-RetryRail-Replay-Token"),
    ] = None,
) -> ReplayResponse:
    """Run only when explicitly enabled outside production and token-authenticated."""

    settings, service, _database, _metrics, _detector = _demo_resources(
        request,
        replay_token,
    )

    return await _run_replay(settings=settings, service=service, body=body)


@router.post("/run", summary="Run the bounded local detection demo")
async def run_demo(
    body: ReplayRequest,
    request: Request,
    replay_token: Annotated[
        str | None,
        Header(alias="X-RetryRail-Replay-Token"),
    ] = None,
) -> DemoRunResponse:
    """Replay synthetic events, drain finite projections and refresh the detector."""

    settings, service, database, metrics, detector = _demo_resources(
        request,
        replay_token,
    )
    replay_report = await _run_replay(
        settings=settings,
        service=service,
        body=body,
    )
    worker = OutboxWorker(
        database,
        metrics,
        worker_id=f"demo-{uuid.uuid4()}",
        batch_size=settings.worker_batch_size,
        lease_seconds=settings.worker_lease_seconds,
        retry_base_seconds=settings.worker_retry_base_seconds,
    )
    projected = 0
    retried = 0
    dead_lettered = 0
    maximum_cycles = 1 + (replay_report.selected_deliveries // settings.worker_batch_size)
    for _cycle_index in range(maximum_cycles + 1):
        cycle = await worker.run_once()
        projected += cycle.completed
        retried += cycle.retried
        dead_lettered += cycle.dead_lettered
        if cycle.claimed == 0:
            break
    detection = await detector.refresh(settings.merchant_id)
    return _demo_response(
        replay_report=replay_report,
        projected=projected,
        retried=retried,
        dead_lettered=dead_lettered,
        detection=detection,
    )


def _demo_resources(
    request: Request,
    replay_token: str | None,
) -> tuple[Settings, EventIngestionService, Database, PipelineMetrics, DetectionService]:
    settings = request.app.state.settings
    service = request.app.state.ingestion_service
    database = request.app.state.database
    metrics = request.app.state.metrics
    detector = request.app.state.detection_service
    if (
        not isinstance(settings, Settings)
        or not isinstance(service, EventIngestionService)
        or not isinstance(database, Database)
        or not isinstance(metrics, PipelineMetrics)
        or not isinstance(detector, DetectionService)
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": "SERVICE_NOT_READY"},
        )
    if settings.environment is Environment.PRODUCTION or not settings.replay_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"reason_code": "REPLAY_DISABLED"},
        )
    supplied = replay_token or ""
    expected = settings.replay_token.get_secret_value()
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"reason_code": "REPLAY_AUTHENTICATION_FAILED"},
        )
    return settings, service, database, metrics, detector


async def _run_replay(
    *,
    settings: Settings,
    service: EventIngestionService,
    body: ReplayRequest,
) -> ReplayResponse:
    """Map ingestion conflicts and storage faults identically for both demo routes."""

    try:
        report = await ReplayRunner(service, settings).run(
            ReplayMode(body.mode),
            limit=body.limit,
        )
    except EventIdentityConflictError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"reason_code": error.reason_code},
        ) from error
    except EventPersistenceError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": error.reason_code},
        ) from error
    return ReplayResponse(synthetic=True, **asdict(report))


def _demo_response(
    *,
    replay_report: ReplayResponse,
    projected: int,
    retried: int,
    dead_lettered: int,
    detection: DetectionRefreshResult,
) -> DemoRunResponse:
    return DemoRunResponse(
        replay=replay_report,
        projected=projected,
        retried=retried,
        dead_lettered=dead_lettered,
        detector_run_id=detection.run_id,
        detector_reused=detection.reused,
        source_events=detection.source_events,
        attempts=detection.attempts,
        aggregates=detection.aggregates,
        incidents=detection.incidents,
        active_incidents=detection.active_incidents,
        at_risk_gmv_subunits=detection.at_risk_gmv_subunits,
        synthetic=True,
    )
