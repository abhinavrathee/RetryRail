"""Protected synthetic replay HTTP boundary for the local reviewer demo."""

import hmac
from dataclasses import asdict
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from retryrail.config import Environment, Settings
from retryrail.events.ingestion import (
    EventIdentityConflictError,
    EventIngestionService,
    EventPersistenceError,
)
from retryrail.replay import ReplayMode, ReplayRunner

router = APIRouter(prefix="/v1/demo", tags=["demo"])


class ReplayRequest(BaseModel):
    """Bound one replay invocation to a known partition and finite size."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["required_cases"] = "required_cases"
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

    settings = request.app.state.settings
    service = request.app.state.ingestion_service
    if not isinstance(settings, Settings) or not isinstance(service, EventIngestionService):
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
