"""Liveness and readiness endpoints."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from retryrail import __version__
from retryrail.config import Settings
from retryrail.db.session import Database

router = APIRouter(prefix="/health", tags=["health"])


class HealthResponse(BaseModel):
    """Small bounded health response with no configuration leakage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok", "ready"]
    service: Literal["retryrail-api"] = "retryrail-api"
    version: str = __version__


@router.get("/live", summary="Process liveness")
def live() -> HealthResponse:
    """Confirm that the HTTP process can serve requests."""

    return HealthResponse(status="ok")


@router.get("/ready", summary="Configuration and database readiness")
async def ready(request: Request) -> HealthResponse:
    """Require database connectivity and the exact expected migration revision."""

    settings = request.app.state.settings
    database = request.app.state.database
    if not isinstance(settings, Settings) or not isinstance(database, Database):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": "SERVICE_NOT_READY"},
        )
    readiness = await database.readiness()
    if not readiness.ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": readiness.reason_code},
        )
    return HealthResponse(status="ready")
