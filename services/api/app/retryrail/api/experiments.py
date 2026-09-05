"""Authenticated read-only API for the frozen synthetic M5 impact report."""

import hmac
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Path, Request, status

from retryrail.config import Settings
from retryrail.experiments.models import RecoveryExperimentReport
from retryrail.experiments.service import (
    ExperimentReportNotFoundError,
    ExperimentReportService,
)
from retryrail.recovery.models import RecoveryErrorResponse

ExperimentPath = Annotated[
    str,
    Path(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_-]+$"),
]
MerchantAuthorization = Annotated[
    str | None,
    Header(alias="X-RetryRail-Merchant-Authorization"),
]

router = APIRouter(prefix="/api/v1", tags=["experiments"])


@router.get(
    "/experiments/{experiment_id}",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": RecoveryErrorResponse},
        status.HTTP_404_NOT_FOUND: {"model": RecoveryErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": RecoveryErrorResponse},
    },
    summary="Read the frozen synthetic incremental recovered-GMV report",
)
def get_experiment_report(
    request: Request,
    experiment_id: ExperimentPath,
    authorization: MerchantAuthorization = None,
) -> RecoveryExperimentReport:
    """Return immutable measurement evidence; this route has no side effect."""

    service, _settings = _authenticated_service(request, authorization)
    try:
        report = service.get(experiment_id)
    except ExperimentReportNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"reason_code": "EXPERIMENT_NOT_FOUND"},
        ) from error
    request.app.state.metrics.experiment_report_reads.labels(result="succeeded").inc()
    return report


def _authenticated_service(
    request: Request,
    authorization: str | None,
) -> tuple[ExperimentReportService, Settings]:
    settings = request.app.state.settings
    service = request.app.state.experiment_report_service
    if not isinstance(settings, Settings) or not isinstance(service, ExperimentReportService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": "SERVICE_NOT_READY"},
        )
    supplied = authorization or ""
    expected = settings.merchant_approval_secret.get_secret_value()
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        request.app.state.metrics.experiment_report_reads.labels(
            result="unauthorized"
        ).inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"reason_code": "MERCHANT_AUTHENTICATION_FAILED"},
        )
    return service, settings
