"""Merchant-scoped read APIs for detector overview and incident evidence."""

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import AwareDatetime, ConfigDict, Field, ValidationError
from sqlalchemy import desc, func, select

from retryrail.config import Settings
from retryrail.contracts.domain import (
    CohortPredicate,
    IncidentContract,
    IncidentEvidence,
    IncidentStatus,
    StrictContract,
)
from retryrail.db.session import Database
from retryrail.db.tables import (
    DetectionRunRecord,
    IncidentObservationRecord,
    IncidentRecord,
)
from retryrail.detection.config import load_detector_release_decision
from retryrail.detection.models import (
    DetectorReleaseStatus,
    DetectorReleaseTarget,
    DetectorStatistics,
    DiagnosisSnapshot,
)
from retryrail.detection.runtime_activation import load_detector_v4_activation
from retryrail.detection.v2_models import V2DetectorStatistics

router = APIRouter(prefix="/api/v1", tags=["incidents"])


class IncidentSummary(StrictContract):
    """Typed reviewer-facing incident plus bounded policy eligibility state."""

    incident: IncidentContract
    action_eligible: bool
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    diagnosis: DiagnosisSnapshot


class IncidentListResponse(StrictContract):
    """Finite merchant-scoped incident page with an explicit synthetic label."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[IncidentSummary, ...]
    count: int = Field(ge=0)
    synthetic: bool


class IncidentObservation(StrictContract):
    """One immutable passing observation from the incident timeline."""

    observation_id: str
    evaluated_at: AwareDatetime
    statistics: DetectorStatistics | V2DetectorStatistics
    evidence_event_ids: tuple[str, ...] = Field(min_length=1)


class IncidentDetailResponse(StrictContract):
    """Complete evidence view used by deterministic planning and later UI."""

    summary: IncidentSummary
    peak_statistics: DetectorStatistics | V2DetectorStatistics
    observations: tuple[IncidentObservation, ...] = Field(min_length=1)
    evidence_labels: tuple[
        Literal["verified_observation", "inferred_hypothesis", "unknown"], ...
    ] = Field(min_length=3, max_length=3)
    synthetic: bool


class OverviewResponse(StrictContract):
    """Aggregate merchant state without exposing cross-tenant identifiers."""

    detector_version: str
    detector_release_status: DetectorReleaseStatus
    detector_release_failed_targets: tuple[DetectorReleaseTarget, ...]
    active_incidents: int = Field(ge=0)
    action_eligible_incidents: int = Field(ge=0)
    total_incidents: int = Field(ge=0)
    at_risk_gmv_subunits: int = Field(ge=0)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    data_as_of: AwareDatetime | None
    synthetic: bool


@router.get("/overview")
async def overview(request: Request) -> OverviewResponse:
    """Return current detector state for the configured merchant only."""

    database, settings = _resources(request)
    async with database.sessions() as session:
        total = int(
            await session.scalar(
                select(func.count())
                .select_from(IncidentRecord)
                .where(IncidentRecord.merchant_id == settings.merchant_id)
            )
            or 0
        )
        active = int(
            await session.scalar(
                select(func.count())
                .select_from(IncidentRecord)
                .where(
                    IncidentRecord.merchant_id == settings.merchant_id,
                    IncidentRecord.status == "open",
                )
            )
            or 0
        )
        action_eligible = int(
            await session.scalar(
                select(func.count())
                .select_from(IncidentRecord)
                .where(
                    IncidentRecord.merchant_id == settings.merchant_id,
                    IncidentRecord.status == "open",
                    IncidentRecord.action_eligible.is_(True),
                )
            )
            or 0
        )
        at_risk = int(
            await session.scalar(
                select(func.coalesce(func.sum(IncidentRecord.gmv_at_risk_subunits), 0))
                .where(
                    IncidentRecord.merchant_id == settings.merchant_id,
                    IncidentRecord.status == "open",
                )
            )
            or 0
        )
        latest_run = await session.scalar(
            select(DetectionRunRecord)
            .where(DetectionRunRecord.merchant_id == settings.merchant_id)
            .order_by(desc(DetectionRunRecord.created_at))
            .limit(1)
        )
        latest_incident = await session.scalar(
            select(IncidentRecord)
            .where(IncidentRecord.merchant_id == settings.merchant_id)
            .order_by(desc(IncidentRecord.opened_at))
            .limit(1)
        )
    if latest_run is None or latest_run.detector_version == "detector_v4_0_0":
        activation = load_detector_v4_activation()
        detector_version = (
            latest_run.detector_version
            if latest_run is not None
            else activation.detector_version
        )
        release_status = DetectorReleaseStatus(activation.status.value)
        release_failed_targets: tuple[DetectorReleaseTarget, ...] = ()
    else:
        release = load_detector_release_decision()
        detector_version = latest_run.detector_version
        release_status = release.status
        release_failed_targets = release.failed_targets
    return OverviewResponse(
        detector_version=detector_version,
        detector_release_status=release_status,
        detector_release_failed_targets=release_failed_targets,
        active_incidents=active,
        action_eligible_incidents=action_eligible,
        total_incidents=total,
        at_risk_gmv_subunits=at_risk,
        currency=latest_incident.currency if latest_incident is not None else "INR",
        data_as_of=latest_run.source_watermark if latest_run is not None else None,
        synthetic=(latest_incident.synthetic if latest_incident is not None else True),
    )


@router.get("/incidents")
async def list_incidents(
    request: Request,
    incident_status: Annotated[
        Literal["open", "resolved"] | None,
        Query(alias="status"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> IncidentListResponse:
    """List only the configured merchant's bounded incident records."""

    database, settings = _resources(request)
    statement = select(IncidentRecord).where(
        IncidentRecord.merchant_id == settings.merchant_id
    )
    if incident_status is not None:
        statement = statement.where(IncidentRecord.status == incident_status)
    statement = statement.order_by(desc(IncidentRecord.opened_at)).limit(limit)
    async with database.sessions() as session:
        records = tuple((await session.scalars(statement)).all())
    items = tuple(_summary(item) for item in records)
    return IncidentListResponse(
        items=items,
        count=len(items),
        synthetic=all(item.incident.synthetic for item in items),
    )


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, request: Request) -> IncidentDetailResponse:
    """Return evidence only when both incident identity and merchant scope match."""

    database, settings = _resources(request)
    async with database.sessions() as session:
        record = await session.scalar(
            select(IncidentRecord).where(
                IncidentRecord.incident_id == incident_id,
                IncidentRecord.merchant_id == settings.merchant_id,
            )
        )
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"reason_code": "INCIDENT_NOT_FOUND"},
            )
        observation_records = tuple(
            (
                await session.scalars(
                    select(IncidentObservationRecord)
                    .where(
                        IncidentObservationRecord.incident_id == incident_id,
                        IncidentObservationRecord.merchant_id == settings.merchant_id,
                    )
                    .order_by(IncidentObservationRecord.evaluated_at)
                )
            ).all()
        )
    try:
        observations = tuple(
            IncidentObservation(
                observation_id=item.observation_id,
                evaluated_at=item.evaluated_at,
                statistics=_statistics(item.statistics),
                evidence_event_ids=tuple(item.evidence_event_ids),
            )
            for item in observation_records
        )
        peak = _statistics(record.peak_statistics)
        summary = _summary(record)
    except ValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"reason_code": "INCIDENT_EVIDENCE_INVALID"},
        ) from error
    return IncidentDetailResponse(
        summary=summary,
        peak_statistics=peak,
        observations=observations,
        evidence_labels=(
            "verified_observation",
            "inferred_hypothesis",
            "unknown",
        ),
        synthetic=record.synthetic,
    )


def _summary(record: IncidentRecord) -> IncidentSummary:
    try:
        statistics = _statistics(record.peak_statistics)
        diagnosis = DiagnosisSnapshot.model_validate(record.diagnosis)
        affected_cohort = tuple(
            CohortPredicate.model_validate(item) for item in record.affected_cohort
        )
        incident = IncidentContract(
            incident_id=record.incident_id,
            merchant_id=record.merchant_id,
            status=IncidentStatus(record.status),
            detector_version=record.detector_version,
            opened_at=record.opened_at,
            last_observed_at=record.last_observed_at,
            resolved_at=record.resolved_at,
            affected_cohort=affected_cohort,
            evidence_event_ids=tuple(record.evidence_event_ids),
            evidence=_incident_evidence(statistics),
            likely_error_sources=diagnosis.likely_causes,
            gmv_at_risk_subunits=record.gmv_at_risk_subunits,
            currency=record.currency,
            synthetic=record.synthetic,
        )
    except (ValidationError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"reason_code": "INCIDENT_EVIDENCE_INVALID"},
        ) from error
    return IncidentSummary(
        incident=incident,
        action_eligible=load_detector_v4_activation().allows_incident(record),
        detector_config_sha256=record.detector_config_sha256,
        diagnosis=diagnosis,
    )


def _statistics(
    document: dict[str, object],
) -> DetectorStatistics | V2DetectorStatistics:
    """Reload either historical v1 or activated v4 evidence without coercion."""

    if "cohort_level" in document:
        return V2DetectorStatistics.model_validate(document)
    return DetectorStatistics.model_validate(document)


def _incident_evidence(
    statistics: DetectorStatistics | V2DetectorStatistics,
) -> IncidentEvidence:
    """Map versioned detector evidence into the frozen incident summary contract."""

    if isinstance(statistics, V2DetectorStatistics):
        return IncidentEvidence(
            baseline_attempts=statistics.baseline_attempts,
            baseline_successes=statistics.baseline_attempts - statistics.baseline_failures,
            current_attempts=statistics.current_attempts,
            current_successes=statistics.current_attempts - statistics.current_failures,
            minimum_attempts=statistics.minimum_current_attempts,
            observed_success_rate_drop_bps=statistics.actionable_rate_drop_bps,
            confidence_ppm=statistics.confidence_ppm,
            excess_failures=statistics.excess_actionable_failures,
        )
    return IncidentEvidence(
        baseline_attempts=statistics.baseline_attempts,
        baseline_successes=statistics.baseline_successes,
        current_attempts=statistics.current_attempts,
        current_successes=statistics.current_successes,
        minimum_attempts=statistics.minimum_current_attempts,
        observed_success_rate_drop_bps=statistics.success_rate_drop_bps,
        confidence_ppm=statistics.confidence_ppm,
        excess_failures=statistics.excess_failures,
    )


def _resources(request: Request) -> tuple[Database, Settings]:
    database = request.app.state.database
    settings = request.app.state.settings
    if not isinstance(database, Database) or not isinstance(settings, Settings):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": "SERVICE_NOT_READY"},
        )
    return database, settings
