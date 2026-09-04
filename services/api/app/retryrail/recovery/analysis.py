"""M4.5 deterministic incident brief and model-unavailable plan fallback."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog
from pydantic import ValidationError
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from retryrail.config import Settings
from retryrail.contracts.domain import CohortPredicate
from retryrail.db.session import Database
from retryrail.db.tables import (
    IncidentRecord,
    PaymentEventRecord,
    RulesBasedIncidentBriefRecord,
)
from retryrail.detection.models import DetectorStatistics, DiagnosisSnapshot
from retryrail.detection.runtime_activation import load_detector_v4_activation
from retryrail.detection.v2_models import V2DetectorStatistics
from retryrail.observability.metrics import PipelineMetrics
from retryrail.recovery.integrity import canonical_sha256, stable_identifier
from retryrail.recovery.models import (
    RulesBasedIncidentAnalysisResponse,
    RulesBasedIncidentBrief,
    RulesBasedPlanFallback,
    RulesExpectedBenefit,
    RulesHypothesis,
    RulesVerifiedEvidence,
)
from retryrail.recovery.workflow import (
    IncidentNotFoundError,
    MerchantScopeError,
    RecoveryEvidenceInvalidError,
    RecoveryPersistenceError,
)

LOGGER = structlog.get_logger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class RulesBasedIncidentAnalyst:
    """Build and persist grounded briefs without importing any model provider."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        metrics: PipelineMetrics,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._database = database
        self._settings = settings
        self._metrics = metrics
        self._clock = clock
        self._detector_activation = load_detector_v4_activation()

    async def analyze(
        self,
        *,
        merchant_id: str,
        incident_id: str,
    ) -> RulesBasedIncidentAnalysisResponse:
        """Create or exactly replay one brief for the current incident snapshot."""

        self._require_merchant(merchant_id)
        try:
            async with self._database.sessions() as session, session.begin():
                incident = await session.scalar(
                    select(IncidentRecord)
                    .where(
                        IncidentRecord.incident_id == incident_id,
                        IncidentRecord.merchant_id == merchant_id,
                    )
                    .with_for_update()
                )
                if incident is None:
                    raise IncidentNotFoundError
                await _validate_event_citations(session, incident)
                source_sha256 = canonical_sha256(_source_snapshot(incident))
                existing = await session.scalar(
                    select(RulesBasedIncidentBriefRecord).where(
                        RulesBasedIncidentBriefRecord.incident_id == incident_id,
                        RulesBasedIncidentBriefRecord.source_snapshot_sha256 == source_sha256,
                    )
                )
                if existing is not None:
                    brief = _materialize_brief(existing, source_sha256=source_sha256)
                    disposition = "replayed"
                else:
                    brief = _build_brief(incident, source_sha256=source_sha256)
                    now = self._clock_utc()
                    record = RulesBasedIncidentBriefRecord(
                        brief_id=brief.brief_id,
                        incident_id=brief.incident_id,
                        merchant_id=merchant_id,
                        source_snapshot_sha256=source_sha256,
                        brief_sha256=canonical_sha256(brief),
                        brief_document=brief.model_dump(mode="json"),
                        analyst_mode="deterministic_rules",
                        model_status="unavailable",
                        fallback_used=True,
                        created_at=now,
                    )
                    try:
                        async with session.begin_nested():
                            session.add(record)
                            await session.flush()
                    except IntegrityError:
                        existing = await session.scalar(
                            select(RulesBasedIncidentBriefRecord).where(
                                RulesBasedIncidentBriefRecord.incident_id == incident_id,
                                RulesBasedIncidentBriefRecord.source_snapshot_sha256
                                == source_sha256,
                            )
                        )
                        if existing is None:
                            raise
                        brief = _materialize_brief(
                            existing,
                            source_sha256=source_sha256,
                        )
                        disposition = "replayed"
                    else:
                        disposition = "created"
        except SQLAlchemyError as error:
            LOGGER.warning(
                "rules_fallback_persistence_failed",
                merchant_id=merchant_id,
                incident_id=incident_id,
                reason_code=RecoveryPersistenceError.reason_code,
            )
            raise RecoveryPersistenceError from error

        plan_available = self._detector_activation.allows_incident(incident)
        self._metrics.rules_fallback_analyses.labels(result=disposition).inc()
        LOGGER.info(
            "rules_fallback_analysis_completed",
            disposition=disposition,
            merchant_id=merchant_id,
            incident_id=incident_id,
            brief_id=brief.brief_id,
            plan_available=plan_available,
        )
        return RulesBasedIncidentAnalysisResponse(
            disposition=disposition,
            brief=brief,
            plan_fallback=RulesBasedPlanFallback(
                incident_id=incident_id,
                can_create_plan=plan_available,
                reason_code=(
                    "RULES_FALLBACK_PLAN_AVAILABLE"
                    if plan_available
                    else "INCIDENT_NOT_ACTION_ELIGIBLE"
                ),
                plan_endpoint=f"/api/v1/incidents/{incident_id}/plans",
                synthetic=incident.synthetic,
            ),
        )

    def _require_merchant(self, merchant_id: str) -> None:
        if merchant_id != self._settings.merchant_id:
            raise MerchantScopeError

    def _clock_utc(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RecoveryEvidenceInvalidError
        return now.astimezone(UTC)


def _source_snapshot(incident: IncidentRecord) -> dict[str, object]:
    return {
        "incident_id": incident.incident_id,
        "merchant_id": incident.merchant_id,
        "detector_version": incident.detector_version,
        "detector_config_sha256": incident.detector_config_sha256,
        "affected_cohort": incident.affected_cohort,
        "status": incident.status,
        "opened_at": incident.opened_at,
        "last_observed_at": incident.last_observed_at,
        "resolved_at": incident.resolved_at,
        "peak_statistics": incident.peak_statistics,
        "diagnosis": incident.diagnosis,
        "evidence_event_ids": incident.evidence_event_ids,
        "gmv_at_risk_subunits": incident.gmv_at_risk_subunits,
        "currency": incident.currency,
        "action_eligible": incident.action_eligible,
        "synthetic": incident.synthetic,
    }


async def _validate_event_citations(
    session: "AsyncSession",
    incident: IncidentRecord,
) -> None:
    """Require every detector citation to resolve to a verified merchant event."""

    expected = set(incident.evidence_event_ids)
    if not expected:
        raise RecoveryEvidenceInvalidError
    records = tuple(
        (
            await session.scalars(
                select(PaymentEventRecord).where(
                    PaymentEventRecord.merchant_id == incident.merchant_id,
                    PaymentEventRecord.signature_status == "verified",
                    or_(
                        PaymentEventRecord.internal_id.in_(expected),
                        PaymentEventRecord.razorpay_event_id.in_(expected),
                    ),
                )
            )
        ).all()
    )
    observed = {
        identifier
        for record in records
        for identifier in (record.internal_id, record.razorpay_event_id)
        if identifier in expected
    }
    synthetic_mismatch = any(
        record.synthetic is not incident.synthetic for record in records
    )
    if observed != expected or synthetic_mismatch:
        raise RecoveryEvidenceInvalidError


def _build_brief(
    incident: IncidentRecord,
    *,
    source_sha256: str,
) -> RulesBasedIncidentBrief:
    try:
        statistics = _statistics(incident.peak_statistics)
        diagnosis = DiagnosisSnapshot.model_validate(incident.diagnosis)
        cohort = tuple(CohortPredicate.model_validate(item) for item in incident.affected_cohort)
    except ValidationError as error:
        raise RecoveryEvidenceInvalidError from error
    event_ids = tuple(incident.evidence_event_ids)
    if not event_ids or not cohort:
        raise RecoveryEvidenceInvalidError
    event_set = set(event_ids)
    hypotheses = tuple(
        RulesHypothesis(
            statement=item.statement,
            confidence_ppm=item.confidence_ppm,
            evidence_event_ids=item.evidence_event_ids,
        )
        for item in diagnosis.hypotheses
    )
    if any(not set(hypothesis.evidence_event_ids).issubset(event_set) for hypothesis in hypotheses):
        raise RecoveryEvidenceInvalidError
    top_attribution = diagnosis.verified_attributions[0]
    if not set(top_attribution.evidence_event_ids).issubset(event_set):
        raise RecoveryEvidenceInvalidError
    cohort_text = ", ".join(
        f"{predicate.dimension.value}={predicate.value}" for predicate in cohort
    )
    brief_id = stable_identifier("brief", incident.merchant_id, source_sha256)
    if isinstance(statistics, V2DetectorStatistics):
        rate_label = "actionable failure-rate increase"
        rate_bps = statistics.actionable_rate_drop_bps
    else:
        rate_label = "success-rate drop"
        rate_bps = statistics.success_rate_drop_bps
    evidence = (
        RulesVerifiedEvidence(
            evidence_id=stable_identifier("evidence", incident.merchant_id, f"{brief_id}:rate"),
            statement=(
                f"Verified merchant-local {cohort_text} {rate_label} is "
                f"{rate_bps} bps across "
                f"{statistics.current_attempts} current attempts."
            ),
            evidence_event_ids=event_ids,
        ),
        RulesVerifiedEvidence(
            evidence_id=stable_identifier("evidence", incident.merchant_id, f"{brief_id}:gmv"),
            statement=(
                f"Observed at-risk value is {incident.gmv_at_risk_subunits} "
                f"{incident.currency} subunits; this is exposure, not recovered or "
                "incremental GMV."
            ),
            evidence_event_ids=event_ids,
        ),
        RulesVerifiedEvidence(
            evidence_id=stable_identifier(
                "evidence",
                incident.merchant_id,
                f"{brief_id}:attribution",
            ),
            statement=(
                f"Top verified attribution is {top_attribution.dimension.value}="
                f"{top_attribution.value} with {top_attribution.contribution_ppm} ppm "
                "of measured excess failures."
            ),
            evidence_event_ids=top_attribution.evidence_event_ids,
        ),
    )
    return RulesBasedIncidentBrief(
        brief_id=brief_id,
        incident_id=incident.incident_id,
        executive_summary=(
            f"RetryRail detected a merchant-local payment degradation in {cohort_text}; "
            f"{incident.gmv_at_risk_subunits} {incident.currency} subunits are observed "
            "at risk. A standard payment link is the only proposed template and still "
            "requires merchant approval plus fresh policy validation."
        ),
        executive_summary_evidence_ids=event_ids,
        verified_evidence=evidence,
        hypotheses=hypotheses,
        unknowns=diagnosis.unknowns,
        expected_benefit=RulesExpectedBenefit(
            opportunity_gmv_subunits=incident.gmv_at_risk_subunits,
            currency=incident.currency,
        ),
        confidence=statistics.confidence_ppm,
        stop_conditions=(
            "POLICY_INCIDENT_NOT_ACTION_ELIGIBLE",
            "POLICY_OPERATING_MODE_ANALYZE_ONLY",
            "POLICY_CUSTOMER_OPTED_OUT",
            "POLICY_ATTEMPT_CAP_REACHED",
            "POLICY_COOLDOWN_ACTIVE",
            "POLICY_PLAN_EXPIRED",
            "POLICY_KILL_SWITCH_ON",
            "POLICY_PAYMENT_ALREADY_RECOVERED",
        ),
        synthetic=incident.synthetic,
    )


def _statistics(
    document: dict[str, object],
) -> DetectorStatistics | V2DetectorStatistics:
    """Reload the exact detector evidence version used by the incident."""

    if "cohort_level" in document:
        return V2DetectorStatistics.model_validate(document)
    return DetectorStatistics.model_validate(document)


def _materialize_brief(
    record: RulesBasedIncidentBriefRecord,
    *,
    source_sha256: str,
) -> RulesBasedIncidentBrief:
    try:
        brief = RulesBasedIncidentBrief.model_validate(record.brief_document)
    except ValidationError as error:
        raise RecoveryEvidenceInvalidError from error
    if (
        record.analyst_mode != "deterministic_rules"
        or record.model_status != "unavailable"
        or record.fallback_used is not True
        or record.source_snapshot_sha256 != source_sha256
        or record.brief_id != brief.brief_id
        or record.incident_id != brief.incident_id
        or record.brief_sha256 != canonical_sha256(brief)
    ):
        raise RecoveryEvidenceInvalidError
    return brief
