"""M6 orchestration: redacted provider analysis with deterministic fallback."""

import time
from collections.abc import Callable
from datetime import UTC, datetime

import structlog
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from retryrail.config import Settings
from retryrail.contracts.domain import CohortPredicate, IncidentEvidence, IncidentStatus
from retryrail.db.session import Database
from retryrail.db.tables import IncidentRecord, ModelIncidentAnalysisRecord
from retryrail.detection.models import DetectorStatistics, DiagnosisSnapshot
from retryrail.detection.runtime_activation import load_detector_v4_activation
from retryrail.detection.v2_models import V2DetectorStatistics
from retryrail.observability.metrics import PipelineMetrics
from retryrail.recovery.analysis import RulesBasedIncidentAnalyst, validate_event_citations
from retryrail.recovery.analyst_models import (
    REQUIRED_ANALYST_STOP_CONDITIONS,
    AnalystFallbackResponse,
    AnalystModelStatus,
    AnalystProvenance,
    IncidentAnalysisResult,
    IncidentSnapshot,
    ModelIncidentAnalysis,
    ModelIncidentAnalysisDraft,
    ModelIncidentAnalysisResponse,
)
from retryrail.recovery.integrity import canonical_sha256, stable_identifier
from retryrail.recovery.models import RulesBasedPlanFallback
from retryrail.recovery.openai_analyst import (
    IncidentAnalystInvalidResponseError,
    IncidentAnalystProvider,
    IncidentAnalystProviderError,
)
from retryrail.recovery.workflow import (
    IncidentNotFoundError,
    MerchantScopeError,
    RecoveryEvidenceInvalidError,
    RecoveryPersistenceError,
)

LOGGER = structlog.get_logger(__name__)

_UNSUPPORTED_SCOPE_PHRASES = (
    "ecosystem-wide",
    "global outage",
    "all merchants",
    "razorpay outage",
    "platform-wide",
)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class IncidentAnalyst:
    """Keep model advice behind grounding, persistence, policy and approval boundaries."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        metrics: PipelineMetrics,
        fallback: RulesBasedIncidentAnalyst,
        provider: IncidentAnalystProvider | None,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._database = database
        self._settings = settings
        self._metrics = metrics
        self._fallback = fallback
        self._provider = provider
        self._clock = clock

    async def analyze(
        self,
        *,
        merchant_id: str,
        incident_id: str,
    ) -> IncidentAnalysisResult:
        """Return a grounded advisory analysis or complete through rules fallback."""

        if merchant_id != self._settings.merchant_id:
            raise MerchantScopeError
        if self._provider is None:
            self._metrics.incident_analyses.labels(
                result=AnalystModelStatus.UNAVAILABLE.value
            ).inc()
            self._metrics.agent_requests.labels(
                result=AnalystModelStatus.UNAVAILABLE.value
            ).inc()
            self._metrics.agent_fallbacks.labels(reason="ANALYST_NOT_CONFIGURED").inc()
            return await self._fallback_response(
                merchant_id=merchant_id,
                incident_id=incident_id,
                status=AnalystModelStatus.UNAVAILABLE,
                reason_code="ANALYST_NOT_CONFIGURED",
                attempted_model=None,
                provider_latency_ms=None,
            )

        # Persist a deterministic, content-bound baseline before any provider call.
        # This keeps the recovery audit independently reconstructable even when the
        # advisory model path succeeds.
        await self._fallback.analyze(
            merchant_id=merchant_id,
            incident_id=incident_id,
        )
        snapshot = await self._load_snapshot(
            merchant_id=merchant_id,
            incident_id=incident_id,
        )
        existing = await self._load_existing(snapshot)
        if existing is not None:
            self._metrics.incident_analyses.labels(result="replayed").inc()
            self._metrics.agent_requests.labels(result="replayed").inc()
            return ModelIncidentAnalysisResponse(
                disposition="replayed",
                analysis=existing,
                plan_fallback=_plan_fallback(snapshot),
            )

        provider_started = time.perf_counter()
        try:
            provider_result = await self._provider.analyze(snapshot)
            _validate_provenance(
                provider_result.provenance,
                provider=self._provider,
                settings=self._settings,
            )
            _validate_grounding(snapshot, provider_result.draft)
            analysis = ModelIncidentAnalysis(
                analysis_id=stable_identifier(
                    "analysis",
                    merchant_id,
                    (
                        f"{snapshot.snapshot_id}:{self._provider.model}:"
                        f"{provider_result.provenance.prompt_version}:"
                        f"{provider_result.provenance.evaluator_version}"
                    ),
                ),
                incident_id=incident_id,
                snapshot_id=snapshot.snapshot_id,
                brief=provider_result.draft.brief,
                proposal=provider_result.draft.proposal,
                provenance=provider_result.provenance,
                synthetic=snapshot.synthetic,
            )
            disposition, persisted = await self._persist(snapshot, analysis)
        except IncidentAnalystProviderError as error:
            provider_latency_seconds = max(time.perf_counter() - provider_started, 0.0)
            self._metrics.incident_analyses.labels(result=error.status.value).inc()
            self._metrics.agent_requests.labels(result=error.status.value).inc()
            self._metrics.agent_fallbacks.labels(reason=error.reason_code).inc()
            self._metrics.incident_analysis_latency.observe(provider_latency_seconds)
            self._metrics.agent_latency.observe(provider_latency_seconds)
            return await self._fallback_response(
                merchant_id=merchant_id,
                incident_id=incident_id,
                status=error.status,
                reason_code=error.reason_code,
                attempted_model=self._provider.model,
                provider_latency_ms=round(provider_latency_seconds * 1_000),
            )

        self._metrics.incident_analyses.labels(result=disposition).inc()
        self._metrics.agent_requests.labels(result=disposition).inc()
        self._metrics.incident_analysis_latency.observe(persisted.provenance.latency_ms / 1_000)
        self._metrics.agent_latency.observe(persisted.provenance.latency_ms / 1_000)
        self._metrics.incident_analysis_tokens.labels(direction="input").inc(
            persisted.provenance.input_tokens
        )
        self._metrics.incident_analysis_tokens.labels(direction="output").inc(
            persisted.provenance.output_tokens
        )
        if persisted.provenance.estimated_cost_microusd is not None:
            self._metrics.incident_analysis_estimated_cost.inc(
                persisted.provenance.estimated_cost_microusd
            )
            self._metrics.agent_estimated_cost.inc(
                persisted.provenance.estimated_cost_microusd
            )
        LOGGER.info(
            "incident_analysis_completed",
            merchant_id=merchant_id,
            incident_id=incident_id,
            analysis_id=persisted.analysis_id,
            model=persisted.provenance.model,
            result=disposition,
            fallback_used=False,
            latency_ms=persisted.provenance.latency_ms,
            estimated_cost_microusd=persisted.provenance.estimated_cost_microusd,
        )
        return ModelIncidentAnalysisResponse(
            disposition=disposition,
            analysis=persisted,
            plan_fallback=_plan_fallback(snapshot),
        )

    async def _load_snapshot(
        self,
        *,
        merchant_id: str,
        incident_id: str,
    ) -> IncidentSnapshot:
        try:
            async with self._database.sessions() as session:
                incident = await session.scalar(
                    select(IncidentRecord).where(
                        IncidentRecord.incident_id == incident_id,
                        IncidentRecord.merchant_id == merchant_id,
                    )
                )
                if incident is None:
                    raise IncidentNotFoundError
                await validate_event_citations(session, incident)
                return _build_snapshot(incident)
        except SQLAlchemyError as error:
            raise RecoveryPersistenceError from error

    async def _load_existing(
        self,
        snapshot: IncidentSnapshot,
    ) -> ModelIncidentAnalysis | None:
        if self._provider is None:  # pragma: no cover - guarded by caller
            return None
        source_sha256 = canonical_sha256(snapshot)
        try:
            async with self._database.sessions() as session:
                record = await session.scalar(
                    select(ModelIncidentAnalysisRecord).where(
                        ModelIncidentAnalysisRecord.incident_id == snapshot.incident_id,
                        ModelIncidentAnalysisRecord.source_snapshot_sha256 == source_sha256,
                        ModelIncidentAnalysisRecord.model == self._provider.model,
                        ModelIncidentAnalysisRecord.prompt_version
                        == self._settings.incident_analyst_prompt_version,
                        ModelIncidentAnalysisRecord.evaluator_version
                        == self._settings.incident_analyst_evaluator_version,
                    )
                )
        except SQLAlchemyError as error:
            raise RecoveryPersistenceError from error
        return _materialize(record, source_sha256=source_sha256) if record else None

    async def _persist(
        self,
        snapshot: IncidentSnapshot,
        analysis: ModelIncidentAnalysis,
    ) -> tuple[str, ModelIncidentAnalysis]:
        source_sha256 = canonical_sha256(snapshot)
        provenance = analysis.provenance
        record = ModelIncidentAnalysisRecord(
            analysis_id=analysis.analysis_id,
            incident_id=analysis.incident_id,
            merchant_id=self._settings.merchant_id,
            snapshot_id=analysis.snapshot_id,
            source_snapshot_sha256=source_sha256,
            analysis_sha256=canonical_sha256(analysis),
            analysis_document=analysis.model_dump(mode="json"),
            provider=provenance.provider,
            model=provenance.model,
            prompt_version=provenance.prompt_version,
            output_schema_version=provenance.output_schema_version,
            evaluator_version=provenance.evaluator_version,
            model_status=analysis.model_status,
            fallback_used=analysis.fallback_used,
            latency_ms=provenance.latency_ms,
            input_tokens=provenance.input_tokens,
            output_tokens=provenance.output_tokens,
            total_tokens=provenance.total_tokens,
            estimated_cost_microusd=provenance.estimated_cost_microusd,
            pricing_version=provenance.pricing_version,
            schema_repair_attempts=provenance.schema_repair_attempts,
            provider_storage_enabled=False,
            created_at=self._clock_utc(),
        )
        try:
            async with self._database.sessions() as session, session.begin():
                try:
                    async with session.begin_nested():
                        session.add(record)
                        await session.flush()
                except IntegrityError:
                    existing = await session.scalar(
                        select(ModelIncidentAnalysisRecord).where(
                            ModelIncidentAnalysisRecord.incident_id == snapshot.incident_id,
                            ModelIncidentAnalysisRecord.source_snapshot_sha256 == source_sha256,
                            ModelIncidentAnalysisRecord.model == provenance.model,
                            ModelIncidentAnalysisRecord.prompt_version == provenance.prompt_version,
                            ModelIncidentAnalysisRecord.evaluator_version
                            == provenance.evaluator_version,
                        )
                    )
                    if existing is None:
                        raise
                    return "replayed", _materialize(
                        existing,
                        source_sha256=source_sha256,
                    )
        except SQLAlchemyError as error:
            raise RecoveryPersistenceError from error
        return "created", analysis

    async def _fallback_response(
        self,
        *,
        merchant_id: str,
        incident_id: str,
        status: AnalystModelStatus,
        reason_code: str,
        attempted_model: str | None,
        provider_latency_ms: int | None,
    ) -> AnalystFallbackResponse:
        fallback = await self._fallback.analyze(
            merchant_id=merchant_id,
            incident_id=incident_id,
        )
        LOGGER.info(
            "incident_analysis_fallback_completed",
            merchant_id=merchant_id,
            incident_id=incident_id,
            model_status=status.value,
            attempted_model=attempted_model,
            reason_code=reason_code,
            fallback_used=True,
            latency_ms=provider_latency_ms,
            estimated_cost_microusd=None,
        )
        return AnalystFallbackResponse(
            disposition=fallback.disposition.value,
            brief=fallback.brief,
            plan_fallback=fallback.plan_fallback,
            model_status=status,
            attempted_model=attempted_model,
            prompt_version=self._settings.incident_analyst_prompt_version,
            evaluator_version=self._settings.incident_analyst_evaluator_version,
            fallback_reason_code=reason_code,
        )

    def _clock_utc(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RecoveryEvidenceInvalidError
        return now.astimezone(UTC)


def _build_snapshot(incident: IncidentRecord) -> IncidentSnapshot:
    try:
        statistics = _statistics(incident.peak_statistics)
        diagnosis = DiagnosisSnapshot.model_validate(incident.diagnosis)
        cohort = tuple(CohortPredicate.model_validate(item) for item in incident.affected_cohort)
        evidence = _incident_evidence(statistics)
    except (ValidationError, ValueError) as error:
        raise RecoveryEvidenceInvalidError from error
    effective_action_eligible = load_detector_v4_activation().allows_incident(incident)
    snapshot_source = {
        "incident_id": incident.incident_id,
        "detector_version": incident.detector_version,
        "status": incident.status,
        "opened_at": incident.opened_at,
        "last_observed_at": incident.last_observed_at,
        "cohort": incident.affected_cohort,
        "statistics": incident.peak_statistics,
        "diagnosis": incident.diagnosis,
        "gmv_at_risk_subunits": incident.gmv_at_risk_subunits,
        "currency": incident.currency,
        "action_eligible": effective_action_eligible,
        "synthetic": incident.synthetic,
    }
    source_sha256 = canonical_sha256(snapshot_source)
    return IncidentSnapshot(
        snapshot_id=stable_identifier("snapshot", incident.merchant_id, source_sha256),
        incident_id=incident.incident_id,
        detector_version=incident.detector_version,
        status=IncidentStatus(incident.status),
        opened_at=incident.opened_at,
        last_observed_at=incident.last_observed_at,
        affected_cohort=cohort,
        evidence=evidence,
        verified_attributions=diagnosis.verified_attributions[:3],
        detector_hypotheses=tuple(item.statement for item in diagnosis.hypotheses),
        unknowns=diagnosis.unknowns,
        gmv_at_risk_subunits=incident.gmv_at_risk_subunits,
        currency=incident.currency,
        action_eligible=effective_action_eligible,
        synthetic=incident.synthetic,
    )


def _statistics(document: dict[str, object]) -> DetectorStatistics | V2DetectorStatistics:
    if "cohort_level" in document:
        return V2DetectorStatistics.model_validate(document)
    return DetectorStatistics.model_validate(document)


def _incident_evidence(
    statistics: DetectorStatistics | V2DetectorStatistics,
) -> IncidentEvidence:
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


def _validate_grounding(snapshot: IncidentSnapshot, draft: object) -> None:
    if not isinstance(draft, ModelIncidentAnalysisDraft):
        raise IncidentAnalystInvalidResponseError
    allowed_ids = {
        event_id
        for attribution in snapshot.verified_attributions
        for event_id in attribution.evidence_event_ids
    }
    cited_groups = (
        draft.brief.executive_summary_evidence_ids,
        draft.proposal.evidence_ids,
        *(item.evidence_ids for item in draft.brief.verified_evidence),
        *(item.evidence_ids for item in draft.brief.hypotheses),
    )
    if any(not set(group).issubset(allowed_ids) for group in cited_groups):
        raise IncidentAnalystInvalidResponseError
    combined_text = " ".join(
        (
            draft.brief.executive_summary,
            draft.proposal.rationale,
            *(item.statement for item in draft.brief.verified_evidence),
            *(item.statement for item in draft.brief.hypotheses),
            *draft.brief.unknowns,
        )
    ).lower()
    if any(phrase in combined_text for phrase in _UNSUPPORTED_SCOPE_PHRASES):
        raise IncidentAnalystInvalidResponseError
    if (
        draft.proposal.opportunity_gmv_subunits != snapshot.gmv_at_risk_subunits
        or draft.proposal.currency != snapshot.currency
        or frozenset(draft.proposal.stop_conditions) != REQUIRED_ANALYST_STOP_CONDITIONS
    ):
        raise IncidentAnalystInvalidResponseError


def _validate_provenance(
    provenance: AnalystProvenance,
    *,
    provider: IncidentAnalystProvider,
    settings: Settings,
) -> None:
    """Reject provider telemetry that is not bound to this configured request."""

    if (
        provenance.model != provider.model
        or provenance.prompt_version != settings.incident_analyst_prompt_version
        or provenance.evaluator_version != settings.incident_analyst_evaluator_version
        or provenance.output_schema_version != "1.0.0"
        or provenance.response_stored_by_provider is not False
    ):
        raise IncidentAnalystInvalidResponseError


def _plan_fallback(snapshot: IncidentSnapshot) -> RulesBasedPlanFallback:
    return RulesBasedPlanFallback(
        incident_id=snapshot.incident_id,
        can_create_plan=snapshot.action_eligible,
        reason_code=(
            "RULES_FALLBACK_PLAN_AVAILABLE"
            if snapshot.action_eligible
            else "INCIDENT_NOT_ACTION_ELIGIBLE"
        ),
        plan_endpoint=f"/api/v1/incidents/{snapshot.incident_id}/plans",
        synthetic=snapshot.synthetic,
    )


def _materialize(
    record: ModelIncidentAnalysisRecord,
    *,
    source_sha256: str,
) -> ModelIncidentAnalysis:
    try:
        analysis = ModelIncidentAnalysis.model_validate(record.analysis_document)
    except ValidationError as error:
        raise RecoveryEvidenceInvalidError from error
    provenance = analysis.provenance
    if (
        record.analysis_id != analysis.analysis_id
        or record.incident_id != analysis.incident_id
        or record.snapshot_id != analysis.snapshot_id
        or record.source_snapshot_sha256 != source_sha256
        or record.analysis_sha256 != canonical_sha256(analysis)
        or record.provider != provenance.provider
        or record.model != provenance.model
        or record.prompt_version != provenance.prompt_version
        or record.output_schema_version != provenance.output_schema_version
        or record.evaluator_version != provenance.evaluator_version
        or record.model_status != analysis.model_status
        or record.fallback_used is not False
        or record.latency_ms != provenance.latency_ms
        or record.input_tokens != provenance.input_tokens
        or record.output_tokens != provenance.output_tokens
        or record.total_tokens != provenance.total_tokens
        or record.estimated_cost_microusd != provenance.estimated_cost_microusd
        or record.pricing_version != provenance.pricing_version
        or record.schema_repair_attempts != provenance.schema_repair_attempts
        or record.provider_storage_enabled is not False
    ):
        raise RecoveryEvidenceInvalidError
    return analysis
