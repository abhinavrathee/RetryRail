"""Typed contracts for the pre-release detector-v2 candidate."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import (
    CohortDimension,
    CohortPredicate,
    IncidentStatus,
    StrictContract,
)
from retryrail.detection.models import (
    AggregateWindow,
    AttemptFact,
    DiagnosisSnapshot,
)
from retryrail.events.models import Currency, PaymentMethod


class V2CohortLevel(StrEnum):
    """The two allowlisted hierarchy levels evaluated by detector v2."""

    METHOD = "method"
    METHOD_ISSUER = "method_issuer"


class V2GateReason(StrEnum):
    """Ordered, human-reviewable result of one v2 cohort evaluation."""

    PASSED = "statistical_and_business_gates_pass"
    CURRENT_SAMPLE = "blocked_by_minimum_sample_gate"
    BASELINE_SAMPLE = "blocked_by_baseline_sample_gate"
    NON_ACTIONABLE_SOURCE = "blocked_by_non_actionable_error_source"
    ACTIONABLE_FAILURES = "blocked_by_minimum_actionable_failure_gate"
    RATE_DROP = "blocked_by_actionable_rate_drop_gate"
    CONFIDENCE = "blocked_by_confidence_gate"
    EXCESS_FAILURES = "blocked_by_excess_failure_gate"
    BUSINESS_IMPACT = "blocked_by_business_impact_gate"
    CONFIRMATION = "blocked_by_confirmation_gate"


class V2CandidateDisposition(StrEnum):
    """Why a visible candidate did or did not become a confirmed incident."""

    CONFIRMED = "confirmed"
    STATISTICAL_SIGNAL_LOST = "statistical_signal_lost"
    CONFIRMATION_EXPIRED = "confirmation_expired"
    PARTITION_ENDED = "partition_ended_before_confirmation"


class DetectorV2Config(StrictContract):
    """Frozen transparent configuration developed only on approved data."""

    schema_version: Literal["2.0.0"] = "2.0.0"
    detector_version: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    protocol_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    development_dataset_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    development_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    frozen_at: AwareDatetime
    candidate_levels: tuple[V2CohortLevel, ...] = Field(min_length=2, max_length=2)
    step_minutes: int = Field(gt=0, le=60)
    current_window_minutes: tuple[int, ...] = Field(min_length=1, max_length=6)
    baseline_lookback_minutes: int = Field(gt=0, le=10_080)
    method_minimum_current_attempts: int = Field(gt=0)
    issuer_minimum_current_attempts: int = Field(gt=0)
    issuer_minimum_attempts_per_hour: int = Field(gt=0)
    method_baseline_minimum_attempts: int = Field(gt=0)
    issuer_baseline_minimum_attempts: int = Field(gt=0)
    minimum_actionable_failures: int = Field(gt=0)
    method_minimum_actionable_rate_drop_bps: int = Field(gt=0, le=10_000)
    issuer_minimum_actionable_rate_drop_bps: int = Field(gt=0, le=10_000)
    method_confidence_threshold_ppm: int = Field(gt=500_000, le=1_000_000)
    issuer_confidence_threshold_ppm: int = Field(gt=500_000, le=1_000_000)
    minimum_excess_actionable_failures: int = Field(gt=0)
    minimum_at_risk_gmv_subunits: int = Field(gt=0)
    recent_evidence_minutes: int = Field(gt=0, le=60)
    method_confirmation_signals: int = Field(ge=3, le=12)
    method_confirmation_evidence_steps: int = Field(ge=2, le=12)
    method_confirmation_unique_actionable_failures: int = Field(ge=2, le=100)
    method_confirmation_requires_fresh_latest_step: Literal[True] = True
    issuer_confirmation_signals: int = Field(ge=2, le=12)
    issuer_confirmation_evidence_steps: int = Field(ge=1, le=12)
    issuer_confirmation_unique_actionable_failures: int = Field(ge=2, le=100)
    issuer_confirmation_requires_fresh_latest_step: Literal[True] = True
    issuer_confirmation_minimum_post_open_attempts: int = Field(gt=0)
    issuer_confirmation_maximum_minutes: int = Field(gt=0, le=240)
    suppressed_candidate_cooldown_minutes: int = Field(ge=0, le=1_440)
    healthy_window_minutes: int = Field(gt=0, le=1_440)
    actionable_error_sources: tuple[str, ...] = Field(min_length=1, max_length=8)
    non_actionable_error_sources: tuple[str, ...] = Field(min_length=1, max_length=8)
    attribution_minimum_failures: int = Field(gt=0)
    attribution_issuer_share_ppm: int = Field(gt=0, le=1_000_000)

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        """Reject ambiguous hierarchy, windows, sources and confirmation rules."""

        if self.candidate_levels != (
            V2CohortLevel.METHOD,
            V2CohortLevel.METHOD_ISSUER,
        ):
            msg = "candidate levels must be method followed by method_issuer"
            raise ValueError(msg)
        windows = self.current_window_minutes
        if tuple(sorted(set(windows))) != windows:
            msg = "current windows must be unique and strictly increasing"
            raise ValueError(msg)
        aligned = (
            *windows,
            self.baseline_lookback_minutes,
            self.recent_evidence_minutes,
            self.suppressed_candidate_cooldown_minutes,
            self.healthy_window_minutes,
            self.issuer_confirmation_maximum_minutes,
        )
        if any(value % self.step_minutes for value in aligned):
            msg = "detector durations must align to the detector step"
            raise ValueError(msg)
        if self.recent_evidence_minutes > windows[0]:
            msg = "recent evidence window cannot exceed the narrowest current window"
            raise ValueError(msg)
        confirmation_rules = (
            (
                self.method_confirmation_signals,
                self.method_confirmation_evidence_steps,
            ),
            (
                self.issuer_confirmation_signals,
                self.issuer_confirmation_evidence_steps,
            ),
        )
        if any(evidence > signals for signals, evidence in confirmation_rules):
            msg = "confirmation evidence steps cannot exceed confirmation signals"
            raise ValueError(msg)
        actionable = set(self.actionable_error_sources)
        non_actionable = set(self.non_actionable_error_sources)
        if len(actionable) != len(self.actionable_error_sources) or len(
            non_actionable
        ) != len(self.non_actionable_error_sources):
            msg = "error-source allowlists must contain unique values"
            raise ValueError(msg)
        if actionable & non_actionable:
            msg = "actionable and non-actionable error sources must be disjoint"
            raise ValueError(msg)
        if any(value != value.lower() for value in actionable | non_actionable):
            msg = "error-source allowlists must be lowercase"
            raise ValueError(msg)
        return self


class V2DetectorStatistics(StrictContract):
    """Complete counts and thresholds for one hierarchical decision."""

    evaluated_at: AwareDatetime
    cohort_level: V2CohortLevel
    cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=2)
    current_window_minutes: int = Field(gt=0)
    current_started_at: AwareDatetime
    baseline_started_at: AwareDatetime
    baseline_ended_at: AwareDatetime
    baseline_attempts: int = Field(ge=0)
    baseline_failures: int = Field(ge=0)
    baseline_actionable_failures: int = Field(ge=0)
    current_attempts: int = Field(ge=0)
    current_failures: int = Field(ge=0)
    current_actionable_failures: int = Field(ge=0)
    current_non_actionable_failures: int = Field(ge=0)
    recent_actionable_failures: int = Field(ge=0)
    baseline_actionable_failure_rate_bps: int = Field(ge=0, le=10_000)
    current_actionable_failure_rate_bps: int = Field(ge=0, le=10_000)
    actionable_rate_drop_bps: int = Field(ge=0, le=10_000)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    excess_actionable_failures: int = Field(ge=0)
    at_risk_gmv_subunits: int = Field(ge=0)
    currency: Currency
    gate_reason: V2GateReason
    minimum_current_attempts: int = Field(gt=0)
    baseline_minimum_attempts: int = Field(gt=0)
    minimum_actionable_failures: int = Field(gt=0)
    minimum_actionable_rate_drop_bps: int = Field(gt=0)
    confidence_threshold_ppm: int = Field(gt=0)
    minimum_excess_actionable_failures: int = Field(gt=0)
    minimum_at_risk_gmv_subunits: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        """Keep cohort shape, counts and time intervals exactly reconcilable."""

        expected_size = 1 if self.cohort_level is V2CohortLevel.METHOD else 2
        if len(self.cohort) != expected_size:
            msg = "cohort size must agree with its hierarchy level"
            raise ValueError(msg)
        dimensions = tuple(item.dimension for item in self.cohort)
        expected_dimensions = (
            (CohortDimension.METHOD,)
            if expected_size == 1
            else (CohortDimension.METHOD, CohortDimension.ISSUER)
        )
        if dimensions != expected_dimensions:
            msg = "cohort predicates must use canonical hierarchy order"
            raise ValueError(msg)
        if self.baseline_actionable_failures > self.baseline_failures:
            msg = "baseline actionable failures cannot exceed total failures"
            raise ValueError(msg)
        if self.current_actionable_failures > self.current_failures:
            msg = "current actionable failures cannot exceed total failures"
            raise ValueError(msg)
        if (
            self.current_actionable_failures
            + self.current_non_actionable_failures
            != self.current_failures
        ):
            msg = "current failure classifications must reconcile"
            raise ValueError(msg)
        if self.recent_actionable_failures > self.current_actionable_failures:
            msg = "recent actionable failures cannot exceed current actionable failures"
            raise ValueError(msg)
        if not (
            self.baseline_started_at
            <= self.baseline_ended_at
            <= self.current_started_at
            < self.evaluated_at
        ):
            msg = "detector windows must be ordered and non-overlapping"
            raise ValueError(msg)
        return self


class V2DetectionSignal(StrictContract):
    """One passing cohort decision with fresh-evidence identities."""

    merchant_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    method: PaymentMethod
    cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=2)
    statistics: V2DetectorStatistics
    evidence_event_ids: tuple[str, ...] = Field(min_length=1)
    actionable_evidence_event_ids: tuple[str, ...] = Field(min_length=1)
    recent_actionable_event_ids: tuple[str, ...]
    confirmation_error_signature: str = Field(min_length=3, max_length=320)
    recent_confirmation_event_ids: tuple[str, ...]

    @model_validator(mode="after")
    def validate_signal(self) -> Self:
        """Bind identities and evidence subsets to the evaluated cohort."""

        if self.cohort != self.statistics.cohort:
            msg = "signal cohort must equal its statistics cohort"
            raise ValueError(msg)
        if self.cohort[0].value != self.method.value:
            msg = "signal method must equal the method cohort predicate"
            raise ValueError(msg)
        evidence = set(self.evidence_event_ids)
        actionable = set(self.actionable_evidence_event_ids)
        recent = set(self.recent_actionable_event_ids)
        confirmation = set(self.recent_confirmation_event_ids)
        if (
            not actionable.issubset(evidence)
            or not recent.issubset(actionable)
            or not confirmation.issubset(recent)
        ):
            msg = "signal evidence identifiers must form nested subsets"
            raise ValueError(msg)
        return self


class V2SuppressedCandidate(StrictContract):
    """Auditable statistical evidence that never became a confirmed incident."""

    candidate_id: str = Field(pattern=r"^cand_[a-f0-9]{24}$")
    merchant_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    detector_version: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    started_at: AwareDatetime
    last_observed_at: AwareDatetime
    cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=2)
    signals: tuple[V2DetectionSignal, ...] = Field(min_length=1)
    disposition: Literal[
        V2CandidateDisposition.STATISTICAL_SIGNAL_LOST,
        V2CandidateDisposition.CONFIRMATION_EXPIRED,
        V2CandidateDisposition.PARTITION_ENDED,
    ]
    gate_reason: Literal[
        V2GateReason.CURRENT_SAMPLE,
        V2GateReason.CONFIRMATION,
    ]
    runtime_action_eligible: Literal[False] = False
    synthetic: bool

    @model_validator(mode="after")
    def validate_candidate_lifecycle(self) -> Self:
        """Require monotonic evidence and a matching summary interval."""

        if self.last_observed_at < self.started_at:
            msg = "candidate last observation cannot precede its start"
            raise ValueError(msg)
        if self.signals[0].statistics.evaluated_at != self.started_at:
            msg = "candidate start must equal its first signal time"
            raise ValueError(msg)
        if self.signals[-1].statistics.evaluated_at != self.last_observed_at:
            msg = "candidate end must equal its last signal time"
            raise ValueError(msg)
        return self


class V2DetectedIncident(StrictContract):
    """Confirmed candidate prediction; globally action-blocked until R4."""

    incident_id: str = Field(pattern=r"^inc_[a-f0-9]{24}$")
    merchant_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    detector_version: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    status: IncidentStatus
    opened_at: AwareDatetime
    confirmed_at: AwareDatetime
    last_observed_at: AwareDatetime
    resolved_at: AwareDatetime | None = None
    detector_cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=2)
    affected_cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=2)
    peak_signal: V2DetectionSignal
    observations: tuple[V2DetectionSignal, ...] = Field(min_length=1)
    diagnosis: DiagnosisSnapshot
    confirmation_evidence_steps: int = Field(gt=0)
    confirmation_unique_actionable_failures: int = Field(gt=0)
    candidate_actionable: Literal[True] = True
    runtime_action_eligible: Literal[False] = False
    synthetic: bool

    @model_validator(mode="after")
    def validate_incident_lifecycle(self) -> Self:
        """Separate first detection, confirmation and release authorization."""

        if not self.opened_at <= self.confirmed_at <= self.last_observed_at:
            msg = "incident timestamps must be monotonic"
            raise ValueError(msg)
        if self.observations[0].statistics.evaluated_at != self.opened_at:
            msg = "incident opening must equal its first statistical signal"
            raise ValueError(msg)
        if self.status is IncidentStatus.RESOLVED:
            if self.resolved_at is None or self.resolved_at < self.last_observed_at:
                msg = "resolved incidents require a valid resolution time"
                raise ValueError(msg)
        elif self.resolved_at is not None:
            msg = "open incidents cannot have a resolution time"
            raise ValueError(msg)
        return self


@dataclass(frozen=True, slots=True)
class V2DetectorRunResult:
    """Label-free candidate output retained before any evaluation truth is loaded."""

    detector_version: str
    partition_started_at: datetime
    partition_ended_at: datetime
    attempts: tuple[AttemptFact, ...]
    aggregates: tuple[AggregateWindow, ...]
    incidents: tuple[V2DetectedIncident, ...]
    suppressed_candidates: tuple[V2SuppressedCandidate, ...]
