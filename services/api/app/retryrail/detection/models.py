"""Typed detector configuration, evidence and runtime result models."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import (
    CohortDimension,
    CohortPredicate,
    DatasetSplit,
    IncidentStatus,
    StrictContract,
)
from retryrail.events.models import Currency, ErrorEvidence, PaymentMethod


class DetectorConfig(StrictContract):
    """Frozen transparent thresholds selected only on the tuning partition."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    detector_version: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    frozen_at: AwareDatetime
    threshold_source_split: Literal[DatasetSplit.TUNING] = DatasetSplit.TUNING
    candidate_dimension: Literal["method"] = "method"
    step_minutes: int = Field(gt=0, le=60)
    current_window_minutes: tuple[int, ...] = Field(min_length=1, max_length=6)
    baseline_lookback_minutes: int = Field(gt=0, le=10_080)
    minimum_current_attempts: int = Field(gt=0)
    baseline_minimum_attempts: int = Field(gt=0)
    minimum_current_failures: int = Field(gt=0)
    minimum_success_rate_drop_bps: int = Field(gt=0, le=10_000)
    confidence_threshold_ppm: int = Field(gt=500_000, le=1_000_000)
    ewma_alpha_ppm: int = Field(gt=0, lt=1_000_000)
    ewma_drop_threshold_bps: int = Field(gt=0, le=10_000)
    cusum_allowance_bps: int = Field(ge=0, le=10_000)
    cusum_threshold_milli: int = Field(gt=0)
    minimum_excess_failures: int = Field(gt=0)
    minimum_at_risk_gmv_subunits: int = Field(gt=0)
    healthy_window_minutes: int = Field(gt=0, le=1_440)
    attribution_minimum_failures: int = Field(gt=0)
    attribution_issuer_share_ppm: int = Field(gt=0, le=1_000_000)

    @model_validator(mode="after")
    def validate_windows(self) -> Self:
        """Require deterministic, aligned and increasingly wider windows."""

        windows = self.current_window_minutes
        if tuple(sorted(set(windows))) != windows:
            msg = "current windows must be unique and strictly increasing"
            raise ValueError(msg)
        if any(window % self.step_minutes for window in windows):
            msg = "current windows must align to the detector step"
            raise ValueError(msg)
        if self.baseline_lookback_minutes % self.step_minutes:
            msg = "baseline lookback must align to the detector step"
            raise ValueError(msg)
        if self.healthy_window_minutes % self.step_minutes:
            msg = "healthy window must align to the detector step"
            raise ValueError(msg)
        if self.minimum_current_failures > self.minimum_current_attempts:
            msg = "minimum failures cannot exceed minimum attempts"
            raise ValueError(msg)
        return self


class DetectorReleaseStatus(StrEnum):
    """Whether a frozen detector may feed consequential recovery policy."""

    QUALIFIED = "qualified"
    BLOCKED = "blocked"


class DetectorReleaseTarget(StrEnum):
    """Stable target identifiers recorded by the blind release decision."""

    PRECISION = "precision"
    RECALL = "recall"
    TOP_1_ATTRIBUTION = "top_1_attribution"
    MEDIAN_DETECTION_DELAY = "median_detection_delay"


class DetectorReleaseDecision(StrictContract):
    """Machine-readable fail-closed decision derived from held-out results."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    detector_version: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    dataset_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evaluation_split: Literal[DatasetSplit.HELDOUT] = DatasetSplit.HELDOUT
    source_report_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    evaluated_at: AwareDatetime
    status: DetectorReleaseStatus
    failed_targets: tuple[DetectorReleaseTarget, ...]
    action_eligible: bool
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        """Prevent contradictory qualification and action-eligibility states."""

        if len(set(self.failed_targets)) != len(self.failed_targets):
            msg = "failed release targets must be unique"
            raise ValueError(msg)
        qualified = self.status is DetectorReleaseStatus.QUALIFIED
        if qualified != (not self.failed_targets):
            msg = "release status must agree with failed targets"
            raise ValueError(msg)
        if self.action_eligible is not qualified:
            msg = "only a qualified detector can be action eligible"
            raise ValueError(msg)
        return self


class DetectorGateReason(StrEnum):
    """Ordered, machine-readable reason for a candidate decision."""

    PASSED = "statistical_and_business_gates_pass"
    CURRENT_SAMPLE = "blocked_by_minimum_sample_gate"
    BASELINE_SAMPLE = "blocked_by_baseline_sample_gate"
    CURRENT_FAILURES = "blocked_by_minimum_failure_gate"
    RATE_DROP = "blocked_by_rate_drop_gate"
    CONFIDENCE = "blocked_by_confidence_gate"
    EWMA = "blocked_by_ewma_gate"
    CUSUM = "blocked_by_cusum_gate"
    EXCESS_FAILURES = "blocked_by_excess_failure_gate"
    BUSINESS_IMPACT = "blocked_by_business_impact_gate"


@dataclass(frozen=True, slots=True)
class AttemptFact:
    """One terminal payment attempt reconstructed without evaluation labels."""

    merchant_id: str
    payment_id: str
    occurred_at: datetime
    amount_subunits: int
    currency: str
    method: PaymentMethod
    issuer: str | None
    failed: bool
    error: ErrorEvidence | None
    event_ids: tuple[str, ...]
    synthetic: bool


@dataclass(frozen=True, slots=True)
class AggregateWindow:
    """Exactly reconcilable five-minute aggregate for one configured cohort."""

    merchant_id: str
    cohort_key: str
    cohort: tuple[CohortPredicate, ...]
    window_start: datetime
    window_end: datetime
    attempts: int
    successes: int
    failures: int
    gmv_subunits: int
    failed_gmv_subunits: int
    currency: str
    synthetic: bool


class DetectorStatistics(StrictContract):
    """Every numeric input and threshold needed to reproduce one decision."""

    evaluated_at: AwareDatetime
    current_window_minutes: int = Field(gt=0)
    current_started_at: AwareDatetime
    baseline_started_at: AwareDatetime
    baseline_ended_at: AwareDatetime
    baseline_attempts: int = Field(ge=0)
    baseline_successes: int = Field(ge=0)
    baseline_failures: int = Field(ge=0)
    current_attempts: int = Field(ge=0)
    current_successes: int = Field(ge=0)
    current_failures: int = Field(ge=0)
    baseline_failure_rate_bps: int = Field(ge=0, le=10_000)
    current_failure_rate_bps: int = Field(ge=0, le=10_000)
    success_rate_drop_bps: int = Field(ge=0, le=10_000)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    ewma_failure_rate_bps: int = Field(ge=0, le=10_000)
    ewma_drop_bps: int = Field(ge=0, le=10_000)
    cusum_milli: int = Field(ge=0)
    excess_failures: int = Field(ge=0)
    at_risk_gmv_subunits: int = Field(ge=0)
    currency: Currency
    gate_reason: DetectorGateReason
    minimum_current_attempts: int = Field(gt=0)
    baseline_minimum_attempts: int = Field(gt=0)
    minimum_current_failures: int = Field(gt=0)
    minimum_success_rate_drop_bps: int = Field(gt=0)
    confidence_threshold_ppm: int = Field(gt=0)
    ewma_drop_threshold_bps: int = Field(gt=0)
    cusum_threshold_milli: int = Field(gt=0)
    minimum_excess_failures: int = Field(gt=0)
    minimum_at_risk_gmv_subunits: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_counts_and_time(self) -> Self:
        """Reject internally inconsistent evidence snapshots."""

        if self.baseline_successes + self.baseline_failures != self.baseline_attempts:
            msg = "baseline outcome counts must equal baseline attempts"
            raise ValueError(msg)
        if self.current_successes + self.current_failures != self.current_attempts:
            msg = "current outcome counts must equal current attempts"
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


class AttributionItem(StrictContract):
    """Verified contribution of one slice to excess failures."""

    dimension: CohortDimension
    value: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    rank: int = Field(gt=0)
    current_attempts: int = Field(gt=0)
    current_failures: int = Field(ge=0)
    baseline_attempts: int = Field(gt=0)
    baseline_failures: int = Field(ge=0)
    expected_failures_milli: int = Field(ge=0)
    excess_failures_milli: int = Field(ge=0)
    contribution_ppm: int = Field(ge=0, le=1_000_000)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    evidence_event_ids: tuple[str, ...] = Field(min_length=1)
    evidence_kind: Literal["verified_observation"] = "verified_observation"


class DiagnosisHypothesis(StrictContract):
    """Explicitly inferred merchant-local interpretation of verified evidence."""

    statement: str = Field(min_length=1, max_length=300)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    evidence_event_ids: tuple[str, ...] = Field(min_length=1)
    evidence_kind: Literal["inferred_hypothesis"] = "inferred_hypothesis"


class DiagnosisSnapshot(StrictContract):
    """Facts, hypotheses and unknowns kept distinct for later UI and AI use."""

    verified_attributions: tuple[AttributionItem, ...] = Field(min_length=1)
    hypotheses: tuple[DiagnosisHypothesis, ...] = Field(min_length=1, max_length=3)
    unknowns: tuple[str, ...] = Field(min_length=1, max_length=5)
    likely_causes: tuple[str, ...] = Field(min_length=1, max_length=3)


@dataclass(frozen=True, slots=True)
class DetectionSignal:
    """One passing method-cohort decision at a fixed event-time cutoff."""

    merchant_id: str
    method: PaymentMethod
    statistics: DetectorStatistics
    evidence_event_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetectedIncident:
    """One merged episode produced by the deterministic state machine."""

    incident_id: str
    merchant_id: str
    detector_version: str
    status: IncidentStatus
    opened_at: datetime
    last_observed_at: datetime
    resolved_at: datetime | None
    detector_cohort: tuple[CohortPredicate, ...]
    affected_cohort: tuple[CohortPredicate, ...]
    peak_signal: DetectionSignal
    observations: tuple[DetectionSignal, ...]
    diagnosis: DiagnosisSnapshot
    synthetic: bool


@dataclass(frozen=True, slots=True)
class DetectorRunResult:
    """Complete deterministic output before persistence or label comparison."""

    detector_version: str
    partition_started_at: datetime
    partition_ended_at: datetime
    attempts: tuple[AttemptFact, ...]
    aggregates: tuple[AggregateWindow, ...]
    incidents: tuple[DetectedIncident, ...]
