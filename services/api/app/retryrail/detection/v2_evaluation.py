"""Detector-v2 prediction, development scoring and pre-blind freeze artifacts."""

import argparse
import hashlib
import json
import math
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from statistics import median
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import (
    CohortDimension,
    CohortPredicate,
    IncidentStatus,
    StrictContract,
)
from retryrail.detection.models import AttemptFact, DiagnosisSnapshot
from retryrail.detection.v2_config import (
    detector_v2_config_sha256,
    load_detector_v2_config,
)
from retryrail.detection.v2_engine import DetectorV2Engine
from retryrail.detection.v2_models import (
    DetectorV2Config,
    V2DetectedIncident,
    V2DetectionSignal,
    V2DetectorRunResult,
    V2DetectorStatistics,
    V2GateReason,
    V2SuppressedCandidate,
)
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.synthetic.models import ScenarioKind
from retryrail.synthetic.v2_generator import (
    GeneratedV2Artifact,
    build_development_dataset,
)
from retryrail.synthetic.v2_models import (
    V2DatasetRole,
    V2EvaluationProtocol,
    V2ScenarioDefinition,
    V2ScenarioFamily,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_PROTOCOL_PATH = _REPOSITORY_ROOT / "evals/protocols/detector_v2.protocol.json"
_PREDICTION_PATH = (
    _REPOSITORY_ROOT / "evals/reports/detector_v2.development.predictions.json"
)
_REPORT_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v2.development.report.json"
_FREEZE_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v2.freeze.json"
_MATCHER_VERSION = "detector_v2_matcher_v1_0_0"
_PRECISION_TARGET_PPM = 900_000
_RECALL_TARGET_PPM = 850_000
_TOP_1_TARGET_PPM = 800_000
_DETECTION_DELAY_TARGET_SECONDS = 600
_CANDIDATE_SOURCE_PATHS = (
    "services/api/app/retryrail/contracts/domain.py",
    "services/api/app/retryrail/detection/engine.py",
    "services/api/app/retryrail/detection/models.py",
    "services/api/app/retryrail/detection/v2_config.py",
    "services/api/app/retryrail/detection/v2_engine.py",
    "services/api/app/retryrail/detection/v2_evaluation.py",
    "services/api/app/retryrail/detection/v2_models.py",
    "services/api/app/retryrail/events/models.py",
)


class V2PredictionArtifact(StrictContract):
    """Persistable label-free output produced before evaluation truth is loaded."""

    schema_version: Literal["2.0.0"] = "2.0.0"
    prediction_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    detector_version: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = (
        "detector_v2_matcher_v1_0_0"
    )
    dataset_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    dataset_role: V2DatasetRole
    seed_commitment_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_records: int = Field(gt=0)
    partition_started_at: AwareDatetime
    partition_ended_at: AwareDatetime
    predicted_at: AwareDatetime
    labels_loaded: Literal[False] = False
    incidents: tuple[V2DetectedIncident, ...]
    suppressed_candidates: tuple[V2SuppressedCandidate, ...]
    release_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_prediction(self) -> "V2PredictionArtifact":
        """Keep event-time identity and incident versioning internally bound."""

        if not self.partition_started_at < self.partition_ended_at < self.predicted_at:
            msg = "prediction timestamps must be strictly ordered"
            raise ValueError(msg)
        incident_mismatch = any(
            item.detector_version != self.detector_version for item in self.incidents
        )
        candidate_mismatch = any(
            item.detector_version != self.detector_version
            for item in self.suppressed_candidates
        )
        if incident_mismatch or candidate_mismatch:
            msg = "all prediction outputs must use the artifact detector version"
            raise ValueError(msg)
        return self


class V2DevelopmentTargetError(RuntimeError):
    """The candidate cannot be frozen because development targets failed."""


class V2EvaluationCase(StrictContract):
    """One exact scenario decision or unmatched confirmed prediction."""

    scenario_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    scenario_family: V2ScenarioFamily | Literal["background"]
    scenario_kind: Literal["true_incident", "hard_negative", "background"]
    expected_incident: bool
    detected_incident: bool
    matched_incident_id: str | None = None
    expected_cohort: tuple[CohortPredicate, ...]
    observed_cohort: tuple[CohortPredicate, ...]
    expected_top_causes: tuple[str, ...] = Field(max_length=3)
    observed_top_causes: tuple[str, ...] = Field(max_length=3)
    detection_delay_seconds: int | None = Field(default=None, ge=0)
    confirmation_delay_seconds: int | None = Field(default=None, ge=0)
    gate_reason: str = Field(min_length=3, max_length=80)


class V2IncidentEvaluationSummary(StrictContract):
    """Compact incident evidence used in the score report without duplication."""

    incident_id: str
    status: IncidentStatus
    opened_at: AwareDatetime
    confirmed_at: AwareDatetime
    last_observed_at: AwareDatetime
    resolved_at: AwareDatetime | None
    detector_cohort: tuple[CohortPredicate, ...]
    affected_cohort: tuple[CohortPredicate, ...]
    observation_count: int = Field(gt=0)
    peak_statistics: V2DetectorStatistics
    diagnosis: DiagnosisSnapshot
    confirmation_evidence_steps: int = Field(gt=0)
    confirmation_unique_actionable_failures: int = Field(gt=0)
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True


class V2TargetResults(StrictContract):
    """Precommitted target comparisons with no hidden pass criteria."""

    precision_target_ppm: Literal[900_000] = 900_000
    precision_passed: bool
    recall_target_ppm: Literal[850_000] = 850_000
    recall_passed: bool
    top_1_attribution_target_ppm: Literal[800_000] = 800_000
    top_1_attribution_passed: bool
    median_detection_delay_target_seconds: Literal[600] = 600
    median_detection_delay_passed: bool
    hard_negative_action_eligible_incidents_target: Literal[0] = 0
    hard_negative_action_eligible_incidents_passed: bool
    baseline_leakage_violations_target: Literal[0] = 0
    baseline_leakage_violations_passed: bool
    evidence_reconciliation_violations_target: Literal[0] = 0
    evidence_reconciliation_violations_passed: bool

    @property
    def all_passed(self) -> bool:
        """Return whether every precommitted target passes."""

        return all(
            (
                self.precision_passed,
                self.recall_passed,
                self.top_1_attribution_passed,
                self.median_detection_delay_passed,
                self.hard_negative_action_eligible_incidents_passed,
                self.baseline_leakage_violations_passed,
                self.evidence_reconciliation_violations_passed,
            )
        )


class V2DevelopmentReport(StrictContract):
    """Development-only scorecard that cannot qualify the runtime detector."""

    schema_version: Literal["2.0.0"] = "2.0.0"
    report_id: Literal["detector_v2_development_report_v1"] = (
        "detector_v2_development_report_v1"
    )
    protocol_id: Literal["detector_v2_protocol_v1"] = "detector_v2_protocol_v1"
    detector_version: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = (
        "detector_v2_matcher_v1_0_0"
    )
    dataset_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    dataset_role: Literal[V2DatasetRole.DEVELOPMENT] = V2DatasetRole.DEVELOPMENT
    dataset_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    truth_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    prediction_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evaluated_at: AwareDatetime
    labels_loaded_after_prediction_bytes: Literal[True] = True
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True
    payment_attempts: int = Field(gt=0)
    raw_normalized_events: int = Field(gt=0)
    predicted_incidents: int = Field(ge=0)
    suppressed_candidates: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision_ppm: int = Field(ge=0, le=1_000_000)
    recall_ppm: int = Field(ge=0, le=1_000_000)
    top_1_attribution_ppm: int = Field(ge=0, le=1_000_000)
    top_3_attribution_ppm: int = Field(ge=0, le=1_000_000)
    median_detection_delay_seconds: int | None = Field(default=None, ge=0)
    maximum_detection_delay_seconds: int | None = Field(default=None, ge=0)
    median_confirmation_delay_seconds: int | None = Field(default=None, ge=0)
    maximum_confirmation_delay_seconds: int | None = Field(default=None, ge=0)
    hard_negative_action_eligible_incidents: int = Field(ge=0)
    baseline_leakage_violations: int = Field(ge=0)
    evidence_reconciliation_violations: int = Field(ge=0)
    development_targets_passed: bool
    targets: V2TargetResults
    cases: tuple[V2EvaluationCase, ...] = Field(min_length=1)
    incidents: tuple[V2IncidentEvaluationSummary, ...]
    limitations: tuple[str, ...] = Field(min_length=3)

    @model_validator(mode="after")
    def validate_target_summary(self) -> "V2DevelopmentReport":
        """Prevent the development summary from disagreeing with target results."""

        if self.development_targets_passed is not self.targets.all_passed:
            msg = "development target summary must equal all target comparisons"
            raise ValueError(msg)
        return self


class V2CandidateFreeze(StrictContract):
    """Machine-readable R2 freeze; intentionally contains no blind nonce."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    freeze_id: Literal["detector_v2_candidate_freeze_v1"] = (
        "detector_v2_candidate_freeze_v1"
    )
    status: Literal["candidate_frozen_for_blind"] = "candidate_frozen_for_blind"
    protocol_id: Literal["detector_v2_protocol_v1"] = "detector_v2_protocol_v1"
    protocol_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    generator_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    detector_version: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_source_paths: tuple[str, ...] = Field(min_length=8)
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = (
        "detector_v2_matcher_v1_0_0"
    )
    development_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    development_prediction_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    development_report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    frozen_at: AwareDatetime
    development_targets_passed: Literal[True] = True
    official_blind_nonce_sha256: None = None
    official_blind_run_id: None = None
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True


@dataclass(frozen=True, slots=True)
class V2PredictionBuild:
    """Prediction bytes and internal run retained before label loading."""

    artifact: V2PredictionArtifact
    content: bytes
    sha256: str
    run: V2DetectorRunResult


@dataclass(frozen=True, slots=True)
class _DevelopmentRuntime:
    dataset_id: str
    seed_commitment_sha256: str
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    event_artifact: GeneratedV2Artifact


@dataclass(frozen=True, slots=True)
class _DevelopmentTruth:
    manifest_sha256: str
    normalized_events: int
    scenarios: tuple[V2ScenarioDefinition, ...]
    truth_artifact_sha256: str


def candidate_bundle_sha256(root: Path = _REPOSITORY_ROOT) -> str:
    """Bind detector, matcher, evaluator and shared consumed contracts."""

    digest = hashlib.sha256()
    for relative_path in _CANDIDATE_SOURCE_PATHS:
        digest.update(relative_path.encode())
        digest.update(b"\0")
        source = (root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        digest.update(source)
        digest.update(b"\0")
    return digest.hexdigest()


def predict_runtime(
    *,
    dataset_id: str,
    dataset_role: V2DatasetRole,
    seed_commitment_sha256: str,
    starts_at: AwareDatetime,
    ends_at: AwareDatetime,
    event_artifact: GeneratedV2Artifact,
    config: DetectorV2Config | None = None,
) -> V2PredictionBuild:
    """Produce canonical predictions from runtime events without truth arguments."""

    selected_config = config or load_detector_v2_config()
    events = tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in event_artifact.content.splitlines()
    )
    run = DetectorV2Engine(selected_config).run(
        events,
        partition_started_at=starts_at,
        partition_ended_at=ends_at,
    )
    artifact = V2PredictionArtifact(
        prediction_id=f"prediction_{dataset_role.value}_{selected_config.detector_version}",
        detector_version=selected_config.detector_version,
        detector_config_sha256=detector_v2_config_sha256(),
        candidate_bundle_sha256=candidate_bundle_sha256(),
        dataset_id=dataset_id,
        dataset_role=dataset_role,
        seed_commitment_sha256=seed_commitment_sha256,
        event_artifact_sha256=event_artifact.sha256,
        event_records=event_artifact.records,
        partition_started_at=starts_at,
        partition_ended_at=ends_at,
        predicted_at=ends_at + timedelta(minutes=5),
        incidents=run.incidents,
        suppressed_candidates=run.suppressed_candidates,
    )
    content = _canonical_json(artifact)
    return V2PredictionBuild(
        artifact=artifact,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        run=run,
    )


def score_predictions(
    prediction: V2PredictionBuild,
    *,
    scenarios: tuple[V2ScenarioDefinition, ...],
    dataset_manifest_sha256: str,
    truth_artifact_sha256: str,
    normalized_events: int,
    config: DetectorV2Config | None = None,
) -> V2DevelopmentReport:
    """Load labels only after canonical prediction bytes already exist."""

    selected_config = config or load_detector_v2_config()
    cases, matches = _score_cases(prediction.run, scenarios, selected_config)
    metrics = _metrics(cases)
    baseline_violations = _baseline_leakage_violations(
        prediction.run,
        scenarios,
        matches,
    )
    evidence_violations = _evidence_reconciliation_violations(
        prediction.run,
        selected_config,
    )
    hard_negative_alerts = sum(
        item.scenario_kind == "hard_negative" and item.detected_incident
        for item in cases
    )
    targets = V2TargetResults(
        precision_passed=metrics.precision_ppm >= _PRECISION_TARGET_PPM,
        recall_passed=metrics.recall_ppm >= _RECALL_TARGET_PPM,
        top_1_attribution_passed=metrics.top_1_ppm >= _TOP_1_TARGET_PPM,
        median_detection_delay_passed=(
            metrics.median_detection_delay is not None
            and metrics.median_detection_delay <= _DETECTION_DELAY_TARGET_SECONDS
        ),
        hard_negative_action_eligible_incidents_passed=hard_negative_alerts == 0,
        baseline_leakage_violations_passed=baseline_violations == 0,
        evidence_reconciliation_violations_passed=evidence_violations == 0,
    )
    return V2DevelopmentReport(
        detector_version=selected_config.detector_version,
        detector_config_sha256=prediction.artifact.detector_config_sha256,
        candidate_bundle_sha256=prediction.artifact.candidate_bundle_sha256,
        dataset_id=prediction.artifact.dataset_id,
        dataset_manifest_sha256=dataset_manifest_sha256,
        event_artifact_sha256=prediction.artifact.event_artifact_sha256,
        truth_artifact_sha256=truth_artifact_sha256,
        prediction_artifact_sha256=prediction.sha256,
        evaluated_at=prediction.artifact.predicted_at + timedelta(minutes=5),
        payment_attempts=len(prediction.run.attempts),
        raw_normalized_events=normalized_events,
        predicted_incidents=len(prediction.run.incidents),
        suppressed_candidates=len(prediction.run.suppressed_candidates),
        true_positives=metrics.true_positives,
        false_positives=metrics.false_positives,
        false_negatives=metrics.false_negatives,
        precision_ppm=metrics.precision_ppm,
        recall_ppm=metrics.recall_ppm,
        top_1_attribution_ppm=metrics.top_1_ppm,
        top_3_attribution_ppm=metrics.top_3_ppm,
        median_detection_delay_seconds=metrics.median_detection_delay,
        maximum_detection_delay_seconds=metrics.maximum_detection_delay,
        median_confirmation_delay_seconds=metrics.median_confirmation_delay,
        maximum_confirmation_delay_seconds=metrics.maximum_confirmation_delay,
        hard_negative_action_eligible_incidents=hard_negative_alerts,
        baseline_leakage_violations=baseline_violations,
        evidence_reconciliation_violations=evidence_violations,
        development_targets_passed=targets.all_passed,
        targets=targets,
        cases=cases,
        incidents=tuple(_incident_summary(item) for item in prediction.run.incidents),
        limitations=(
            "Development results are synthetic tuning evidence, not a release claim.",
            "The official nonce-derived blind batch has not been generated or scored.",
            "Every candidate incident remains runtime action-ineligible until R4.",
            "First-signal delay and later deterministic confirmation delay are separate.",
        ),
    )


@dataclass(frozen=True, slots=True)
class _Metrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision_ppm: int
    recall_ppm: int
    top_1_ppm: int
    top_3_ppm: int
    median_detection_delay: int | None
    maximum_detection_delay: int | None
    median_confirmation_delay: int | None
    maximum_confirmation_delay: int | None


def _metrics(cases: Sequence[V2EvaluationCase]) -> _Metrics:
    true_positives = sum(
        item.expected_incident and item.detected_incident for item in cases
    )
    false_positives = sum(
        not item.expected_incident and item.detected_incident for item in cases
    )
    false_negatives = sum(
        item.expected_incident and not item.detected_incident for item in cases
    )
    matched = tuple(
        item for item in cases if item.expected_incident and item.detected_incident
    )
    top_1 = sum(
        bool(item.expected_top_causes)
        and bool(item.observed_top_causes)
        and item.expected_top_causes[0] == item.observed_top_causes[0]
        for item in matched
    )
    top_3 = sum(
        bool(item.expected_top_causes)
        and item.expected_top_causes[0] in item.observed_top_causes[:3]
        for item in matched
    )
    detection_delays = tuple(
        item.detection_delay_seconds
        for item in matched
        if item.detection_delay_seconds is not None
    )
    confirmation_delays = tuple(
        item.confirmation_delay_seconds
        for item in matched
        if item.confirmation_delay_seconds is not None
    )
    return _Metrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision_ppm=_ratio_ppm(
            true_positives,
            true_positives + false_positives,
            empty_value=1_000_000,
        ),
        recall_ppm=_ratio_ppm(
            true_positives,
            true_positives + false_negatives,
            empty_value=1_000_000,
        ),
        top_1_ppm=_ratio_ppm(top_1, len(matched), empty_value=0),
        top_3_ppm=_ratio_ppm(top_3, len(matched), empty_value=0),
        median_detection_delay=_median(detection_delays),
        maximum_detection_delay=max(detection_delays, default=None),
        median_confirmation_delay=_median(confirmation_delays),
        maximum_confirmation_delay=max(confirmation_delays, default=None),
    )


def _score_cases(
    run: V2DetectorRunResult,
    scenarios: tuple[V2ScenarioDefinition, ...],
    config: DetectorV2Config,
) -> tuple[tuple[V2EvaluationCase, ...], dict[str, str]]:
    cases: list[V2EvaluationCase] = []
    claimed: set[str] = set()
    matches: dict[str, str] = {}
    for scenario in scenarios:
        incident = next(
            (
                item
                for item in run.incidents
                if item.incident_id not in claimed
                and _matches_scenario(item, scenario)
            ),
            None,
        )
        if incident is not None:
            claimed.add(incident.incident_id)
            matches[scenario.scenario_id] = incident.incident_id
        cases.append(_scenario_case(run, scenario, incident, config))
    cases.extend(
        _background_case(item)
        for item in run.incidents
        if item.incident_id not in claimed
    )
    return tuple(cases), matches


def _scenario_case(
    run: V2DetectorRunResult,
    scenario: V2ScenarioDefinition,
    incident: V2DetectedIncident | None,
    config: DetectorV2Config,
) -> V2EvaluationCase:
    expected_causes = _expected_causes(scenario)
    observed_causes = incident.diagnosis.likely_causes if incident is not None else ()
    detection_delay = None
    confirmation_delay = None
    if incident is not None and scenario.kind is ScenarioKind.TRUE_INCIDENT:
        detection_delay = max(int((incident.opened_at - scenario.starts_at).total_seconds()), 0)
        confirmation_delay = max(
            int((incident.confirmed_at - scenario.starts_at).total_seconds()),
            0,
        )
    return V2EvaluationCase(
        scenario_id=scenario.scenario_id,
        scenario_family=scenario.family,
        scenario_kind=scenario.kind.value,
        expected_incident=scenario.should_open_incident,
        detected_incident=incident is not None,
        matched_incident_id=incident.incident_id if incident is not None else None,
        expected_cohort=scenario.affected_cohort,
        observed_cohort=incident.affected_cohort if incident is not None else (),
        expected_top_causes=expected_causes,
        observed_top_causes=observed_causes,
        detection_delay_seconds=detection_delay,
        confirmation_delay_seconds=confirmation_delay,
        gate_reason=(
            V2GateReason.PASSED.value
            if incident is not None
            else _scenario_gate_reason(run, scenario, config)
        ),
    )


def _background_case(incident: V2DetectedIncident) -> V2EvaluationCase:
    return V2EvaluationCase(
        scenario_id=f"background_{incident.incident_id}",
        scenario_family="background",
        scenario_kind="background",
        expected_incident=False,
        detected_incident=True,
        matched_incident_id=incident.incident_id,
        expected_cohort=(),
        observed_cohort=incident.affected_cohort,
        expected_top_causes=(),
        observed_top_causes=incident.diagnosis.likely_causes,
        gate_reason=V2GateReason.PASSED.value,
    )


def _incident_summary(incident: V2DetectedIncident) -> V2IncidentEvaluationSummary:
    return V2IncidentEvaluationSummary(
        incident_id=incident.incident_id,
        status=incident.status,
        opened_at=incident.opened_at,
        confirmed_at=incident.confirmed_at,
        last_observed_at=incident.last_observed_at,
        resolved_at=incident.resolved_at,
        detector_cohort=incident.detector_cohort,
        affected_cohort=incident.affected_cohort,
        observation_count=len(incident.observations),
        peak_statistics=incident.peak_signal.statistics,
        diagnosis=incident.diagnosis,
        confirmation_evidence_steps=incident.confirmation_evidence_steps,
        confirmation_unique_actionable_failures=(
            incident.confirmation_unique_actionable_failures
        ),
    )


def _matches_scenario(
    incident: V2DetectedIncident,
    scenario: V2ScenarioDefinition,
) -> bool:
    expected = {item.dimension: item.value for item in scenario.affected_cohort}
    observed = {
        item.dimension: item.value
        for item in (*incident.detector_cohort, *incident.affected_cohort)
    }
    return (
        expected.get(CohortDimension.METHOD) == observed.get(CohortDimension.METHOD)
        and (
            CohortDimension.ISSUER not in expected
            or expected[CohortDimension.ISSUER] == observed.get(CohortDimension.ISSUER)
        )
        and scenario.starts_at <= incident.opened_at < scenario.ends_at
    )


def _scenario_gate_reason(
    run: V2DetectorRunResult,
    scenario: V2ScenarioDefinition,
    config: DetectorV2Config,
) -> str:
    suppressed = tuple(
        item
        for item in run.suppressed_candidates
        if _candidate_matches_scenario(item, scenario)
    )
    suppressed_reasons = {item.gate_reason for item in suppressed}
    engine = DetectorV2Engine(config)
    reasons: list[V2GateReason] = []
    cutoff = scenario.starts_at + timedelta(minutes=config.step_minutes)
    while cutoff <= scenario.ends_at:
        evaluation = engine.evaluate_cohort(
            run.attempts,
            cohort=scenario.affected_cohort,
            evaluated_at=cutoff,
            partition_started_at=run.partition_started_at,
        )
        reasons.append(evaluation.statistics.gate_reason)
        cutoff += timedelta(minutes=config.step_minutes)
    priority = (
        V2GateReason.NON_ACTIONABLE_SOURCE,
        V2GateReason.CURRENT_SAMPLE,
        V2GateReason.CONFIRMATION,
        V2GateReason.BASELINE_SAMPLE,
        V2GateReason.ACTIONABLE_FAILURES,
        V2GateReason.BUSINESS_IMPACT,
        V2GateReason.EXCESS_FAILURES,
        V2GateReason.CONFIDENCE,
        V2GateReason.RATE_DROP,
    )
    available = {*reasons, *suppressed_reasons}
    return next(
        (item.value for item in priority if item in available),
        reasons[-1].value if reasons else V2GateReason.CURRENT_SAMPLE.value,
    )


def _candidate_matches_scenario(
    candidate: V2SuppressedCandidate,
    scenario: V2ScenarioDefinition,
) -> bool:
    expected_method = scenario.affected_cohort[0].value
    observed_method = candidate.cohort[0].value
    expected_issuer = next(
        (
            item.value
            for item in scenario.affected_cohort
            if item.dimension is CohortDimension.ISSUER
        ),
        None,
    )
    observed_issuer = next(
        (
            item.value
            for item in candidate.cohort
            if item.dimension is CohortDimension.ISSUER
        ),
        None,
    )
    return (
        expected_method == observed_method
        and (expected_issuer is None or expected_issuer == observed_issuer)
        and scenario.starts_at <= candidate.started_at < scenario.ends_at
    )


def _expected_causes(scenario: V2ScenarioDefinition) -> tuple[str, ...]:
    error = scenario.expected_root_cause
    return tuple(
        value for value in (error.reason, error.source, error.step) if value is not None
    )[:3]


def _baseline_leakage_violations(
    run: V2DetectorRunResult,
    scenarios: tuple[V2ScenarioDefinition, ...],
    matches: dict[str, str],
) -> int:
    incidents = {item.incident_id: item for item in run.incidents}
    violations = 0
    for scenario in scenarios:
        incident_id = matches.get(scenario.scenario_id)
        if incident_id is None or scenario.kind is not ScenarioKind.TRUE_INCIDENT:
            continue
        incident = incidents[incident_id]
        violations += int(
            any(
                signal.statistics.baseline_ended_at > scenario.starts_at
                for signal in incident.observations
            )
        )
    return violations


def _evidence_reconciliation_violations(
    run: V2DetectorRunResult,
    config: DetectorV2Config,
) -> int:
    signals = tuple(
        signal
        for incident in run.incidents
        for signal in incident.observations
    ) + tuple(
        signal
        for candidate in run.suppressed_candidates
        for signal in candidate.signals
    )
    violations = sum(_signal_reconciliation_violation(run, signal, config) for signal in signals)
    method_aggregates = tuple(
        item
        for item in run.aggregates
        if len(item.cohort) == 1
        and item.cohort[0].dimension is CohortDimension.METHOD
    )
    aggregate_mismatch = (
        sum(item.attempts for item in method_aggregates) != len(run.attempts)
        or sum(item.failures for item in method_aggregates)
        != sum(item.failed for item in run.attempts)
        or any(item.successes + item.failures != item.attempts for item in run.aggregates)
    )
    return violations + int(aggregate_mismatch)


def _signal_reconciliation_violation(
    run: V2DetectorRunResult,
    signal: V2DetectionSignal,
    config: DetectorV2Config,
) -> int:
    stats = signal.statistics
    current = tuple(
        item
        for item in run.attempts
        if _attempt_matches(item, signal.cohort)
        and stats.current_started_at <= item.occurred_at < stats.evaluated_at
    )
    baseline = tuple(
        item
        for item in run.attempts
        if _attempt_matches(item, signal.cohort)
        and stats.baseline_started_at
        <= item.occurred_at
        < stats.baseline_ended_at
    )
    recent = tuple(
        item
        for item in current
        if stats.evaluated_at - timedelta(minutes=config.recent_evidence_minutes)
        <= item.occurred_at
    )
    actionable = tuple(item for item in current if _is_actionable(item, config))
    baseline_actionable = tuple(
        item for item in baseline if _is_actionable(item, config)
    )
    recent_actionable = tuple(item for item in recent if _is_actionable(item, config))
    recent_confirmation = tuple(
        item
        for item in recent_actionable
        if _error_signature(item) == signal.confirmation_error_signature
    )
    mismatch = (
        len(current) != stats.current_attempts
        or sum(item.failed for item in current) != stats.current_failures
        or len(actionable) != stats.current_actionable_failures
        or len(recent_actionable) != stats.recent_actionable_failures
        or len(baseline) != stats.baseline_attempts
        or sum(item.failed for item in baseline) != stats.baseline_failures
        or len(baseline_actionable) != stats.baseline_actionable_failures
        or _event_ids(current) != signal.evidence_event_ids
        or _event_ids(actionable) != signal.actionable_evidence_event_ids
        or _event_ids(recent_actionable) != signal.recent_actionable_event_ids
        or _event_ids(recent_confirmation) != signal.recent_confirmation_event_ids
    )
    return int(mismatch)


def _attempt_matches(
    attempt: AttemptFact,
    cohort: Sequence[CohortPredicate],
) -> bool:
    values = {
        CohortDimension.METHOD: attempt.method.value,
        CohortDimension.ISSUER: attempt.issuer,
    }
    return all(values.get(item.dimension) == item.value for item in cohort)


def _is_actionable(attempt: AttemptFact, config: DetectorV2Config) -> bool:
    error = attempt.error
    return (
        attempt.failed
        and error is not None
        and error.source in config.actionable_error_sources
    )


def _error_signature(attempt: AttemptFact) -> str:
    error = attempt.error
    if error is None:
        return "unknown|unknown|unknown|unknown"
    return "|".join(
        value or "unknown"
        for value in (error.code, error.source, error.step, error.reason)
    )


def _event_ids(attempts: Iterable[AttemptFact]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                event_id
                for item in attempts
                for event_id in item.event_ids
            }
        )
    )


def _development_runtime() -> _DevelopmentRuntime:
    dataset = build_development_dataset()
    return _DevelopmentRuntime(
        dataset_id=dataset.manifest.dataset_id,
        seed_commitment_sha256=dataset.manifest.seed_commitment_sha256,
        starts_at=dataset.manifest.starts_at,
        ends_at=dataset.manifest.ends_at,
        event_artifact=dataset.event_artifact,
    )


def _development_truth() -> _DevelopmentTruth:
    dataset = build_development_dataset()
    return _DevelopmentTruth(
        manifest_sha256=dataset.manifest_sha256,
        normalized_events=dataset.manifest.normalized_events,
        scenarios=dataset.manifest.scenarios,
        truth_artifact_sha256=dataset.truth_artifact.sha256,
    )


def render_development_artifacts() -> dict[Path, bytes]:
    """Generate prediction bytes before loading development truth and scoring."""

    runtime = _development_runtime()
    prediction = predict_runtime(
        dataset_id=runtime.dataset_id,
        dataset_role=V2DatasetRole.DEVELOPMENT,
        seed_commitment_sha256=runtime.seed_commitment_sha256,
        starts_at=runtime.starts_at,
        ends_at=runtime.ends_at,
        event_artifact=runtime.event_artifact,
    )
    # This separate build is the only point at which scenario labels enter.
    truth = _development_truth()
    report = score_predictions(
        prediction,
        scenarios=truth.scenarios,
        dataset_manifest_sha256=truth.manifest_sha256,
        truth_artifact_sha256=truth.truth_artifact_sha256,
        normalized_events=truth.normalized_events,
    )
    report_content = _canonical_json(report)
    protocol = V2EvaluationProtocol.model_validate_json(_PROTOCOL_PATH.read_bytes())
    if not report.development_targets_passed:
        raise V2DevelopmentTargetError
    freeze = V2CandidateFreeze(
        protocol_sha256=hashlib.sha256(_PROTOCOL_PATH.read_bytes()).hexdigest(),
        generator_bundle_sha256=protocol.generator_bundle_sha256,
        detector_version=report.detector_version,
        detector_config_sha256=report.detector_config_sha256,
        candidate_bundle_sha256=report.candidate_bundle_sha256,
        candidate_source_paths=_CANDIDATE_SOURCE_PATHS,
        development_manifest_sha256=truth.manifest_sha256,
        development_prediction_sha256=prediction.sha256,
        development_report_sha256=hashlib.sha256(report_content).hexdigest(),
        frozen_at=load_detector_v2_config().frozen_at,
    )
    return {
        _PREDICTION_PATH: prediction.content,
        _REPORT_PATH: report_content,
        _FREEZE_PATH: _canonical_json(freeze),
    }


def check_development_artifacts() -> list[str]:
    """Return every missing or stale R2 prediction/report/freeze artifact."""

    findings: list[str] = []
    for path, expected in render_development_artifacts().items():
        if not path.is_file():
            findings.append(f"missing {path.relative_to(_REPOSITORY_ROOT).as_posix()}")
        elif path.read_bytes() != expected:
            findings.append(f"stale {path.relative_to(_REPOSITORY_ROOT).as_posix()}")
    return findings


def write_development_artifacts() -> None:
    """Atomically write the canonical R2 artifacts."""

    for path, content in render_development_artifacts().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_bytes(content)
        temporary.replace(path)


def _canonical_json(model: StrictContract) -> bytes:
    return (
        json.dumps(
            model.model_dump(mode="json", exclude_none=True),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def _ratio_ppm(numerator: int, denominator: int, *, empty_value: int) -> int:
    if denominator == 0:
        return empty_value
    return math.floor((numerator / denominator) * 1_000_000 + 0.5)


def _median(values: Sequence[int]) -> int | None:
    if not values:
        return None
    return math.floor(median(values) + 0.5)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the frozen development prediction, report and candidate freeze",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="write development artifacts; this command cannot accept a blind nonce",
    )
    parser.add_argument(
        "--print-report",
        action="store_true",
        help="render the development report without writing repository files",
    )
    return parser


def main() -> None:
    """Write/check only R2 development artifacts; blind orchestration is absent."""

    arguments = _parser().parse_args()
    selected = sum((arguments.check, arguments.write, arguments.print_report))
    if selected != 1:
        sys.stderr.write("choose exactly one of --check, --write or --print-report\n")
        raise SystemExit(2)
    if arguments.write:
        write_development_artifacts()
        sys.stdout.write("wrote detector-v2 development prediction, report and freeze\n")
        return
    if arguments.check:
        findings = check_development_artifacts()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write(
            "detector-v2 candidate artifacts are current; official blind remains unopened\n"
        )
        return
    sys.stdout.buffer.write(render_development_artifacts()[_REPORT_PATH])


if __name__ == "__main__":  # pragma: no cover
    main()
