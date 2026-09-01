"""Frozen detector evaluation with post-detection label loading and drift checks."""

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from statistics import median
from typing import Literal

from pydantic import AwareDatetime, Field

from retryrail.contracts.domain import (
    CohortDimension,
    CohortPredicate,
    DatasetSplit,
    DetectorEvaluationContract,
    EvaluationCaseResult,
    IncidentStatus,
    StrictContract,
)
from retryrail.detection.config import (
    detector_config_path,
    detector_config_sha256,
    load_detector_config,
)
from retryrail.detection.engine import DetectorEngine
from retryrail.detection.models import (
    DetectedIncident,
    DetectorConfig,
    DetectorGateReason,
    DetectorReleaseDecision,
    DetectorReleaseStatus,
    DetectorReleaseTarget,
    DetectorRunResult,
    DetectorStatistics,
    DiagnosisSnapshot,
)
from retryrail.events.models import NormalizedPaymentEvent, PaymentMethod
from retryrail.synthetic.generator import GeneratedDataset, build_dataset
from retryrail.synthetic.models import ScenarioDefinition, ScenarioKind

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_REPORT_DIRECTORY = _REPOSITORY_ROOT / "evals/reports"
_PRECISION_TARGET_PPM = 900_000
_RECALL_TARGET_PPM = 850_000
_TOP_1_TARGET_PPM = 800_000
_MTTD_TARGET_SECONDS = 600


class DetailedEvaluationCase(StrictContract):
    """Human-reviewable decision and timing for one scenario or extra alert."""

    scenario_id: str = Field(min_length=3, max_length=80)
    scenario_kind: Literal["true_incident", "hard_negative", "background"]
    expected_incident: bool
    detected_incident: bool
    matched_incident_id: str | None = None
    expected_cohort: tuple[CohortPredicate, ...]
    observed_cohort: tuple[CohortPredicate, ...]
    expected_top_causes: tuple[str, ...] = Field(max_length=3)
    observed_top_causes: tuple[str, ...] = Field(max_length=3)
    detection_delay_seconds: int | None = Field(default=None, ge=0)
    gate_reason: str


class IncidentEvaluationSummary(StrictContract):
    """Compact incident artifact with all peak evidence needed to reconcile it."""

    incident_id: str
    status: IncidentStatus
    opened_at: AwareDatetime
    last_observed_at: AwareDatetime
    resolved_at: AwareDatetime | None
    affected_cohort: tuple[CohortPredicate, ...]
    observation_count: int = Field(gt=0)
    peak_statistics: DetectorStatistics
    diagnosis: DiagnosisSnapshot
    peak_evidence_event_ids: tuple[str, ...] = Field(min_length=1)
    synthetic: Literal[True] = True


class EvaluationTargets(StrictContract):
    """Explicit release-target comparison with no hidden pass criteria."""

    precision_target_ppm: int = _PRECISION_TARGET_PPM
    precision_passed: bool
    recall_target_ppm: int = _RECALL_TARGET_PPM
    recall_passed: bool
    top_1_attribution_target_ppm: int = _TOP_1_TARGET_PPM
    top_1_attribution_passed: bool
    median_detection_delay_target_seconds: int = _MTTD_TARGET_SECONDS
    median_detection_delay_passed: bool


class DetailedDetectorReport(StrictContract):
    """Reproducible M3 report including metrics absent from the frozen M1 schema."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    report_id: str
    detector_version: str
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    detector_frozen_at: AwareDatetime
    threshold_source_split: Literal[DatasetSplit.TUNING] = DatasetSplit.TUNING
    dataset_id: str
    dataset_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    dataset_split: DatasetSplit
    evaluated_at: AwareDatetime
    labels_loaded_after_detection: Literal[True] = True
    heldout_thresholds_frozen_before_partition: bool
    synthetic: Literal[True] = True
    payment_attempts: int = Field(ge=0)
    method_aggregate_attempts: int = Field(ge=0)
    raw_normalized_events: int = Field(ge=0)
    predicted_incidents: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision_ppm: int = Field(ge=0, le=1_000_000)
    recall_ppm: int = Field(ge=0, le=1_000_000)
    top_1_attribution_ppm: int = Field(ge=0, le=1_000_000)
    top_3_attribution_ppm: int = Field(ge=0, le=1_000_000)
    median_detection_delay_seconds: int | None = Field(default=None, ge=0)
    maximum_detection_delay_seconds: int | None = Field(default=None, ge=0)
    hard_negative_action_eligible_incidents: int = Field(ge=0)
    baseline_leakage_violations: int = Field(ge=0)
    evidence_reconciliation_violations: int = Field(ge=0)
    targets: EvaluationTargets
    cases: tuple[DetailedEvaluationCase, ...] = Field(min_length=1)
    incidents: tuple[IncidentEvaluationSummary, ...]
    limitations: tuple[str, ...] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class EvaluationArtifacts:
    """Detailed report plus the M1 held-out schema when applicable."""

    detailed: DetailedDetectorReport
    heldout_contract: DetectorEvaluationContract | None


def evaluate_partition(
    dataset: GeneratedDataset,
    config: DetectorConfig,
    split: DatasetSplit,
) -> EvaluationArtifacts:
    """Detect first, then load scenario labels through a separate code path."""

    partition = next(item for item in dataset.manifest.partitions if item.split is split)
    event_artifact = next(
        item for item in dataset.artifacts if item.path == partition.event_artifact
    )
    events = tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in event_artifact.content.splitlines()
    )
    detector_result = DetectorEngine(config).run(
        events,
        partition_started_at=partition.starts_at,
        partition_ended_at=partition.ends_at,
    )

    # This is the only point at which labels enter the evaluation flow.
    scenarios = tuple(
        item for item in dataset.manifest.scenarios if item.split is split
    )
    cases, matched_incident_ids = _score_cases(detector_result, scenarios, config)
    true_positives = sum(
        item.expected_incident and item.detected_incident for item in cases
    )
    false_positives = sum(
        not item.expected_incident and item.detected_incident for item in cases
    )
    false_negatives = sum(
        item.expected_incident and not item.detected_incident for item in cases
    )
    precision_ppm = _ratio_ppm(
        true_positives,
        true_positives + false_positives,
        empty_value=1_000_000,
    )
    recall_ppm = _ratio_ppm(
        true_positives,
        true_positives + false_negatives,
        empty_value=1_000_000,
    )
    matched_true_cases = tuple(
        item
        for item in cases
        if item.expected_incident and item.detected_incident
    )
    top_1 = sum(
        bool(item.expected_top_causes)
        and bool(item.observed_top_causes)
        and item.expected_top_causes[0] == item.observed_top_causes[0]
        for item in matched_true_cases
    )
    top_3 = sum(
        bool(item.expected_top_causes)
        and item.expected_top_causes[0] in item.observed_top_causes[:3]
        for item in matched_true_cases
    )
    top_1_ppm = _ratio_ppm(top_1, len(matched_true_cases), empty_value=0)
    top_3_ppm = _ratio_ppm(top_3, len(matched_true_cases), empty_value=0)
    delays = tuple(
        item.detection_delay_seconds
        for item in matched_true_cases
        if item.detection_delay_seconds is not None
    )
    median_delay = _round_half_up(median(delays)) if delays else None
    maximum_delay = max(delays, default=None)
    baseline_violations = _baseline_leakage_violations(
        detector_result,
        scenarios,
        matched_incident_ids,
    )
    evidence_violations = _evidence_reconciliation_violations(detector_result)
    hard_negative_alerts = sum(
        item.scenario_kind == "hard_negative" and item.detected_incident
        for item in cases
    )
    method_aggregate_attempts = sum(
        item.attempts
        for item in detector_result.aggregates
        if len(item.cohort) == 1
        and item.cohort[0].dimension is CohortDimension.METHOD
    )
    evaluated_at = partition.ends_at + timedelta(minutes=5)
    targets = EvaluationTargets(
        precision_passed=precision_ppm >= _PRECISION_TARGET_PPM,
        recall_passed=recall_ppm >= _RECALL_TARGET_PPM,
        top_1_attribution_passed=top_1_ppm >= _TOP_1_TARGET_PPM,
        median_detection_delay_passed=(
            median_delay is not None and median_delay <= _MTTD_TARGET_SECONDS
        ),
    )
    detailed = DetailedDetectorReport(
        report_id=f"detector_report_{split.value}_v1",
        detector_version=config.detector_version,
        detector_config_sha256=detector_config_sha256(),
        detector_frozen_at=config.frozen_at,
        dataset_id=dataset.manifest.dataset_id,
        dataset_manifest_sha256=dataset.manifest_sha256,
        dataset_split=split,
        evaluated_at=evaluated_at,
        heldout_thresholds_frozen_before_partition=(
            split is not DatasetSplit.HELDOUT
            or config.frozen_at <= partition.starts_at
        ),
        payment_attempts=len(detector_result.attempts),
        method_aggregate_attempts=method_aggregate_attempts,
        raw_normalized_events=len(events),
        predicted_incidents=len(detector_result.incidents),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision_ppm=precision_ppm,
        recall_ppm=recall_ppm,
        top_1_attribution_ppm=top_1_ppm,
        top_3_attribution_ppm=top_3_ppm,
        median_detection_delay_seconds=median_delay,
        maximum_detection_delay_seconds=maximum_delay,
        hard_negative_action_eligible_incidents=hard_negative_alerts,
        baseline_leakage_violations=baseline_violations,
        evidence_reconciliation_violations=evidence_violations,
        targets=targets,
        cases=cases,
        incidents=tuple(_incident_summary(item) for item in detector_result.incidents),
        limitations=(
            "Results are synthetic submission evidence, not Razorpay production claims.",
            (
                "Method-level detection is the frozen P0 default; issuer and error "
                "fields refine diagnosis."
            ),
            (
                "The confidence calculation is a transparent asymptotic proportion "
                "test, not causal proof."
            ),
        ),
    )
    heldout_contract = None
    if split is DatasetSplit.HELDOUT:
        heldout_contract = DetectorEvaluationContract(
            evaluation_id="detector_eval_heldout_v1",
            detector_version=config.detector_version,
            dataset_manifest_sha256=dataset.manifest_sha256,
            evaluated_at=evaluated_at,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision_ppm=precision_ppm,
            recall_ppm=recall_ppm,
            top_1_attribution_ppm=top_1_ppm,
            top_3_attribution_ppm=top_3_ppm,
            cases=tuple(
                EvaluationCaseResult(
                    scenario_id=item.scenario_id,
                    expected_incident=item.expected_incident,
                    detected_incident=item.detected_incident,
                    expected_top_causes=item.expected_top_causes,
                    observed_top_causes=item.observed_top_causes,
                )
                for item in cases
            ),
        )
    return EvaluationArtifacts(detailed=detailed, heldout_contract=heldout_contract)


def _score_cases(
    run: DetectorRunResult,
    scenarios: tuple[ScenarioDefinition, ...],
    config: DetectorConfig,
) -> tuple[tuple[DetailedEvaluationCase, ...], dict[str, str]]:
    cases: list[DetailedEvaluationCase] = []
    claimed_incidents: set[str] = set()
    matched_incident_ids: dict[str, str] = {}
    for scenario in scenarios:
        match = next(
            (
                item
                for item in run.incidents
                if item.incident_id not in claimed_incidents
                and _matches_scenario(item, scenario)
            ),
            None,
        )
        if match is not None:
            claimed_incidents.add(match.incident_id)
            matched_incident_ids[scenario.scenario_id] = match.incident_id
        expected_causes = _expected_causes(scenario)
        observed_causes = match.diagnosis.likely_causes if match is not None else ()
        delay = None
        if match is not None and scenario.kind is ScenarioKind.TRUE_INCIDENT:
            delay = max(
                int((match.opened_at - scenario.starts_at).total_seconds()),
                0,
            )
        gate_reason = (
            DetectorGateReason.PASSED.value
            if match is not None
            else _scenario_gate_reason(run, scenario, config)
        )
        cases.append(
            DetailedEvaluationCase(
                scenario_id=scenario.scenario_id,
                scenario_kind=scenario.kind.value,
                expected_incident=scenario.should_open_incident,
                detected_incident=match is not None,
                matched_incident_id=match.incident_id if match is not None else None,
                expected_cohort=scenario.affected_cohort,
                observed_cohort=match.affected_cohort if match is not None else (),
                expected_top_causes=expected_causes,
                observed_top_causes=observed_causes,
                detection_delay_seconds=delay,
                gate_reason=gate_reason,
            )
        )
    for incident in run.incidents:
        if incident.incident_id in claimed_incidents:
            continue
        cases.append(
            DetailedEvaluationCase(
                scenario_id=f"background_{incident.incident_id}",
                scenario_kind="background",
                expected_incident=False,
                detected_incident=True,
                matched_incident_id=incident.incident_id,
                expected_cohort=(),
                observed_cohort=incident.affected_cohort,
                expected_top_causes=(),
                observed_top_causes=incident.diagnosis.likely_causes,
                gate_reason=DetectorGateReason.PASSED.value,
            )
        )
    return tuple(cases), matched_incident_ids


def _matches_scenario(
    incident: DetectedIncident,
    scenario: ScenarioDefinition,
) -> bool:
    expected_method = next(
        (
            item.value
            for item in scenario.affected_cohort
            if item.dimension is CohortDimension.METHOD
        ),
        None,
    )
    observed_method = next(
        (
            item.value
            for item in incident.affected_cohort
            if item.dimension is CohortDimension.METHOD
        ),
        None,
    )
    return (
        expected_method == observed_method
        and scenario.starts_at <= incident.opened_at < scenario.ends_at
    )


def _scenario_gate_reason(
    run: DetectorRunResult,
    scenario: ScenarioDefinition,
    config: DetectorConfig,
) -> str:
    method_value = next(
        item.value
        for item in scenario.affected_cohort
        if item.dimension is CohortDimension.METHOD
    )
    method = PaymentMethod(method_value)
    engine = DetectorEngine(config)
    reasons: list[DetectorGateReason] = []
    cutoff = scenario.starts_at + timedelta(minutes=engine.config.step_minutes)
    while cutoff <= scenario.ends_at:
        statistics, _ = engine.evaluate_method(
            run.attempts,
            method=method,
            evaluated_at=cutoff,
            partition_started_at=run.partition_started_at,
        )
        reasons.append(statistics.gate_reason)
        cutoff += timedelta(minutes=engine.config.step_minutes)
    if DetectorGateReason.PASSED in reasons:
        return DetectorGateReason.PASSED.value
    if DetectorGateReason.CURRENT_SAMPLE in reasons:
        return DetectorGateReason.CURRENT_SAMPLE.value
    return reasons[-1].value if reasons else DetectorGateReason.CURRENT_SAMPLE.value


def _expected_causes(scenario: ScenarioDefinition) -> tuple[str, ...]:
    error = scenario.expected_root_cause
    return tuple(
        value
        for value in (error.reason, error.source, error.step)
        if value is not None
    )[:3]


def _baseline_leakage_violations(
    run: DetectorRunResult,
    scenarios: tuple[ScenarioDefinition, ...],
    matched_incident_ids: dict[str, str],
) -> int:
    incidents = {item.incident_id: item for item in run.incidents}
    violations = 0
    for scenario in scenarios:
        incident_id = matched_incident_ids.get(scenario.scenario_id)
        if incident_id is None or scenario.kind is not ScenarioKind.TRUE_INCIDENT:
            continue
        incident = incidents[incident_id]
        if any(
            observation.statistics.baseline_ended_at > scenario.starts_at
            for observation in incident.observations
        ):
            violations += 1
    return violations


def _evidence_reconciliation_violations(run: DetectorRunResult) -> int:
    valid_event_ids = {
        event_id for item in run.attempts for event_id in item.event_ids
    }
    violations = 0
    for incident in run.incidents:
        signal = incident.peak_signal
        stats = signal.statistics
        current = tuple(
            item
            for item in run.attempts
            if item.method is signal.method
            and stats.current_started_at <= item.occurred_at < stats.evaluated_at
        )
        baseline = tuple(
            item
            for item in run.attempts
            if item.method is signal.method
            and stats.baseline_started_at
            <= item.occurred_at
            < stats.baseline_ended_at
        )
        mismatch = (
            len(current) != stats.current_attempts
            or sum(item.failed for item in current) != stats.current_failures
            or len(baseline) != stats.baseline_attempts
            or sum(item.failed for item in baseline) != stats.baseline_failures
            or not set(signal.evidence_event_ids).issubset(valid_event_ids)
        )
        violations += int(mismatch)
    return violations


def _incident_summary(incident: DetectedIncident) -> IncidentEvaluationSummary:
    return IncidentEvaluationSummary(
        incident_id=incident.incident_id,
        status=incident.status,
        opened_at=incident.opened_at,
        last_observed_at=incident.last_observed_at,
        resolved_at=incident.resolved_at,
        affected_cohort=incident.affected_cohort,
        observation_count=len(incident.observations),
        peak_statistics=incident.peak_signal.statistics,
        diagnosis=incident.diagnosis,
        peak_evidence_event_ids=incident.peak_signal.evidence_event_ids,
    )


def _ratio_ppm(numerator: int, denominator: int, *, empty_value: int) -> int:
    if denominator == 0:
        return empty_value
    return _round_half_up((numerator / denominator) * 1_000_000)


def _round_half_up(value: float) -> int:
    return int(value + 0.5)


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


def render_reports() -> dict[Path, bytes]:
    """Regenerate all frozen M3 artifacts in memory without writing files."""

    dataset = build_dataset()
    config = load_detector_config()
    tuning = evaluate_partition(dataset, config, DatasetSplit.TUNING)
    heldout = evaluate_partition(dataset, config, DatasetSplit.HELDOUT)
    if heldout.heldout_contract is None:
        raise AssertionError
    release_decision = _release_decision(heldout.detailed)
    return {
        _REPORT_DIRECTORY / "tuning.detector_report.v1.json": _canonical_json(
            tuning.detailed
        ),
        _REPORT_DIRECTORY / "heldout.detector_report.v1.json": _canonical_json(
            heldout.detailed
        ),
        _REPORT_DIRECTORY / "heldout.detector_evaluation.v1.json": _canonical_json(
            heldout.heldout_contract
        ),
        _REPORT_DIRECTORY / "detector_v1.release.json": _canonical_json(
            release_decision
        ),
    }


def _release_decision(report: DetailedDetectorReport) -> DetectorReleaseDecision:
    """Derive action eligibility solely from the committed held-out targets."""

    failed_targets: list[DetectorReleaseTarget] = []
    target_results = (
        (DetectorReleaseTarget.PRECISION, report.targets.precision_passed),
        (DetectorReleaseTarget.RECALL, report.targets.recall_passed),
        (
            DetectorReleaseTarget.TOP_1_ATTRIBUTION,
            report.targets.top_1_attribution_passed,
        ),
        (
            DetectorReleaseTarget.MEDIAN_DETECTION_DELAY,
            report.targets.median_detection_delay_passed,
        ),
    )
    for target, passed in target_results:
        if not passed:
            failed_targets.append(target)
    qualified = not failed_targets
    return DetectorReleaseDecision(
        detector_version=report.detector_version,
        detector_config_sha256=report.detector_config_sha256,
        dataset_manifest_sha256=report.dataset_manifest_sha256,
        source_report_id=report.report_id,
        evaluated_at=report.evaluated_at,
        status=(
            DetectorReleaseStatus.QUALIFIED
            if qualified
            else DetectorReleaseStatus.BLOCKED
        ),
        failed_targets=tuple(failed_targets),
        action_eligible=qualified,
    )


def check_reports() -> list[str]:
    """Return deterministic drift findings for committed evaluation evidence."""

    findings: list[str] = []
    for path, expected in render_reports().items():
        if not path.is_file():
            findings.append(f"missing {path.relative_to(_REPOSITORY_ROOT).as_posix()}")
        elif path.read_bytes() != expected:
            findings.append(f"stale {path.relative_to(_REPOSITORY_ROOT).as_posix()}")
    return findings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed reports against the frozen detector and dataset",
    )
    parser.add_argument(
        "--print-report",
        choices=("tuning", "heldout", "heldout-contract"),
        help="render one report to stdout without writing the repository",
    )
    return parser


def main() -> None:
    """Check report drift or render one deterministic artifact."""

    arguments = _parser().parse_args()
    if not arguments.check and arguments.print_report is None:
        sys.stderr.write("choose --check or --print-report\n")
        raise SystemExit(2)
    if arguments.check:
        findings = check_reports()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write(
            "detector evaluation reports are current; thresholds remain frozen at "
            f"{detector_config_path().relative_to(_REPOSITORY_ROOT).as_posix()}\n"
        )
        return
    reports = render_reports()
    names = {
        "tuning": "tuning.detector_report.v1.json",
        "heldout": "heldout.detector_report.v1.json",
        "heldout-contract": "heldout.detector_evaluation.v1.json",
    }
    selected = _REPORT_DIRECTORY / names[arguments.print_report]
    sys.stdout.buffer.write(reports[selected])


if __name__ == "__main__":  # pragma: no cover
    main()
