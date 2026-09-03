"""Deterministic adversarial qualification for the detector-v4 candidate."""

import argparse
import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, Field, ValidationError, model_validator

from retryrail.contracts.domain import IncidentStatus, StrictContract
from retryrail.detection.engine import DetectorInputError
from retryrail.detection.v4_config import (
    detector_v4_config_sha256,
    load_detector_v4_config,
)
from retryrail.detection.v4_engine import DetectorV4Engine
from retryrail.detection.v4_evaluation import (
    V4DevelopmentPartitionReport,
    V4DevelopmentSuiteReport,
    V4PredictionArtifact,
    candidate_bundle_sha256,
    canonical_contract_json,
)
from retryrail.detection.v4_models import (
    DetectorV4Config,
    V4ScopeDisposition,
)
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.synthetic.v2_generator import build_development_dataset

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_REPORT_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v4.adversarial.json"
_SUITE_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v4.development.json"
_PARTITION_PATHS = (
    (
        _REPOSITORY_ROOT / "evals/reports/detector_v4.prior_development.predictions.json",
        _REPOSITORY_ROOT / "evals/reports/detector_v4.prior_development.report.json",
    ),
    (
        _REPOSITORY_ROOT
        / "evals/reports/detector_v4.revealed_v2_predecessor.predictions.json",
        _REPOSITORY_ROOT / "evals/reports/detector_v4.revealed_v2_predecessor.report.json",
    ),
    (
        _REPOSITORY_ROOT
        / "evals/reports/detector_v4.revealed_v3_predecessor.predictions.json",
        _REPOSITORY_ROOT / "evals/reports/detector_v4.revealed_v3_predecessor.report.json",
    ),
)
_V3_GAMMA_SCENARIO_ID = "scenario_v2_blind_02_issuer_provider_degradation"
_V3_GAMMA_OPENED_AT = "2026-10-01T08:15:00+00:00"
_V3_LATE_PARENT_OPENED_AT = "2026-10-01T10:30:00+00:00"
_ISSUER_COHORT_SIZE = 2
_BROAD_SCOPE_MINIMUM_CONFIRMED_CHILDREN = 2


class V4AdversarialCase(StrictContract):
    """One reproducible detector-v4 safety or reliability assertion."""

    case_id: str = Field(pattern=r"^[a-z0-9_]+$")
    category: Literal[
        "temporal_safety",
        "lifecycle",
        "hierarchy",
        "overlap",
        "serialization",
        "hard_negative",
        "provenance",
        "ordering",
        "input_validation",
    ]
    passed: bool
    observations: tuple[str, ...] = Field(min_length=1, max_length=8)


class V4AdversarialReport(StrictContract):
    """Pre-nonce adversarial decision bound to exact candidate identities."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    report_id: Literal["detector_v4_adversarial_v1"] = "detector_v4_adversarial_v1"
    protocol_id: Literal["detector_v4_protocol_v1"] = "detector_v4_protocol_v1"
    detector_version: Literal["detector_v4_0_0"] = "detector_v4_0_0"
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evaluated_at: AwareDatetime
    cases: tuple[V4AdversarialCase, ...] = Field(min_length=15)
    all_cases_passed: bool
    official_blind_nonce_sha256: None = None
    official_blind_run_id: None = None
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        """Require unique cases and an exact all-cases summary."""

        case_ids = tuple(item.case_id for item in self.cases)
        if len(set(case_ids)) != len(case_ids):
            msg = "adversarial case identifiers must be unique"
            raise ValueError(msg)
        if self.all_cases_passed is not all(item.passed for item in self.cases):
            msg = "adversarial summary must equal every case result"
            raise ValueError(msg)
        return self


class V4AdversarialError(RuntimeError):
    """The candidate cannot freeze because an adversarial assertion failed."""


def _load_evidence() -> tuple[
    V4DevelopmentSuiteReport,
    tuple[V4PredictionArtifact, V4PredictionArtifact, V4PredictionArtifact],
    tuple[
        V4DevelopmentPartitionReport,
        V4DevelopmentPartitionReport,
        V4DevelopmentPartitionReport,
    ],
]:
    suite = V4DevelopmentSuiteReport.model_validate_json(_SUITE_PATH.read_bytes())
    predictions = tuple(
        V4PredictionArtifact.model_validate_json(prediction_path.read_bytes())
        for prediction_path, _ in _PARTITION_PATHS
    )
    reports = tuple(
        V4DevelopmentPartitionReport.model_validate_json(report_path.read_bytes())
        for _, report_path in _PARTITION_PATHS
    )
    return suite, predictions, reports  # type: ignore[return-value]


def _same_method_incidents_do_not_overlap(prediction: V4PredictionArtifact) -> bool:
    ordered = sorted(prediction.incidents, key=lambda item: item.opened_at)
    for index, left in enumerate(ordered):
        left_end = left.resolved_at or prediction.partition_ended_at
        for right in ordered[index + 1 :]:
            if left.detector_cohort[0].value != right.detector_cohort[0].value:
                continue
            right_end = right.resolved_at or prediction.partition_ended_at
            if left.opened_at <= right_end and right.opened_at <= left_end:
                return False
    return True


def _configuration_weakening_is_rejected(config: DetectorV4Config) -> bool:
    changes: tuple[dict[str, object], ...] = (
        {"baseline_guard_minutes": 55},
        {"method_minimum_current_attempts": 9},
        {"issuer_confidence_threshold_ppm": 899_999},
        {"minimum_at_risk_gmv_subunits": 49_999},
        {"scope_arbitration_strategy": "labels_choose_winner"},
    )
    for change in changes:
        try:
            DetectorV4Config.model_validate(config.model_dump(mode="json") | change)
        except ValidationError:
            continue
        return False
    return True


def build_adversarial_report() -> V4AdversarialReport:
    """Execute hierarchy, overlap, serialization, temporal and provenance checks."""

    config = load_detector_v4_config()
    suite, predictions, reports = _load_evidence()
    dataset = build_development_dataset()
    scenario = dataset.manifest.scenarios[0]
    cutoff = scenario.starts_at + timedelta(minutes=5)
    engine = DetectorV4Engine(config)

    first_statistics = engine.evaluate_cohort(
        (),
        cohort=scenario.affected_cohort,
        evaluated_at=cutoff,
        partition_started_at=dataset.manifest.starts_at,
    ).statistics
    gap_minutes = int(
        (
            first_statistics.current_started_at - first_statistics.baseline_ended_at
        ).total_seconds()
        // 60
    )
    temporal_passed = (
        config.baseline_guard_minutes >= max(config.current_window_minutes)
        and first_statistics.baseline_ended_at
        == cutoff - timedelta(minutes=config.baseline_guard_minutes)
        and first_statistics.baseline_ended_at <= first_statistics.current_started_at
    )
    boundary_observations = (
        "configured_windows=" + ",".join(str(item) for item in config.current_window_minutes),
        f"selected_gap_minutes={gap_minutes}",
    )
    later = engine.evaluate_cohort(
        (),
        cohort=scenario.affected_cohort,
        evaluated_at=cutoff + timedelta(minutes=30),
        partition_started_at=dataset.manifest.starts_at,
        frozen_baseline=(
            first_statistics.baseline_started_at,
            first_statistics.baseline_ended_at,
        ),
    ).statistics
    frozen_passed = (
        later.baseline_started_at == first_statistics.baseline_started_at
        and later.baseline_ended_at == first_statistics.baseline_ended_at
    )

    naive_time_rejected = False
    try:
        engine.evaluate_cohort(
            (),
            cohort=scenario.affected_cohort,
            evaluated_at=cutoff.replace(tzinfo=None),
            partition_started_at=dataset.manifest.starts_at,
        )
    except DetectorInputError:
        naive_time_rejected = True

    events = tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in dataset.event_artifact.content.splitlines()
    )
    ordering_end = dataset.manifest.starts_at + timedelta(hours=2)
    compact_events = tuple(item for item in events if item.occurred_at < ordering_end)
    ordered = engine.run(
        compact_events,
        partition_started_at=dataset.manifest.starts_at,
        partition_ended_at=ordering_end,
    )
    reversed_run = engine.run(
        reversed(compact_events),
        partition_started_at=dataset.manifest.starts_at,
        partition_ended_at=ordering_end,
    )

    v3_report = reports[2]
    v3_prediction = predictions[2]
    gamma_case = next(
        item for item in v3_report.metrics.cases if item.scenario_id == _V3_GAMMA_SCENARIO_ID
    )
    gamma_incident = next(
        item
        for item in v3_prediction.incidents
        if item.incident_id == gamma_case.matched_incident_id
    )
    late_parent = next(
        (
            item
            for item in v3_prediction.arbitrations
            if item.candidate_opened_at.isoformat() == _V3_LATE_PARENT_OPENED_AT
            and len(item.candidate_cohort) == 1
            and item.candidate_cohort[0].value == "netbanking"
        ),
        None,
    )
    canonical_child_passed = (
        gamma_case.detected_incident
        and gamma_incident.opened_at.isoformat() == _V3_GAMMA_OPENED_AT
        and len(gamma_incident.detector_cohort) == _ISSUER_COHORT_SIZE
        and late_parent is not None
        and late_parent.selected_incident_id == gamma_incident.incident_id
    )

    all_arbitrations = tuple(item for prediction in predictions for item in prediction.arbitrations)
    single_child = tuple(
        item
        for item in all_arbitrations
        if item.disposition is V4ScopeDisposition.PARENT_NOT_SELECTED_SINGLE_CHILD
    )
    multi_child = tuple(
        item
        for item in all_arbitrations
        if item.disposition is V4ScopeDisposition.CHILD_NOT_SELECTED_MULTI_CHILD_BREADTH
    )
    arbitration_reconciles = all(
        len(prediction.arbitrations) == report.metrics.arbitrated_confirmed_candidates
        and len({item.arbitration_id for item in prediction.arbitrations})
        == len(prediction.arbitrations)
        and len({item.candidate_id for item in prediction.arbitrations})
        == len(prediction.arbitrations)
        and all(
            item.selected_incident_id in {incident.incident_id for incident in prediction.incidents}
            for item in prediction.arbitrations
        )
        for prediction, report in zip(predictions, reports, strict=True)
    )
    overlap_passed = all(_same_method_incidents_do_not_overlap(item) for item in predictions)

    hard_negative_cases = tuple(
        item for report in reports for item in report.metrics.cases if not item.expected_incident
    )
    hard_negatives_passed = bool(hard_negative_cases) and all(
        not item.detected_incident for item in hard_negative_cases
    ) and all(report.metrics.hard_negative_action_eligible_incidents == 0 for report in reports)
    evidence_passed = all(
        report.metrics.baseline_leakage_violations == 0
        and report.metrics.evidence_reconciliation_violations == 0
        for report in reports
    )
    prediction_paths = tuple(path for path, _ in _PARTITION_PATHS)
    label_free_passed = all(
        prediction.labels_loaded is False
        and prediction.release_action_eligible is False
        and all(not item.runtime_action_eligible for item in prediction.incidents)
        and all(not item.runtime_action_eligible for item in prediction.arbitrations)
        for prediction in predictions
    ) and all(
        token not in path.read_bytes()
        for path in prediction_paths
        for token in (b'"scenario_id"', b'"scenario_family"', b'"expected_incident"')
    )

    serialization_passed = True
    open_incident_ids: list[str] = []
    for (_, report_path), report in zip(_PARTITION_PATHS, reports, strict=True):
        content = report_path.read_bytes()
        raw = json.loads(content)
        incident_rows = raw["metrics"]["incidents"]
        serialization_passed = serialization_passed and all(
            "resolved_at" in item for item in incident_rows
        )
        serialization_passed = serialization_passed and canonical_contract_json(report) == content
        open_incident_ids.extend(
            item.incident_id
            for item in report.metrics.incidents
            if item.status is IncidentStatus.OPEN and item.resolved_at is None
        )
    serialization_passed = serialization_passed and len(open_incident_ids) == 1

    nonce_free_passed = (
        suite.official_blind_nonce_sha256 is None
        and suite.official_blind_run_id is None
        and not suite.official_blind_evaluated
        and not suite.release_qualified
        and not suite.runtime_action_eligible
        and all(not report.runtime_action_eligible for report in reports)
    )
    cases = (
        _case(
            "guard_covers_every_window",
            "temporal_safety",
            passed=temporal_passed,
            observations=boundary_observations,
        ),
        _case(
            "opening_baseline_freezes",
            "temporal_safety",
            passed=frozen_passed,
            observations=(f"baseline_ended_at={later.baseline_ended_at.isoformat()}",),
        ),
        _case(
            "gate_and_strategy_weakening_rejected",
            "input_validation",
            passed=_configuration_weakening_is_rejected(config),
            observations=("mutations_rejected=5",),
        ),
        _case(
            "naive_time_rejected",
            "input_validation",
            passed=naive_time_rejected,
            observations=("timezone_requirement=aware",),
        ),
        _case(
            "out_of_order_input_invariant",
            "ordering",
            passed=ordered == reversed_run,
            observations=(f"event_records={len(compact_events)}",),
        ),
        _case(
            "canonical_child_survives_parent_lifecycle",
            "lifecycle",
            passed=canonical_child_passed,
            observations=(
                f"child_opened_at={gamma_incident.opened_at.isoformat()}",
                f"late_parent_audited={late_parent is not None}",
            ),
        ),
        _case(
            "single_child_selects_child",
            "hierarchy",
            passed=bool(single_child)
            and all(item.confirmed_child_cohort_count == 1 for item in single_child),
            observations=(f"parent_loser_records={len(single_child)}",),
        ),
        _case(
            "multi_child_breadth_selects_parent",
            "hierarchy",
            passed=bool(multi_child)
            and all(
                item.confirmed_child_cohort_count
                >= _BROAD_SCOPE_MINIMUM_CONFIRMED_CHILDREN
                for item in multi_child
            ),
            observations=(f"child_loser_records={len(multi_child)}",),
        ),
        _case(
            "arbitration_receipts_reconcile",
            "overlap",
            passed=arbitration_reconciles,
            observations=(f"arbitration_records={len(all_arbitrations)}",),
        ),
        _case(
            "same_method_incidents_do_not_overlap",
            "overlap",
            passed=overlap_passed,
            observations=(f"partitions={len(predictions)}",),
        ),
        _case(
            "all_hard_negatives_suppressed",
            "hard_negative",
            passed=hard_negatives_passed,
            observations=(f"hard_negative_cases={len(hard_negative_cases)}",),
        ),
        _case(
            "evidence_reconciles_without_leakage",
            "temporal_safety",
            passed=evidence_passed,
            observations=(
                "partitions=3",
                "leakage_violations=0",
                "reconciliation_violations=0",
            ),
        ),
        _case(
            "prediction_artifacts_are_label_free",
            "provenance",
            passed=label_free_passed,
            observations=(f"prediction_artifacts={len(predictions)}",),
        ),
        _case(
            "required_nullable_reports_round_trip",
            "serialization",
            passed=serialization_passed,
            observations=(
                f"report_artifacts={len(reports)}",
                f"open_incidents={len(open_incident_ids)}",
            ),
        ),
        _case(
            "development_evidence_remains_nonce_free",
            "provenance",
            passed=nonce_free_passed,
            observations=("official_blind_evaluated=false", "runtime_action_eligible=false"),
        ),
    )
    return V4AdversarialReport(
        detector_config_sha256=detector_v4_config_sha256(),
        candidate_bundle_sha256=candidate_bundle_sha256(),
        evaluated_at=suite.evaluated_at + timedelta(minutes=5),
        cases=cases,
        all_cases_passed=all(item.passed for item in cases),
    )


def _case(
    case_id: str,
    category: Literal[
        "temporal_safety",
        "lifecycle",
        "hierarchy",
        "overlap",
        "serialization",
        "hard_negative",
        "provenance",
        "ordering",
        "input_validation",
    ],
    *,
    passed: bool,
    observations: tuple[str, ...],
) -> V4AdversarialCase:
    return V4AdversarialCase(
        case_id=case_id,
        category=category,
        passed=passed,
        observations=observations,
    )


def render_adversarial_report() -> bytes:
    """Return canonical detector-v4 adversarial evidence bytes."""

    return canonical_contract_json(build_adversarial_report())


def check_adversarial_report() -> list[str]:
    """Return missing, stale or failing adversarial evidence findings."""

    expected = render_adversarial_report()
    findings: list[str] = []
    if not _REPORT_PATH.is_file():
        findings.append(f"missing {_REPORT_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}")
    elif _REPORT_PATH.read_bytes() != expected:
        findings.append(f"stale {_REPORT_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}")
    report = V4AdversarialReport.model_validate_json(expected)
    if not report.all_cases_passed:
        findings.extend(
            f"failed adversarial case {item.case_id}" for item in report.cases if not item.passed
        )
    return findings


def write_adversarial_report() -> None:
    """Write the report atomically only when every deterministic case passes."""

    content = render_adversarial_report()
    report = V4AdversarialReport.model_validate_json(content)
    if not report.all_cases_passed:
        raise V4AdversarialError
    _REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = _REPORT_PATH.with_name(f".{_REPORT_PATH.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(_REPORT_PATH)


def report_sha256() -> str:
    """Return the committed detector-v4 adversarial report identity."""

    return hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--print", action="store_true")
    return parser


def main() -> None:
    """Manage the deterministic R5.3 adversarial report."""

    arguments = _parser().parse_args()
    if arguments.write:
        write_adversarial_report()
        sys.stdout.write("wrote passing detector-v4 adversarial report\n")
        return
    if arguments.check:
        findings = check_adversarial_report()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write("detector-v4 adversarial suite passed; release remains blocked\n")
        return
    sys.stdout.buffer.write(render_adversarial_report())


if __name__ == "__main__":  # pragma: no cover
    main()
