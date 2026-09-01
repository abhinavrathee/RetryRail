"""Deterministic adversarial qualification for the detector-v3 candidate."""

import argparse
import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, Field, ValidationError, model_validator

from retryrail.contracts.domain import StrictContract
from retryrail.detection.engine import DetectorInputError
from retryrail.detection.v3_config import (
    detector_v3_config_sha256,
    load_detector_v3_config,
)
from retryrail.detection.v3_engine import DetectorV3Engine
from retryrail.detection.v3_evaluation import (
    V3DevelopmentPartitionReport,
    V3DevelopmentSuiteReport,
    V3PredictionArtifact,
    candidate_bundle_sha256,
)
from retryrail.detection.v3_models import DetectorV3Config
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.synthetic.v2_generator import build_development_dataset

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_REPORT_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v3.adversarial.json"
_SUITE_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v3.development.json"
_PRIOR_REPORT_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v3.prior_development.report.json"
_REVEALED_REPORT_PATH = (
    _REPOSITORY_ROOT / "evals/reports/detector_v3.revealed_predecessor.report.json"
)
_PREDICTION_PATHS = (
    _REPOSITORY_ROOT / "evals/reports/detector_v3.prior_development.predictions.json",
    _REPOSITORY_ROOT / "evals/reports/detector_v3.revealed_predecessor.predictions.json",
)
_EXPECTED_HARD_NEGATIVES = 8
_DISCLOSED_SLOW_CASE_SECONDS = 2_100
_METHOD_CONFIRMATION_MAXIMUM_MINUTES = 30
_METHOD_CONFIRMATION_SIGNALS = 4
_METHOD_CONFIRMATION_EVIDENCE_STEPS = 3
_METHOD_CONFIRMATION_UNIQUE_FAILURES = 4


class V3AdversarialCase(StrictContract):
    """One reproducible safety or reliability assertion."""

    case_id: str = Field(pattern=r"^[a-z0-9_]+$")
    category: Literal[
        "temporal_safety",
        "lifecycle",
        "hard_negative",
        "provenance",
        "ordering",
        "input_validation",
    ]
    passed: bool
    observations: tuple[str, ...] = Field(min_length=1, max_length=8)


class V3AdversarialReport(StrictContract):
    """Pre-blind adversarial decision bound to exact candidate identities."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    report_id: Literal["detector_v3_adversarial_v1"] = "detector_v3_adversarial_v1"
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evaluated_at: AwareDatetime
    cases: tuple[V3AdversarialCase, ...] = Field(min_length=8)
    all_cases_passed: bool
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


class V3AdversarialError(RuntimeError):
    """The candidate cannot freeze because an adversarial assertion failed."""


def build_adversarial_report() -> V3AdversarialReport:
    """Execute deterministic label, temporal, lifecycle and ordering checks."""

    config = load_detector_v3_config()
    suite = V3DevelopmentSuiteReport.model_validate_json(_SUITE_PATH.read_bytes())
    reports = (
        V3DevelopmentPartitionReport.model_validate_json(_PRIOR_REPORT_PATH.read_bytes()),
        V3DevelopmentPartitionReport.model_validate_json(_REVEALED_REPORT_PATH.read_bytes()),
    )
    predictions = tuple(
        V3PredictionArtifact.model_validate_json(path.read_bytes()) for path in _PREDICTION_PATHS
    )
    dataset = build_development_dataset()
    scenario = dataset.manifest.scenarios[0]
    cutoff = scenario.starts_at + timedelta(minutes=5)
    engine = DetectorV3Engine(config)
    boundary_observations: list[str] = []
    temporal_passed = True
    first_statistics = None
    for window_minutes in config.current_window_minutes:
        variant = DetectorV3Config.model_validate(
            config.model_dump(mode="json") | {"current_window_minutes": [window_minutes]}
        )
        statistics = (
            DetectorV3Engine(variant)
            .evaluate_cohort(
                (),
                cohort=scenario.affected_cohort,
                evaluated_at=cutoff,
                partition_started_at=dataset.manifest.starts_at,
            )
            .statistics
        )
        first_statistics = first_statistics or statistics
        gap_minutes = int(
            (statistics.current_started_at - statistics.baseline_ended_at).total_seconds() // 60
        )
        temporal_passed = temporal_passed and (
            statistics.baseline_ended_at
            == cutoff - timedelta(minutes=config.baseline_guard_minutes)
            and statistics.baseline_ended_at <= statistics.current_started_at
        )
        boundary_observations.append(f"window_{window_minutes}_gap_minutes={gap_minutes}")
    if first_statistics is None:
        raise V3AdversarialError
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

    invalid_guard_rejected = False
    try:
        DetectorV3Config.model_validate(
            config.model_dump(mode="json") | {"baseline_guard_minutes": 55}
        )
    except ValidationError:
        invalid_guard_rejected = True

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
    ordering_passed = ordered == reversed_run

    hard_negative_cases = tuple(
        item for report in reports for item in report.metrics.cases if not item.expected_incident
    )
    hard_negatives_passed = (
        len(hard_negative_cases) == _EXPECTED_HARD_NEGATIVES
        and all(not item.detected_incident for item in hard_negative_cases)
        and all(report.metrics.hard_negative_action_eligible_incidents == 0 for report in reports)
    )
    evidence_passed = all(
        report.metrics.baseline_leakage_violations == 0
        and report.metrics.evidence_reconciliation_violations == 0
        for report in reports
    )
    label_free_passed = all(
        prediction.labels_loaded is False
        and prediction.release_action_eligible is False
        and all(not item.runtime_action_eligible for item in prediction.incidents)
        for prediction in predictions
    ) and all(
        token not in path.read_bytes()
        for path in _PREDICTION_PATHS
        for token in (b'"scenario_id"', b'"expected_incident"')
    )
    slow_case_seconds = reports[1].metrics.maximum_detection_delay_seconds
    slow_case_preserved = slow_case_seconds == _DISCLOSED_SLOW_CASE_SECONDS
    lifecycle_passed = (
        config.method_confirmation_tolerates_statistical_misses
        and config.method_confirmation_maximum_minutes == _METHOD_CONFIRMATION_MAXIMUM_MINUTES
        and config.method_confirmation_signals == _METHOD_CONFIRMATION_SIGNALS
        and config.method_confirmation_evidence_steps == _METHOD_CONFIRMATION_EVIDENCE_STEPS
        and config.method_confirmation_unique_actionable_failures
        == _METHOD_CONFIRMATION_UNIQUE_FAILURES
        and config.method_confirmation_requires_fresh_latest_step
    )
    cases = (
        _case(
            "guard_covers_every_window",
            "temporal_safety",
            passed=temporal_passed,
            observations=tuple(boundary_observations),
        ),
        _case(
            "opening_baseline_freezes",
            "temporal_safety",
            passed=frozen_passed,
            observations=(f"baseline_ended_at={later.baseline_ended_at.isoformat()}",),
        ),
        _case(
            "guard_weakening_rejected",
            "input_validation",
            passed=invalid_guard_rejected,
            observations=("attempted_guard_minutes=55",),
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
            passed=ordering_passed,
            observations=(f"event_records={len(compact_events)}",),
        ),
        _case(
            "bounded_method_confirmation",
            "lifecycle",
            passed=lifecycle_passed,
            observations=("maximum_minutes=30", "fresh_latest_step=true"),
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
                "partitions=2",
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
            "slow_case_remains_disclosed",
            "provenance",
            passed=slow_case_preserved,
            observations=(f"maximum_detection_delay_seconds={slow_case_seconds}",),
        ),
    )
    return V3AdversarialReport(
        detector_config_sha256=detector_v3_config_sha256(),
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
        "hard_negative",
        "provenance",
        "ordering",
        "input_validation",
    ],
    *,
    passed: bool,
    observations: tuple[str, ...],
) -> V3AdversarialCase:
    return V3AdversarialCase(
        case_id=case_id,
        category=category,
        passed=passed,
        observations=observations,
    )


def render_adversarial_report() -> bytes:
    """Return the canonical adversarial report bytes."""

    return _canonical_json(build_adversarial_report())


def check_adversarial_report() -> list[str]:
    """Return missing, stale or failing adversarial evidence findings."""

    expected = render_adversarial_report()
    findings: list[str] = []
    if not _REPORT_PATH.is_file():
        findings.append(f"missing {_REPORT_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}")
    elif _REPORT_PATH.read_bytes() != expected:
        findings.append(f"stale {_REPORT_PATH.relative_to(_REPOSITORY_ROOT).as_posix()}")
    report = V3AdversarialReport.model_validate_json(expected)
    if not report.all_cases_passed:
        findings.extend(
            f"failed adversarial case {item.case_id}" for item in report.cases if not item.passed
        )
    return findings


def write_adversarial_report() -> None:
    """Write the report only when every deterministic case passes."""

    content = render_adversarial_report()
    report = V3AdversarialReport.model_validate_json(content)
    if not report.all_cases_passed:
        raise V3AdversarialError
    _REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = _REPORT_PATH.with_name(f".{_REPORT_PATH.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(_REPORT_PATH)


def _canonical_json(value: StrictContract) -> bytes:
    return (
        json.dumps(
            value.model_dump(mode="json", exclude_none=True),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def report_sha256() -> str:
    """Return the committed adversarial report identity."""

    return hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--print", action="store_true")
    return parser


def main() -> None:
    """Manage the deterministic R4.3 adversarial report."""

    arguments = _parser().parse_args()
    if arguments.write:
        write_adversarial_report()
        sys.stdout.write("wrote passing detector-v3 adversarial report\n")
        return
    if arguments.check:
        findings = check_adversarial_report()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write("detector-v3 adversarial suite passed; release remains blocked\n")
        return
    sys.stdout.buffer.write(render_adversarial_report())


if __name__ == "__main__":  # pragma: no cover
    main()
