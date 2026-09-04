"""Freeze and verify the deterministic M5 recovery experiment in two stages."""

# Ruff's TRY003 rule conflicts with this verifier's deliberately specific evidence errors.
# The messages contain only repository-relative paths and fixed reason text.
# ruff: noqa: TRY003

import argparse
import hashlib
import json
import math
import sys
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from retryrail.experiments.models import (
    AmountBandDefinition,
    BootstrapDesign,
    BootstrapUncertainty,
    CostAssumptions,
    EligibilityDefinition,
    ExperimentArm,
    ExperimentArmSummary,
    ExperimentAssignment,
    ExperimentAssignmentFreeze,
    ExperimentSource,
    IncrementalValueSummary,
    RecoveryExperimentProtocol,
    RecoveryExperimentReport,
    RecoveryOutcome,
    RecoveryOutcomeBatch,
    StratumAssignmentSummary,
)
from retryrail.recovery.integrity import canonical_sha256, stable_identifier
from retryrail.synthetic.models import ExperimentDesign
from retryrail.synthetic.v2_models import V2AttemptTruth, V2DatasetManifest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_RUN_ID = "detector_v4_official_blind_5497598109b06d21c625"
_RUN_ROOT = Path("evals/blind/detector_v4/runs") / _RUN_ID
_GENERATED_ROOT = Path("evals/generated/detector_v4/blind") / _RUN_ID
_SOURCE_MANIFEST_PATH = _RUN_ROOT / "blind.dataset_manifest.v1.json"
_SOURCE_TRUTH_PATH = _GENERATED_ROOT / "blind.attempt_truth.v1.jsonl"
_DETECTOR_RELEASE_PATH = _RUN_ROOT / "blind.release.v1.json"
_DEFAULT_MANIFEST_PATH = Path("fixtures/manifests/default.v1.json")
_EXPERIMENT_ROOT = Path("evals/experiments/recovery_v1")
_PROTOCOL_PATH = _EXPERIMENT_ROOT / "protocol.json"
_ASSIGNMENT_PATH = _EXPERIMENT_ROOT / "assignment.freeze.json"
_OUTCOME_PATH = _EXPERIMENT_ROOT / "outcomes.v1.json"
_REPORT_PATH = Path("evals/reports/recovery_experiment_v1.report.json")
_SOURCE_MANIFEST_SHA256 = "30547b03a068b8d303dba11feb1e981b1eee4a85c721825e382687d0f1dca7d6"
_SOURCE_TRUTH_SHA256 = "35d0e4904572d7a72891f5eae0c7a8f145f8092da7da7a7b7ad393f581654d27"
_DETECTOR_RELEASE_SHA256 = (
    "da633356f34e358327be73bf733165b9993fdbb4d159bf7ace9fa512813a0faa"
)
_EXPERIMENT_ID = "recovery_experiment_v1"
_PROTOCOL_ID = "recovery_experiment_protocol_v1"
_ASSIGNMENT_FROZEN_AT = datetime(2026, 10, 3, 0, 20, tzinfo=UTC)
_OUTCOMES_GENERATED_AT = datetime(2026, 10, 4, 0, 5, tzinfo=UTC)
_BOOTSTRAP_REPLICATES = 10_000
_PPM_TOTAL = 1_000_000
_BPS_TOTAL = 10_000
_MILLI_TOTAL = 1_000
_EXPECTED_SOURCE_RECORDS = 5_760

class ExperimentEvidenceError(RuntimeError):
    """Raised when a frozen source, assignment or outcome identity does not reconcile."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_document(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ExperimentEvidenceError(f"invalid JSON evidence: {path.as_posix()}") from error
    if not isinstance(value, dict):
        msg = f"JSON evidence must be an object: {path.as_posix()}"
        raise ExperimentEvidenceError(msg)
    return value


def _load_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    try:
        return model.model_validate(_json_document(path))
    except ValidationError as error:
        raise ExperimentEvidenceError(f"invalid typed evidence: {path.as_posix()}") from error


def _render_model(value: BaseModel) -> str:
    return f"{json.dumps(value.model_dump(mode='json'), indent=2, sort_keys=True)}\n"


def _rows_sha256[ModelT: BaseModel](rows: Sequence[ModelT]) -> str:
    return canonical_sha256({"rows": [row.model_dump(mode="json") for row in rows]})


def _verify_file(path: Path, expected_sha256: str) -> None:
    if not path.is_file() or _sha256_file(path) != expected_sha256:
        msg = f"frozen artifact identity mismatch: {path.as_posix()}"
        raise ExperimentEvidenceError(msg)


def build_protocol(root: Path = _REPOSITORY_ROOT) -> RecoveryExperimentProtocol:
    """Build the protocol only after verifying every inherited source identity."""

    manifest_path = root / _SOURCE_MANIFEST_PATH
    truth_path = root / _SOURCE_TRUTH_PATH
    release_path = root / _DETECTOR_RELEASE_PATH
    _verify_file(manifest_path, _SOURCE_MANIFEST_SHA256)
    _verify_file(truth_path, _SOURCE_TRUTH_SHA256)
    _verify_file(release_path, _DETECTOR_RELEASE_SHA256)
    try:
        source_manifest = V2DatasetManifest.model_validate(_json_document(manifest_path))
        design = ExperimentDesign.model_validate(
            _json_document(root / _DEFAULT_MANIFEST_PATH)["experiment_design"]
        )
    except (KeyError, ValidationError) as error:
        raise ExperimentEvidenceError("frozen source manifest or M1 design is invalid") from error
    release = _json_document(release_path)
    _validate_source_evidence(source_manifest, release)
    return RecoveryExperimentProtocol(
        protocol_id=_PROTOCOL_ID,
        experiment_id=_EXPERIMENT_ID,
        frozen_at=design.frozen_at,
        source=ExperimentSource(
            dataset_id=source_manifest.dataset_id,
            merchant_id=source_manifest.merchant_id,
            currency=source_manifest.currency,
            manifest_path=_SOURCE_MANIFEST_PATH.as_posix(),
            manifest_sha256=_SOURCE_MANIFEST_SHA256,
            truth_path=_SOURCE_TRUTH_PATH.as_posix(),
            truth_sha256=_SOURCE_TRUTH_SHA256,
            truth_records=source_manifest.payment_attempts,
            detector_version="detector_v4_0_0",
            detector_release_path=_DETECTOR_RELEASE_PATH.as_posix(),
            detector_release_sha256=_DETECTOR_RELEASE_SHA256,
            detector_release_qualified=True,
            synthetic=True,
        ),
        design=design,
        eligibility=EligibilityDefinition(required_currency=source_manifest.currency),
        amount_bands=(
            AmountBandDefinition(
                band_id="amount_under_100000",
                lower_bound_subunits=0,
                upper_bound_subunits=100_000,
            ),
            AmountBandDefinition(
                band_id="amount_100000_to_249999",
                lower_bound_subunits=100_000,
                upper_bound_subunits=250_000,
            ),
            AmountBandDefinition(
                band_id="amount_250000_and_above",
                lower_bound_subunits=250_000,
            ),
        ),
        bootstrap=BootstrapDesign(
            replicates=_BOOTSTRAP_REPLICATES,
            namespace="recovery_bootstrap_v1",
        ),
        costs=CostAssumptions(
            currency=source_manifest.currency,
            action_cost_per_treatment_subunits=200,
            false_intervention_cost_per_unrecovered_treatment_subunits=300,
        ),
        synthetic=True,
    )


def _validate_source_evidence(
    manifest: V2DatasetManifest,
    release: dict[str, Any],
) -> None:
    """Refuse a non-blind, unqualified, mismatched or incomplete source batch."""

    truth_artifact = next(
        (item for item in manifest.artifacts if item.path == _SOURCE_TRUTH_PATH.as_posix()),
        None,
    )
    expected_release = {
        "run_id": _RUN_ID,
        "detector_version": "detector_v4_0_0",
        "dataset_manifest_sha256": _SOURCE_MANIFEST_SHA256,
        "status": "qualified",
        "release_qualified": True,
        "approved_for_m4_integration": True,
        "synthetic": True,
    }
    if (
        manifest.dataset_role.value != "blind"
        or manifest.payment_attempts != _EXPECTED_SOURCE_RECORDS
        or truth_artifact is None
        or truth_artifact.sha256 != _SOURCE_TRUTH_SHA256
        or truth_artifact.records != _EXPECTED_SOURCE_RECORDS
        or any(release.get(key) != value for key, value in expected_release.items())
    ):
        raise ExperimentEvidenceError("source batch is not the qualified frozen v4 blind evidence")


def _load_truth(protocol: RecoveryExperimentProtocol, root: Path) -> tuple[V2AttemptTruth, ...]:
    path = root / protocol.source.truth_path
    _verify_file(path, protocol.source.truth_sha256)
    rows: list[V2AttemptTruth] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    raise ExperimentEvidenceError(f"blank truth row at line {line_number}")
                rows.append(V2AttemptTruth.model_validate_json(line))
    except (OSError, UnicodeError, ValidationError) as error:
        raise ExperimentEvidenceError("truth artifact failed strict row validation") from error
    if len(rows) != protocol.source.truth_records:
        raise ExperimentEvidenceError("truth row count differs from the frozen manifest")
    payment_ids = tuple(row.payment_id for row in rows)
    if len(set(payment_ids)) != len(payment_ids):
        raise ExperimentEvidenceError("truth artifact contains duplicate payment identifiers")
    return tuple(rows)


def _amount_band(protocol: RecoveryExperimentProtocol, amount_subunits: int) -> str:
    for band in protocol.amount_bands:
        if amount_subunits < band.lower_bound_subunits:
            continue
        if band.upper_bound_subunits is None or amount_subunits < band.upper_bound_subunits:
            return band.band_id
    raise ExperimentEvidenceError("eligible amount did not match a predeclared band")


def _stratum_key(row: V2AttemptTruth, amount_band: str) -> tuple[str, str, str]:
    return (row.method.value, row.issuer, amount_band)


def _stratum_id(key: tuple[str, str, str]) -> str:
    material = "\x1f".join(key).encode()
    return f"stratum_{hashlib.sha256(material).hexdigest()}"


def _assignment_rank(
    protocol: RecoveryExperimentProtocol,
    key: tuple[str, str, str],
    payment_id: str,
) -> str:
    material = "\x1f".join(
        (
            protocol.design.assignment_namespace,
            protocol.experiment_id,
            *key,
            payment_id,
        )
    ).encode()
    return hashlib.sha256(material).hexdigest()


def _control_counts_by_stratum(
    protocol: RecoveryExperimentProtocol,
    grouped: dict[tuple[str, str, str], list[V2AttemptTruth]],
) -> dict[tuple[str, str, str], int]:
    """Hamilton-apportion the exact global holdout total across declared strata."""

    control_bps = protocol.design.control_allocation_bps
    eligible_count = sum(len(rows) for rows in grouped.values())
    target = _round_ratio(eligible_count * control_bps, _BPS_TOTAL)
    counts = {key: len(rows) * control_bps // _BPS_TOTAL for key, rows in grouped.items()}
    remaining = target - sum(counts.values())
    priorities = sorted(
        grouped,
        key=lambda key: (
            -(len(grouped[key]) * control_bps % _BPS_TOTAL),
            hashlib.sha256("\x1f".join(key).encode()).hexdigest(),
        ),
    )
    for key in priorities[:remaining]:
        counts[key] += 1
    if sum(counts.values()) != target:
        raise ExperimentEvidenceError("stratified holdout apportionment did not reconcile")
    return counts


def build_assignment_freeze(
    protocol: RecoveryExperimentProtocol,
    root: Path = _REPOSITORY_ROOT,
) -> ExperimentAssignmentFreeze:
    """Scan the complete source, freeze eligibility, then assign without outcome access."""

    source_rows = _load_truth(protocol, root)
    eligible = tuple(
        row
        for row in source_rows
        if row.expected_incident_member
        and row.failed
        and row.synthetic
        and row.dataset_role.value == protocol.eligibility.required_dataset_role
        and row.currency == protocol.eligibility.required_currency
    )
    if not eligible:
        raise ExperimentEvidenceError("predeclared eligibility produced no rows")
    grouped: dict[tuple[str, str, str], list[V2AttemptTruth]] = defaultdict(list)
    for row in eligible:
        grouped[_stratum_key(row, _amount_band(protocol, row.amount_subunits))].append(row)
    control_counts = _control_counts_by_stratum(protocol, grouped)
    assignments: list[ExperimentAssignment] = []
    for key in sorted(grouped):
        ranked = sorted(
            grouped[key],
            key=lambda row: _assignment_rank(protocol, key, row.payment_id),
        )
        for index, row in enumerate(ranked):
            if row.scenario_id is None:
                raise ExperimentEvidenceError("eligible incident member lacks a scenario")
            rank = _assignment_rank(protocol, key, row.payment_id)
            arm = (
                ExperimentArm.CONTROL
                if index < control_counts[key]
                else ExperimentArm.TREATMENT
            )
            assignments.append(
                ExperimentAssignment(
                    experiment_id=protocol.experiment_id,
                    assignment_id=stable_identifier(
                        "assignment",
                        protocol.source.merchant_id,
                        f"{protocol.experiment_id}:{row.payment_id}",
                    ),
                    attempt_id=row.attempt_id,
                    payment_id=row.payment_id,
                    scenario_id=row.scenario_id,
                    eligible_at=row.occurred_at,
                    assigned_at=row.occurred_at + timedelta(seconds=1),
                    amount_subunits=row.amount_subunits,
                    currency=row.currency,
                    method=row.method,
                    issuer=row.issuer,
                    amount_band=key[2],
                    stratum_id=_stratum_id(key),
                    arm=arm,
                    assignment_rank_sha256=rank,
                    synthetic=True,
                )
            )
    ordered_assignments = tuple(sorted(assignments, key=lambda item: item.payment_id))
    balance = _summarize_balance(protocol, ordered_assignments)
    treatment_count = sum(
        item.arm is ExperimentArm.TREATMENT for item in ordered_assignments
    )
    return ExperimentAssignmentFreeze(
        freeze_id="recovery_assignment_freeze_v1",
        experiment_id=protocol.experiment_id,
        protocol_sha256=canonical_sha256(protocol),
        frozen_at=_ASSIGNMENT_FROZEN_AT,
        source_rows_scanned=len(source_rows),
        eligible_count=len(ordered_assignments),
        eligible_gmv_subunits=sum(item.amount_subunits for item in ordered_assignments),
        currency=protocol.source.currency,
        treatment_count=treatment_count,
        control_count=len(ordered_assignments) - treatment_count,
        eligibility_snapshot_sha256=_rows_sha256(
            tuple(sorted(eligible, key=lambda item: item.payment_id))
        ),
        assignments_sha256=_rows_sha256(ordered_assignments),
        assignments=ordered_assignments,
        balance_by_stratum=balance,
        synthetic=True,
    )


def _summarize_balance(
    protocol: RecoveryExperimentProtocol,
    assignments: Sequence[ExperimentAssignment],
) -> tuple[StratumAssignmentSummary, ...]:
    grouped: dict[str, list[ExperimentAssignment]] = defaultdict(list)
    for assignment in assignments:
        grouped[assignment.stratum_id].append(assignment)
    summaries: list[StratumAssignmentSummary] = []
    for stratum_id in sorted(grouped):
        rows = grouped[stratum_id]
        first = rows[0]
        control = tuple(item for item in rows if item.arm is ExperimentArm.CONTROL)
        treatment = tuple(item for item in rows if item.arm is ExperimentArm.TREATMENT)
        observed_control_bps = _round_ratio(len(control) * _BPS_TOTAL, len(rows))
        summaries.append(
            StratumAssignmentSummary(
                stratum_id=stratum_id,
                method=first.method,
                issuer=first.issuer,
                amount_band=first.amount_band,
                eligible_count=len(rows),
                treatment_count=len(treatment),
                control_count=len(control),
                treatment_gmv_subunits=sum(item.amount_subunits for item in treatment),
                control_gmv_subunits=sum(item.amount_subunits for item in control),
                observed_control_allocation_bps=observed_control_bps,
                allocation_deviation_bps=abs(
                    observed_control_bps - protocol.design.control_allocation_bps
                ),
            )
        )
    return tuple(summaries)


def build_outcome_batch(
    protocol: RecoveryExperimentProtocol,
    freeze: ExperimentAssignmentFreeze,
) -> RecoveryOutcomeBatch:
    """Generate one deterministic same-payment outcome after assignment is immutable."""

    _validate_freeze_identity(protocol, freeze)
    outcomes: list[RecoveryOutcome] = []
    window = protocol.design.attribution_window_seconds
    for assignment in freeze.assignments:
        material = (
            f"{protocol.design.outcome_namespace}\x1f{protocol.experiment_id}\x1f"
            f"{assignment.assignment_id}\x1f{assignment.arm.value}"
        ).encode()
        draw = hashlib.sha256(material).hexdigest()
        score_bps = int(draw[:16], 16) % _BPS_TOTAL
        recovery_rate_bps = (
            protocol.design.treatment_recovery_rate_bps
            if assignment.arm is ExperimentArm.TREATMENT
            else protocol.design.control_recovery_rate_bps
        )
        recovered = score_bps < recovery_rate_bps
        delay_seconds = 1 + (int(draw[16:32], 16) % window)
        false_intervention = assignment.arm is ExperimentArm.TREATMENT and not recovered
        outcomes.append(
            RecoveryOutcome(
                experiment_id=protocol.experiment_id,
                assignment_id=assignment.assignment_id,
                payment_id=assignment.payment_id,
                arm=assignment.arm,
                eligible_at=assignment.eligible_at,
                observed_at=assignment.eligible_at + timedelta(seconds=delay_seconds),
                attribution_window_seconds=window,
                outcome_draw_sha256=draw,
                recovered=recovered,
                amount_subunits=assignment.amount_subunits,
                recovered_gmv_subunits=assignment.amount_subunits if recovered else 0,
                currency=assignment.currency,
                action_cost_subunits=(
                    protocol.costs.action_cost_per_treatment_subunits
                    if assignment.arm is ExperimentArm.TREATMENT
                    else 0
                ),
                false_intervention=false_intervention,
                false_intervention_cost_subunits=(
                    protocol.costs.false_intervention_cost_per_unrecovered_treatment_subunits
                    if false_intervention
                    else 0
                ),
                synthetic=True,
            )
        )
    ordered = tuple(sorted(outcomes, key=lambda item: item.payment_id))
    return RecoveryOutcomeBatch(
        batch_id="recovery_outcome_batch_v1",
        experiment_id=protocol.experiment_id,
        protocol_sha256=canonical_sha256(protocol),
        assignment_freeze_sha256=canonical_sha256(freeze),
        generated_at=_OUTCOMES_GENERATED_AT,
        outcome_count=len(ordered),
        outcomes_sha256=_rows_sha256(ordered),
        outcomes=ordered,
        synthetic=True,
    )


def _validate_freeze_identity(
    protocol: RecoveryExperimentProtocol,
    freeze: ExperimentAssignmentFreeze,
) -> None:
    if (
        freeze.experiment_id != protocol.experiment_id
        or freeze.protocol_sha256 != canonical_sha256(protocol)
        or freeze.assignments_sha256 != _rows_sha256(freeze.assignments)
        or freeze.outcomes_observed
    ):
        raise ExperimentEvidenceError("assignment freeze does not match the protocol")


def _validate_outcomes(
    protocol: RecoveryExperimentProtocol,
    freeze: ExperimentAssignmentFreeze,
    batch: RecoveryOutcomeBatch,
) -> None:
    if (
        batch.experiment_id != protocol.experiment_id
        or batch.protocol_sha256 != canonical_sha256(protocol)
        or batch.assignment_freeze_sha256 != canonical_sha256(freeze)
        or batch.outcomes_sha256 != _rows_sha256(batch.outcomes)
        or batch.outcome_count != freeze.eligible_count
    ):
        raise ExperimentEvidenceError("outcome batch does not match its frozen inputs")
    assignments = {item.assignment_id: item for item in freeze.assignments}
    for outcome in batch.outcomes:
        assignment = assignments.get(outcome.assignment_id)
        if assignment is None or (
            outcome.payment_id != assignment.payment_id
            or outcome.arm is not assignment.arm
            or outcome.eligible_at != assignment.eligible_at
            or outcome.amount_subunits != assignment.amount_subunits
            or outcome.currency != assignment.currency
            or outcome.attribution_window_seconds != protocol.design.attribution_window_seconds
        ):
            raise ExperimentEvidenceError("outcome is not bound to its frozen assignment")


def _round_ratio(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ExperimentEvidenceError("ratio denominator must be positive")
    if numerator >= 0:
        return (numerator + denominator // 2) // denominator
    return -((-numerator + denominator // 2) // denominator)


def _arm_summary(
    arm: ExperimentArm,
    assignments: Sequence[ExperimentAssignment],
    outcomes: Sequence[RecoveryOutcome],
) -> ExperimentArmSummary:
    eligible_gmv = sum(item.amount_subunits for item in assignments)
    recovered_gmv = sum(item.recovered_gmv_subunits for item in outcomes)
    recovered_count = sum(item.recovered for item in outcomes)
    return ExperimentArmSummary(
        arm=arm,
        eligible_count=len(assignments),
        eligible_gmv_subunits=eligible_gmv,
        recovered_count=recovered_count,
        recovery_rate_ppm=_round_ratio(recovered_count * _PPM_TOTAL, len(assignments)),
        recovered_gmv_subunits=recovered_gmv,
        value_per_eligible_subunits_rounded=_round_ratio(recovered_gmv, len(assignments)),
        action_count=sum(item.action_cost_subunits > 0 for item in outcomes),
        action_cost_subunits=sum(item.action_cost_subunits for item in outcomes),
        false_intervention_count=sum(item.false_intervention for item in outcomes),
        false_intervention_cost_subunits=sum(
            item.false_intervention_cost_subunits for item in outcomes
        ),
    )


def _uplift_bps(
    treatment_successes: int,
    treatment_count: int,
    control_successes: int,
    control_count: int,
) -> int:
    numerator = treatment_successes * control_count - control_successes * treatment_count
    return _round_ratio(numerator * _BPS_TOTAL, treatment_count * control_count)


def _incremental_gmv(
    treatment_gmv: int,
    treatment_count: int,
    control_gmv: int,
    control_count: int,
) -> tuple[int, int]:
    natural = _round_ratio(control_gmv * treatment_count, control_count)
    return treatment_gmv - natural, natural


def _bootstrap_draw_index(
    seed_sha256: str,
    replicate: int,
    arm: ExperimentArm,
    draw_index: int,
    population_size: int,
) -> int:
    material = f"{seed_sha256}\x1f{replicate}\x1f{arm.value}\x1f{draw_index}".encode()
    return int(hashlib.sha256(material).hexdigest()[:16], 16) % population_size


def _percentile_bounds(values: list[int], confidence_level_ppm: int) -> tuple[int, int]:
    ordered = sorted(values)
    tail_ppm = (_PPM_TOTAL - confidence_level_ppm) // 2
    last = len(ordered) - 1
    lower_index = tail_ppm * last // _PPM_TOTAL
    upper_numerator = (_PPM_TOTAL - tail_ppm) * last
    upper_index = math.ceil(upper_numerator / _PPM_TOTAL)
    return ordered[lower_index], ordered[upper_index]


def _bootstrap_uncertainty(
    protocol: RecoveryExperimentProtocol,
    treatment: Sequence[RecoveryOutcome],
    control: Sequence[RecoveryOutcome],
    *,
    incremental_point: int,
    uplift_point_bps: int,
) -> BootstrapUncertainty:
    seed = hashlib.sha256(
        "\x1f".join(
            (
                protocol.bootstrap.namespace,
                protocol.experiment_id,
                canonical_sha256(protocol),
            )
        ).encode()
    ).hexdigest()
    incremental_values: list[int] = []
    uplift_values: list[int] = []
    for replicate in range(protocol.bootstrap.replicates):
        treatment_sample = tuple(
            treatment[
                _bootstrap_draw_index(
                    seed,
                    replicate,
                    ExperimentArm.TREATMENT,
                    draw_index,
                    len(treatment),
                )
            ]
            for draw_index in range(len(treatment))
        )
        control_sample = tuple(
            control[
                _bootstrap_draw_index(
                    seed,
                    replicate,
                    ExperimentArm.CONTROL,
                    draw_index,
                    len(control),
                )
            ]
            for draw_index in range(len(control))
        )
        treatment_gmv = sum(item.recovered_gmv_subunits for item in treatment_sample)
        control_gmv = sum(item.recovered_gmv_subunits for item in control_sample)
        incremental, _ = _incremental_gmv(
            treatment_gmv,
            len(treatment_sample),
            control_gmv,
            len(control_sample),
        )
        incremental_values.append(incremental)
        uplift_values.append(
            _uplift_bps(
                sum(item.recovered for item in treatment_sample),
                len(treatment_sample),
                sum(item.recovered for item in control_sample),
                len(control_sample),
            )
        )
    incremental_lower, incremental_upper = _percentile_bounds(
        incremental_values,
        protocol.bootstrap.confidence_level_ppm,
    )
    uplift_lower, uplift_upper = _percentile_bounds(
        uplift_values,
        protocol.bootstrap.confidence_level_ppm,
    )
    return BootstrapUncertainty(
        method=protocol.bootstrap.method,
        replicates=protocol.bootstrap.replicates,
        confidence_level_ppm=protocol.bootstrap.confidence_level_ppm,
        bootstrap_seed_sha256=seed,
        incremental_gmv_lower_subunits=incremental_lower,
        incremental_gmv_point_subunits=incremental_point,
        incremental_gmv_upper_subunits=incremental_upper,
        incremental_gmv_interval_includes_zero=incremental_lower <= 0 <= incremental_upper,
        recovery_rate_uplift_lower_bps=uplift_lower,
        recovery_rate_uplift_point_bps=uplift_point_bps,
        recovery_rate_uplift_upper_bps=uplift_upper,
        recovery_rate_interval_includes_zero=uplift_lower <= 0 <= uplift_upper,
    )


def build_report(
    protocol: RecoveryExperimentProtocol,
    freeze: ExperimentAssignmentFreeze,
    batch: RecoveryOutcomeBatch,
) -> RecoveryExperimentReport:
    """Compute raw and causal value separately, with precommitted uncertainty."""

    _validate_freeze_identity(protocol, freeze)
    _validate_outcomes(protocol, freeze, batch)
    assignments_by_arm = {
        arm: tuple(item for item in freeze.assignments if item.arm is arm)
        for arm in ExperimentArm
    }
    outcomes_by_arm = {
        arm: tuple(item for item in batch.outcomes if item.arm is arm) for arm in ExperimentArm
    }
    treatment = _arm_summary(
        ExperimentArm.TREATMENT,
        assignments_by_arm[ExperimentArm.TREATMENT],
        outcomes_by_arm[ExperimentArm.TREATMENT],
    )
    control = _arm_summary(
        ExperimentArm.CONTROL,
        assignments_by_arm[ExperimentArm.CONTROL],
        outcomes_by_arm[ExperimentArm.CONTROL],
    )
    incremental_gmv, estimated_natural = _incremental_gmv(
        treatment.recovered_gmv_subunits,
        treatment.eligible_count,
        control.recovered_gmv_subunits,
        control.eligible_count,
    )
    uplift_bps = _uplift_bps(
        treatment.recovered_count,
        treatment.eligible_count,
        control.recovered_count,
        control.eligible_count,
    )
    uncertainty = _bootstrap_uncertainty(
        protocol,
        outcomes_by_arm[ExperimentArm.TREATMENT],
        outcomes_by_arm[ExperimentArm.CONTROL],
        incremental_point=incremental_gmv,
        uplift_point_bps=uplift_bps,
    )
    value = IncrementalValueSummary(
        currency=freeze.currency,
        gross_treatment_recovered_gmv_subunits=treatment.recovered_gmv_subunits,
        observed_control_recovered_gmv_subunits=control.recovered_gmv_subunits,
        estimated_natural_recovery_in_treatment_subunits=estimated_natural,
        incremental_recovered_gmv_subunits=incremental_gmv,
        action_cost_subunits=treatment.action_cost_subunits,
        false_intervention_cost_subunits=treatment.false_intervention_cost_subunits,
        net_recovered_value_subunits=(
            incremental_gmv
            - treatment.action_cost_subunits
            - treatment.false_intervention_cost_subunits
        ),
        absolute_recovery_rate_uplift_bps=uplift_bps,
        incremental_recovered_payments_milli=_round_ratio(
            (
                treatment.recovered_count * control.eligible_count
                - control.recovered_count * treatment.eligible_count
            )
            * _MILLI_TOTAL,
            control.eligible_count,
        ),
    )
    if uncertainty.incremental_gmv_interval_includes_zero:
        conclusion = "inconclusive_synthetic_experiment"
    elif uncertainty.incremental_gmv_lower_subunits > 0:
        conclusion = "statistically_positive_synthetic_incremental_value"
    else:
        conclusion = "statistically_negative_synthetic_incremental_value"
    return RecoveryExperimentReport(
        report_id="recovery_experiment_report_v1",
        experiment_id=protocol.experiment_id,
        generated_at=batch.generated_at,
        protocol_sha256=canonical_sha256(protocol),
        assignment_freeze_sha256=canonical_sha256(freeze),
        outcome_batch_sha256=canonical_sha256(batch),
        source_manifest_sha256=protocol.source.manifest_sha256,
        source_truth_sha256=protocol.source.truth_sha256,
        source_rows_scanned=freeze.source_rows_scanned,
        eligible_count=freeze.eligible_count,
        treatment=treatment,
        control=control,
        balance_by_stratum=freeze.balance_by_stratum,
        value=value,
        uncertainty=uncertainty,
        conclusion=conclusion,
        synthetic=True,
    )


def _write_or_check(path: Path, content: str, *, check: bool) -> bool:
    if check:
        return path.is_file() and path.read_text(encoding="utf-8") == content
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def freeze_stage(*, root: Path = _REPOSITORY_ROOT, check: bool = False) -> tuple[str, ...]:
    """Write or verify only protocol and assignment artifacts; never touch outcomes."""

    protocol = build_protocol(root)
    freeze = build_assignment_freeze(protocol, root)
    expected = (
        (_PROTOCOL_PATH, _render_model(protocol)),
        (_ASSIGNMENT_PATH, _render_model(freeze)),
    )
    return tuple(
        path.as_posix()
        for relative, content in expected
        if not _write_or_check(root / relative, content, check=check)
        for path in (relative,)
    )


def evaluation_stage(
    *,
    root: Path = _REPOSITORY_ROOT,
    check: bool = False,
) -> tuple[str, ...]:
    """Write or verify outcomes and report only after loading the exact frozen inputs."""

    protocol = _load_model(root / _PROTOCOL_PATH, RecoveryExperimentProtocol)
    freeze = _load_model(root / _ASSIGNMENT_PATH, ExperimentAssignmentFreeze)
    expected_protocol = build_protocol(root)
    expected_freeze = build_assignment_freeze(expected_protocol, root)
    if protocol != expected_protocol or freeze != expected_freeze:
        raise ExperimentEvidenceError(
            "committed assignment inputs differ from source-derived freeze"
        )
    batch = build_outcome_batch(protocol, freeze)
    report = build_report(protocol, freeze, batch)
    expected = (
        (_OUTCOME_PATH, _render_model(batch)),
        (_REPORT_PATH, _render_model(report)),
    )
    return tuple(
        path.as_posix()
        for relative, content in expected
        if not _write_or_check(root / relative, content, check=check)
        for path in (relative,)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="stage", required=True)
    for stage in ("freeze", "evaluate"):
        command = subparsers.add_parser(stage)
        command.add_argument(
            "--check",
            action="store_true",
            help="verify committed bytes without writing",
        )
    return parser


def main() -> None:
    """Run one explicitly separated experiment stage."""

    arguments = _parser().parse_args()
    try:
        stale = (
            freeze_stage(check=arguments.check)
            if arguments.stage == "freeze"
            else evaluation_stage(check=arguments.check)
        )
    except ExperimentEvidenceError as error:
        sys.stderr.write(f"experiment evidence error: {error}\n")
        raise SystemExit(1) from None
    if stale:
        sys.stderr.write("missing or stale experiment artifacts:\n")
        sys.stderr.write("\n".join(f"- {path}" for path in stale) + "\n")
        raise SystemExit(1)
    verb = "verified" if arguments.check else "wrote"
    artifact_count = 2
    sys.stdout.write(f"{verb} {artifact_count} {arguments.stage} artifacts\n")


if __name__ == "__main__":  # pragma: no cover
    main()
