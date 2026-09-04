"""M5 experiment assignment, attribution, value and uncertainty tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.experiments.evaluation import (
    ExperimentEvidenceError,
    build_assignment_freeze,
    build_outcome_batch,
    build_protocol,
    build_report,
    freeze_stage,
)
from retryrail.experiments.models import ExperimentArm, RecoveryOutcome
from retryrail.recovery.integrity import canonical_sha256

_ROOT = Path(__file__).resolve().parents[4]


def test_assignment_freeze_scans_the_full_source_and_is_byte_stable() -> None:
    protocol = build_protocol(_ROOT)
    first = build_assignment_freeze(protocol, _ROOT)
    second = build_assignment_freeze(protocol, _ROOT)

    assert first == second
    assert first.source_rows_scanned == 5_760
    assert first.eligible_count == 280
    assert first.eligible_gmv_subunits == 50_022_000
    assert first.treatment_count == 224
    assert first.control_count == 56
    assert len(first.balance_by_stratum) == 20
    assert first.outcomes_observed is False
    assert first.protocol_sha256 == canonical_sha256(protocol)
    assert len({item.payment_id for item in first.assignments}) == 280
    assert sum(item.control_count for item in first.balance_by_stratum) == 56
    assert sum(item.treatment_count for item in first.balance_by_stratum) == 224
    assert all(item.synthetic for item in first.assignments)


def test_outcome_attribution_and_incremental_report_are_complete() -> None:
    protocol = build_protocol(_ROOT)
    freeze = build_assignment_freeze(protocol, _ROOT)
    batch = build_outcome_batch(protocol, freeze)
    report = build_report(protocol, freeze, batch)

    assert batch.outcome_count == freeze.eligible_count
    assert batch.assignment_freeze_sha256 == canonical_sha256(freeze)
    assert {item.assignment_id for item in batch.outcomes} == {
        item.assignment_id for item in freeze.assignments
    }
    assert all(
        0 <= (item.observed_at - item.eligible_at).total_seconds()
        <= protocol.design.attribution_window_seconds
        for item in batch.outcomes
    )
    assert all(item.synthetic for item in batch.outcomes)
    assert report.treatment.eligible_count == 224
    assert report.control.eligible_count == 56
    assert report.value.gross_treatment_recovered_gmv_subunits != (
        report.value.incremental_recovered_gmv_subunits
    )
    assert report.value.incremental_recovered_gmv_subunits == (
        report.value.gross_treatment_recovered_gmv_subunits
        - report.value.estimated_natural_recovery_in_treatment_subunits
    )
    assert report.value.net_recovered_value_subunits == (
        report.value.incremental_recovered_gmv_subunits
        - report.value.action_cost_subunits
        - report.value.false_intervention_cost_subunits
    )
    assert report.uncertainty.replicates == 10_000
    assert report.metric_scope == "synthetic_batch_not_live_merchant_performance"
    assert report.gross_recovery_is_not_incremental is True


def test_outcome_generation_rejects_tampered_assignment_freeze() -> None:
    protocol = build_protocol(_ROOT)
    freeze = build_assignment_freeze(protocol, _ROOT)
    first = freeze.assignments[0]
    changed_arm = (
        ExperimentArm.CONTROL
        if first.arm is ExperimentArm.TREATMENT
        else ExperimentArm.TREATMENT
    )
    tampered = freeze.model_copy(
        update={
            "assignments": (
                first.model_copy(update={"arm": changed_arm}),
                *freeze.assignments[1:],
            )
        }
    )

    with pytest.raises(ExperimentEvidenceError, match="assignment freeze"):
        build_outcome_batch(protocol, tampered)


def test_control_outcome_cannot_carry_intervention_cost() -> None:
    protocol = build_protocol(_ROOT)
    freeze = build_assignment_freeze(protocol, _ROOT)
    assignment = next(item for item in freeze.assignments if item.arm is ExperimentArm.CONTROL)

    with pytest.raises(ValidationError, match="holdout outcomes"):
        RecoveryOutcome(
            experiment_id=protocol.experiment_id,
            assignment_id=assignment.assignment_id,
            payment_id=assignment.payment_id,
            arm=ExperimentArm.CONTROL,
            eligible_at=assignment.eligible_at,
            observed_at=assignment.assigned_at,
            attribution_window_seconds=protocol.design.attribution_window_seconds,
            outcome_draw_sha256="a" * 64,
            recovered=False,
            amount_subunits=assignment.amount_subunits,
            recovered_gmv_subunits=0,
            currency=assignment.currency,
            action_cost_subunits=1,
            false_intervention=False,
            false_intervention_cost_subunits=0,
            synthetic=True,
        )


def test_committed_assignment_artifacts_match_the_deterministic_builders() -> None:
    assert freeze_stage(root=_ROOT, check=True) == ()
