"""Deterministic truth-set, split-isolation and reliability contract tests."""

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from retryrail.contracts.domain import DatasetSplit
from retryrail.events.models import NormalizedPaymentEvent, PaymentEventType, PaymentStatus
from retryrail.synthetic.generator import build_dataset, check_dataset, main, write_dataset
from retryrail.synthetic.models import (
    AttemptGroundTruth,
    ExpectedDeliveryDisposition,
    ReliabilityCase,
    ScenarioKind,
    SyntheticDatasetManifest,
    WebhookDeliveryInstruction,
)


def _artifact_content(path_suffix: str) -> bytes:
    dataset = build_dataset()
    return next(
        artifact.content for artifact in dataset.artifacts if artifact.path.endswith(path_suffix)
    )


def _parse_events(path_suffix: str) -> tuple[NormalizedPaymentEvent, ...]:
    return tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in _artifact_content(path_suffix).splitlines()
    )


def _parse_truth(path_suffix: str) -> tuple[AttemptGroundTruth, ...]:
    return tuple(
        AttemptGroundTruth.model_validate_json(line)
        for line in _artifact_content(path_suffix).splitlines()
    )


def _parse_deliveries() -> tuple[WebhookDeliveryInstruction, ...]:
    return tuple(
        WebhookDeliveryInstruction.model_validate_json(line)
        for line in _artifact_content("webhook_deliveries.v1.jsonl").splitlines()
    )


def test_default_dataset_is_byte_deterministic_and_large_enough() -> None:
    first = build_dataset()
    second = build_dataset()

    assert first.manifest_content == second.manifest_content
    assert first.manifest_sha256 == second.manifest_sha256
    assert [artifact.content for artifact in first.artifacts] == [
        artifact.content for artifact in second.artifacts
    ]
    assert first.manifest.total_payment_attempts == 2_880
    assert first.manifest.total_normalized_events > first.manifest.total_payment_attempts
    assert first.manifest.synthetic is True


def test_tuning_and_heldout_partitions_are_physically_disjoint() -> None:
    tuning_events = _parse_events("tuning.normalized_events.v1.jsonl")
    heldout_events = _parse_events("heldout.normalized_events.v1.jsonl")
    tuning_truth = _parse_truth("tuning.attempt_truth.v1.jsonl")
    heldout_truth = _parse_truth("heldout.attempt_truth.v1.jsonl")

    assert len(tuning_truth) == len(heldout_truth) == 1_440
    assert {item.split for item in tuning_truth} == {DatasetSplit.TUNING}
    assert {item.split for item in heldout_truth} == {DatasetSplit.HELDOUT}
    assert {event.razorpay_event_id for event in tuning_events}.isdisjoint(
        event.razorpay_event_id for event in heldout_events
    )
    assert {item.payment_id for item in tuning_truth}.isdisjoint(
        item.payment_id for item in heldout_truth
    )

    serialized_events = b"".join(
        artifact
        for artifact in (
            _artifact_content("tuning.normalized_events.v1.jsonl"),
            _artifact_content("heldout.normalized_events.v1.jsonl"),
        )
    )
    for evaluation_only_field in (
        b"scenario_id",
        b"expected_incident_member",
        b"split",
        b"seeded_failure_rate_bps",
    ):
        assert evaluation_only_field not in serialized_events


def test_truth_manifest_contains_three_incidents_and_a_low_sample_hard_negative() -> None:
    scenarios = build_dataset().manifest.scenarios
    incidents = [scenario for scenario in scenarios if scenario.kind is ScenarioKind.TRUE_INCIDENT]
    hard_negatives = [
        scenario for scenario in scenarios if scenario.kind is ScenarioKind.HARD_NEGATIVE
    ]

    assert len(incidents) == 3
    assert len(hard_negatives) == 1
    assert all(scenario.should_open_incident for scenario in incidents)
    assert all(scenario.actual_attempt_count >= 20 for scenario in incidents)
    assert all(scenario.actual_failure_count > 0 for scenario in incidents)
    assert hard_negatives[0].should_open_incident is False
    assert hard_negatives[0].actual_attempt_count < 20
    assert hard_negatives[0].expected_gate_reason == "blocked_by_minimum_sample_gate"


def test_every_attempt_reconciles_to_unique_normalized_events() -> None:
    events = (*_parse_events("tuning.normalized_events.v1.jsonl"), *_parse_events(
        "heldout.normalized_events.v1.jsonl"
    ))
    truth = (*_parse_truth("tuning.attempt_truth.v1.jsonl"), *_parse_truth(
        "heldout.attempt_truth.v1.jsonl"
    ))
    event_by_id = {event.razorpay_event_id: event for event in events}

    assert len(event_by_id) == len(events)
    assert len({item.attempt_id for item in truth}) == len(truth)
    assert len({item.payment_id for item in truth}) == len(truth)
    for item in truth:
        linked_events = [event_by_id[event_id] for event_id in item.normalized_event_ids]
        assert {event.payment.payment_id for event in linked_events} == {item.payment_id}
        assert {event.payment.amount_subunits for event in linked_events} == {
            item.amount_subunits
        }
        if item.final_status is PaymentStatus.FAILED:
            assert [event.event_type for event in linked_events] == [PaymentEventType.FAILED]
        else:
            assert {event.event_type for event in linked_events} == {
                PaymentEventType.AUTHORIZED,
                PaymentEventType.CAPTURED,
            }


def test_delivery_schedule_encodes_security_duplicate_delay_and_ordering_cases() -> None:
    deliveries = _parse_deliveries()
    sequences = [delivery.sequence for delivery in deliveries]
    cases = Counter(
        delivery.reliability_case
        for delivery in deliveries
        if delivery.reliability_case is not None
    )

    assert sequences == list(range(1, len(deliveries) + 1))
    assert cases[ReliabilityCase.DUPLICATE] == 4
    assert cases[ReliabilityCase.DELAYED] == 1
    assert cases[ReliabilityCase.OUT_OF_ORDER] == 2
    assert cases[ReliabilityCase.INVALID_SIGNATURE] == 1
    assert cases[ReliabilityCase.MISSING_SIGNATURE] == 1
    assert cases[ReliabilityCase.MODIFIED_BODY] == 1

    duplicate_deliveries = [
        delivery
        for delivery in deliveries
        if delivery.reliability_case is ReliabilityCase.DUPLICATE
    ]
    assert len({delivery.razorpay_event_id for delivery in duplicate_deliveries}) == 1
    assert [delivery.delivery_attempt for delivery in duplicate_deliveries] == [1, 2, 3, 4]
    assert sum(
        delivery.expected_disposition is ExpectedDeliveryDisposition.DUPLICATE
        for delivery in duplicate_deliveries
    ) == 3

    rejected_security_cases = {
        delivery.reliability_case
        for delivery in deliveries
        if delivery.expected_disposition is ExpectedDeliveryDisposition.REJECTED_SIGNATURE
    }
    assert rejected_security_cases == {
        ReliabilityCase.INVALID_SIGNATURE,
        ReliabilityCase.MISSING_SIGNATURE,
        ReliabilityCase.MODIFIED_BODY,
    }

    events = {
        event.razorpay_event_id: event
        for event in (
            *_parse_events("tuning.normalized_events.v1.jsonl"),
            *_parse_events("heldout.normalized_events.v1.jsonl"),
        )
    }
    out_of_order = [
        delivery
        for delivery in deliveries
        if delivery.reliability_case is ReliabilityCase.OUT_OF_ORDER
    ]
    delivered_types = [events[delivery.razorpay_event_id].event_type for delivery in out_of_order]
    assert delivered_types == [PaymentEventType.CAPTURED, PaymentEventType.AUTHORIZED]

    delayed = next(
        delivery
        for delivery in deliveries
        if delivery.reliability_case is ReliabilityCase.DELAYED
    )
    assert delayed.delivered_at - events[delayed.razorpay_event_id].occurred_at >= timedelta(
        hours=2
    )


def test_artifact_digests_and_manifest_sidecar_are_exact(tmp_path: Path) -> None:
    dataset = write_dataset(tmp_path)

    assert check_dataset(tmp_path) == []
    for digest in dataset.manifest.artifacts:
        content = (tmp_path / digest.path).read_bytes()
        assert hashlib.sha256(content).hexdigest() == digest.sha256
        assert len(content) == digest.bytes
        assert len(content.splitlines()) == digest.records

    manifest_path = tmp_path / "fixtures/manifests/default.v1.json"
    manifest = SyntheticDatasetManifest.model_validate_json(manifest_path.read_bytes())
    assert manifest == dataset.manifest
    schema = json.loads(
        (
            Path(__file__).resolve().parents[4]
            / "contracts/domain/synthetic_dataset_manifest.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(json.loads(manifest_path.read_bytes()))
    digest_text = (tmp_path / "fixtures/manifests/default.v1.sha256").read_text()
    assert digest_text == f"{dataset.manifest_sha256}  default.v1.json\n"


def test_dataset_check_reports_missing_manifest_and_stale_generated_file(tmp_path: Path) -> None:
    dataset = write_dataset(tmp_path)
    artifact_path = tmp_path / dataset.artifacts[0].path
    artifact_path.write_bytes(b"stale\n")
    (tmp_path / "fixtures/manifests/default.v1.json").unlink()

    assert check_dataset(tmp_path) == [
        "missing fixtures/manifests/default.v1.json",
        f"stale {dataset.artifacts[0].path}",
    ]


def test_seed_cli_check_success_and_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_dataset(tmp_path)
    monkeypatch.setattr("sys.argv", ["retryrail-seed", "--check", "--output-root", str(tmp_path)])
    main()
    assert "synthetic dataset is current" in capsys.readouterr().out

    missing_root = tmp_path / "missing"
    monkeypatch.setattr(
        "sys.argv",
        ["retryrail-seed", "--check", "--output-root", str(missing_root)],
    )
    with pytest.raises(SystemExit):
        main()
    assert "missing fixtures/manifests/default.v1.json" in capsys.readouterr().err


def test_experiment_design_was_frozen_before_generated_observations() -> None:
    design = build_dataset().manifest.experiment_design

    assert design.frozen_at == datetime(2026, 8, 31, tzinfo=UTC)
    assert design.eligibility_frozen_before_assignment is True
    assert design.treatment_allocation_bps + design.control_allocation_bps == 10_000
    assert design.assignment_namespace != design.outcome_namespace
    assert design.treatment_recovery_rate_bps > design.control_recovery_rate_bps
    assert design.inconclusive_when_interval_crosses_zero is True


def test_committed_manifest_matches_generator() -> None:
    root = Path(__file__).resolve().parents[4]

    assert check_dataset(root) == []
    committed = (root / "fixtures/manifests/default.v1.json").read_bytes()
    assert json.loads(committed) == build_dataset().manifest.model_dump(
        mode="json",
        exclude_none=True,
    )


def test_dataset_documentation_tracks_committed_identity() -> None:
    root = Path(__file__).resolve().parents[4]
    dataset = build_dataset()
    documentation = (root / "docs/DATASET.md").read_text(encoding="utf-8")

    assert dataset.manifest_sha256 in documentation
    assert f"{dataset.manifest.total_payment_attempts:,}" in documentation
    assert f"{dataset.manifest.total_normalized_events:,}" in documentation
