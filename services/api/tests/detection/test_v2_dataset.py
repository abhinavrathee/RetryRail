"""Detector-v2 protocol, data isolation and blind-nonce regression tests."""

import json
from itertools import pairwise
from pathlib import Path

import pytest

from retryrail.synthetic.models import ScenarioKind
from retryrail.synthetic.v2_generator import (
    assemble_blind_dataset,
    build_blind_runtime,
    build_development_dataset,
    build_evaluation_protocol,
    check_v2_artifacts,
    generator_bundle_sha256,
    load_blind_truth,
)
from retryrail.synthetic.v2_models import V2DatasetRole, V2ScenarioFamily

_TEST_NONCE_ALPHA = "detector-v2-test-nonce-alpha"
_TEST_NONCE_BETA = "detector-v2-test-nonce-beta"
_RUNTIME_FORBIDDEN_LABELS = {
    "dataset_role",
    "expected_incident_member",
    "scenario_id",
    "split",
}


def test_development_dataset_is_reconciled_and_runtime_label_free() -> None:
    dataset = build_development_dataset()
    manifest = dataset.manifest

    assert manifest.dataset_role is V2DatasetRole.DEVELOPMENT
    assert manifest.payment_attempts == dataset.truth_artifact.records == 5_760
    assert manifest.normalized_events == dataset.event_artifact.records
    assert manifest.true_incident_count == 6
    assert manifest.hard_negative_count == 4
    assert len(manifest.scenarios) == 10
    assert all(item.actual_attempt_count > 0 for item in manifest.scenarios)
    assert all(
        item.actual_failure_count <= item.actual_attempt_count
        for item in manifest.scenarios
    )
    assert manifest.event_artifact.startswith("fixtures/generated/")
    assert manifest.truth_artifact.startswith("evals/generated/")
    first_event = json.loads(dataset.event_artifact.content.splitlines()[0])
    assert _RUNTIME_FORBIDDEN_LABELS.isdisjoint(first_event)


def test_blind_nonce_is_deterministic_but_changes_the_unseen_batch() -> None:
    first = build_blind_runtime(_TEST_NONCE_ALPHA, official=False)
    repeated = build_blind_runtime(_TEST_NONCE_ALPHA, official=False)
    different = build_blind_runtime(_TEST_NONCE_BETA, official=False)

    assert first.event_artifact.content == repeated.event_artifact.content
    assert first.seed_commitment_sha256 == repeated.seed_commitment_sha256
    assert first.event_artifact.sha256 != different.event_artifact.sha256
    assert first.seed_commitment_sha256 != different.seed_commitment_sha256
    assert _TEST_NONCE_ALPHA.encode() not in first.event_artifact.content
    first_event = json.loads(first.event_artifact.content.splitlines()[0])
    assert _RUNTIME_FORBIDDEN_LABELS.isdisjoint(first_event)


def test_blind_truth_is_loaded_separately_and_scenarios_are_precommitted() -> None:
    runtime = build_blind_runtime(_TEST_NONCE_ALPHA, official=False)
    truth = load_blind_truth(_TEST_NONCE_ALPHA, official=False)
    dataset = assemble_blind_dataset(runtime, truth)
    scenarios = dataset.manifest.scenarios

    assert dataset.manifest.dataset_role is V2DatasetRole.BLIND
    assert sum(item.kind is ScenarioKind.TRUE_INCIDENT for item in scenarios) == 6
    assert sum(item.kind is ScenarioKind.HARD_NEGATIVE for item in scenarios) == 4
    assert {
        family: sum(item.family is family for item in scenarios)
        for family in V2ScenarioFamily
    } == {
        V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION: 3,
        V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION: 3,
        V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE: 2,
        V2ScenarioFamily.LOW_VOLUME_SPIKE: 1,
        V2ScenarioFamily.TRANSIENT_PROVIDER_BURST: 1,
    }
    ordered = sorted(scenarios, key=lambda item: item.starts_at)
    assert all(
        left.ends_at <= right.starts_at for left, right in pairwise(ordered)
    )
    assert all(item.actual_attempt_count > 0 for item in scenarios)
    assert all(
        item.expected_root_cause.source == "customer"
        for item in scenarios
        if item.family is V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE
    )


def test_official_blind_nonce_rejects_short_and_known_test_values() -> None:
    with pytest.raises(ValueError, match="at least 16"):
        build_blind_runtime("too-short", official=True)
    with pytest.raises(ValueError, match="test nonces"):
        build_blind_runtime(_TEST_NONCE_ALPHA, official=True)


def test_protocol_and_committed_development_identity_are_current() -> None:
    protocol = build_evaluation_protocol()

    assert protocol.official_blind_nonce_after_candidate_freeze is True
    assert protocol.predictions_persisted_before_blind_labels_loaded is True
    assert protocol.configuration_change_requires_new_nonce is True
    assert protocol.official_blind_true_incidents == 6
    assert protocol.official_blind_hard_negatives == 4
    assert len(protocol.generator_bundle_sha256) == 64
    assert check_v2_artifacts() == []


def test_generator_bundle_identity_is_cross_platform_line_ending_safe(
    tmp_path: Path,
) -> None:
    source_root = Path(__file__).resolve().parents[4]
    relative_paths = (
        "services/api/app/retryrail/events/models.py",
        "services/api/app/retryrail/synthetic/models.py",
        "services/api/app/retryrail/synthetic/v2_models.py",
        "services/api/app/retryrail/synthetic/v2_generator.py",
    )
    for relative_path in relative_paths:
        source = (source_root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.replace(b"\n", b"\r\n"))

    assert generator_bundle_sha256(tmp_path) == generator_bundle_sha256(source_root)
