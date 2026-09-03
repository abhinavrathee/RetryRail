"""Detector-v4 remediation protocol and evidence-boundary tests."""

import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from retryrail.detection import v4_protocol
from retryrail.detection.v2_blind_models import V2BlindNonceReveal
from retryrail.detection.v3_blind_models import V3BlindNonceReveal
from retryrail.detection.v4_protocol import (
    V4BlindProcedure,
    V4CandidateConstraints,
    V4DevelopmentEvidence,
    V4EvaluationProtocol,
    V4HierarchyFailureAnalysis,
    V4ReportContractConstraints,
    build_v4_protocol,
    check_v4_protocol,
    render_v4_protocol,
)

_V2_REVEAL = Path(
    "evals/blind/detector_v2/runs/"
    "detector_v2_official_blind_ef49a16703b1612ef774/nonce.reveal.json"
)
_V3_RUN_ROOT = Path(
    "evals/blind/detector_v3/runs/"
    "detector_v3_official_blind_1a1852634945b54e300a"
)
_V3_REVEAL = _V3_RUN_ROOT / "nonce.reveal.json"
_V3_REPORT = _V3_RUN_ROOT / "blind.report.v1.json"
_V3_RELEASE = _V3_RUN_ROOT / "blind.release.v1.json"
_V3_COMPLETION = _V3_RUN_ROOT / "completion.receipt.json"
_TEST_NONCES = (
    "detector-v2-test-nonce-alpha",
    "detector-v2-test-nonce-beta",
    "detector-v3-test-nonce-alpha",
    "detector-v3-test-nonce-beta",
    "detector-v3-second-public-test-nonce",
)


def test_protocol_preserves_failure_targets_and_action_boundary() -> None:
    protocol = build_v4_protocol()
    failure = protocol.observed_predecessor_failure

    assert protocol.status == "precommitted_before_candidate"
    assert protocol.predecessor_detector_version == "detector_v3_0_0"
    assert failure.status == "blocked_invalid"
    assert failure.failed_targets == ("precision", "recall")
    assert (failure.true_positives, failure.false_positives, failure.false_negatives) == (
        5,
        1,
        1,
    )
    assert failure.precision_ppm == failure.recall_ppm == 833_333
    assert failure.writer_defect_path == "incidents[5].resolved_at"
    assert protocol.release_targets.precision_ppm == 900_000
    assert protocol.release_targets.recall_ppm == 850_000
    assert protocol.release_targets.top_1_attribution_ppm == 800_000
    assert protocol.release_targets.median_detection_delay_seconds == 600
    assert protocol.release_targets.hard_negative_action_eligible_incidents == 0
    assert protocol.release_targets.baseline_leakage_violations == 0
    assert protocol.release_targets.evidence_reconciliation_violations == 0
    assert protocol.candidate_constraints.runtime_action_eligible_before_qualification is False


def test_failure_trace_records_child_starvation_without_relaxing_matcher() -> None:
    protocol = build_v4_protocol()
    trace = protocol.observed_predecessor_failure.hierarchy
    constraints = protocol.candidate_constraints

    assert tuple((item.dimension.value, item.value) for item in trace.expected_child_cohort) == (
        ("method", "netbanking"),
        ("issuer", "issuer_synthetic_gamma"),
    )
    assert tuple((item.dimension.value, item.value) for item in trace.observed_parent_cohort) == (
        ("method", "netbanking"),
    )
    assert trace.child_independent_passing_steps == 9
    assert trace.v3_active_state_scope == "payment_method"
    assert trace.root_cause_class == "parent_candidate_and_cooldown_starved_passing_child"
    assert constraints.candidate_state_key_includes_canonical_cohort
    assert constraints.parent_and_child_candidates_observed_independently
    assert constraints.parent_state_and_cooldown_cannot_block_child
    assert constraints.deterministic_label_free_scope_arbitration
    assert constraints.at_most_one_incident_per_overlapping_method_episode
    assert constraints.losing_candidates_receive_audit_disposition
    assert constraints.matcher_semantics_must_not_be_relaxed
    assert constraints.core_gate_threshold_lowering_requires_new_protocol


@pytest.mark.parametrize(
    "mutation",
    ["child_shape", "different_parent", "timeline"],
)
def test_failure_trace_rejects_shape_parent_or_timeline_drift(mutation: str) -> None:
    content = build_v4_protocol().observed_predecessor_failure.hierarchy.model_dump(mode="json")
    if mutation == "child_shape":
        content["expected_child_cohort"][1]["dimension"] = "method"
        expected = "canonical method/issuer child cohort"
    elif mutation == "different_parent":
        content["observed_parent_cohort"][0]["value"] = "card"
        expected = "direct parent"
    else:
        content["parent_incident_opened_at"] = content["parent_candidate_started_at"]
        expected = "timestamps changed"

    with pytest.raises(ValidationError, match=expected):
        V4HierarchyFailureAnalysis.model_validate(content)


def test_only_three_revealed_partitions_are_approved_for_development() -> None:
    protocol = build_v4_protocol()
    evidence = protocol.allowed_development_evidence

    assert tuple(item.origin for item in evidence) == (
        "prior_development",
        "revealed_blocked_blind",
        "revealed_blocked_invalid_blind",
    )
    assert all(item.labels_authorized_for_development for item in evidence)
    assert all(not item.eligible_as_future_blind_evidence for item in evidence)
    assert all(item.synthetic for item in evidence)

    repository_root = Path(__file__).resolve().parents[4]
    for partition in evidence:
        for artifact in partition.artifacts:
            content = (repository_root / artifact.path).read_bytes()
            assert hashlib.sha256(content).hexdigest() == artifact.sha256


def test_fresh_v4_nonce_is_absent_and_every_known_nonce_digest_is_denied() -> None:
    repository_root = Path(__file__).resolve().parents[4]
    content = render_v4_protocol()
    protocol = V4EvaluationProtocol.model_validate_json(content)
    procedure = protocol.blind_procedure
    v2_reveal = V2BlindNonceReveal.model_validate_json(
        (repository_root / _V2_REVEAL).read_bytes()
    )
    v3_reveal = V3BlindNonceReveal.model_validate_json(
        (repository_root / _V3_REVEAL).read_bytes()
    )

    assert len(procedure.consumed_and_test_nonce_sha256) == 7
    assert v2_reveal.nonce_sha256 in procedure.consumed_and_test_nonce_sha256
    assert v3_reveal.nonce_sha256 in procedure.consumed_and_test_nonce_sha256
    assert v2_reveal.nonce.encode() not in content
    assert v3_reveal.nonce.encode() not in content
    assert all(value.encode() not in content for value in _TEST_NONCES)
    assert procedure.fresh_v4_nonce_created is False
    assert procedure.fresh_v4_nonce_digest_present is False
    assert procedure.fresh_v4_run_id_present is False
    assert procedure.nonce_created_after_candidate_matcher_evaluator_runner_freeze


def test_candidate_and_report_contract_constraints_fail_closed() -> None:
    candidate = V4CandidateConstraints()
    report = V4ReportContractConstraints()

    assert candidate.guarded_frozen_baseline_preserved
    assert candidate.development_partitions_must_pass_individually
    assert candidate.hard_negative_confirmation_required
    assert candidate.evidence_reconciliation_required
    assert report.required_nullable_fields_are_emitted
    assert report.open_incident_fixture_required
    assert report.strict_model_reload_required
    assert report.canonical_byte_round_trip_required
    assert report.report_preflight_required_before_nonce
    assert report.historical_v3_evidence_rewrite_forbidden

    with pytest.raises(ValidationError):
        V4CandidateConstraints(parent_state_and_cooldown_cannot_block_child=False)
    with pytest.raises(ValidationError):
        V4ReportContractConstraints(required_nullable_fields_are_emitted=False)


def test_nonce_digests_must_be_unique() -> None:
    procedure = build_v4_protocol().blind_procedure
    duplicate = procedure.model_dump(mode="json") | {
        "consumed_and_test_nonce_sha256": ["a" * 64] * 7
    }

    with pytest.raises(ValidationError, match="must be unique"):
        V4BlindProcedure.model_validate(duplicate)


@pytest.mark.parametrize("duplicate_field", ["path", "sha256"])
def test_development_evidence_rejects_duplicate_artifact_identity(
    duplicate_field: str,
) -> None:
    evidence = build_v4_protocol().allowed_development_evidence[0]
    content = evidence.model_dump(mode="json")
    content["artifacts"][1][duplicate_field] = content["artifacts"][0][duplicate_field]

    with pytest.raises(ValidationError, match="must be unique"):
        V4DevelopmentEvidence.model_validate(content)


@pytest.mark.parametrize("mode", ["duplicate_id", "wrong_roles", "duplicate_global_path"])
def test_protocol_rejects_ambiguous_development_partitions(mode: str) -> None:
    content = build_v4_protocol().model_dump(mode="json")
    if mode == "duplicate_id":
        content["allowed_development_evidence"][2]["evidence_id"] = content[
            "allowed_development_evidence"
        ][1]["evidence_id"]
        expected = "identifiers must be unique"
    elif mode == "wrong_roles":
        content["allowed_development_evidence"][2]["origin"] = "revealed_blocked_blind"
        expected = "three authorized revealed evidence roles"
    else:
        content["allowed_development_evidence"][2]["artifacts"][0]["path"] = content[
            "allowed_development_evidence"
        ][1]["artifacts"][0]["path"]
        expected = "paths must be globally unique"

    with pytest.raises(ValidationError, match=expected):
        V4EvaluationProtocol.model_validate(content)


def test_protocol_check_and_atomic_write_cover_missing_and_stale_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b'{"protocol":"synthetic"}\n'
    monkeypatch.setattr(v4_protocol, "render_v4_protocol", lambda _root: expected)

    assert check_v4_protocol(tmp_path) == ["missing evals/protocols/detector_v4.protocol.json"]
    target = tmp_path / "evals/protocols/detector_v4.protocol.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"stale\n")
    assert check_v4_protocol(tmp_path) == ["stale evals/protocols/detector_v4.protocol.json"]

    v4_protocol.write_v4_protocol(tmp_path)

    assert target.read_bytes() == expected
    assert not (target.parent / f".{target.name}.tmp").exists()


def test_committed_protocol_matches_canonical_predecessor_evidence() -> None:
    protocol_path = Path(__file__).resolve().parents[4] / (
        "evals/protocols/detector_v4.protocol.json"
    )

    assert check_v4_protocol() == []
    assert protocol_path.read_bytes() == render_v4_protocol()


def _canonical_json(value: object) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    )


def _copy_builder_inputs(root: Path) -> V4EvaluationProtocol:
    repository_root = Path(__file__).resolve().parents[4]
    protocol = build_v4_protocol()
    relative_paths = {
        Path("evals/protocols/detector_v3.protocol.json"),
        Path("evals/golden/detector_v3.freeze.json"),
        Path("evals/golden/detector_v3.blind_procedure.freeze.json"),
        *(
            Path(artifact.path)
            for partition in protocol.allowed_development_evidence
            for artifact in partition.artifacts
        ),
    }
    for relative in relative_paths:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repository_root / relative, target)
    return protocol


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("release_targets", "failed targets changed"),
        ("completion", "blocked, consumed evidence boundary changed"),
        ("nonce_chain", "nonce evidence does not reconcile"),
        ("report_summary", "report summary changed"),
        ("false_negative", "false-negative evidence changed"),
        ("false_positive", "false-positive evidence changed"),
        ("report_shape", "missing cases or incidents"),
        ("incident_shape", "recorded open incident"),
        ("writer_defect", "report defect changed"),
    ],
)
def test_builder_rejects_predecessor_evidence_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected: str,
) -> None:
    protocol = _copy_builder_inputs(tmp_path)
    monkeypatch.setattr(
        v4_protocol,
        "generator_bundle_sha256",
        lambda _root: protocol.benchmark_generator_bundle_sha256,
    )
    if mode == "release_targets":
        path = tmp_path / _V3_RELEASE
        value = json.loads(path.read_bytes())
        value["failed_targets"] = ["precision"]
    elif mode == "completion":
        path = tmp_path / _V3_COMPLETION
        value = json.loads(path.read_bytes())
        value["release_qualified"] = True
        value["approved_for_m4_integration"] = True
    elif mode == "nonce_chain":
        path = tmp_path / _V3_RELEASE
        value = json.loads(path.read_bytes())
        value["nonce_sha256"] = "0" * 64
    else:
        path = tmp_path / _V3_REPORT
        value = json.loads(path.read_bytes())
        if mode == "report_summary":
            value["precision_ppm"] = 833_334
        elif mode == "false_negative":
            value["cases"][1]["gate_reason"] = "blocked_by_confidence_gate"
        elif mode == "false_positive":
            value["cases"][-1]["matched_incident_id"] = "inc_" + "0" * 24
        elif mode == "report_shape":
            value["cases"] = "invalid"
        elif mode == "incident_shape":
            value["incidents"] = value["incidents"][:5]
        else:
            value["incidents"][5]["resolved_at"] = None
    path.write_text(_canonical_json(value), encoding="utf-8", newline="\n")

    with pytest.raises((TypeError, ValueError), match=expected):
        build_v4_protocol(tmp_path)


def test_builder_rejects_generator_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(v4_protocol, "generator_bundle_sha256", lambda _root: "0" * 64)

    with pytest.raises(ValueError, match="generator no longer matches"):
        build_v4_protocol()


def test_cli_check_write_print_and_failure_paths(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    written: list[bool] = []
    monkeypatch.setattr(v4_protocol, "write_v4_protocol", lambda: written.append(True))
    monkeypatch.setattr(sys, "argv", ["retryrail-v4-protocol", "--write"])
    v4_protocol.main()
    assert written == [True]
    assert "wrote detector-v4" in capfd.readouterr().out

    monkeypatch.setattr(v4_protocol, "check_v4_protocol", list)
    monkeypatch.setattr(sys, "argv", ["retryrail-v4-protocol", "--check"])
    v4_protocol.main()
    assert "no v4 candidate or nonce" in capfd.readouterr().out

    monkeypatch.setattr(v4_protocol, "render_v4_protocol", lambda: b"rendered\n")
    monkeypatch.setattr(sys, "argv", ["retryrail-v4-protocol", "--print"])
    v4_protocol.main()
    assert capfd.readouterr().out == "rendered\n"

    monkeypatch.setattr(v4_protocol, "check_v4_protocol", lambda: ["stale protocol"])
    monkeypatch.setattr(sys, "argv", ["retryrail-v4-protocol", "--check"])
    with pytest.raises(SystemExit, match="1"):
        v4_protocol.main()
    assert capfd.readouterr().err == "stale protocol\n"
