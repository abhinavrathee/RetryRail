"""Precommit and verify the detector-v4 remediation protocol."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import CohortDimension, CohortPredicate, StrictContract
from retryrail.detection.v2_blind_models import V2BlindNonceReveal
from retryrail.detection.v3_blind_models import (
    V3BlindCompletionReceipt,
    V3BlindNonceReveal,
    V3BlindReleaseDecision,
    V3BlindReleaseStatus,
    V3BlindReleaseTarget,
)
from retryrail.detection.v3_blind_postrun import V3BlindPostRunAuditRecord
from retryrail.detection.v3_protocol import V3EvaluationProtocol
from retryrail.synthetic.models import ArtifactPath, Sha256Digest
from retryrail.synthetic.v2_generator import generator_bundle_sha256
from retryrail.synthetic.v2_models import V2ReleaseTargets

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_PROTOCOL_PATH = Path("evals/protocols/detector_v4.protocol.json")
_V3_PROTOCOL_PATH = Path("evals/protocols/detector_v3.protocol.json")
_V3_CANDIDATE_FREEZE_PATH = Path("evals/golden/detector_v3.freeze.json")
_V3_PROCEDURE_FREEZE_PATH = Path("evals/golden/detector_v3.blind_procedure.freeze.json")
_V2_DEVELOPMENT_MANIFEST_PATH = Path("fixtures/manifests/detector-v2-development.v1.json")
_V2_DEVELOPMENT_REPORT_PATH = Path("evals/reports/detector_v2.development.report.json")
_V2_RUN_ID = "detector_v2_official_blind_ef49a16703b1612ef774"
_V2_RUN_ROOT = Path("evals/blind/detector_v2/runs") / _V2_RUN_ID
_V3_RUN_ID = "detector_v3_official_blind_1a1852634945b54e300a"
_V3_RUN_ROOT = Path("evals/blind/detector_v3/runs") / _V3_RUN_ID
_V2_REVEAL_PATH = _V2_RUN_ROOT / "nonce.reveal.json"
_V3_REVEAL_PATH = _V3_RUN_ROOT / "nonce.reveal.json"
_V3_REPORT_PATH = _V3_RUN_ROOT / "blind.report.v1.json"
_V3_RELEASE_PATH = _V3_RUN_ROOT / "blind.release.v1.json"
_V3_COMPLETION_PATH = _V3_RUN_ROOT / "completion.receipt.json"
_V3_POSTRUN_PATH = _V3_RUN_ROOT / "postrun.audit.v1.json"
_DEFECT_INCIDENT_INDEX = 5
_TEST_NONCES = (
    "detector-v2-test-nonce-alpha",
    "detector-v2-test-nonce-beta",
    "detector-v3-test-nonce-alpha",
    "detector-v3-test-nonce-beta",
    "detector-v3-second-public-test-nonce",
)


class V4EvidenceArtifact(StrictContract):
    """One immutable artifact authorized as detector-v4 development evidence."""

    path: ArtifactPath
    sha256: Sha256Digest


class V4DevelopmentEvidence(StrictContract):
    """One complete, already-revealed partition permitted for v4 tuning."""

    evidence_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    origin: Literal[
        "prior_development",
        "revealed_blocked_blind",
        "revealed_blocked_invalid_blind",
    ]
    artifacts: tuple[V4EvidenceArtifact, ...] = Field(min_length=2, max_length=8)
    labels_authorized_for_development: Literal[True] = True
    eligible_as_future_blind_evidence: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_artifacts(self) -> Self:
        """Reject duplicate paths or identities within one evidence partition."""

        paths = tuple(item.path for item in self.artifacts)
        digests = tuple(item.sha256 for item in self.artifacts)
        if len(set(paths)) != len(paths):
            msg = "development evidence artifact paths must be unique"
            raise ValueError(msg)
        if len(set(digests)) != len(digests):
            msg = "development evidence artifact digests must be unique"
            raise ValueError(msg)
        return self


class V4HierarchyFailureAnalysis(StrictContract):
    """Reproducible diagnosis of the paired v3 false negative and false positive."""

    false_negative_scenario_id: Literal[
        "scenario_v2_blind_02_issuer_provider_degradation"
    ]
    false_positive_incident_id: Literal["inc_01ebb86d73b3f7d17df502a3"]
    expected_child_cohort: tuple[CohortPredicate, CohortPredicate]
    observed_parent_cohort: tuple[CohortPredicate]
    child_first_independent_pass_at: AwareDatetime
    child_last_independent_pass_at: AwareDatetime
    child_independent_passing_steps: Literal[9] = 9
    parent_candidate_started_at: AwareDatetime
    parent_candidate_suppressed_at: AwareDatetime
    parent_incident_opened_at: AwareDatetime
    parent_incident_confirmed_at: AwareDatetime
    v3_active_state_scope: Literal["payment_method"] = "payment_method"
    root_cause_class: Literal["parent_candidate_and_cooldown_starved_passing_child"] = (
        "parent_candidate_and_cooldown_starved_passing_child"
    )

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        """Keep the hierarchy and replay timeline exact and internally ordered."""

        expected_child_dimensions = (CohortDimension.METHOD, CohortDimension.ISSUER)
        if tuple(item.dimension for item in self.expected_child_cohort) != (
            expected_child_dimensions
        ):
            msg = "expected v3 miss must use the canonical method/issuer child cohort"
            raise ValueError(msg)
        if self.expected_child_cohort[:1] != self.observed_parent_cohort:
            msg = "observed parent cohort must be the expected child's direct parent"
            raise ValueError(msg)
        if not (
            self.child_first_independent_pass_at
            <= self.parent_candidate_started_at
            <= self.parent_candidate_suppressed_at
            < self.child_last_independent_pass_at
            < self.parent_incident_opened_at
            < self.parent_incident_confirmed_at
        ):
            msg = "v3 hierarchy failure trace timestamps changed"
            raise ValueError(msg)
        return self


class V4ObservedPredecessorFailure(StrictContract):
    """Exact blocked and invalid detector-v3 outcome that v4 must remediate."""

    status: Literal["blocked_invalid"] = "blocked_invalid"
    true_positives: Literal[5] = 5
    false_positives: Literal[1] = 1
    false_negatives: Literal[1] = 1
    precision_ppm: Literal[833333] = 833333
    recall_ppm: Literal[833333] = 833333
    failed_targets: tuple[Literal["precision"], Literal["recall"]]
    frozen_report_schema_valid: Literal[False] = False
    writer_defect_code: Literal["required_optional_field_omitted_by_canonical_writer"] = (
        "required_optional_field_omitted_by_canonical_writer"
    )
    writer_defect_path: Literal["incidents[5].resolved_at"] = "incidents[5].resolved_at"
    hierarchy: V4HierarchyFailureAnalysis


class V4CandidateConstraints(StrictContract):
    """Structural remediation boundaries fixed before v4 implementation or tuning."""

    detector_decides_degradation: Literal[True] = True
    runtime_truth_labels_forbidden: Literal[True] = True
    runtime_action_eligible_before_qualification: Literal[False] = False
    candidate_state_key_includes_canonical_cohort: Literal[True] = True
    parent_and_child_candidates_observed_independently: Literal[True] = True
    parent_state_and_cooldown_cannot_block_child: Literal[True] = True
    deterministic_label_free_scope_arbitration: Literal[True] = True
    at_most_one_incident_per_overlapping_method_episode: Literal[True] = True
    losing_candidates_receive_audit_disposition: Literal[True] = True
    matcher_semantics_must_not_be_relaxed: Literal[True] = True
    core_statistical_and_business_gates_preserved: Literal[True] = True
    core_gate_threshold_lowering_requires_new_protocol: Literal[True] = True
    guarded_frozen_baseline_preserved: Literal[True] = True
    baseline_and_current_windows_non_overlapping: Literal[True] = True
    development_partitions_must_pass_individually: Literal[True] = True
    hard_negative_confirmation_required: Literal[True] = True
    evidence_reconciliation_required: Literal[True] = True


class V4ReportContractConstraints(StrictContract):
    """Pre-nonce report serialization requirements learned from the v3 defect."""

    required_nullable_fields_are_emitted: Literal[True] = True
    open_incident_fixture_required: Literal[True] = True
    strict_model_reload_required: Literal[True] = True
    canonical_byte_round_trip_required: Literal[True] = True
    report_preflight_required_before_nonce: Literal[True] = True
    historical_v3_evidence_rewrite_forbidden: Literal[True] = True


class V4BlindProcedure(StrictContract):
    """Fail-closed rules for a future, separately frozen v4 official run."""

    official_nonce_required: Literal[True] = True
    nonce_minimum_characters: Literal[16] = 16
    nonce_maximum_characters: Literal[256] = 256
    nonce_is_public_and_non_secret: Literal[True] = True
    fresh_v4_nonce_created: Literal[False] = False
    fresh_v4_nonce_digest_present: Literal[False] = False
    fresh_v4_run_id_present: Literal[False] = False
    nonce_created_after_candidate_matcher_evaluator_runner_freeze: Literal[True] = True
    one_official_run_per_frozen_candidate: Literal[True] = True
    predictions_persisted_before_truth_access: Literal[True] = True
    prediction_bytes_reproduced_before_truth_access: Literal[True] = True
    append_only_evidence: Literal[True] = True
    any_post_nonce_failure_consumes_run_slot: Literal[True] = True
    configuration_or_contract_change_requires_new_nonce: Literal[True] = True
    consumed_and_test_nonce_sha256: tuple[Sha256Digest, ...] = Field(min_length=7)

    @model_validator(mode="after")
    def validate_forbidden_nonces(self) -> Self:
        """Make nonce-reuse rejection complete and unambiguous."""

        if len(set(self.consumed_and_test_nonce_sha256)) != len(
            self.consumed_and_test_nonce_sha256
        ):
            msg = "consumed and test nonce digests must be unique"
            raise ValueError(msg)
        return self


class V4EvaluationProtocol(StrictContract):
    """Machine-readable M3R.5 boundary established before detector-v4 code."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    protocol_id: Literal["detector_v4_protocol_v1"] = "detector_v4_protocol_v1"
    status: Literal["precommitted_before_candidate"] = "precommitted_before_candidate"
    precommitted_at: AwareDatetime
    predecessor_detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    predecessor_run_id: Literal["detector_v3_official_blind_1a1852634945b54e300a"]
    predecessor_protocol_sha256: Sha256Digest
    predecessor_candidate_freeze_sha256: Sha256Digest
    predecessor_procedure_freeze_sha256: Sha256Digest
    predecessor_release_sha256: Sha256Digest
    predecessor_postrun_audit_sha256: Sha256Digest
    benchmark_dataset_id: Literal["retryrail_detector_v2_blind_v1"] = (
        "retryrail_detector_v2_blind_v1"
    )
    benchmark_generator_version: Literal["detector_v2_generator_v1_0_0"] = (
        "detector_v2_generator_v1_0_0"
    )
    benchmark_generator_bundle_sha256: Sha256Digest
    benchmark_distribution_unchanged_after_failure: Literal[True] = True
    allowed_development_evidence: tuple[
        V4DevelopmentEvidence,
        V4DevelopmentEvidence,
        V4DevelopmentEvidence,
    ]
    observed_predecessor_failure: V4ObservedPredecessorFailure
    candidate_constraints: V4CandidateConstraints
    report_contract_constraints: V4ReportContractConstraints
    blind_procedure: V4BlindProcedure
    release_targets: V2ReleaseTargets
    rules: tuple[str, ...] = Field(min_length=15)

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        """Keep evidence roles, failed targets and remediation scope exact."""

        evidence_ids = tuple(item.evidence_id for item in self.allowed_development_evidence)
        if len(set(evidence_ids)) != len(evidence_ids):
            msg = "development evidence identifiers must be unique"
            raise ValueError(msg)
        origins = tuple(item.origin for item in self.allowed_development_evidence)
        if origins != (
            "prior_development",
            "revealed_blocked_blind",
            "revealed_blocked_invalid_blind",
        ):
            msg = "v4 requires exactly the three authorized revealed evidence roles"
            raise ValueError(msg)
        paths = tuple(
            artifact.path
            for partition in self.allowed_development_evidence
            for artifact in partition.artifacts
        )
        if len(set(paths)) != len(paths):
            msg = "development evidence paths must be globally unique"
            raise ValueError(msg)
        if self.observed_predecessor_failure.failed_targets != ("precision", "recall"):
            msg = "v4 must remediate both observed detector-v3 metric failures"
            raise ValueError(msg)
        return self


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reference(root: Path, relative_path: Path) -> V4EvidenceArtifact:
    return V4EvidenceArtifact(path=relative_path.as_posix(), sha256=_sha256(root / relative_path))


def _nonce_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _canonical_json(value: Any) -> bytes:
    payload = value.model_dump(mode="json") if isinstance(value, StrictContract) else value
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def _load_json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    content = path.read_bytes()
    value = json.loads(content)
    if not isinstance(value, dict) or content != _canonical_json(value):
        msg = f"predecessor evidence is not canonical JSON: {path.as_posix()}"
        raise ValueError(msg)
    return value, content


def _validate_predecessor_report(root: Path) -> None:
    report, _ = _load_json_object(root / _V3_REPORT_PATH)
    expected_summary = {
        "run_id": _V3_RUN_ID,
        "detector_version": "detector_v3_0_0",
        "true_positives": 5,
        "false_positives": 1,
        "false_negatives": 1,
        "precision_ppm": 833_333,
        "recall_ppm": 833_333,
        "release_qualified": False,
        "approved_for_m4_integration": False,
        "runtime_action_eligible": False,
    }
    if any(report.get(key) != value for key, value in expected_summary.items()):
        msg = "detector-v3 report summary changed from the accepted failure analysis"
        raise ValueError(msg)

    cases = report.get("cases")
    incidents = report.get("incidents")
    if not isinstance(cases, list) or not isinstance(incidents, list):
        msg = "detector-v3 report is missing cases or incidents"
        raise TypeError(msg)
    missed = next(
        (
            item
            for item in cases
            if isinstance(item, dict)
            and item.get("scenario_id")
            == "scenario_v2_blind_02_issuer_provider_degradation"
        ),
        None,
    )
    false_positive = next(
        (
            item
            for item in cases
            if isinstance(item, dict)
            and item.get("scenario_id") == "background_inc_01ebb86d73b3f7d17df502a3"
        ),
        None,
    )
    expected_child = [
        {"dimension": "method", "value": "netbanking"},
        {"dimension": "issuer", "value": "issuer_synthetic_gamma"},
    ]
    observed_parent = [{"dimension": "method", "value": "netbanking"}]
    if not isinstance(missed, dict) or any(
        (
            missed.get("expected_incident") is not True,
            missed.get("detected_incident") is not False,
            missed.get("expected_cohort") != expected_child,
            missed.get("gate_reason") != "blocked_by_minimum_actionable_failure_gate",
        )
    ):
        msg = "detector-v3 false-negative evidence changed"
        raise ValueError(msg)
    if not isinstance(false_positive, dict) or any(
        (
            false_positive.get("expected_incident") is not False,
            false_positive.get("detected_incident") is not True,
            false_positive.get("matched_incident_id") != "inc_01ebb86d73b3f7d17df502a3",
            false_positive.get("observed_cohort") != observed_parent,
        )
    ):
        msg = "detector-v3 false-positive evidence changed"
        raise ValueError(msg)
    if len(incidents) <= _DEFECT_INCIDENT_INDEX or not isinstance(
        incidents[_DEFECT_INCIDENT_INDEX], dict
    ):
        msg = "detector-v3 report no longer contains the recorded open incident"
        raise ValueError(msg)
    missing = tuple(
        f"incidents[{index}].resolved_at"
        for index, incident in enumerate(incidents)
        if isinstance(incident, dict) and "resolved_at" not in incident
    )
    if missing != ("incidents[5].resolved_at",):
        msg = "detector-v3 report defect changed from the accepted failure analysis"
        raise ValueError(msg)


def _v2_evidence(root: Path) -> tuple[V4DevelopmentEvidence, V4DevelopmentEvidence]:
    return (
        V4DevelopmentEvidence(
            evidence_id="detector_v2_development_v1",
            origin="prior_development",
            artifacts=(
                _reference(root, _V2_DEVELOPMENT_MANIFEST_PATH),
                _reference(root, _V2_DEVELOPMENT_REPORT_PATH),
            ),
        ),
        V4DevelopmentEvidence(
            evidence_id=_V2_RUN_ID,
            origin="revealed_blocked_blind",
            artifacts=tuple(
                _reference(root, _V2_RUN_ROOT / name)
                for name in (
                    "blind.dataset_manifest.v1.json",
                    "blind.predictions.v1.json",
                    "blind.report.v1.json",
                    "blind.release.v1.json",
                    "nonce.reveal.json",
                )
            ),
        ),
    )


def _v3_evidence(root: Path) -> V4DevelopmentEvidence:
    return V4DevelopmentEvidence(
        evidence_id=_V3_RUN_ID,
        origin="revealed_blocked_invalid_blind",
        artifacts=tuple(
            _reference(root, _V3_RUN_ROOT / name)
            for name in (
                "blind.dataset_manifest.v1.json",
                "blind.predictions.v1.json",
                "blind.report.v1.json",
                "blind.release.v1.json",
                "completion.receipt.json",
                "postrun.audit.v1.json",
                "nonce.reveal.json",
            )
        ),
    )


def build_v4_protocol(root: Path = _REPOSITORY_ROOT) -> V4EvaluationProtocol:
    """Build the canonical protocol from immutable v2 and v3 evidence."""

    v3_protocol = V3EvaluationProtocol.model_validate_json((root / _V3_PROTOCOL_PATH).read_bytes())
    v2_reveal = V2BlindNonceReveal.model_validate_json((root / _V2_REVEAL_PATH).read_bytes())
    v3_reveal = V3BlindNonceReveal.model_validate_json((root / _V3_REVEAL_PATH).read_bytes())
    release = V3BlindReleaseDecision.model_validate_json((root / _V3_RELEASE_PATH).read_bytes())
    completion = V3BlindCompletionReceipt.model_validate_json(
        (root / _V3_COMPLETION_PATH).read_bytes()
    )
    audit = V3BlindPostRunAuditRecord.model_validate_json((root / _V3_POSTRUN_PATH).read_bytes())
    if release.status is not V3BlindReleaseStatus.BLOCKED:
        msg = "detector-v4 remediation requires a blocked detector-v3 predecessor"
        raise ValueError(msg)
    if release.failed_targets != (
        V3BlindReleaseTarget.PRECISION,
        V3BlindReleaseTarget.RECALL,
    ):
        msg = "detector-v3 failed targets changed from the accepted analysis"
        raise ValueError(msg)
    if any(
        (
            completion.release_qualified,
            completion.approved_for_m4_integration,
            audit.release_qualified,
            audit.approved_for_m4_integration,
            audit.rerun_permitted,
        )
    ):
        msg = "detector-v3 blocked, consumed evidence boundary changed"
        raise ValueError(msg)
    if len({release.nonce_sha256, completion.nonce_sha256, v3_reveal.nonce_sha256}) != 1:
        msg = "detector-v3 nonce evidence does not reconcile"
        raise ValueError(msg)
    _validate_predecessor_report(root)
    current_generator_sha256 = generator_bundle_sha256(root)
    if current_generator_sha256 != v3_protocol.benchmark_generator_bundle_sha256:
        msg = "frozen benchmark generator no longer matches the v3 protocol"
        raise ValueError(msg)

    parent = CohortPredicate(dimension=CohortDimension.METHOD, value="netbanking")
    child = CohortPredicate(
        dimension=CohortDimension.ISSUER,
        value="issuer_synthetic_gamma",
    )
    prior_evidence = _v2_evidence(root)
    return V4EvaluationProtocol(
        precommitted_at=datetime(2026, 9, 3, 2, 30, tzinfo=UTC),
        predecessor_run_id=_V3_RUN_ID,
        predecessor_protocol_sha256=_sha256(root / _V3_PROTOCOL_PATH),
        predecessor_candidate_freeze_sha256=_sha256(root / _V3_CANDIDATE_FREEZE_PATH),
        predecessor_procedure_freeze_sha256=_sha256(root / _V3_PROCEDURE_FREEZE_PATH),
        predecessor_release_sha256=_sha256(root / _V3_RELEASE_PATH),
        predecessor_postrun_audit_sha256=_sha256(root / _V3_POSTRUN_PATH),
        benchmark_generator_bundle_sha256=current_generator_sha256,
        allowed_development_evidence=(*prior_evidence, _v3_evidence(root)),
        observed_predecessor_failure=V4ObservedPredecessorFailure(
            failed_targets=("precision", "recall"),
            hierarchy=V4HierarchyFailureAnalysis(
                false_negative_scenario_id=(
                    "scenario_v2_blind_02_issuer_provider_degradation"
                ),
                false_positive_incident_id="inc_01ebb86d73b3f7d17df502a3",
                expected_child_cohort=(parent, child),
                observed_parent_cohort=(parent,),
                child_first_independent_pass_at=datetime(2026, 10, 1, 8, 15, tzinfo=UTC),
                child_last_independent_pass_at=datetime(2026, 10, 1, 9, 10, tzinfo=UTC),
                parent_candidate_started_at=datetime(2026, 10, 1, 8, 15, tzinfo=UTC),
                parent_candidate_suppressed_at=datetime(2026, 10, 1, 8, 25, tzinfo=UTC),
                parent_incident_opened_at=datetime(2026, 10, 1, 10, 30, tzinfo=UTC),
                parent_incident_confirmed_at=datetime(2026, 10, 1, 11, 0, tzinfo=UTC),
            ),
        ),
        candidate_constraints=V4CandidateConstraints(),
        report_contract_constraints=V4ReportContractConstraints(),
        blind_procedure=V4BlindProcedure(
            consumed_and_test_nonce_sha256=(
                v2_reveal.nonce_sha256,
                v3_reveal.nonce_sha256,
                *(_nonce_sha256(value) for value in _TEST_NONCES),
            )
        ),
        release_targets=v3_protocol.release_targets,
        rules=(
            "Detector v2 and v3 source, configuration and evidence remain immutable.",
            "All three authorized partitions are revealed development evidence, never blind again.",
            "The benchmark generator and scenario distribution remain frozen after both failures.",
            "No partition, scenario or transaction outside the allowlist may influence v4 tuning.",
            "Runtime prediction cannot receive scenario labels, truth membership "
            "or an LLM decision.",
            "Parent and child cohorts are observed independently under canonical "
            "cohort state keys.",
            "A parent candidate, incident or cooldown cannot starve a passing child candidate.",
            "Scope arbitration is deterministic, label-free and emits at most one "
            "overlapping incident.",
            "Every non-selected passing candidate receives an explicit auditable disposition.",
            "Core sample, actionability, rate, confidence, excess, impact and "
            "confirmation gates remain.",
            "Matcher semantics cannot be relaxed to relabel a broad parent as an issuer match.",
            "Each development partition must independently pass every unchanged release target.",
            "Required nullable report fields are emitted and open reports round-trip byte exactly.",
            "Candidate, matcher, evaluator, contracts and runner freeze before nonce creation.",
            "Blind prediction bytes are durable and reproducible before truth access.",
            "Any post-nonce failure consumes that run slot and remains append-only and blocked.",
            "A fresh v4 nonce and run identity are absent from this pre-candidate artifact.",
            "M4 begins only from a qualified v4 decision and still requires deterministic policy.",
        ),
    )


def render_v4_protocol(root: Path = _REPOSITORY_ROOT) -> bytes:
    """Render the exact protocol bytes committed before candidate work."""

    return _canonical_json(build_v4_protocol(root))


def check_v4_protocol(root: Path = _REPOSITORY_ROOT) -> list[str]:
    """Return every missing or stale detector-v4 protocol finding."""

    path = root / _PROTOCOL_PATH
    if not path.is_file():
        return [f"missing {_PROTOCOL_PATH.as_posix()}"]
    if path.read_bytes() != render_v4_protocol(root):
        return [f"stale {_PROTOCOL_PATH.as_posix()}"]
    return []


def write_v4_protocol(root: Path = _REPOSITORY_ROOT) -> None:
    """Atomically write only the pre-candidate protocol artifact."""

    path = root / _PROTOCOL_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(render_v4_protocol(root))
    temporary.replace(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--print", action="store_true")
    return parser


def main() -> None:
    """Manage only the M3R.5 pre-candidate protocol boundary."""

    arguments = _parser().parse_args()
    if arguments.write:
        write_v4_protocol()
        sys.stdout.write("wrote detector-v4 pre-candidate protocol\n")
        return
    if arguments.check:
        findings = check_v4_protocol()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write(
            "detector-v4 protocol is current; no v4 candidate or nonce is part of it\n"
        )
        return
    sys.stdout.buffer.write(render_v4_protocol())


if __name__ == "__main__":  # pragma: no cover
    main()
