"""Precommit and verify the detector-v3 remediation protocol."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v2_blind_models import (
    V2BlindNonceReveal,
    V2BlindReleaseDecision,
    V2BlindReleaseStatus,
    V2BlindReleaseTarget,
)
from retryrail.synthetic.models import ArtifactPath, Sha256Digest
from retryrail.synthetic.v2_generator import generator_bundle_sha256
from retryrail.synthetic.v2_models import V2EvaluationProtocol, V2ReleaseTargets

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_PROTOCOL_PATH = Path("evals/protocols/detector_v3.protocol.json")
_V2_PROTOCOL_PATH = Path("evals/protocols/detector_v2.protocol.json")
_V2_DEVELOPMENT_MANIFEST_PATH = Path("fixtures/manifests/detector-v2-development.v1.json")
_V2_DEVELOPMENT_REPORT_PATH = Path("evals/reports/detector_v2.development.report.json")
_PREDECESSOR_RUN_ID = "detector_v2_official_blind_ef49a16703b1612ef774"
_PREDECESSOR_RUN_ROOT = Path("evals/blind/detector_v2/runs") / _PREDECESSOR_RUN_ID
_PREDECESSOR_MANIFEST_PATH = _PREDECESSOR_RUN_ROOT / "blind.dataset_manifest.v1.json"
_PREDECESSOR_PREDICTION_PATH = _PREDECESSOR_RUN_ROOT / "blind.predictions.v1.json"
_PREDECESSOR_REPORT_PATH = _PREDECESSOR_RUN_ROOT / "blind.report.v1.json"
_PREDECESSOR_RELEASE_PATH = _PREDECESSOR_RUN_ROOT / "blind.release.v1.json"
_PREDECESSOR_REVEAL_PATH = _PREDECESSOR_RUN_ROOT / "nonce.reveal.json"
_TEST_NONCES = (
    "detector-v2-test-nonce-alpha",
    "detector-v2-test-nonce-beta",
    "detector-v3-test-nonce-alpha",
    "detector-v3-test-nonce-beta",
)


class V3EvidenceArtifact(StrictContract):
    """One immutable artifact authorized as detector-v3 development evidence."""

    path: ArtifactPath
    sha256: Sha256Digest


class V3DevelopmentEvidence(StrictContract):
    """One complete, already-revealed partition permitted for v3 tuning."""

    evidence_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    origin: Literal["prior_development", "revealed_blocked_blind"]
    artifacts: tuple[V3EvidenceArtifact, ...] = Field(min_length=2, max_length=6)
    labels_authorized_for_development: Literal[True] = True
    eligible_as_future_blind_evidence: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_artifacts(self) -> Self:
        """Reject duplicate paths or identities within a development partition."""

        paths = tuple(item.path for item in self.artifacts)
        digests = tuple(item.sha256 for item in self.artifacts)
        if len(set(paths)) != len(paths):
            msg = "development evidence artifact paths must be unique"
            raise ValueError(msg)
        if len(set(digests)) != len(digests):
            msg = "development evidence artifact digests must be unique"
            raise ValueError(msg)
        return self


class V3CandidateConstraints(StrictContract):
    """Structural remediation boundaries fixed before v3 candidate tuning."""

    detector_decides_degradation: Literal[True] = True
    runtime_truth_labels_forbidden: Literal[True] = True
    runtime_action_eligible_before_qualification: Literal[False] = False
    baseline_guard_is_candidate_configuration: Literal[True] = True
    baseline_guard_covers_maximum_current_window: Literal[True] = True
    baseline_frozen_after_first_signal: Literal[True] = True
    baseline_and_current_windows_non_overlapping: Literal[True] = True
    first_signal_and_confirmation_timestamps_separate: Literal[True] = True
    development_partitions_must_pass_individually: Literal[True] = True
    hard_negative_confirmation_required: Literal[True] = True
    evidence_reconciliation_required: Literal[True] = True


class V3BlindProcedure(StrictContract):
    """Fail-closed rules for the future detector-v3 official blind run."""

    official_nonce_required: Literal[True] = True
    nonce_minimum_characters: Literal[16] = 16
    nonce_maximum_characters: Literal[256] = 256
    nonce_is_public_and_non_secret: Literal[True] = True
    nonce_created_after_candidate_and_runner_freeze: Literal[True] = True
    one_official_run_per_frozen_candidate: Literal[True] = True
    predictions_persisted_before_truth_access: Literal[True] = True
    prediction_bytes_reproduced_before_truth_access: Literal[True] = True
    append_only_evidence: Literal[True] = True
    configuration_change_requires_new_nonce: Literal[True] = True
    prior_and_test_nonce_sha256: tuple[Sha256Digest, ...] = Field(min_length=5)

    @model_validator(mode="after")
    def validate_forbidden_nonces(self) -> Self:
        """Make nonce reuse detection unambiguous."""

        if len(set(self.prior_and_test_nonce_sha256)) != len(self.prior_and_test_nonce_sha256):
            msg = "prior and test nonce digests must be unique"
            raise ValueError(msg)
        return self


class V3EvaluationProtocol(StrictContract):
    """Machine-readable M3R.4 process contract established before v3 code."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    status: Literal["precommitted_before_candidate"] = "precommitted_before_candidate"
    precommitted_at: AwareDatetime
    predecessor_detector_version: Literal["detector_v2_0_0"] = "detector_v2_0_0"
    predecessor_run_id: Literal["detector_v2_official_blind_ef49a16703b1612ef774"]
    predecessor_release_sha256: Sha256Digest
    predecessor_failed_targets: tuple[
        Literal["median_detection_delay"], Literal["baseline_leakage"]
    ]
    benchmark_dataset_id: Literal["retryrail_detector_v2_blind_v1"] = (
        "retryrail_detector_v2_blind_v1"
    )
    benchmark_generator_version: Literal["detector_v2_generator_v1_0_0"] = (
        "detector_v2_generator_v1_0_0"
    )
    benchmark_generator_bundle_sha256: Sha256Digest
    benchmark_distribution_unchanged_after_failure: Literal[True] = True
    allowed_development_evidence: tuple[V3DevelopmentEvidence, V3DevelopmentEvidence]
    candidate_constraints: V3CandidateConstraints
    blind_procedure: V3BlindProcedure
    release_targets: V2ReleaseTargets
    rules: tuple[str, ...] = Field(min_length=10)

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        """Keep predecessor facts, evidence roles and blind boundaries exact."""

        if self.predecessor_failed_targets != (
            "median_detection_delay",
            "baseline_leakage",
        ):
            msg = "v3 must remediate both observed v2 release failures"
            raise ValueError(msg)
        evidence_ids = tuple(item.evidence_id for item in self.allowed_development_evidence)
        if len(set(evidence_ids)) != len(evidence_ids):
            msg = "development evidence identifiers must be unique"
            raise ValueError(msg)
        origins = {item.origin for item in self.allowed_development_evidence}
        if origins != {"prior_development", "revealed_blocked_blind"}:
            msg = "v3 requires prior development and revealed blocked evidence"
            raise ValueError(msg)
        return self


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reference(root: Path, relative_path: Path) -> V3EvidenceArtifact:
    return V3EvidenceArtifact(
        path=relative_path.as_posix(),
        sha256=_sha256(root / relative_path),
    )


def _nonce_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def build_v3_protocol(root: Path = _REPOSITORY_ROOT) -> V3EvaluationProtocol:
    """Build the canonical protocol from immutable predecessor evidence."""

    v2_protocol = V2EvaluationProtocol.model_validate_json((root / _V2_PROTOCOL_PATH).read_bytes())
    predecessor_release = V2BlindReleaseDecision.model_validate_json(
        (root / _PREDECESSOR_RELEASE_PATH).read_bytes()
    )
    predecessor_reveal = V2BlindNonceReveal.model_validate_json(
        (root / _PREDECESSOR_REVEAL_PATH).read_bytes()
    )
    if predecessor_release.status is not V2BlindReleaseStatus.BLOCKED:
        msg = "detector-v3 remediation requires a blocked predecessor release"
        raise ValueError(msg)
    expected_failures = (
        V2BlindReleaseTarget.MEDIAN_DETECTION_DELAY,
        V2BlindReleaseTarget.BASELINE_LEAKAGE,
    )
    if predecessor_release.failed_targets != expected_failures:
        msg = "predecessor release failures changed from the accepted analysis"
        raise ValueError(msg)
    if predecessor_release.nonce_sha256 != predecessor_reveal.nonce_sha256:
        msg = "predecessor release and nonce reveal do not reconcile"
        raise ValueError(msg)
    current_generator_sha256 = generator_bundle_sha256(root)
    if current_generator_sha256 != v2_protocol.generator_bundle_sha256:
        msg = "frozen benchmark generator no longer matches its v2 protocol"
        raise ValueError(msg)

    return V3EvaluationProtocol(
        precommitted_at=datetime(2026, 9, 1, 17, 15, tzinfo=UTC),
        predecessor_run_id=_PREDECESSOR_RUN_ID,
        predecessor_release_sha256=_sha256(root / _PREDECESSOR_RELEASE_PATH),
        predecessor_failed_targets=(
            "median_detection_delay",
            "baseline_leakage",
        ),
        benchmark_generator_bundle_sha256=current_generator_sha256,
        allowed_development_evidence=(
            V3DevelopmentEvidence(
                evidence_id="detector_v2_development_v1",
                origin="prior_development",
                artifacts=(
                    _reference(root, _V2_DEVELOPMENT_MANIFEST_PATH),
                    _reference(root, _V2_DEVELOPMENT_REPORT_PATH),
                ),
            ),
            V3DevelopmentEvidence(
                evidence_id=_PREDECESSOR_RUN_ID,
                origin="revealed_blocked_blind",
                artifacts=(
                    _reference(root, _PREDECESSOR_MANIFEST_PATH),
                    _reference(root, _PREDECESSOR_PREDICTION_PATH),
                    _reference(root, _PREDECESSOR_REPORT_PATH),
                    _reference(root, _PREDECESSOR_RELEASE_PATH),
                    _reference(root, _PREDECESSOR_REVEAL_PATH),
                ),
            ),
        ),
        candidate_constraints=V3CandidateConstraints(),
        blind_procedure=V3BlindProcedure(
            prior_and_test_nonce_sha256=(
                predecessor_reveal.nonce_sha256,
                *(_nonce_sha256(value) for value in _TEST_NONCES),
            )
        ),
        release_targets=V2ReleaseTargets(),
        rules=(
            "Detector v2 source, configuration and failed evidence remain immutable.",
            "The revealed v2 official run is development evidence and is never blind again.",
            "The benchmark generator and scenario distribution remain frozen after failure.",
            "Only the two identified development partitions may influence v3 tuning.",
            "Runtime prediction code cannot receive scenario labels or truth membership.",
            "A guarded pre-incident baseline is frozen after the first passing signal.",
            "Development targets must pass separately on both permitted partitions.",
            "The candidate, matcher, evaluator and runner freeze before nonce creation.",
            "Blind prediction bytes are durable and reproducible before truth access.",
            "No threshold, algorithm or matching change is allowed after nonce creation.",
            "Any failed v3 result remains append-only and globally action-ineligible.",
            "M4 begins only from a qualified v3 release decision and still requires policy.",
        ),
    )


def _canonical_json(value: StrictContract) -> bytes:
    return (
        json.dumps(
            value.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def render_v3_protocol(root: Path = _REPOSITORY_ROOT) -> bytes:
    """Render the exact protocol bytes committed before candidate work."""

    return _canonical_json(build_v3_protocol(root))


def check_v3_protocol(root: Path = _REPOSITORY_ROOT) -> list[str]:
    """Return every missing or stale detector-v3 protocol finding."""

    path = root / _PROTOCOL_PATH
    if not path.is_file():
        return [f"missing {_PROTOCOL_PATH.as_posix()}"]
    if path.read_bytes() != render_v3_protocol(root):
        return [f"stale {_PROTOCOL_PATH.as_posix()}"]
    return []


def write_v3_protocol(root: Path = _REPOSITORY_ROOT) -> None:
    """Atomically write only the pre-candidate protocol artifact."""

    path = root / _PROTOCOL_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(render_v3_protocol(root))
    temporary.replace(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--print", action="store_true")
    return parser


def main() -> None:
    """Manage only the M3R.4 pre-candidate protocol boundary."""

    arguments = _parser().parse_args()
    if arguments.write:
        write_v3_protocol()
        sys.stdout.write("wrote detector-v3 pre-candidate protocol\n")
        return
    if arguments.check:
        findings = check_v3_protocol()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write(
            "detector-v3 protocol is current; candidate and blind nonce remain unfrozen\n"
        )
        return
    sys.stdout.buffer.write(render_v3_protocol())


if __name__ == "__main__":  # pragma: no cover
    main()
