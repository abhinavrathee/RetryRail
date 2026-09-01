"""Detector-v3 development evaluation across both precommitted partitions."""

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v2_blind_models import V2BlindNonceReveal
from retryrail.detection.v2_evaluation import (
    V2DevelopmentReport,
    V2EvaluationCase,
    V2IncidentEvaluationSummary,
    V2PredictionArtifact,
    V2PredictionBuild,
    V2TargetResults,
    score_predictions,
)
from retryrail.detection.v2_models import V2DetectorRunResult
from retryrail.detection.v3_config import (
    detector_v3_config_sha256,
    load_detector_v3_config,
)
from retryrail.detection.v3_engine import DetectorV3Engine
from retryrail.detection.v3_models import DetectorV3Config
from retryrail.detection.v3_protocol import (
    V3EvaluationProtocol,
    check_v3_protocol,
)
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.synthetic.v2_generator import (
    GeneratedV2Artifact,
    GeneratedV2Dataset,
    build_blind_runtime,
    build_development_dataset,
    load_blind_truth,
)
from retryrail.synthetic.v2_models import (
    V2DatasetManifest,
    V2DatasetRole,
    V2ScenarioDefinition,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_PROTOCOL_PATH = _REPOSITORY_ROOT / "evals/protocols/detector_v3.protocol.json"
_PREDECESSOR_RUN_ID = "detector_v2_official_blind_ef49a16703b1612ef774"
_PREDECESSOR_RUN_ROOT = _REPOSITORY_ROOT / "evals/blind/detector_v2/runs" / _PREDECESSOR_RUN_ID
_PREDECESSOR_MANIFEST_PATH = _PREDECESSOR_RUN_ROOT / "blind.dataset_manifest.v1.json"
_PREDECESSOR_REVEAL_PATH = _PREDECESSOR_RUN_ROOT / "nonce.reveal.json"
_SUITE_REPORT_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v3.development.json"
_CANDIDATE_SOURCE_PATHS = (
    "services/api/app/retryrail/contracts/domain.py",
    "services/api/app/retryrail/detection/engine.py",
    "services/api/app/retryrail/detection/models.py",
    "services/api/app/retryrail/detection/v2_engine.py",
    "services/api/app/retryrail/detection/v2_evaluation.py",
    "services/api/app/retryrail/detection/v2_models.py",
    "services/api/app/retryrail/detection/v3_adversarial.py",
    "services/api/app/retryrail/detection/v3_config.py",
    "services/api/app/retryrail/detection/v3_engine.py",
    "services/api/app/retryrail/detection/v3_evaluation.py",
    "services/api/app/retryrail/detection/v3_models.py",
    "services/api/app/retryrail/events/models.py",
)


class V3DevelopmentOrigin(StrEnum):
    """Where one permitted detector-v3 development partition came from."""

    PRIOR_DEVELOPMENT = "prior_development"
    REVEALED_BLOCKED_BLIND = "revealed_blocked_blind"


class V3PredictionArtifact(V2PredictionArtifact):
    """Label-free v3 output with explicit historical-development provenance."""

    schema_version: Literal["3.0.0"] = "3.0.0"  # type: ignore[assignment]
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    development_evidence_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    development_origin: V3DevelopmentOrigin
    dataset_role: Literal[V2DatasetRole.DEVELOPMENT] = V2DatasetRole.DEVELOPMENT
    source_dataset_role: V2DatasetRole
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = "detector_v2_matcher_v1_0_0"


class V3DevelopmentMetrics(StrictContract):
    """Complete unchanged target score for one approved development partition."""

    payment_attempts: int = Field(gt=0)
    raw_normalized_events: int = Field(gt=0)
    predicted_incidents: int = Field(ge=0)
    suppressed_candidates: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision_ppm: int = Field(ge=0, le=1_000_000)
    recall_ppm: int = Field(ge=0, le=1_000_000)
    top_1_attribution_ppm: int = Field(ge=0, le=1_000_000)
    top_3_attribution_ppm: int = Field(ge=0, le=1_000_000)
    median_detection_delay_seconds: int | None = Field(default=None, ge=0)
    maximum_detection_delay_seconds: int | None = Field(default=None, ge=0)
    median_confirmation_delay_seconds: int | None = Field(default=None, ge=0)
    maximum_confirmation_delay_seconds: int | None = Field(default=None, ge=0)
    hard_negative_action_eligible_incidents: int = Field(ge=0)
    baseline_leakage_violations: int = Field(ge=0)
    evidence_reconciliation_violations: int = Field(ge=0)
    development_targets_passed: bool
    targets: V2TargetResults
    cases: tuple[V2EvaluationCase, ...] = Field(min_length=1)
    incidents: tuple[V2IncidentEvaluationSummary, ...]

    @model_validator(mode="after")
    def validate_targets(self) -> Self:
        """Prevent a partition summary from disagreeing with target flags."""

        if self.development_targets_passed is not self.targets.all_passed:
            msg = "development target summary must equal all target comparisons"
            raise ValueError(msg)
        return self


class V3DevelopmentPartitionReport(StrictContract):
    """Development-only v3 report that cannot qualify runtime activation."""

    schema_version: Literal["3.0.0"] = "3.0.0"
    report_id: str = Field(pattern=r"^detector_v3_development_[A-Za-z0-9_-]+$")
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = "detector_v2_matcher_v1_0_0"
    development_evidence_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    development_origin: V3DevelopmentOrigin
    source_dataset_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    source_dataset_role: V2DatasetRole
    source_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    truth_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    prediction_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evaluated_at: AwareDatetime
    labels_loaded_after_prediction_bytes: Literal[True] = True
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True
    metrics: V3DevelopmentMetrics
    limitations: tuple[str, ...] = Field(min_length=4)


class V3DevelopmentPartitionSummary(StrictContract):
    """Digest-bound partition result included in the suite decision."""

    development_evidence_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    development_origin: V3DevelopmentOrigin
    prediction_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    report_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    development_targets_passed: bool
    precision_ppm: int = Field(ge=0, le=1_000_000)
    recall_ppm: int = Field(ge=0, le=1_000_000)
    top_1_attribution_ppm: int = Field(ge=0, le=1_000_000)
    median_detection_delay_seconds: int | None = Field(default=None, ge=0)
    baseline_leakage_violations: int = Field(ge=0)
    evidence_reconciliation_violations: int = Field(ge=0)


class V3DevelopmentSuiteReport(StrictContract):
    """Fail-closed R4.2 decision across every approved development partition."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    report_id: Literal["detector_v3_development_suite_v1"] = "detector_v3_development_suite_v1"
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    protocol_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = "detector_v2_matcher_v1_0_0"
    evaluated_at: AwareDatetime
    partitions: tuple[V3DevelopmentPartitionSummary, V3DevelopmentPartitionSummary]
    all_development_partitions_passed: bool
    candidate_ready_for_adversarial_freeze: bool
    candidate_frozen: Literal[False] = False
    official_blind_nonce_sha256: None = None
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_suite(self) -> Self:
        """Require both unique precommitted partitions before advancing."""

        evidence_ids = tuple(item.development_evidence_id for item in self.partitions)
        if evidence_ids != (
            "detector_v2_development_v1",
            _PREDECESSOR_RUN_ID,
        ):
            msg = "development suite partitions must use canonical evidence order"
            raise ValueError(msg)
        passed = all(item.development_targets_passed for item in self.partitions)
        if self.all_development_partitions_passed is not passed:
            msg = "development suite pass flag must equal every partition result"
            raise ValueError(msg)
        if self.candidate_ready_for_adversarial_freeze is not passed:
            msg = "adversarial-freeze readiness must equal the suite result"
            raise ValueError(msg)
        return self


class V3DevelopmentTargetError(RuntimeError):
    """The candidate cannot advance because one development partition failed."""


class V3EvidenceDriftReason(StrEnum):
    """Stable reasons for fail-closed development evidence rejection."""

    PROTOCOL_STALE = "detector-v3 protocol is missing or stale"
    PROTOCOL_IDENTITY = "detector-v3 protocol identities do not reconcile"
    DEVELOPMENT_IDENTITY = "detector-v3 development evidence changed"
    REVEALED_MANIFEST = "revealed development manifest changed"
    REVEALED_RUNTIME = "revealed runtime does not reproduce its manifest"
    REVEALED_TRUTH = "revealed truth does not reproduce its manifest"


class V3EvidenceDriftError(RuntimeError):
    """A precommitted development or protocol identity no longer matches."""

    def __init__(
        self,
        reason: V3EvidenceDriftReason,
        *,
        detail: str | None = None,
    ) -> None:
        self.reason = reason
        self.detail = detail
        message = reason.value if detail is None else f"{reason.value}: {detail}"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class V3PredictionBuild:
    """Prediction bytes and label-free internal run retained before scoring."""

    artifact: V3PredictionArtifact
    content: bytes
    sha256: str
    run: V2DetectorRunResult


@dataclass(frozen=True, slots=True)
class _DevelopmentRuntime:
    evidence_id: str
    origin: V3DevelopmentOrigin
    source_dataset_id: str
    source_dataset_role: V2DatasetRole
    source_manifest_sha256: str
    seed_commitment_sha256: str
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    event_artifact: GeneratedV2Artifact


@dataclass(frozen=True, slots=True)
class _DevelopmentTruth:
    normalized_events: int
    scenarios: tuple[V2ScenarioDefinition, ...]
    truth_artifact_sha256: str


def candidate_bundle_sha256(root: Path = _REPOSITORY_ROOT) -> str:
    """Bind inherited evidence semantics plus every detector-v3 source."""

    digest = hashlib.sha256()
    for relative_path in _CANDIDATE_SOURCE_PATHS:
        digest.update(relative_path.encode())
        digest.update(b"\0")
        source = (root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        digest.update(source)
        digest.update(b"\0")
    return digest.hexdigest()


def candidate_source_paths() -> tuple[str, ...]:
    """Return the ordered source identities consumed by the candidate bundle."""

    return _CANDIDATE_SOURCE_PATHS


def predict_runtime(
    runtime: _DevelopmentRuntime,
    *,
    config: DetectorV3Config | None = None,
) -> V3PredictionBuild:
    """Create canonical v3 predictions without accepting any truth argument."""

    selected_config = config or load_detector_v3_config()
    events = tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in runtime.event_artifact.content.splitlines()
    )
    run = DetectorV3Engine(selected_config).run(
        events,
        partition_started_at=runtime.starts_at,
        partition_ended_at=runtime.ends_at,
    )
    artifact = V3PredictionArtifact(
        prediction_id=f"prediction_development_{selected_config.detector_version}_{runtime.origin.value}",
        detector_version=selected_config.detector_version,
        detector_config_sha256=detector_v3_config_sha256(),
        candidate_bundle_sha256=candidate_bundle_sha256(),
        development_evidence_id=runtime.evidence_id,
        development_origin=runtime.origin,
        source_dataset_role=runtime.source_dataset_role,
        dataset_id=runtime.source_dataset_id,
        seed_commitment_sha256=runtime.seed_commitment_sha256,
        event_artifact_sha256=runtime.event_artifact.sha256,
        event_records=runtime.event_artifact.records,
        partition_started_at=runtime.starts_at,
        partition_ended_at=runtime.ends_at,
        predicted_at=runtime.ends_at + timedelta(minutes=5),
        incidents=run.incidents,
        suppressed_candidates=run.suppressed_candidates,
    )
    content = _canonical_json(artifact)
    return V3PredictionBuild(
        artifact=artifact,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        run=run,
    )


def score_prediction(
    prediction: V3PredictionBuild,
    runtime: _DevelopmentRuntime,
    truth: _DevelopmentTruth,
    *,
    config: DetectorV3Config | None = None,
) -> V3DevelopmentPartitionReport:
    """Score only after the caller has materialized canonical prediction bytes."""

    selected_config = config or load_detector_v3_config()
    reference = score_predictions(
        V2PredictionBuild(
            artifact=prediction.artifact,
            content=prediction.content,
            sha256=prediction.sha256,
            run=prediction.run,
        ),
        scenarios=truth.scenarios,
        dataset_manifest_sha256=runtime.source_manifest_sha256,
        truth_artifact_sha256=truth.truth_artifact_sha256,
        normalized_events=truth.normalized_events,
        config=selected_config,
    )
    metrics = _development_metrics(reference)
    return V3DevelopmentPartitionReport(
        report_id=f"detector_v3_development_{runtime.origin.value}",
        detector_config_sha256=prediction.artifact.detector_config_sha256,
        candidate_bundle_sha256=prediction.artifact.candidate_bundle_sha256,
        development_evidence_id=runtime.evidence_id,
        development_origin=runtime.origin,
        source_dataset_id=runtime.source_dataset_id,
        source_dataset_role=runtime.source_dataset_role,
        source_manifest_sha256=runtime.source_manifest_sha256,
        event_artifact_sha256=prediction.artifact.event_artifact_sha256,
        truth_artifact_sha256=truth.truth_artifact_sha256,
        prediction_artifact_sha256=prediction.sha256,
        evaluated_at=reference.evaluated_at,
        metrics=metrics,
        limitations=(
            "This is synthetic development evidence, not production performance.",
            "The revealed predecessor partition is no longer blind evidence.",
            "The unchanged v2 matcher is reused to preserve score comparability.",
            "Development success cannot qualify release or enable runtime actions.",
        ),
    )


def _development_metrics(reference: V2DevelopmentReport) -> V3DevelopmentMetrics:
    return V3DevelopmentMetrics(
        payment_attempts=reference.payment_attempts,
        raw_normalized_events=reference.raw_normalized_events,
        predicted_incidents=reference.predicted_incidents,
        suppressed_candidates=reference.suppressed_candidates,
        true_positives=reference.true_positives,
        false_positives=reference.false_positives,
        false_negatives=reference.false_negatives,
        precision_ppm=reference.precision_ppm,
        recall_ppm=reference.recall_ppm,
        top_1_attribution_ppm=reference.top_1_attribution_ppm,
        top_3_attribution_ppm=reference.top_3_attribution_ppm,
        median_detection_delay_seconds=reference.median_detection_delay_seconds,
        maximum_detection_delay_seconds=reference.maximum_detection_delay_seconds,
        median_confirmation_delay_seconds=reference.median_confirmation_delay_seconds,
        maximum_confirmation_delay_seconds=reference.maximum_confirmation_delay_seconds,
        hard_negative_action_eligible_incidents=(reference.hard_negative_action_eligible_incidents),
        baseline_leakage_violations=reference.baseline_leakage_violations,
        evidence_reconciliation_violations=reference.evidence_reconciliation_violations,
        development_targets_passed=reference.development_targets_passed,
        targets=reference.targets,
        cases=reference.cases,
        incidents=reference.incidents,
    )


def render_development_artifacts() -> Mapping[Path, bytes]:
    """Render prediction-first reports for both approved development partitions."""

    config = load_detector_v3_config()
    protocol = _validated_protocol(config)
    original_dataset = build_development_dataset()
    runtimes = (
        _original_runtime(original_dataset, config),
        _revealed_runtime(config),
    )
    # This tuple is complete before the revealed truth loader is called below.
    predictions = tuple(predict_runtime(runtime, config=config) for runtime in runtimes)
    truths = (
        _DevelopmentTruth(
            normalized_events=original_dataset.manifest.normalized_events,
            scenarios=original_dataset.manifest.scenarios,
            truth_artifact_sha256=original_dataset.truth_artifact.sha256,
        ),
        _revealed_truth(config),
    )
    reports = tuple(
        score_prediction(prediction, runtime, truth, config=config)
        for prediction, runtime, truth in zip(predictions, runtimes, truths, strict=True)
    )
    output: dict[Path, bytes] = {}
    summaries: list[V3DevelopmentPartitionSummary] = []
    for prediction, report in zip(predictions, reports, strict=True):
        prediction_path, report_path = _partition_paths(report.development_origin)
        report_content = _canonical_json(report)
        output[prediction_path] = prediction.content
        output[report_path] = report_content
        metrics = report.metrics
        summaries.append(
            V3DevelopmentPartitionSummary(
                development_evidence_id=report.development_evidence_id,
                development_origin=report.development_origin,
                prediction_artifact_sha256=prediction.sha256,
                report_artifact_sha256=hashlib.sha256(report_content).hexdigest(),
                development_targets_passed=metrics.development_targets_passed,
                precision_ppm=metrics.precision_ppm,
                recall_ppm=metrics.recall_ppm,
                top_1_attribution_ppm=metrics.top_1_attribution_ppm,
                median_detection_delay_seconds=metrics.median_detection_delay_seconds,
                baseline_leakage_violations=metrics.baseline_leakage_violations,
                evidence_reconciliation_violations=(metrics.evidence_reconciliation_violations),
            )
        )
    all_passed = all(item.development_targets_passed for item in summaries)
    suite = V3DevelopmentSuiteReport(
        protocol_sha256=hashlib.sha256(_PROTOCOL_PATH.read_bytes()).hexdigest(),
        detector_config_sha256=detector_v3_config_sha256(),
        candidate_bundle_sha256=candidate_bundle_sha256(),
        evaluated_at=max(report.evaluated_at for report in reports),
        partitions=(summaries[0], summaries[1]),
        all_development_partitions_passed=all_passed,
        candidate_ready_for_adversarial_freeze=all_passed,
    )
    if suite.protocol_sha256 != config.protocol_sha256:
        raise V3EvidenceDriftError(V3EvidenceDriftReason.PROTOCOL_IDENTITY)
    if protocol.protocol_id != suite.protocol_id:
        raise V3EvidenceDriftError(V3EvidenceDriftReason.PROTOCOL_IDENTITY)
    output[_SUITE_REPORT_PATH] = _canonical_json(suite)
    return output


def _validated_protocol(config: DetectorV3Config) -> V3EvaluationProtocol:
    findings = check_v3_protocol()
    if findings:
        raise V3EvidenceDriftError(
            V3EvidenceDriftReason.PROTOCOL_STALE,
            detail="; ".join(findings),
        )
    content = _PROTOCOL_PATH.read_bytes()
    if hashlib.sha256(content).hexdigest() != config.protocol_sha256:
        raise V3EvidenceDriftError(V3EvidenceDriftReason.PROTOCOL_IDENTITY)
    protocol = V3EvaluationProtocol.model_validate_json(content)
    evidence_ids = tuple(item.evidence_id for item in protocol.allowed_development_evidence)
    if evidence_ids != config.development_evidence_ids:
        raise V3EvidenceDriftError(V3EvidenceDriftReason.DEVELOPMENT_IDENTITY)
    return protocol


def _original_runtime(
    dataset: GeneratedV2Dataset,
    config: DetectorV3Config,
) -> _DevelopmentRuntime:
    if (
        dataset.manifest.dataset_id != config.development_dataset_id
        or dataset.manifest_sha256 != config.development_manifest_sha256
    ):
        raise V3EvidenceDriftError(V3EvidenceDriftReason.DEVELOPMENT_IDENTITY)
    return _DevelopmentRuntime(
        evidence_id="detector_v2_development_v1",
        origin=V3DevelopmentOrigin.PRIOR_DEVELOPMENT,
        source_dataset_id=dataset.manifest.dataset_id,
        source_dataset_role=dataset.manifest.dataset_role,
        source_manifest_sha256=dataset.manifest_sha256,
        seed_commitment_sha256=dataset.manifest.seed_commitment_sha256,
        starts_at=dataset.manifest.starts_at,
        ends_at=dataset.manifest.ends_at,
        event_artifact=dataset.event_artifact,
    )


def _revealed_runtime(config: DetectorV3Config) -> _DevelopmentRuntime:
    manifest = V2DatasetManifest.model_validate_json(_PREDECESSOR_MANIFEST_PATH.read_bytes())
    manifest_sha256 = hashlib.sha256(_PREDECESSOR_MANIFEST_PATH.read_bytes()).hexdigest()
    if manifest_sha256 != config.revealed_development_manifest_sha256:
        raise V3EvidenceDriftError(V3EvidenceDriftReason.REVEALED_MANIFEST)
    reveal = V2BlindNonceReveal.model_validate_json(_PREDECESSOR_REVEAL_PATH.read_bytes())
    runtime = build_blind_runtime(reveal.nonce, official=False)
    event_digest = next(item for item in manifest.artifacts if item.path == manifest.event_artifact)
    if (
        runtime.dataset_id != manifest.dataset_id
        or runtime.seed_commitment_sha256 != manifest.seed_commitment_sha256
        or runtime.starts_at != manifest.starts_at
        or runtime.ends_at != manifest.ends_at
        or runtime.event_artifact.sha256 != event_digest.sha256
        or runtime.event_artifact.records != event_digest.records
    ):
        raise V3EvidenceDriftError(V3EvidenceDriftReason.REVEALED_RUNTIME)
    return _DevelopmentRuntime(
        evidence_id=_PREDECESSOR_RUN_ID,
        origin=V3DevelopmentOrigin.REVEALED_BLOCKED_BLIND,
        source_dataset_id=runtime.dataset_id,
        source_dataset_role=manifest.dataset_role,
        source_manifest_sha256=manifest_sha256,
        seed_commitment_sha256=runtime.seed_commitment_sha256,
        starts_at=runtime.starts_at,
        ends_at=runtime.ends_at,
        event_artifact=runtime.event_artifact,
    )


def _revealed_truth(config: DetectorV3Config) -> _DevelopmentTruth:
    manifest = V2DatasetManifest.model_validate_json(_PREDECESSOR_MANIFEST_PATH.read_bytes())
    manifest_sha256 = hashlib.sha256(_PREDECESSOR_MANIFEST_PATH.read_bytes()).hexdigest()
    if manifest_sha256 != config.revealed_development_manifest_sha256:
        raise V3EvidenceDriftError(V3EvidenceDriftReason.REVEALED_MANIFEST)
    reveal = V2BlindNonceReveal.model_validate_json(_PREDECESSOR_REVEAL_PATH.read_bytes())
    truth = load_blind_truth(reveal.nonce, official=False)
    truth_digest = next(item for item in manifest.artifacts if item.path == manifest.truth_artifact)
    if (
        truth.dataset_id != manifest.dataset_id
        or truth.seed_commitment_sha256 != manifest.seed_commitment_sha256
        or truth.truth_artifact.sha256 != truth_digest.sha256
        or truth.truth_artifact.records != truth_digest.records
        or truth.normalized_events != manifest.normalized_events
        or truth.scenarios != manifest.scenarios
    ):
        raise V3EvidenceDriftError(V3EvidenceDriftReason.REVEALED_TRUTH)
    return _DevelopmentTruth(
        normalized_events=truth.normalized_events,
        scenarios=truth.scenarios,
        truth_artifact_sha256=truth.truth_artifact.sha256,
    )


def _partition_paths(origin: V3DevelopmentOrigin) -> tuple[Path, Path]:
    stem = {
        V3DevelopmentOrigin.PRIOR_DEVELOPMENT: "detector_v3.prior_development",
        V3DevelopmentOrigin.REVEALED_BLOCKED_BLIND: ("detector_v3.revealed_predecessor"),
    }[origin]
    return (
        _REPOSITORY_ROOT / f"evals/reports/{stem}.predictions.json",
        _REPOSITORY_ROOT / f"evals/reports/{stem}.report.json",
    )


def check_development_artifacts() -> list[str]:
    """Return every missing, stale or non-passing R4.2 artifact finding."""

    expected = render_development_artifacts()
    findings: list[str] = []
    for path, content in expected.items():
        relative = path.relative_to(_REPOSITORY_ROOT).as_posix()
        if not path.is_file():
            findings.append(f"missing {relative}")
        elif path.read_bytes() != content:
            findings.append(f"stale {relative}")
    suite = V3DevelopmentSuiteReport.model_validate_json(expected[_SUITE_REPORT_PATH])
    if not suite.all_development_partitions_passed:
        findings.append("detector-v3 development partitions did not all pass")
    return findings


def write_development_artifacts() -> None:
    """Write canonical artifacts only when both development partitions pass."""

    artifacts = render_development_artifacts()
    suite = V3DevelopmentSuiteReport.model_validate_json(artifacts[_SUITE_REPORT_PATH])
    if not suite.all_development_partitions_passed:
        raise V3DevelopmentTargetError
    for path, content in artifacts.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_bytes(content)
        temporary.replace(path)


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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--print-suite", action="store_true")
    return parser


def main() -> None:
    """Manage development-only v3 artifacts; no future blind nonce is accepted."""

    arguments = _parser().parse_args()
    if arguments.write:
        write_development_artifacts()
        sys.stdout.write("wrote passing detector-v3 development artifacts\n")
        return
    if arguments.check:
        findings = check_development_artifacts()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write(
            "detector-v3 passes both development partitions; release remains blocked\n"
        )
        return
    sys.stdout.buffer.write(render_development_artifacts()[_SUITE_REPORT_PATH])


if __name__ == "__main__":  # pragma: no cover
    main()
