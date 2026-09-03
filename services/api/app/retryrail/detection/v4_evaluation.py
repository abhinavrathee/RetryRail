"""Detector-v4 development evaluation across three precommitted partitions."""

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import IncidentStatus, StrictContract
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
from retryrail.detection.v3_blind_models import V3BlindNonceReveal
from retryrail.detection.v4_config import (
    detector_v4_config_sha256,
    load_detector_v4_config,
)
from retryrail.detection.v4_engine import DetectorV4Engine
from retryrail.detection.v4_models import (
    DetectorV4Config,
    V4DetectorRunResult,
    V4ScopeArbitration,
)
from retryrail.detection.v4_protocol import (
    V4EvaluationProtocol,
    check_v4_protocol,
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
_PROTOCOL_PATH = _REPOSITORY_ROOT / "evals/protocols/detector_v4.protocol.json"
_V2_RUN_ID = "detector_v2_official_blind_ef49a16703b1612ef774"
_V3_RUN_ID = "detector_v3_official_blind_1a1852634945b54e300a"
_V2_RUN_ROOT = _REPOSITORY_ROOT / "evals/blind/detector_v2/runs" / _V2_RUN_ID
_V3_RUN_ROOT = _REPOSITORY_ROOT / "evals/blind/detector_v3/runs" / _V3_RUN_ID
_V2_MANIFEST_PATH = _V2_RUN_ROOT / "blind.dataset_manifest.v1.json"
_V3_MANIFEST_PATH = _V3_RUN_ROOT / "blind.dataset_manifest.v1.json"
_V2_REVEAL_PATH = _V2_RUN_ROOT / "nonce.reveal.json"
_V3_REVEAL_PATH = _V3_RUN_ROOT / "nonce.reveal.json"
_SUITE_REPORT_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v4.development.json"
_CANDIDATE_SOURCE_PATHS = (
    "services/api/app/retryrail/contracts/domain.py",
    "services/api/app/retryrail/detection/engine.py",
    "services/api/app/retryrail/detection/models.py",
    "services/api/app/retryrail/detection/v2_engine.py",
    "services/api/app/retryrail/detection/v2_evaluation.py",
    "services/api/app/retryrail/detection/v2_models.py",
    "services/api/app/retryrail/detection/v4_adversarial.py",
    "services/api/app/retryrail/detection/v4_config.py",
    "services/api/app/retryrail/detection/v4_engine.py",
    "services/api/app/retryrail/detection/v4_evaluation.py",
    "services/api/app/retryrail/detection/v4_models.py",
    "services/api/app/retryrail/events/models.py",
)


class V4DevelopmentOrigin(StrEnum):
    """Where one permitted detector-v4 development partition came from."""

    PRIOR_DEVELOPMENT = "prior_development"
    REVEALED_V2_BLOCKED_BLIND = "revealed_v2_blocked_blind"
    REVEALED_V3_BLOCKED_INVALID_BLIND = "revealed_v3_blocked_invalid_blind"


class V4PredictionArtifact(V2PredictionArtifact):
    """Label-free v4 output with hierarchy-arbitration evidence."""

    schema_version: Literal["4.0.0"] = "4.0.0"  # type: ignore[assignment]
    protocol_id: Literal["detector_v4_protocol_v1"] = "detector_v4_protocol_v1"
    development_evidence_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    development_origin: V4DevelopmentOrigin
    dataset_role: Literal[V2DatasetRole.DEVELOPMENT] = V2DatasetRole.DEVELOPMENT
    source_dataset_role: V2DatasetRole
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = (
        "detector_v2_matcher_v1_0_0"
    )
    arbitrations: tuple[V4ScopeArbitration, ...]

    @model_validator(mode="after")
    def validate_arbitration_references(self) -> Self:
        """Require unique loser records that point to emitted incidents."""

        incidents = {item.incident_id: item for item in self.incidents}
        arbitration_ids = tuple(item.arbitration_id for item in self.arbitrations)
        candidate_ids = tuple(item.candidate_id for item in self.arbitrations)
        if len(set(arbitration_ids)) != len(arbitration_ids):
            msg = "scope arbitration identities must be unique"
            raise ValueError(msg)
        if len(set(candidate_ids)) != len(candidate_ids):
            msg = "each confirmed losing candidate may be arbitrated only once"
            raise ValueError(msg)
        if any(item.selected_incident_id not in incidents for item in self.arbitrations):
            msg = "scope arbitration must reference an emitted incident"
            raise ValueError(msg)
        if any(
            item.selected_cohort != incidents[item.selected_incident_id].detector_cohort
            for item in self.arbitrations
        ):
            msg = "selected arbitration cohort must equal the emitted detector cohort"
            raise ValueError(msg)
        suppressed_ids = {item.candidate_id for item in self.suppressed_candidates}
        if suppressed_ids.intersection(candidate_ids):
            msg = "a candidate cannot be both suppressed and scope-arbitrated"
            raise ValueError(msg)
        return self


class V4ReportContractProof(StrictContract):
    """Pre-nonce proof that report bytes honor required-nullable contracts."""

    required_nullable_fields_emitted: Literal[True] = True
    strict_model_reload_passed: Literal[True] = True
    canonical_byte_round_trip_passed: Literal[True] = True
    open_incident_ids: tuple[str, ...]


class V4DevelopmentMetrics(StrictContract):
    """Complete unchanged target score for one approved development partition."""

    payment_attempts: int = Field(gt=0)
    raw_normalized_events: int = Field(gt=0)
    predicted_incidents: int = Field(ge=0)
    suppressed_candidates: int = Field(ge=0)
    arbitrated_confirmed_candidates: int = Field(ge=0)
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
    def validate_metrics(self) -> Self:
        """Reconcile counts and the unchanged target decision."""

        if self.development_targets_passed is not self.targets.all_passed:
            msg = "development target summary must equal all target comparisons"
            raise ValueError(msg)
        if self.predicted_incidents != len(self.incidents):
            msg = "predicted incident count must reconcile with incident summaries"
            raise ValueError(msg)
        observed_counts = (
            sum(item.expected_incident and item.detected_incident for item in self.cases),
            sum(not item.expected_incident and item.detected_incident for item in self.cases),
            sum(item.expected_incident and not item.detected_incident for item in self.cases),
        )
        if observed_counts != (
            self.true_positives,
            self.false_positives,
            self.false_negatives,
        ):
            msg = "development confusion counts must reconcile with evaluation cases"
            raise ValueError(msg)
        return self


class V4DevelopmentPartitionReport(StrictContract):
    """Development-only v4 report that cannot activate runtime actions."""

    schema_version: Literal["4.0.0"] = "4.0.0"
    report_id: str = Field(pattern=r"^detector_v4_development_[A-Za-z0-9_-]+$")
    protocol_id: Literal["detector_v4_protocol_v1"] = "detector_v4_protocol_v1"
    detector_version: Literal["detector_v4_0_0"] = "detector_v4_0_0"
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = (
        "detector_v2_matcher_v1_0_0"
    )
    development_evidence_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    development_origin: V4DevelopmentOrigin
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
    report_contract: V4ReportContractProof
    metrics: V4DevelopmentMetrics
    limitations: tuple[str, ...] = Field(min_length=5)

    @model_validator(mode="after")
    def validate_open_incident_proof(self) -> Self:
        """Bind declared open fixtures to the report's incident summaries."""

        actual = tuple(
            item.incident_id
            for item in self.metrics.incidents
            if item.status is IncidentStatus.OPEN and item.resolved_at is None
        )
        if self.report_contract.open_incident_ids != actual:
            msg = "open-incident serialization proof must match report incidents"
            raise ValueError(msg)
        return self


class V4DevelopmentPartitionSummary(StrictContract):
    """Digest-bound partition score and serialization result."""

    development_evidence_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    development_origin: V4DevelopmentOrigin
    prediction_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    report_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    development_targets_passed: bool
    precision_ppm: int = Field(ge=0, le=1_000_000)
    recall_ppm: int = Field(ge=0, le=1_000_000)
    top_1_attribution_ppm: int = Field(ge=0, le=1_000_000)
    median_detection_delay_seconds: int | None = Field(default=None, ge=0)
    baseline_leakage_violations: int = Field(ge=0)
    evidence_reconciliation_violations: int = Field(ge=0)
    arbitrated_confirmed_candidates: int = Field(ge=0)
    open_incident_count: int = Field(ge=0)
    report_contract_passed: Literal[True] = True


class V4DevelopmentSuiteReport(StrictContract):
    """Fail-closed R5.2 decision across every approved partition."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    report_id: Literal["detector_v4_development_suite_v1"] = (
        "detector_v4_development_suite_v1"
    )
    protocol_id: Literal["detector_v4_protocol_v1"] = "detector_v4_protocol_v1"
    protocol_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    detector_version: Literal["detector_v4_0_0"] = "detector_v4_0_0"
    detector_config_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = (
        "detector_v2_matcher_v1_0_0"
    )
    evaluated_at: AwareDatetime
    partitions: tuple[
        V4DevelopmentPartitionSummary,
        V4DevelopmentPartitionSummary,
        V4DevelopmentPartitionSummary,
    ]
    all_development_partitions_passed: bool
    report_contract_ready_for_freeze: bool
    open_incident_fixture_exercised: bool
    candidate_ready_for_adversarial_freeze: bool
    candidate_frozen: Literal[False] = False
    official_blind_nonce_sha256: None = None
    official_blind_run_id: None = None
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_suite(self) -> Self:
        """Require all three partitions and the real open-incident preflight."""

        evidence_ids = tuple(item.development_evidence_id for item in self.partitions)
        if evidence_ids != (
            "detector_v2_development_v1",
            _V2_RUN_ID,
            _V3_RUN_ID,
        ):
            msg = "development suite partitions must use canonical evidence order"
            raise ValueError(msg)
        passed = all(item.development_targets_passed for item in self.partitions)
        contract_ready = all(item.report_contract_passed for item in self.partitions)
        open_exercised = any(item.open_incident_count > 0 for item in self.partitions)
        ready = passed and contract_ready and open_exercised
        if self.all_development_partitions_passed is not passed:
            msg = "suite pass flag must equal every partition result"
            raise ValueError(msg)
        if self.report_contract_ready_for_freeze is not contract_ready:
            msg = "report-contract readiness must equal every round-trip result"
            raise ValueError(msg)
        if self.open_incident_fixture_exercised is not open_exercised:
            msg = "open-incident preflight must equal observed report evidence"
            raise ValueError(msg)
        if self.candidate_ready_for_adversarial_freeze is not ready:
            msg = "adversarial-freeze readiness must include scores and report preflight"
            raise ValueError(msg)
        return self


class V4DevelopmentTargetError(RuntimeError):
    """The candidate cannot advance because R5.2 did not pass fail-closed."""


class V4EvidenceDriftReason(StrEnum):
    """Stable reasons for fail-closed development evidence rejection."""

    PROTOCOL_STALE = "detector-v4 protocol is missing or stale"
    PROTOCOL_IDENTITY = "detector-v4 protocol identities do not reconcile"
    DEVELOPMENT_IDENTITY = "detector-v4 development evidence changed"
    REVEALED_MANIFEST = "revealed development manifest changed"
    REVEALED_RUNTIME = "revealed runtime does not reproduce its manifest"
    REVEALED_TRUTH = "revealed truth does not reproduce its manifest"
    SERIALIZATION = "detector-v4 canonical serialization preflight failed"


class V4EvidenceDriftError(RuntimeError):
    """A precommitted input or required serialization invariant drifted."""

    def __init__(
        self,
        reason: V4EvidenceDriftReason,
        *,
        detail: str | None = None,
    ) -> None:
        self.reason = reason
        self.detail = detail
        message = reason.value if detail is None else f"{reason.value}: {detail}"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class V4PredictionBuild:
    """Prediction bytes and label-free run retained before scoring."""

    artifact: V4PredictionArtifact
    content: bytes
    sha256: str
    run: V4DetectorRunResult


@dataclass(frozen=True, slots=True)
class _DevelopmentRuntime:
    evidence_id: str
    origin: V4DevelopmentOrigin
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
    """Bind inherited matching semantics plus every v4 candidate source."""

    digest = hashlib.sha256()
    for relative_path in _CANDIDATE_SOURCE_PATHS:
        digest.update(relative_path.encode())
        digest.update(b"\0")
        source = (root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        digest.update(source)
        digest.update(b"\0")
    return digest.hexdigest()


def candidate_source_paths() -> tuple[str, ...]:
    """Return the ordered source identities included in the candidate digest."""

    return _CANDIDATE_SOURCE_PATHS


def predict_runtime(
    runtime: _DevelopmentRuntime,
    *,
    config: DetectorV4Config | None = None,
) -> V4PredictionBuild:
    """Create canonical v4 predictions without accepting truth or labels."""

    selected_config = config or load_detector_v4_config()
    events = tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in runtime.event_artifact.content.splitlines()
    )
    run = DetectorV4Engine(selected_config).run(
        events,
        partition_started_at=runtime.starts_at,
        partition_ended_at=runtime.ends_at,
    )
    artifact = V4PredictionArtifact(
        prediction_id=(
            f"prediction_development_{selected_config.detector_version}_"
            f"{runtime.origin.value}"
        ),
        detector_version=selected_config.detector_version,
        detector_config_sha256=detector_v4_config_sha256(),
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
        arbitrations=run.arbitrations,
    )
    content = canonical_contract_json(artifact)
    _strict_round_trip(V4PredictionArtifact, content)
    return V4PredictionBuild(
        artifact=artifact,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        run=run,
    )


def score_prediction(
    prediction: V4PredictionBuild,
    runtime: _DevelopmentRuntime,
    truth: _DevelopmentTruth,
    *,
    config: DetectorV4Config | None = None,
) -> V4DevelopmentPartitionReport:
    """Score only after the canonical label-free bytes have been materialized."""

    selected_config = config or load_detector_v4_config()
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
    metrics = _development_metrics(
        reference,
        arbitrated_confirmed_candidates=len(prediction.run.arbitrations),
    )
    open_incident_ids = tuple(
        item.incident_id
        for item in metrics.incidents
        if item.status is IncidentStatus.OPEN and item.resolved_at is None
    )
    return V4DevelopmentPartitionReport(
        report_id=f"detector_v4_development_{runtime.origin.value}",
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
        report_contract=V4ReportContractProof(open_incident_ids=open_incident_ids),
        metrics=metrics,
        limitations=(
            "This is synthetic development evidence, not production performance.",
            "All three partitions are revealed and can never be blind evidence again.",
            "The unchanged v2 matcher is reused to preserve exact score comparability.",
            "Scope arbitration consumes only label-free event-time candidate evidence.",
            "Development success cannot qualify release or enable runtime actions.",
        ),
    )


def _development_metrics(
    reference: V2DevelopmentReport,
    *,
    arbitrated_confirmed_candidates: int,
) -> V4DevelopmentMetrics:
    return V4DevelopmentMetrics(
        payment_attempts=reference.payment_attempts,
        raw_normalized_events=reference.raw_normalized_events,
        predicted_incidents=reference.predicted_incidents,
        suppressed_candidates=reference.suppressed_candidates,
        arbitrated_confirmed_candidates=arbitrated_confirmed_candidates,
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
        hard_negative_action_eligible_incidents=(
            reference.hard_negative_action_eligible_incidents
        ),
        baseline_leakage_violations=reference.baseline_leakage_violations,
        evidence_reconciliation_violations=reference.evidence_reconciliation_violations,
        development_targets_passed=reference.development_targets_passed,
        targets=reference.targets,
        cases=reference.cases,
        incidents=reference.incidents,
    )


def render_development_artifacts() -> Mapping[Path, bytes]:
    """Render prediction-first results for all three approved partitions."""

    config = load_detector_v4_config()
    protocol = _validated_protocol(config)
    original_dataset = build_development_dataset()
    runtimes = (
        _original_runtime(original_dataset, config),
        _revealed_v2_runtime(config),
        _revealed_v3_runtime(config),
    )
    # The complete prediction tuple exists before either revealed truth loader runs.
    predictions = tuple(predict_runtime(runtime, config=config) for runtime in runtimes)
    truths = (
        _DevelopmentTruth(
            normalized_events=original_dataset.manifest.normalized_events,
            scenarios=original_dataset.manifest.scenarios,
            truth_artifact_sha256=original_dataset.truth_artifact.sha256,
        ),
        _revealed_v2_truth(config),
        _revealed_v3_truth(config),
    )
    reports = tuple(
        score_prediction(prediction, runtime, truth, config=config)
        for prediction, runtime, truth in zip(predictions, runtimes, truths, strict=True)
    )

    output: dict[Path, bytes] = {}
    summaries: list[V4DevelopmentPartitionSummary] = []
    for prediction, report in zip(predictions, reports, strict=True):
        prediction_path, report_path = _partition_paths(report.development_origin)
        report_content = _render_report(report)
        output[prediction_path] = prediction.content
        output[report_path] = report_content
        metrics = report.metrics
        summaries.append(
            V4DevelopmentPartitionSummary(
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
                evidence_reconciliation_violations=(
                    metrics.evidence_reconciliation_violations
                ),
                arbitrated_confirmed_candidates=(
                    metrics.arbitrated_confirmed_candidates
                ),
                open_incident_count=len(report.report_contract.open_incident_ids),
            )
        )

    all_passed = all(item.development_targets_passed for item in summaries)
    contract_ready = all(item.report_contract_passed for item in summaries)
    open_exercised = any(item.open_incident_count > 0 for item in summaries)
    suite = V4DevelopmentSuiteReport(
        protocol_sha256=hashlib.sha256(_PROTOCOL_PATH.read_bytes()).hexdigest(),
        detector_config_sha256=detector_v4_config_sha256(),
        candidate_bundle_sha256=candidate_bundle_sha256(),
        evaluated_at=max(report.evaluated_at for report in reports),
        partitions=(summaries[0], summaries[1], summaries[2]),
        all_development_partitions_passed=all_passed,
        report_contract_ready_for_freeze=contract_ready,
        open_incident_fixture_exercised=open_exercised,
        candidate_ready_for_adversarial_freeze=(
            all_passed and contract_ready and open_exercised
        ),
    )
    if suite.protocol_sha256 != config.protocol_sha256:
        raise V4EvidenceDriftError(V4EvidenceDriftReason.PROTOCOL_IDENTITY)
    if protocol.protocol_id != suite.protocol_id:
        raise V4EvidenceDriftError(V4EvidenceDriftReason.PROTOCOL_IDENTITY)
    suite_content = canonical_contract_json(suite)
    _strict_round_trip(V4DevelopmentSuiteReport, suite_content)
    output[_SUITE_REPORT_PATH] = suite_content
    return output


def _validated_protocol(config: DetectorV4Config) -> V4EvaluationProtocol:
    findings = check_v4_protocol()
    if findings:
        raise V4EvidenceDriftError(
            V4EvidenceDriftReason.PROTOCOL_STALE,
            detail="; ".join(findings),
        )
    content = _PROTOCOL_PATH.read_bytes()
    if hashlib.sha256(content).hexdigest() != config.protocol_sha256:
        raise V4EvidenceDriftError(V4EvidenceDriftReason.PROTOCOL_IDENTITY)
    protocol = V4EvaluationProtocol.model_validate_json(content)
    evidence_ids = tuple(item.evidence_id for item in protocol.allowed_development_evidence)
    if evidence_ids != config.development_evidence_ids:
        raise V4EvidenceDriftError(V4EvidenceDriftReason.DEVELOPMENT_IDENTITY)
    return protocol


def _original_runtime(
    dataset: GeneratedV2Dataset,
    config: DetectorV4Config,
) -> _DevelopmentRuntime:
    if (
        dataset.manifest.dataset_id != config.development_dataset_id
        or dataset.manifest_sha256 != config.development_manifest_sha256
    ):
        raise V4EvidenceDriftError(V4EvidenceDriftReason.DEVELOPMENT_IDENTITY)
    return _DevelopmentRuntime(
        evidence_id="detector_v2_development_v1",
        origin=V4DevelopmentOrigin.PRIOR_DEVELOPMENT,
        source_dataset_id=dataset.manifest.dataset_id,
        source_dataset_role=dataset.manifest.dataset_role,
        source_manifest_sha256=dataset.manifest_sha256,
        seed_commitment_sha256=dataset.manifest.seed_commitment_sha256,
        starts_at=dataset.manifest.starts_at,
        ends_at=dataset.manifest.ends_at,
        event_artifact=dataset.event_artifact,
    )


def _revealed_v2_runtime(config: DetectorV4Config) -> _DevelopmentRuntime:
    reveal = V2BlindNonceReveal.model_validate_json(_V2_REVEAL_PATH.read_bytes())
    return _revealed_runtime(
        evidence_id=_V2_RUN_ID,
        origin=V4DevelopmentOrigin.REVEALED_V2_BLOCKED_BLIND,
        manifest_path=_V2_MANIFEST_PATH,
        expected_manifest_sha256=config.revealed_v2_development_manifest_sha256,
        nonce=reveal.nonce,
    )


def _revealed_v3_runtime(config: DetectorV4Config) -> _DevelopmentRuntime:
    reveal = V3BlindNonceReveal.model_validate_json(_V3_REVEAL_PATH.read_bytes())
    return _revealed_runtime(
        evidence_id=_V3_RUN_ID,
        origin=V4DevelopmentOrigin.REVEALED_V3_BLOCKED_INVALID_BLIND,
        manifest_path=_V3_MANIFEST_PATH,
        expected_manifest_sha256=config.revealed_v3_development_manifest_sha256,
        nonce=reveal.nonce,
    )


def _revealed_runtime(
    *,
    evidence_id: str,
    origin: V4DevelopmentOrigin,
    manifest_path: Path,
    expected_manifest_sha256: str,
    nonce: str,
) -> _DevelopmentRuntime:
    manifest = V2DatasetManifest.model_validate_json(manifest_path.read_bytes())
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if manifest_sha256 != expected_manifest_sha256:
        raise V4EvidenceDriftError(V4EvidenceDriftReason.REVEALED_MANIFEST)
    runtime = build_blind_runtime(nonce, official=False)
    event_digest = next(item for item in manifest.artifacts if item.path == manifest.event_artifact)
    if (
        runtime.dataset_id != manifest.dataset_id
        or runtime.seed_commitment_sha256 != manifest.seed_commitment_sha256
        or runtime.starts_at != manifest.starts_at
        or runtime.ends_at != manifest.ends_at
        or runtime.event_artifact.sha256 != event_digest.sha256
        or runtime.event_artifact.records != event_digest.records
    ):
        raise V4EvidenceDriftError(V4EvidenceDriftReason.REVEALED_RUNTIME)
    return _DevelopmentRuntime(
        evidence_id=evidence_id,
        origin=origin,
        source_dataset_id=runtime.dataset_id,
        source_dataset_role=manifest.dataset_role,
        source_manifest_sha256=manifest_sha256,
        seed_commitment_sha256=runtime.seed_commitment_sha256,
        starts_at=runtime.starts_at,
        ends_at=runtime.ends_at,
        event_artifact=runtime.event_artifact,
    )


def _revealed_v2_truth(config: DetectorV4Config) -> _DevelopmentTruth:
    reveal = V2BlindNonceReveal.model_validate_json(_V2_REVEAL_PATH.read_bytes())
    return _revealed_truth(
        manifest_path=_V2_MANIFEST_PATH,
        expected_manifest_sha256=config.revealed_v2_development_manifest_sha256,
        nonce=reveal.nonce,
    )


def _revealed_v3_truth(config: DetectorV4Config) -> _DevelopmentTruth:
    reveal = V3BlindNonceReveal.model_validate_json(_V3_REVEAL_PATH.read_bytes())
    return _revealed_truth(
        manifest_path=_V3_MANIFEST_PATH,
        expected_manifest_sha256=config.revealed_v3_development_manifest_sha256,
        nonce=reveal.nonce,
    )


def _revealed_truth(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    nonce: str,
) -> _DevelopmentTruth:
    manifest = V2DatasetManifest.model_validate_json(manifest_path.read_bytes())
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if manifest_sha256 != expected_manifest_sha256:
        raise V4EvidenceDriftError(V4EvidenceDriftReason.REVEALED_MANIFEST)
    truth = load_blind_truth(nonce, official=False)
    truth_digest = next(item for item in manifest.artifacts if item.path == manifest.truth_artifact)
    if (
        truth.dataset_id != manifest.dataset_id
        or truth.seed_commitment_sha256 != manifest.seed_commitment_sha256
        or truth.truth_artifact.sha256 != truth_digest.sha256
        or truth.truth_artifact.records != truth_digest.records
        or truth.normalized_events != manifest.normalized_events
        or truth.scenarios != manifest.scenarios
    ):
        raise V4EvidenceDriftError(V4EvidenceDriftReason.REVEALED_TRUTH)
    return _DevelopmentTruth(
        normalized_events=truth.normalized_events,
        scenarios=truth.scenarios,
        truth_artifact_sha256=truth.truth_artifact.sha256,
    )


def _partition_paths(origin: V4DevelopmentOrigin) -> tuple[Path, Path]:
    stem = {
        V4DevelopmentOrigin.PRIOR_DEVELOPMENT: "detector_v4.prior_development",
        V4DevelopmentOrigin.REVEALED_V2_BLOCKED_BLIND: (
            "detector_v4.revealed_v2_predecessor"
        ),
        V4DevelopmentOrigin.REVEALED_V3_BLOCKED_INVALID_BLIND: (
            "detector_v4.revealed_v3_predecessor"
        ),
    }[origin]
    return (
        _REPOSITORY_ROOT / f"evals/reports/{stem}.predictions.json",
        _REPOSITORY_ROOT / f"evals/reports/{stem}.report.json",
    )


def _render_report(report: V4DevelopmentPartitionReport) -> bytes:
    content = canonical_contract_json(report)
    parsed = _json_object(content)
    metrics = parsed.get("metrics")
    incidents = metrics.get("incidents") if isinstance(metrics, dict) else None
    if not isinstance(incidents, list):
        raise V4EvidenceDriftError(
            V4EvidenceDriftReason.SERIALIZATION,
            detail="report incidents are not a JSON array",
        )
    missing = tuple(
        f"metrics.incidents[{index}].resolved_at"
        for index, incident in enumerate(incidents)
        if not isinstance(incident, dict) or "resolved_at" not in incident
    )
    if missing:
        raise V4EvidenceDriftError(
            V4EvidenceDriftReason.SERIALIZATION,
            detail="missing required nullable fields: " + ", ".join(missing),
        )
    open_ids = tuple(
        str(incident["incident_id"])
        for incident in incidents
        if isinstance(incident, dict)
        and incident.get("status") == IncidentStatus.OPEN.value
        and incident.get("resolved_at") is None
    )
    if open_ids != report.report_contract.open_incident_ids:
        raise V4EvidenceDriftError(
            V4EvidenceDriftReason.SERIALIZATION,
            detail="open incident null fields do not match the typed proof",
        )
    _strict_round_trip(V4DevelopmentPartitionReport, content)
    return content


def _strict_round_trip(model: type[StrictContract], content: bytes) -> None:
    reloaded = model.model_validate_json(content)
    if canonical_contract_json(reloaded) != content:
        raise V4EvidenceDriftError(
            V4EvidenceDriftReason.SERIALIZATION,
            detail=f"{model.__name__} did not reproduce canonical bytes",
        )


def _json_object(content: bytes) -> dict[str, Any]:
    value: Any = json.loads(content)
    if not isinstance(value, dict):
        raise V4EvidenceDriftError(
            V4EvidenceDriftReason.SERIALIZATION,
            detail="canonical contract root must be a JSON object",
        )
    return value


def check_development_artifacts() -> list[str]:
    """Return every missing, stale or non-passing R5.2 artifact finding."""

    expected = render_development_artifacts()
    findings: list[str] = []
    for path, content in expected.items():
        relative = path.relative_to(_REPOSITORY_ROOT).as_posix()
        if not path.is_file():
            findings.append(f"missing {relative}")
        elif path.read_bytes() != content:
            findings.append(f"stale {relative}")
    suite = V4DevelopmentSuiteReport.model_validate_json(expected[_SUITE_REPORT_PATH])
    if not suite.candidate_ready_for_adversarial_freeze:
        findings.append("detector-v4 development or report-contract gates did not pass")
    return findings


def write_development_artifacts() -> None:
    """Atomically write artifacts only when all R5.2 gates pass."""

    artifacts = render_development_artifacts()
    suite = V4DevelopmentSuiteReport.model_validate_json(artifacts[_SUITE_REPORT_PATH])
    if not suite.candidate_ready_for_adversarial_freeze:
        raise V4DevelopmentTargetError
    for path, content in artifacts.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_bytes(content)
        temporary.replace(path)


def canonical_contract_json(value: StrictContract) -> bytes:
    """Emit required nullable fields instead of repeating the v3 omission."""

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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--print-suite", action="store_true")
    return parser


def main() -> None:
    """Manage development-only v4 artifacts; no blind nonce is accepted."""

    arguments = _parser().parse_args()
    if arguments.write:
        write_development_artifacts()
        sys.stdout.write("wrote passing detector-v4 development artifacts\n")
        return
    if arguments.check:
        findings = check_development_artifacts()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        sys.stdout.write(
            "detector-v4 passes all three development partitions; release remains blocked\n"
        )
        return
    sys.stdout.buffer.write(render_development_artifacts()[_SUITE_REPORT_PATH])


if __name__ == "__main__":  # pragma: no cover
    main()
