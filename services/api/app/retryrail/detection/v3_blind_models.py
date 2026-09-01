"""Strict evidence contracts for the one-time detector-v3 blind evaluation."""

import hashlib
from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import StrictContract
from retryrail.detection.v2_evaluation import (
    V2EvaluationCase,
    V2IncidentEvaluationSummary,
    V2PredictionArtifact,
    V2TargetResults,
)
from retryrail.synthetic.models import ArtifactDigest, ArtifactPath, Sha256Digest
from retryrail.synthetic.v2_models import V2DatasetRole


class V3BlindReleaseStatus(StrEnum):
    """Whether the frozen candidate cleared every precommitted blind target."""

    QUALIFIED = "qualified"
    BLOCKED = "blocked"


class V3BlindReleaseTarget(StrEnum):
    """Stable identifiers for every detector-v3 release target."""

    PRECISION = "precision"
    RECALL = "recall"
    TOP_1_ATTRIBUTION = "top_1_attribution"
    MEDIAN_DETECTION_DELAY = "median_detection_delay"
    HARD_NEGATIVE_ACTION_ELIGIBILITY = "hard_negative_action_eligibility"
    BASELINE_LEAKAGE = "baseline_leakage"
    EVIDENCE_RECONCILIATION = "evidence_reconciliation"


class V3BlindFailureStage(StrEnum):
    """Bounded stages that may fail without recording sensitive exception text."""

    PREDICTION = "prediction"
    SCORING = "scoring"


class V3BlindProcedureFreeze(StrictContract):
    """Pre-nonce identity for the already-frozen candidate and blind runner."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    freeze_id: Literal["detector_v3_blind_procedure_freeze_v1"] = (
        "detector_v3_blind_procedure_freeze_v1"
    )
    status: Literal["ready_for_fresh_nonce"] = "ready_for_fresh_nonce"
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    protocol_sha256: Sha256Digest
    candidate_freeze_id: Literal["detector_v3_candidate_freeze_v1"] = (
        "detector_v3_candidate_freeze_v1"
    )
    candidate_freeze_sha256: Sha256Digest
    generator_bundle_sha256: Sha256Digest
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: Sha256Digest
    candidate_bundle_sha256: Sha256Digest
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = "detector_v2_matcher_v1_0_0"
    runner_bundle_sha256: Sha256Digest
    runner_source_paths: tuple[ArtifactPath, ...] = Field(min_length=2)
    nonce_committed: Literal[False] = False
    official_blind_evaluated: Literal[False] = False
    release_qualified: Literal[False] = False
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_source_paths(self) -> Self:
        """Reject duplicate runner sources from the pre-nonce identity."""

        if len(set(self.runner_source_paths)) != len(self.runner_source_paths):
            msg = "blind runner source paths must be unique"
            raise ValueError(msg)
        return self


class V3BlindNonceCommitment(StrictContract):
    """Durable nonce digest written before any blind event is generated."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    commitment_id: str = Field(pattern=r"^commitment_[a-f0-9]{20}$")
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    status: Literal["nonce_committed_before_generation"] = "nonce_committed_before_generation"
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    protocol_sha256: Sha256Digest
    candidate_freeze_sha256: Sha256Digest
    procedure_freeze_sha256: Sha256Digest
    generator_bundle_sha256: Sha256Digest
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: Sha256Digest
    candidate_bundle_sha256: Sha256Digest
    runner_bundle_sha256: Sha256Digest
    nonce_sha256: Sha256Digest
    committed_at: AwareDatetime
    raw_nonce_persisted: Literal[False] = False
    events_generated: Literal[False] = False
    predictions_persisted: Literal[False] = False
    truth_loaded: Literal[False] = False
    synthetic: Literal[True] = True


class V3BlindPredictionArtifact(V2PredictionArtifact):
    """Label-free detector-v3 output persisted before truth authorization."""

    schema_version: Literal["3.0.0"] = "3.0.0"  # type: ignore[assignment]
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    dataset_role: Literal[V2DatasetRole.BLIND] = V2DatasetRole.BLIND


class V3BlindPredictionReceipt(StrictContract):
    """Proof that label-free prediction bytes were durably persisted."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    receipt_id: str = Field(pattern=r"^prediction_receipt_[a-f0-9]{20}$")
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    status: Literal["predictions_persisted_truth_unopened"] = "predictions_persisted_truth_unopened"
    nonce_commitment_sha256: Sha256Digest
    nonce_sha256: Sha256Digest
    procedure_freeze_sha256: Sha256Digest
    dataset_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    dataset_role: Literal[V2DatasetRole.BLIND] = V2DatasetRole.BLIND
    seed_commitment_sha256: Sha256Digest
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    payment_attempts: int = Field(gt=0)
    event_artifact: ArtifactDigest
    prediction_artifact: ArtifactDigest
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: Sha256Digest
    candidate_bundle_sha256: Sha256Digest
    runner_bundle_sha256: Sha256Digest
    predicted_at: AwareDatetime
    persisted_at: AwareDatetime
    prediction_readback_verified: Literal[True] = True
    labels_loaded: Literal[False] = False
    truth_loaded: Literal[False] = False
    release_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_event_time(self) -> Self:
        """Bind the receipt to a complete label-free event-time partition."""

        if not self.starts_at < self.ends_at < self.predicted_at:
            msg = "blind prediction receipt timestamps must be strictly ordered"
            raise ValueError(msg)
        if self.prediction_artifact.records != 1:
            msg = "blind prediction artifact must contain exactly one JSON document"
            raise ValueError(msg)
        if self.event_artifact.path == self.prediction_artifact.path:
            msg = "blind events and predictions must be physically separate"
            raise ValueError(msg)
        return self


class V3BlindTruthAccessReceipt(StrictContract):
    """Marker written only after prediction bytes and hashes are re-verified."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    authorization_id: str = Field(pattern=r"^truth_access_[a-f0-9]{20}$")
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    status: Literal["prediction_verified_truth_access_authorized"] = (
        "prediction_verified_truth_access_authorized"
    )
    nonce_sha256: Sha256Digest
    prediction_receipt_sha256: Sha256Digest
    prediction_artifact_sha256: Sha256Digest
    procedure_freeze_sha256: Sha256Digest
    authorized_at: AwareDatetime
    persisted_prediction_reproduced: Literal[True] = True
    truth_loaded_at_authorization: Literal[False] = False
    synthetic: Literal[True] = True


class V3BlindReport(StrictContract):
    """Official blind scorecard derived by the frozen matcher after prediction."""

    schema_version: Literal["3.0.0"] = "3.0.0"
    report_id: Literal["detector_v3_official_blind_report_v1"] = (
        "detector_v3_official_blind_report_v1"
    )
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: Sha256Digest
    candidate_bundle_sha256: Sha256Digest
    runner_bundle_sha256: Sha256Digest
    matcher_version: Literal["detector_v2_matcher_v1_0_0"] = "detector_v2_matcher_v1_0_0"
    dataset_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    dataset_role: Literal[V2DatasetRole.BLIND] = V2DatasetRole.BLIND
    nonce_sha256: Sha256Digest
    dataset_manifest_sha256: Sha256Digest
    event_artifact_sha256: Sha256Digest
    truth_artifact_sha256: Sha256Digest
    prediction_artifact_sha256: Sha256Digest
    prediction_receipt_sha256: Sha256Digest
    truth_access_receipt_sha256: Sha256Digest
    evaluated_at: AwareDatetime
    labels_loaded_after_prediction_bytes: Literal[True] = True
    official_blind_evaluated: Literal[True] = True
    release_qualified: bool
    approved_for_m4_integration: bool
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True
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
    targets: V2TargetResults
    cases: tuple[V2EvaluationCase, ...] = Field(min_length=1)
    incidents: tuple[V2IncidentEvaluationSummary, ...]
    limitations: tuple[str, ...] = Field(min_length=3)

    @model_validator(mode="after")
    def validate_release_summary(self) -> Self:
        """Prevent blind qualification from disagreeing with target results."""

        if self.release_qualified is not self.targets.all_passed:
            msg = "blind release summary must equal all target comparisons"
            raise ValueError(msg)
        if self.approved_for_m4_integration is not self.release_qualified:
            msg = "M4 integration approval must equal blind qualification"
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
            msg = "blind confusion counts must reconcile with evaluation cases"
            raise ValueError(msg)
        target_checks = (
            self.targets.precision_passed
            is (self.precision_ppm >= self.targets.precision_target_ppm),
            self.targets.recall_passed is (self.recall_ppm >= self.targets.recall_target_ppm),
            self.targets.top_1_attribution_passed
            is (self.top_1_attribution_ppm >= self.targets.top_1_attribution_target_ppm),
            self.targets.median_detection_delay_passed
            is (
                self.median_detection_delay_seconds is not None
                and self.median_detection_delay_seconds
                <= self.targets.median_detection_delay_target_seconds
            ),
            self.targets.hard_negative_action_eligible_incidents_passed
            is (self.hard_negative_action_eligible_incidents == 0),
            self.targets.baseline_leakage_violations_passed
            is (self.baseline_leakage_violations == 0),
            self.targets.evidence_reconciliation_violations_passed
            is (self.evidence_reconciliation_violations == 0),
        )
        if not all(target_checks):
            msg = "blind target flags must reconcile with measured values"
            raise ValueError(msg)
        return self


class V3BlindReleaseDecision(StrictContract):
    """Fail-closed decision that still requires M4 before runtime activation."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    decision_id: Literal["detector_v3_official_blind_release_v1"] = (
        "detector_v3_official_blind_release_v1"
    )
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    source_report_id: Literal["detector_v3_official_blind_report_v1"] = (
        "detector_v3_official_blind_report_v1"
    )
    source_report_sha256: Sha256Digest
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    detector_config_sha256: Sha256Digest
    candidate_bundle_sha256: Sha256Digest
    dataset_manifest_sha256: Sha256Digest
    prediction_artifact_sha256: Sha256Digest
    nonce_sha256: Sha256Digest
    evaluated_at: AwareDatetime
    status: V3BlindReleaseStatus
    failed_targets: tuple[V3BlindReleaseTarget, ...]
    release_qualified: bool
    approved_for_m4_integration: bool
    runtime_action_eligible: Literal[False] = False
    activation_requires_m4: Literal[True] = True
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        """Keep target failures, qualification and integration approval aligned."""

        if len(set(self.failed_targets)) != len(self.failed_targets):
            msg = "failed blind release targets must be unique"
            raise ValueError(msg)
        qualified = self.status is V3BlindReleaseStatus.QUALIFIED
        if qualified is not (not self.failed_targets):
            msg = "blind release status must agree with failed targets"
            raise ValueError(msg)
        if self.release_qualified is not qualified:
            msg = "blind qualification must agree with release status"
            raise ValueError(msg)
        if self.approved_for_m4_integration is not qualified:
            msg = "M4 integration approval must agree with release status"
            raise ValueError(msg)
        return self


class V3BlindNonceReveal(StrictContract):
    """Post-evaluation public nonce disclosure retained for reproducibility."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    reveal_id: str = Field(pattern=r"^nonce_reveal_[a-f0-9]{20}$")
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    nonce: str = Field(min_length=16, max_length=256)
    nonce_sha256: Sha256Digest
    release_decision_sha256: Sha256Digest
    revealed_at: AwareDatetime
    published_after_release_decision: Literal[True] = True
    public_non_secret_value: Literal[True] = True
    reproducibility_only: Literal[True] = True
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_nonce_digest(self) -> Self:
        """Bind the public reveal to the digest committed before generation."""

        if hashlib.sha256(self.nonce.encode()).hexdigest() != self.nonce_sha256:
            msg = "revealed nonce does not match its pre-generation commitment"
            raise ValueError(msg)
        return self


class V3BlindCompletionReceipt(StrictContract):
    """Terminal digest inventory for an append-only official blind run."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    receipt_id: str = Field(pattern=r"^completion_receipt_[a-f0-9]{20}$")
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    status: Literal["official_blind_evaluation_complete"] = "official_blind_evaluation_complete"
    nonce_sha256: Sha256Digest
    procedure_freeze_sha256: Sha256Digest
    prediction_receipt_sha256: Sha256Digest
    truth_access_receipt_sha256: Sha256Digest
    report_sha256: Sha256Digest
    release_decision_sha256: Sha256Digest
    nonce_reveal_sha256: Sha256Digest
    artifacts: tuple[ArtifactDigest, ...] = Field(min_length=8)
    completed_at: AwareDatetime
    predictions_persisted_before_truth: Literal[True] = True
    official_blind_evaluated: Literal[True] = True
    release_qualified: bool
    approved_for_m4_integration: bool
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        """Prevent a completion receipt from overstating integration approval."""

        if self.approved_for_m4_integration is not self.release_qualified:
            msg = "completion integration approval must equal blind qualification"
            raise ValueError(msg)
        paths = tuple(item.path for item in self.artifacts)
        if len(set(paths)) != len(paths):
            msg = "completion artifact paths must be unique"
            raise ValueError(msg)
        return self


class V3BlindFailureReceipt(StrictContract):
    """Safe terminal evidence for a failed run without exception or nonce leakage."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    receipt_id: str = Field(pattern=r"^failure_receipt_[a-f0-9]{20}$")
    run_id: str = Field(pattern=r"^detector_v3_official_blind_[a-f0-9]{20}$")
    status: Literal["official_blind_run_failed"] = "official_blind_run_failed"
    nonce_sha256: Sha256Digest
    failed_stage: V3BlindFailureStage
    recorded_at: AwareDatetime
    truth_may_have_been_loaded: bool
    safe_failure_code: Literal[
        "prediction_stage_failed",
        "scoring_stage_failed",
    ]
    raw_exception_persisted: Literal[False] = False
    requires_new_nonce: Literal[True] = True
    candidate_release_blocked: Literal[True] = True
    runtime_action_eligible: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_failure_stage(self) -> Self:
        """Keep the redacted failure code aligned with its bounded stage."""

        expected_code = f"{self.failed_stage.value}_stage_failed"
        if self.safe_failure_code != expected_code:
            msg = "blind failure code must agree with its stage"
            raise ValueError(msg)
        return self
