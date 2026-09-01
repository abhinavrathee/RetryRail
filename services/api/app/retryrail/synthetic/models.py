"""Strict contracts for generated truth data and delivery reliability cases."""

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from retryrail.contracts.domain import CohortPredicate, DatasetSplit, StrictContract
from retryrail.events.models import (
    Currency,
    Dimension,
    ErrorEvidence,
    Identifier,
    PaymentMethod,
    PaymentStatus,
)

_BASIS_POINTS_TOTAL = 10_000
_MINIMUM_TRUE_INCIDENTS = 3

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
ArtifactPath = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=160,
        pattern=r"^[A-Za-z0-9_./-]+$",
    ),
]


class ScenarioKind(StrEnum):
    """Ground-truth scenario labels kept outside runtime events."""

    TRUE_INCIDENT = "true_incident"
    HARD_NEGATIVE = "hard_negative"


class ScenarioSeverity(StrEnum):
    """Human-reviewable seeded degradation strength."""

    MEDIUM = "medium"
    HIGH = "high"


class ScenarioDefinition(StrictContract):
    """Exact expected episode boundaries and cause labels."""

    scenario_id: Identifier
    split: DatasetSplit
    kind: ScenarioKind
    severity: ScenarioSeverity
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    affected_cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=8)
    baseline_failure_rate_bps: int = Field(ge=0, le=10_000)
    seeded_failure_rate_bps: int = Field(ge=0, le=10_000)
    expected_root_cause: ErrorEvidence
    should_open_incident: bool
    expected_gate_reason: Dimension
    actual_attempt_count: int = Field(ge=0)
    actual_failure_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_scenario(self) -> Self:
        """Keep time, labels and observed counts consistent."""

        if self.ends_at <= self.starts_at:
            msg = "scenario end must be after its start"
            raise ValueError(msg)
        if self.seeded_failure_rate_bps <= self.baseline_failure_rate_bps:
            msg = "seeded failure rate must exceed the baseline rate"
            raise ValueError(msg)
        if self.actual_failure_count > self.actual_attempt_count:
            msg = "scenario failures cannot exceed scenario attempts"
            raise ValueError(msg)
        expected_incident = self.kind is ScenarioKind.TRUE_INCIDENT
        if self.should_open_incident is not expected_incident:
            msg = "scenario kind and incident expectation disagree"
            raise ValueError(msg)
        if not self.expected_root_cause.has_signal():
            msg = "scenarios require structured root-cause evidence"
            raise ValueError(msg)
        return self


class AttemptGroundTruth(StrictContract):
    """Evaluation-only label for one synthetic payment attempt."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    attempt_id: Identifier
    payment_id: Identifier
    split: DatasetSplit
    occurred_at: AwareDatetime
    amount_subunits: int = Field(gt=0)
    currency: Currency
    method: PaymentMethod
    issuer: Dimension
    final_status: Literal[PaymentStatus.FAILED, PaymentStatus.CAPTURED]
    normalized_event_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=2)
    scenario_id: Identifier | None = None
    expected_incident_member: bool
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_membership_label(self) -> Self:
        """Ensure incident membership always names its scenario."""

        if self.expected_incident_member and self.scenario_id is None:
            msg = "incident members require a scenario_id"
            raise ValueError(msg)
        return self


class SignatureMode(StrEnum):
    """Signature condition applied by the future replay boundary."""

    VALID = "valid"
    INVALID = "invalid"
    MISSING = "missing"


class BodyMode(StrEnum):
    """Whether the body is changed after signature calculation."""

    UNMODIFIED = "unmodified"
    MODIFIED_AFTER_SIGNING = "modified_after_signing"


class ExpectedDeliveryDisposition(StrEnum):
    """Expected ingress decision, not a persisted business label."""

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED_SIGNATURE = "rejected_signature"


class ReliabilityCase(StrEnum):
    """Delivery anomalies represented independently from event truth."""

    DUPLICATE = "duplicate"
    DELAYED = "delayed"
    INVALID_SIGNATURE = "invalid_signature"
    MISSING_SIGNATURE = "missing_signature"
    MODIFIED_BODY = "modified_body"
    OUT_OF_ORDER = "out_of_order"


class WebhookDeliveryInstruction(StrictContract):
    """One deterministic webhook delivery attempt for M2 replay."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    sequence: int = Field(gt=0)
    delivery_id: Identifier
    merchant_id: Identifier
    razorpay_event_id: Identifier
    delivery_attempt: int = Field(gt=0, le=10)
    delivered_at: AwareDatetime
    signature_mode: SignatureMode
    body_mode: BodyMode
    expected_disposition: ExpectedDeliveryDisposition
    reliability_case: ReliabilityCase | None = None
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_expected_disposition(self) -> Self:
        """Prevent an invalid or mutated payload from being marked accepted."""

        authentic = (
            self.signature_mode is SignatureMode.VALID
            and self.body_mode is BodyMode.UNMODIFIED
        )
        if (
            authentic
            and self.expected_disposition is ExpectedDeliveryDisposition.REJECTED_SIGNATURE
        ):
            msg = "authentic deliveries cannot expect signature rejection"
            raise ValueError(msg)
        if (
            not authentic
            and self.expected_disposition is not ExpectedDeliveryDisposition.REJECTED_SIGNATURE
        ):
            msg = "unauthentic deliveries must expect signature rejection"
            raise ValueError(msg)
        return self


class ArtifactDigest(StrictContract):
    """Stable identity and record count for one generated artifact."""

    path: ArtifactPath
    sha256: Sha256Digest
    bytes: int = Field(gt=0)
    records: int = Field(gt=0)

    @model_validator(mode="after")
    def reject_path_traversal(self) -> Self:
        """Constrain generated artifacts to safe repository-relative paths."""

        path = PurePosixPath(self.path)
        if path.is_absolute() or ".." in path.parts:
            msg = "artifact path must be repository-relative without traversal"
            raise ValueError(msg)
        return self


class DatasetPartition(StrictContract):
    """Physical split boundary and its exact volume."""

    split: DatasetSplit
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    payment_attempts: int = Field(gt=0)
    normalized_events: int = Field(gt=0)
    event_artifact: ArtifactPath
    truth_artifact: ArtifactPath

    @model_validator(mode="after")
    def validate_time_range(self) -> Self:
        """Reject empty or inverted data windows."""

        if self.ends_at <= self.starts_at:
            msg = "partition end must be after its start"
            raise ValueError(msg)
        return self


class ExperimentDesign(StrictContract):
    """Pre-results assignment and outcome rules frozen for later M5 use."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    design_id: Identifier
    frozen_at: AwareDatetime
    eligibility_frozen_before_assignment: Literal[True] = True
    incident_members_only: Literal[True] = True
    failed_payments_only: Literal[True] = True
    exclude_already_recovered: Literal[True] = True
    assignment_unit: Literal["payment_id"] = "payment_id"
    assignment_hash: Literal["sha256"] = "sha256"
    assignment_namespace: Identifier
    outcome_namespace: Identifier
    treatment_allocation_bps: int = Field(gt=0, lt=10_000)
    control_allocation_bps: int = Field(gt=0, lt=10_000)
    strata: tuple[Dimension, ...] = Field(min_length=1)
    control_recovery_rate_bps: int = Field(ge=0, le=10_000)
    treatment_recovery_rate_bps: int = Field(ge=0, le=10_000)
    attribution_window_seconds: int = Field(gt=0, le=604_800)
    inconclusive_when_interval_crosses_zero: Literal[True] = True
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_precommitted_design(self) -> Self:
        """Keep allocation complete and outcome draws independent of assignment."""

        if (
            self.treatment_allocation_bps + self.control_allocation_bps
            != _BASIS_POINTS_TOTAL
        ):
            msg = "treatment and control allocation must total 10,000 basis points"
            raise ValueError(msg)
        if self.assignment_namespace == self.outcome_namespace:
            msg = "assignment and outcome namespaces must be independent"
            raise ValueError(msg)
        if self.treatment_recovery_rate_bps <= self.control_recovery_rate_bps:
            msg = "seeded treatment recovery rate must exceed control"
            raise ValueError(msg)
        return self


class DeliveryCaseSummary(StrictContract):
    """Reviewable count of every required reliability anomaly."""

    reliability_case: ReliabilityCase
    delivery_attempts: int = Field(gt=0)
    expected_rejections: int = Field(ge=0)
    expected_duplicates: int = Field(ge=0)


class SyntheticDatasetManifest(StrictContract):
    """Committed, human-reviewable identity of the complete M1 truth set."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    dataset_id: Identifier
    generator_version: Identifier
    deterministic_seed: Identifier
    merchant_id: Identifier
    currency: Currency
    synthetic: Literal[True] = True
    total_payment_attempts: int = Field(ge=2_000)
    total_normalized_events: int = Field(gt=0)
    partitions: tuple[DatasetPartition, ...] = Field(min_length=2, max_length=2)
    scenarios: tuple[ScenarioDefinition, ...] = Field(min_length=4)
    delivery_cases: tuple[DeliveryCaseSummary, ...] = Field(min_length=5)
    experiment_design: ExperimentDesign
    artifacts: tuple[ArtifactDigest, ...] = Field(min_length=5)

    @model_validator(mode="after")
    def validate_manifest_totals(self) -> Self:
        """Reconcile totals and enforce the pre-tuning split contract."""

        split_set = {partition.split for partition in self.partitions}
        if split_set != {DatasetSplit.TUNING, DatasetSplit.HELDOUT}:
            msg = "manifest requires one tuning and one held-out partition"
            raise ValueError(msg)
        if sum(part.payment_attempts for part in self.partitions) != self.total_payment_attempts:
            msg = "partition attempt counts do not reconcile with the manifest"
            raise ValueError(msg)
        if sum(part.normalized_events for part in self.partitions) != self.total_normalized_events:
            msg = "partition event counts do not reconcile with the manifest"
            raise ValueError(msg)

        true_incidents = [
            scenario for scenario in self.scenarios if scenario.kind is ScenarioKind.TRUE_INCIDENT
        ]
        hard_negatives = [
            scenario for scenario in self.scenarios if scenario.kind is ScenarioKind.HARD_NEGATIVE
        ]
        if len(true_incidents) < _MINIMUM_TRUE_INCIDENTS or not hard_negatives:
            msg = "manifest requires three true incidents and one hard negative"
            raise ValueError(msg)
        if not any(scenario.split is DatasetSplit.HELDOUT for scenario in true_incidents):
            msg = "held-out partition requires a true incident"
            raise ValueError(msg)
        if not any(scenario.split is DatasetSplit.TUNING for scenario in true_incidents):
            msg = "tuning partition requires a true incident"
            raise ValueError(msg)
        if any(scenario.split is not DatasetSplit.HELDOUT for scenario in hard_negatives):
            msg = "hard negatives must remain in the held-out partition"
            raise ValueError(msg)
        return self
