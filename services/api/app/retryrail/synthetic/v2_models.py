"""Strict contracts for the detector-v2 development and blind protocol."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import CohortPredicate, StrictContract
from retryrail.events.models import Currency, ErrorEvidence, Identifier, PaymentMethod
from retryrail.synthetic.models import ArtifactDigest, ArtifactPath, ScenarioKind, Sha256Digest


class V2DatasetRole(StrEnum):
    """Whether labels may be used for development or only final scoring."""

    DEVELOPMENT = "development"
    BLIND = "blind"


class V2ScenarioFamily(StrEnum):
    """Precommitted scenario families represented in both v2 partitions."""

    METHOD_PROVIDER_DEGRADATION = "method_provider_degradation"
    ISSUER_PROVIDER_DEGRADATION = "issuer_provider_degradation"
    CUSTOMER_BEHAVIOR_SPIKE = "customer_behavior_spike"
    LOW_VOLUME_SPIKE = "low_volume_spike"
    TRANSIENT_PROVIDER_BURST = "transient_provider_burst"


class V2ScenarioDefinition(StrictContract):
    """Evaluation-only expected episode kept outside normalized events."""

    scenario_id: Identifier
    dataset_role: V2DatasetRole
    family: V2ScenarioFamily
    kind: ScenarioKind
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    affected_cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=2)
    baseline_failure_rate_bps: int = Field(ge=0, le=10_000)
    seeded_failure_rate_bps: int = Field(gt=0, le=10_000)
    expected_root_cause: ErrorEvidence
    should_open_incident: bool
    expected_gate_reason: str = Field(min_length=3, max_length=80)
    actual_attempt_count: int = Field(ge=0)
    actual_failure_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_scenario(self) -> Self:
        """Keep scenario semantics and realized counts internally consistent."""

        if self.ends_at <= self.starts_at:
            msg = "scenario end must be after its start"
            raise ValueError(msg)
        if self.seeded_failure_rate_bps <= self.baseline_failure_rate_bps:
            msg = "seeded failure rate must exceed baseline"
            raise ValueError(msg)
        if self.actual_failure_count > self.actual_attempt_count:
            msg = "scenario failures cannot exceed attempts"
            raise ValueError(msg)
        if not self.expected_root_cause.has_signal():
            msg = "scenario root cause requires structured evidence"
            raise ValueError(msg)
        expected_incident = self.kind is ScenarioKind.TRUE_INCIDENT
        if self.should_open_incident is not expected_incident:
            msg = "scenario kind and incident expectation disagree"
            raise ValueError(msg)
        true_families = {
            V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION,
            V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
        }
        if expected_incident is not (self.family in true_families):
            msg = "only precommitted provider-degradation families are incidents"
            raise ValueError(msg)
        return self


class V2AttemptTruth(StrictContract):
    """Evaluation-only v2 attempt label physically separate from runtime events."""

    schema_version: Literal["2.0.0"] = "2.0.0"
    attempt_id: Identifier
    payment_id: Identifier
    dataset_role: V2DatasetRole
    occurred_at: AwareDatetime
    amount_subunits: int = Field(gt=0)
    currency: Currency
    method: PaymentMethod
    issuer: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    failed: bool
    normalized_event_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=2)
    scenario_id: Identifier | None = None
    expected_incident_member: bool
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_membership(self) -> Self:
        """Require incident membership to identify its evaluation scenario."""

        if self.expected_incident_member and self.scenario_id is None:
            msg = "incident members require a scenario id"
            raise ValueError(msg)
        return self


class V2DatasetManifest(StrictContract):
    """Versioned identity for one development or nonce-derived blind batch."""

    schema_version: Literal["2.0.0"] = "2.0.0"
    dataset_id: Identifier
    generator_version: Identifier
    dataset_role: V2DatasetRole
    seed_commitment_sha256: Sha256Digest
    merchant_id: Identifier
    currency: Currency
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    attempt_interval_seconds: Literal[30] = 30
    payment_attempts: int = Field(ge=5_000)
    normalized_events: int = Field(gt=0)
    true_incident_count: int = Field(ge=6)
    hard_negative_count: int = Field(ge=4)
    event_artifact: ArtifactPath
    truth_artifact: ArtifactPath
    scenarios: tuple[V2ScenarioDefinition, ...] = Field(min_length=10, max_length=10)
    artifacts: tuple[ArtifactDigest, ArtifactDigest]
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        """Reconcile counts, role isolation, paths and artifact identities."""

        if self.ends_at <= self.starts_at:
            msg = "dataset end must be after its start"
            raise ValueError(msg)
        if any(item.dataset_role is not self.dataset_role for item in self.scenarios):
            msg = "all scenarios must match the dataset role"
            raise ValueError(msg)
        true_count = sum(item.kind is ScenarioKind.TRUE_INCIDENT for item in self.scenarios)
        hard_count = sum(item.kind is ScenarioKind.HARD_NEGATIVE for item in self.scenarios)
        if (true_count, hard_count) != (
            self.true_incident_count,
            self.hard_negative_count,
        ):
            msg = "manifest scenario counts do not reconcile"
            raise ValueError(msg)
        if self.event_artifact == self.truth_artifact:
            msg = "runtime events and evaluation truth must be physically separate"
            raise ValueError(msg)
        artifact_paths = {item.path for item in self.artifacts}
        if artifact_paths != {self.event_artifact, self.truth_artifact}:
            msg = "manifest artifact identities do not reconcile"
            raise ValueError(msg)
        if sum(item.actual_attempt_count for item in self.scenarios) <= 0:
            msg = "scenarios must match realized attempts"
            raise ValueError(msg)
        return self


class V2ReleaseTargets(StrictContract):
    """Precommitted release thresholds copied from product requirements."""

    precision_ppm: Literal[900_000] = 900_000
    recall_ppm: Literal[850_000] = 850_000
    top_1_attribution_ppm: Literal[800_000] = 800_000
    median_detection_delay_seconds: Literal[600] = 600
    hard_negative_action_eligible_incidents: Literal[0] = 0
    baseline_leakage_violations: Literal[0] = 0
    evidence_reconciliation_violations: Literal[0] = 0


class V2EvaluationProtocol(StrictContract):
    """Immutable process contract established before v2 candidate work."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    protocol_id: Identifier
    status: Literal["precommitted"] = "precommitted"
    precommitted_at: AwareDatetime
    generator_version: Identifier
    generator_bundle_sha256: Sha256Digest
    development_dataset_id: Identifier
    development_manifest_sha256: Sha256Digest
    allowed_development_dataset_ids: tuple[Identifier, ...] = Field(min_length=2)
    official_blind_nonce_required: Literal[True] = True
    official_blind_nonce_minimum_characters: Literal[16] = 16
    official_blind_nonce_after_candidate_freeze: Literal[True] = True
    predictions_persisted_before_blind_labels_loaded: Literal[True] = True
    configuration_change_requires_new_nonce: Literal[True] = True
    official_blind_true_incidents: Literal[6] = 6
    official_blind_hard_negatives: Literal[4] = 4
    scenario_family_counts: dict[V2ScenarioFamily, int]
    forbidden_test_nonce_sha256: tuple[Sha256Digest, ...] = Field(min_length=2)
    release_targets: V2ReleaseTargets
    rules: tuple[str, ...] = Field(min_length=6)

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        """Prevent a protocol that under-specifies the blind scenario suite."""

        if sum(self.scenario_family_counts.values()) != (
            self.official_blind_true_incidents + self.official_blind_hard_negatives
        ):
            msg = "blind scenario family counts must reconcile"
            raise ValueError(msg)
        required = set(V2ScenarioFamily)
        if set(self.scenario_family_counts) != required:
            msg = "every v2 scenario family must be precommitted"
            raise ValueError(msg)
        if len(set(self.allowed_development_dataset_ids)) != len(
            self.allowed_development_dataset_ids
        ):
            msg = "development dataset identifiers must be unique"
            raise ValueError(msg)
        return self
