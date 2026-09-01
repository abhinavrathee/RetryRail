"""Versioned domain contracts frozen before their behavior is implemented."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from retryrail.events.models import Currency, Dimension, Identifier, PaymentMethod


class StrictContract(BaseModel):
    """Immutable contract base that rejects undeclared fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DatasetSplit(StrEnum):
    """Leakage boundary between detector development and final evaluation."""

    TUNING = "tuning"
    HELDOUT = "heldout"


class CohortDimension(StrEnum):
    """Allowlisted dimensions that can define a detector cohort."""

    METHOD = "method"
    ISSUER = "issuer"
    ERROR_SOURCE = "error_source"
    ERROR_STEP = "error_step"
    ERROR_REASON = "error_reason"


class CohortPredicate(StrictContract):
    """One exact, reviewable cohort condition."""

    dimension: CohortDimension
    value: Dimension


class IncidentStatus(StrEnum):
    """States exposed by the incident contract in P0."""

    OPEN = "open"
    RESOLVED = "resolved"


class IncidentEvidence(StrictContract):
    """Counts and confidence required to justify a degradation incident."""

    baseline_attempts: int = Field(gt=0)
    baseline_successes: int = Field(ge=0)
    current_attempts: int = Field(gt=0)
    current_successes: int = Field(ge=0)
    minimum_attempts: int = Field(gt=0)
    observed_success_rate_drop_bps: int = Field(gt=0, le=10_000)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    excess_failures: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        """Keep successes bounded by their corresponding attempt counts."""

        if self.baseline_successes > self.baseline_attempts:
            msg = "baseline successes cannot exceed baseline attempts"
            raise ValueError(msg)
        if self.current_successes > self.current_attempts:
            msg = "current successes cannot exceed current attempts"
            raise ValueError(msg)
        return self


class IncidentContract(StrictContract):
    """Durable evidence-bearing degradation incident boundary."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    incident_id: Identifier
    merchant_id: Identifier
    status: IncidentStatus
    detector_version: Identifier
    opened_at: AwareDatetime
    last_observed_at: AwareDatetime
    resolved_at: AwareDatetime | None = None
    affected_cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=8)
    evidence_event_ids: tuple[Identifier, ...] = Field(min_length=1)
    evidence: IncidentEvidence
    likely_error_sources: tuple[Dimension, ...] = Field(min_length=1, max_length=3)
    gmv_at_risk_subunits: int = Field(ge=0)
    currency: Currency
    synthetic: bool

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        """Enforce monotonic timestamps and resolved-state completeness."""

        if self.last_observed_at < self.opened_at:
            msg = "last_observed_at cannot precede opened_at"
            raise ValueError(msg)
        if self.status is IncidentStatus.RESOLVED:
            if self.resolved_at is None:
                msg = "resolved incidents require resolved_at"
                raise ValueError(msg)
            if self.resolved_at < self.last_observed_at:
                msg = "resolved_at cannot precede last_observed_at"
                raise ValueError(msg)
        elif self.resolved_at is not None:
            msg = "open incidents cannot have resolved_at"
            raise ValueError(msg)
        return self


class OperatingMode(StrEnum):
    """Merchant control modes accepted by the recovery boundary."""

    ANALYZE_ONLY = "analyze_only"
    REVIEW_FIRST = "review_first"


class RecoveryTemplate(StrEnum):
    """Pre-authorized P0 intervention templates."""

    STANDARD_PAYMENT_LINK = "standard_payment_link"


class RecoveryEligibility(StrictContract):
    """Frozen selection rules evaluated before treatment assignment."""

    failed_payments_only: Literal[True] = True
    incident_members_only: Literal[True] = True
    original_amount_required: Literal[True] = True
    currency: Currency
    methods: tuple[PaymentMethod, ...] = Field(min_length=1)
    minimum_amount_subunits: int = Field(gt=0)
    maximum_amount_subunits: int = Field(gt=0)
    verified_consent_required_for_contact: Literal[True] = True
    exclude_opt_outs: Literal[True] = True
    exclude_already_recovered: Literal[True] = True

    @model_validator(mode="after")
    def validate_amount_range(self) -> Self:
        """Reject inverted eligibility ranges."""

        if self.maximum_amount_subunits < self.minimum_amount_subunits:
            msg = "maximum amount cannot be less than minimum amount"
            raise ValueError(msg)
        return self


class RecoveryStoppingRules(StrictContract):
    """Mandatory bounded-execution controls attached to every plan."""

    maximum_actions: int = Field(gt=0, le=10_000)
    maximum_attempts_per_payment: int = Field(gt=0, le=3)
    cooldown_seconds: int = Field(ge=0, le=604_800)
    expires_at: AwareDatetime
    stop_after_recovery: Literal[True] = True
    merchant_kill_switch_enforced: Literal[True] = True


class RecoveryPlanContract(StrictContract):
    """Policy-reviewable proposal that has no authority to execute itself."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    plan_id: Identifier
    incident_id: Identifier
    merchant_id: Identifier
    mode: OperatingMode
    template: RecoveryTemplate
    policy_version: Identifier
    created_at: AwareDatetime
    eligibility: RecoveryEligibility
    stopping_rules: RecoveryStoppingRules
    eligible_payment_count: int = Field(ge=0)
    eligible_gmv_subunits: int = Field(ge=0)
    currency: Currency
    requires_external_approval: Literal[True] = True
    synthetic: bool

    @model_validator(mode="after")
    def validate_expiry_and_currency(self) -> Self:
        """Keep plan lifetime and monetary units internally consistent."""

        if self.stopping_rules.expires_at <= self.created_at:
            msg = "recovery plan expiry must be after creation"
            raise ValueError(msg)
        if self.eligibility.currency != self.currency:
            msg = "eligibility and plan currencies must match"
            raise ValueError(msg)
        return self


class ActionState(StrEnum):
    """Auditable recovery action states, including ambiguous outcomes."""

    PREVIEWED = "previewed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RECONCILIATION_REQUIRED = "reconciliation_required"


_ALLOWED_ACTION_TRANSITIONS: dict[ActionState | None, frozenset[ActionState]] = {
    None: frozenset({ActionState.PREVIEWED}),
    ActionState.PREVIEWED: frozenset({ActionState.AWAITING_APPROVAL}),
    ActionState.AWAITING_APPROVAL: frozenset(
        {ActionState.APPROVED, ActionState.REJECTED, ActionState.EXPIRED}
    ),
    ActionState.APPROVED: frozenset({ActionState.EXECUTING}),
    ActionState.EXECUTING: frozenset(
        {
            ActionState.SUCCEEDED,
            ActionState.FAILED,
            ActionState.RECONCILIATION_REQUIRED,
        }
    ),
    ActionState.RECONCILIATION_REQUIRED: frozenset(
        {ActionState.SUCCEEDED, ActionState.FAILED}
    ),
    ActionState.REJECTED: frozenset(),
    ActionState.EXPIRED: frozenset(),
    ActionState.SUCCEEDED: frozenset(),
    ActionState.FAILED: frozenset(),
}


class ActionActor(StrEnum):
    """Actors permitted to appear in an action audit chain."""

    SYSTEM = "system"
    MERCHANT = "merchant"
    WORKER = "worker"
    RAZORPAY_TEST_MODE = "razorpay_test_mode"


class ActionTransition(StrictContract):
    """One append-only transition in an action receipt."""

    prior_state: ActionState | None
    new_state: ActionState
    occurred_at: AwareDatetime
    actor: ActionActor
    reason_code: Dimension


class ActionReceiptContract(StrictContract):
    """Execute-once receipt with a complete, internally chained history."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    action_id: Identifier
    plan_id: Identifier
    incident_id: Identifier
    merchant_id: Identifier
    idempotency_key: Identifier
    state: ActionState
    transitions: tuple[ActionTransition, ...] = Field(min_length=1)
    external_reference: Identifier | None = None
    verified_at: AwareDatetime | None = None
    synthetic: bool

    @model_validator(mode="after")
    def validate_transition_chain(self) -> Self:
        """Reject broken, non-monotonic or terminally inconsistent histories."""

        previous_state: ActionState | None = None
        for index, transition in enumerate(self.transitions):
            if transition.prior_state is not previous_state:
                msg = f"transition {index} does not continue the prior state"
                raise ValueError(msg)
            if transition.new_state not in _ALLOWED_ACTION_TRANSITIONS[transition.prior_state]:
                msg = (
                    f"transition {transition.prior_state} -> {transition.new_state} is not allowed"
                )
                raise ValueError(msg)
            if index > 0 and transition.occurred_at < self.transitions[index - 1].occurred_at:
                msg = "action transition timestamps must be monotonic"
                raise ValueError(msg)
            previous_state = transition.new_state

        if previous_state is not self.state:
            msg = "receipt state must equal its last transition"
            raise ValueError(msg)
        if self.state is ActionState.SUCCEEDED:
            if self.external_reference is None or self.verified_at is None:
                msg = "succeeded actions require an external reference and verification time"
                raise ValueError(msg)
            if self.verified_at < self.transitions[-1].occurred_at:
                msg = "verified_at cannot precede the final transition"
                raise ValueError(msg)
        return self


class EvaluationCaseResult(StrictContract):
    """One expected-versus-observed detector decision."""

    scenario_id: Identifier
    expected_incident: bool
    detected_incident: bool
    expected_top_causes: tuple[Dimension, ...] = Field(max_length=3)
    observed_top_causes: tuple[Dimension, ...] = Field(max_length=3)


class DetectorEvaluationContract(StrictContract):
    """Held-out detector score report with integer-scaled metrics."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    evaluation_id: Identifier
    detector_version: Identifier
    dataset_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    dataset_split: Literal[DatasetSplit.HELDOUT] = DatasetSplit.HELDOUT
    evaluated_at: AwareDatetime
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision_ppm: int = Field(ge=0, le=1_000_000)
    recall_ppm: int = Field(ge=0, le=1_000_000)
    top_1_attribution_ppm: int = Field(ge=0, le=1_000_000)
    top_3_attribution_ppm: int = Field(ge=0, le=1_000_000)
    cases: tuple[EvaluationCaseResult, ...] = Field(min_length=1)
    synthetic: Literal[True] = True
