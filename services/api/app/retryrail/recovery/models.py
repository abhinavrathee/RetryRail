"""Typed M4.3 preview, decision and token-consumption boundaries."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AnyHttpUrl, AwareDatetime, Field, StringConstraints, model_validator

from retryrail.contracts.domain import (
    ActionState,
    OperatingMode,
    RecoveryPlanContract,
    RecoveryTemplate,
    StrictContract,
)
from retryrail.contracts.recovery import (
    ApprovalDecision,
    ApprovalRecordContract,
    ApprovalStatus,
    PolicyDecision,
    PolicyResultContract,
    RecoveryActionContract,
    RecoveryEffect,
    RecoveryExecutionTarget,
    RecoveryTemplateContract,
    Sha256Digest,
)
from retryrail.events.models import Currency, Identifier
from retryrail.recovery.adapter import PaymentLinkStatus

ApprovalBearer = Annotated[
    str,
    StringConstraints(
        min_length=50,
        max_length=80,
        pattern=r"^rr_apv_[A-Za-z0-9_-]{43}$",
    ),
]


class PreviewPersistenceDisposition(StrEnum):
    """Whether this call wrote evidence or safely reused existing evidence."""

    CREATED = "created"
    REPLAYED = "replayed"
    RETRIEVED = "retrieved"


class TokenDelivery(StrEnum):
    """Raw approval bearers are delivered once and never reconstructed."""

    ISSUED_ONCE = "issued_once"
    NOT_APPLICABLE = "not_applicable"
    NOT_REPEATED = "not_repeated"


class CreateRecoveryPlanRequest(StrictContract):
    """Caller-selected identity only; no policy, money or eligibility facts."""

    payment_id: Identifier
    idempotency_key: Identifier


class ApprovalDecisionRequest(StrictContract):
    """Idempotency input for an authenticated route-specific merchant decision."""

    idempotency_key: Identifier


class RecoveryErrorDetail(StrictContract):
    """Low-cardinality recovery error safe to return to a caller."""

    reason_code: Identifier


class RecoveryErrorResponse(StrictContract):
    """Typed FastAPI error envelope."""

    detail: RecoveryErrorDetail


class RecoverySourceEvidence(StrictContract):
    """Exact PII-free record versions used to assemble one policy snapshot."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    merchant_id: Identifier
    incident_id: Identifier
    payment_id: Identifier
    source_event_internal_id: Identifier
    source_razorpay_event_id: Identifier
    payment_projection_version: int = Field(gt=0)
    recovery_control_version: int = Field(gt=0)
    detector_version: Identifier
    detector_config_sha256: Sha256Digest
    incident_last_observed_at: AwareDatetime
    synthetic: bool


class RecoveryPlanPreview(StrictContract):
    """Complete persisted request/effect preview plus deterministic policy evidence."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    plan: RecoveryPlanContract
    payment_id: Identifier
    amount_subunits: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    template: RecoveryTemplateContract
    execution_target: RecoveryExecutionTarget
    effect: RecoveryEffect
    external_notifications_enabled: Literal[False] = False
    plan_sha256: Sha256Digest
    source_evidence: RecoverySourceEvidence
    source_evidence_sha256: Sha256Digest
    policy_result: PolicyResultContract
    policy_result_sha256: Sha256Digest
    preview_policy_allowed: bool
    persisted_at: AwareDatetime
    synthetic: bool

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        """Prevent a preview from mixing evidence across plans, tenants or payments."""

        context = self.policy_result.context
        if (
            context.plan_id != self.plan.plan_id
            or context.incident_id != self.plan.incident_id
            or context.merchant_id != self.plan.merchant_id
            or context.payment_id != self.payment_id
        ):
            msg = "preview policy context does not bind to its plan"
            raise ValueError(msg)
        if (
            self.source_evidence.merchant_id != self.plan.merchant_id
            or self.source_evidence.incident_id != self.plan.incident_id
            or self.source_evidence.payment_id != self.payment_id
        ):
            msg = "preview source evidence does not bind to its plan"
            raise ValueError(msg)
        if (
            context.proposed_amount_subunits != self.amount_subunits
            or context.proposed_currency != self.currency
            or self.plan.eligible_payment_count != 1
            or self.plan.eligible_gmv_subunits != self.amount_subunits
            or self.plan.currency != self.currency
        ):
            msg = "preview money does not bind to its plan and policy context"
            raise ValueError(msg)
        if (
            context.template is not self.plan.template
            or context.execution_target is not self.execution_target
            or self.template.template is not self.plan.template
            or self.template.effect is not self.effect
        ):
            msg = "preview template or execution target is inconsistent"
            raise ValueError(msg)
        expected_approval = self.policy_result.decision is PolicyDecision.ALLOW
        if self.preview_policy_allowed is not expected_approval:
            msg = "preview allow flag must equal the recorded policy decision"
            raise ValueError(msg)
        if (
            self.synthetic is not self.plan.synthetic
            or self.synthetic is not context.synthetic
            or self.synthetic is not self.source_evidence.synthetic
        ):
            msg = "preview synthetic labels must match"
            raise ValueError(msg)
        return self


class RecoveryPlanPreviewResponse(StrictContract):
    """Idempotent HTTP response for creation, replay or retrieval of a preview."""

    disposition: PreviewPersistenceDisposition
    preview: RecoveryPlanPreview


class PublicApprovalRecord(StrictContract):
    """Approval audit view that deliberately excludes the persisted token hash."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    approval_id: Identifier
    plan_id: Identifier
    incident_id: Identifier
    merchant_id: Identifier
    policy_result_id: Identifier
    plan_sha256: Sha256Digest
    policy_result_sha256: Sha256Digest
    actor_id: Identifier
    actor_type: Literal["merchant"] = "merchant"
    decision: ApprovalDecision
    status: ApprovalStatus
    decided_at: AwareDatetime
    issued_at: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    consumed_at: AwareDatetime | None = None
    single_use: Literal[True] = True
    synthetic: bool

    @classmethod
    def from_internal(cls, record: ApprovalRecordContract) -> "PublicApprovalRecord":
        """Drop the keyed hash before crossing the merchant-facing API boundary."""

        return cls.model_validate(record.model_dump(exclude={"token_hash", "side_effect"}))


class ApprovalDecisionResponse(StrictContract):
    """Merchant decision receipt with an optional one-time raw bearer delivery."""

    disposition: Literal["created", "replayed"]
    approval: PublicApprovalRecord
    approval_token: ApprovalBearer | None = None
    token_delivery: TokenDelivery

    @model_validator(mode="after")
    def validate_token_delivery(self) -> Self:
        """Ensure only the first successful approval response can carry a bearer."""

        if self.approval_token is not None:
            valid_first_issue = (
                self.disposition == "created"
                and self.approval.decision is ApprovalDecision.APPROVE
                and self.approval.status is ApprovalStatus.ISSUED
                and self.token_delivery is TokenDelivery.ISSUED_ONCE
            )
            if not valid_first_issue:
                msg = "approval bearer may only appear on its first issued response"
                raise ValueError(msg)
            return self
        expected = (
            TokenDelivery.NOT_REPEATED
            if self.disposition == "replayed" and self.approval.decision is ApprovalDecision.APPROVE
            else TokenDelivery.NOT_APPLICABLE
        )
        if self.token_delivery is not expected:
            msg = "token delivery status does not match the decision response"
            raise ValueError(msg)
        return self


class ApprovalTokenBinding(StrictContract):
    """Execution-owned values to which an approval bearer is cryptographically bound."""

    merchant_id: Identifier
    incident_id: Identifier
    plan_id: Identifier
    policy_result_id: Identifier
    plan_sha256: Sha256Digest
    policy_result_sha256: Sha256Digest
    consumption_idempotency_key: Identifier


class ExecuteRecoveryPlanRequest(StrictContract):
    """Caller-chosen replay key; every execution fact remains server-owned."""

    idempotency_key: Identifier


class ReconcileRecoveryActionRequest(StrictContract):
    """Idempotency input for one read-only provider reconciliation attempt."""

    idempotency_key: Identifier


class RecoveryExecutionDisposition(StrEnum):
    """Whether execution created, replayed or safely blocked durable evidence."""

    CREATED = "created"
    REPLAYED = "replayed"
    BLOCKED = "blocked"


class ProviderVerificationSource(StrEnum):
    """How RetryRail obtained the authoritative provider representation."""

    CREATE_RESPONSE = "create_response"
    REFERENCE_LOOKUP = "reference_lookup"


class RecoveryProviderReceipt(StrictContract):
    """Redacted immutable proof of one fake or Razorpay Test Mode provider entity."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    provider_receipt_id: Identifier
    dispatch_id: Identifier
    action_id: Identifier
    plan_id: Identifier
    incident_id: Identifier
    merchant_id: Identifier
    execution_target: RecoveryExecutionTarget
    provider_action_id: Identifier
    reference_id: Identifier
    status: PaymentLinkStatus
    amount_subunits: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    short_url: AnyHttpUrl | None = None
    provider_created_at: AwareDatetime
    verified_at: AwareDatetime
    verification_source: ProviderVerificationSource
    request_sha256: Sha256Digest
    response_sha256: Sha256Digest
    external_notifications_enabled: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_provider_receipt(self) -> Self:
        """Require HTTPS Test Mode evidence and monotonic provider timestamps."""

        if self.verified_at < self.provider_created_at:
            msg = "provider receipt verification cannot precede creation"
            raise ValueError(msg)
        if self.short_url is not None and self.short_url.scheme != "https":
            msg = "provider receipt short URL must use HTTPS"
            raise ValueError(msg)
        if (
            self.execution_target is RecoveryExecutionTarget.RAZORPAY_TEST_MODE
            and self.short_url is None
        ):
            msg = "Razorpay Test Mode receipts require the returned short URL"
            raise ValueError(msg)
        return self


class RecoveryExecutionResponse(StrictContract):
    """Typed execution boundary including fresh policy and optional action receipt."""

    disposition: RecoveryExecutionDisposition
    receipt: RecoveryActionContract | None = None
    provider_receipt: RecoveryProviderReceipt | None = None
    execution_policy_result: PolicyResultContract | None = None
    execution_policy_result_sha256: Sha256Digest | None = None
    synthetic: bool

    @model_validator(mode="after")
    def validate_execution_result(self) -> Self:
        """Keep policy denial, expiry and executable receipts unambiguous."""

        if self.disposition is RecoveryExecutionDisposition.BLOCKED:
            if self.receipt is not None or self.provider_receipt is not None:
                msg = "blocked execution cannot contain action or provider receipts"
                raise ValueError(msg)
            if (
                self.execution_policy_result is None
                or self.execution_policy_result.decision is not PolicyDecision.DENY
                or self.execution_policy_result_sha256 is None
            ):
                msg = "blocked execution requires complete denied policy evidence"
                raise ValueError(msg)
            return self
        if self.receipt is None:
            msg = "created and replayed execution require an action receipt"
            raise ValueError(msg)
        if self.synthetic is not self.receipt.synthetic:
            msg = "execution and receipt synthetic labels must match"
            raise ValueError(msg)
        self._validate_provider_binding()
        if self.receipt.execution_policy_result_id is None:
            if self.receipt.state is not ActionState.EXPIRED:
                msg = "only expired receipts may omit execution policy evidence"
                raise ValueError(msg)
            if (
                self.execution_policy_result is not None
                or self.execution_policy_result_sha256 is not None
            ):
                msg = "expired receipt cannot contain execution policy evidence"
                raise ValueError(msg)
            return self
        if (
            self.execution_policy_result is None
            or self.execution_policy_result_sha256 is None
            or self.execution_policy_result.decision is not PolicyDecision.ALLOW
            or self.execution_policy_result.policy_result_id
            != self.receipt.execution_policy_result_id
        ):
            msg = "action receipt requires its complete allowed execution policy"
            raise ValueError(msg)
        return self

    def _validate_provider_binding(self) -> None:
        """Bind optional sanitized provider evidence to one succeeded action."""

        if self.provider_receipt is None or self.receipt is None:
            return
        if (
            self.receipt.state is not ActionState.SUCCEEDED
            or self.provider_receipt.action_id != self.receipt.action_id
            or self.provider_receipt.provider_action_id != self.receipt.provider_action_id
            or self.provider_receipt.execution_target is not self.receipt.execution_target
            or self.provider_receipt.synthetic is not self.receipt.synthetic
        ):
            msg = "provider receipt does not bind to the succeeded action"
            raise ValueError(msg)


class RecoveryReconciliationResponse(StrictContract):
    """Idempotent resolution of an ambiguous fake-provider outcome."""

    disposition: Literal["created", "replayed"]
    receipt: RecoveryActionContract
    provider_receipt: RecoveryProviderReceipt | None = None

    @model_validator(mode="after")
    def validate_terminal_receipt(self) -> Self:
        """Reconciliation must end in a verified success or definite failure."""

        if self.receipt.state not in {ActionState.SUCCEEDED, ActionState.FAILED}:
            msg = "reconciliation response requires a terminal receipt"
            raise ValueError(msg)
        if self.provider_receipt is not None and (
            self.receipt.state is not ActionState.SUCCEEDED
            or self.provider_receipt.action_id != self.receipt.action_id
            or self.provider_receipt.provider_action_id != self.receipt.provider_action_id
        ):
            msg = "reconciliation provider receipt does not bind to its action"
            raise ValueError(msg)
        return self


class RulesVerifiedEvidence(StrictContract):
    """One deterministic factual claim with exact incident event citations."""

    evidence_id: Identifier
    statement: str = Field(min_length=1, max_length=300)
    evidence_event_ids: tuple[Identifier, ...] = Field(min_length=1)
    evidence_kind: Literal["verified_observation"] = "verified_observation"


class RulesHypothesis(StrictContract):
    """A bounded merchant-local interpretation kept separate from observations."""

    statement: str = Field(min_length=1, max_length=300)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    evidence_event_ids: tuple[Identifier, ...] = Field(min_length=1)
    evidence_kind: Literal["inferred_hypothesis"] = "inferred_hypothesis"


class RulesExpectedBenefit(StrictContract):
    """Observed opportunity, deliberately not a forecast or recovered-GMV claim."""

    opportunity_gmv_subunits: int = Field(ge=0)
    currency: Currency
    interpretation: Literal["at_risk_opportunity_not_forecast"] = "at_risk_opportunity_not_forecast"


class RulesCustomerRisk(StrictContract):
    """Customer-impact statement bound to the no-notification fake action."""

    level: Literal["low"] = "low"
    external_notifications_enabled: Literal[False] = False
    statement: Literal[
        "No customer message is sent; any action still requires merchant approval."
    ] = "No customer message is sent; any action still requires merchant approval."


class RulesBasedIncidentBrief(StrictContract):
    """Typed model-unavailable incident brief produced only from validated facts."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    brief_id: Identifier
    incident_id: Identifier
    executive_summary: str = Field(min_length=1, max_length=500)
    executive_summary_evidence_ids: tuple[Identifier, ...] = Field(min_length=1)
    verified_evidence: tuple[RulesVerifiedEvidence, ...] = Field(min_length=3)
    hypotheses: tuple[RulesHypothesis, ...] = Field(min_length=1, max_length=3)
    unknowns: tuple[str, ...] = Field(min_length=1, max_length=5)
    recommended_template: Literal[RecoveryTemplate.STANDARD_PAYMENT_LINK] = (
        RecoveryTemplate.STANDARD_PAYMENT_LINK
    )
    expected_benefit: RulesExpectedBenefit
    customer_risk: RulesCustomerRisk = Field(default_factory=RulesCustomerRisk)
    confidence: int = Field(ge=0, le=1_000_000)
    stop_conditions: tuple[Identifier, ...] = Field(min_length=6)
    analyst_mode: Literal["deterministic_rules"] = "deterministic_rules"
    synthetic: bool

    @model_validator(mode="after")
    def validate_citations(self) -> Self:
        """Require summary and hypotheses to cite the brief's verified event set."""

        cited_events = {
            event_id
            for evidence in self.verified_evidence
            for event_id in evidence.evidence_event_ids
        }
        if not set(self.executive_summary_evidence_ids).issubset(cited_events):
            msg = "executive summary cites evidence outside the verified set"
            raise ValueError(msg)
        if any(
            not set(hypothesis.evidence_event_ids).issubset(cited_events)
            for hypothesis in self.hypotheses
        ):
            msg = "hypothesis cites evidence outside the verified set"
            raise ValueError(msg)
        return self


class RulesBasedPlanFallback(StrictContract):
    """Deterministic bridge to the existing server-owned plan preview boundary."""

    incident_id: Identifier
    mode: Literal[OperatingMode.REVIEW_FIRST] = OperatingMode.REVIEW_FIRST
    recommended_template: Literal[RecoveryTemplate.STANDARD_PAYMENT_LINK] = (
        RecoveryTemplate.STANDARD_PAYMENT_LINK
    )
    can_create_plan: bool
    reason_code: Identifier
    requires_external_approval: Literal[True] = True
    external_notifications_enabled: Literal[False] = False
    plan_endpoint: str = Field(min_length=1, max_length=200)
    synthetic: bool

    @model_validator(mode="after")
    def validate_availability_reason(self) -> Self:
        """Bind availability to one stable reason for UI and audit use."""

        expected = (
            "RULES_FALLBACK_PLAN_AVAILABLE"
            if self.can_create_plan
            else "INCIDENT_NOT_ACTION_ELIGIBLE"
        )
        if self.reason_code != expected:
            msg = "fallback-plan reason does not match availability"
            raise ValueError(msg)
        return self


class RulesAnalysisDisposition(StrEnum):
    """Whether an identical incident snapshot created or replayed its brief."""

    CREATED = "created"
    REPLAYED = "replayed"


class RulesBasedIncidentAnalysisResponse(StrictContract):
    """Persistent deterministic analysis used explicitly when no model is available."""

    disposition: RulesAnalysisDisposition
    brief: RulesBasedIncidentBrief
    plan_fallback: RulesBasedPlanFallback
    model_status: Literal["unavailable"] = "unavailable"
    fallback_used: Literal[True] = True

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        """Keep the brief, fallback proposal and simulation label on one incident."""

        if (
            self.brief.incident_id != self.plan_fallback.incident_id
            or self.brief.synthetic is not self.plan_fallback.synthetic
        ):
            msg = "analysis brief and plan fallback are not bound"
            raise ValueError(msg)
        return self


class RecoveryAuditCompletenessReport(StrictContract):
    """Machine-checkable correlation result for one full recovery action."""

    action_id: Identifier
    incident_id: Identifier
    plan_id: Identifier
    merchant_id: Identifier
    complete: bool
    required_facts: tuple[Identifier, ...] = Field(min_length=1)
    missing_facts: tuple[Identifier, ...]
    transition_count: int = Field(gt=0)
    terminal_state: ActionState
    synthetic: bool

    @model_validator(mode="after")
    def validate_completeness(self) -> Self:
        """Prevent a passing audit report from hiding missing evidence."""

        if self.complete is not (not self.missing_facts):
            msg = "audit completeness must match the missing-fact set"
            raise ValueError(msg)
        if not set(self.missing_facts).issubset(self.required_facts):
            msg = "audit report contains an unknown missing fact"
            raise ValueError(msg)
        return self
