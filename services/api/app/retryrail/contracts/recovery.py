"""M4 recovery contracts with no runtime authority or endpoint side effects."""

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from retryrail.contracts.domain import (
    ActionState,
    OperatingMode,
    RecoveryTemplate,
    StrictContract,
)
from retryrail.events.models import Currency, Identifier

Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^[a-f0-9]{64}$"),
]

STANDARD_PAYMENT_LINK_TEMPLATE_VERSION: Literal["standard_payment_link_v1"] = (
    "standard_payment_link_v1"
)
MAX_APPROVAL_TOKEN_LIFETIME = timedelta(minutes=15)


class SideEffectClass(StrEnum):
    """Bounded side-effect classes exposed at the recovery trust boundary."""

    NONE = "none"
    DURABLE_INTERNAL_WRITE = "durable_internal_write"
    SIMULATED_EXTERNAL_MUTATION = "simulated_external_mutation"
    RAZORPAY_TEST_MODE_MUTATION = "razorpay_test_mode_mutation"


class RecoveryExecutionTarget(StrEnum):
    """The only execution targets admitted by the P0 contracts."""

    DETERMINISTIC_FAKE = "deterministic_fake"
    RAZORPAY_TEST_MODE = "razorpay_test_mode"


class RecoveryEffect(StrEnum):
    """Allowlisted customer-impacting effects that a template may describe."""

    CREATE_STANDARD_PAYMENT_LINK = "create_standard_payment_link"


class RecoveryTemplateContract(StrictContract):
    """Frozen definition of the sole pre-authorized P0 recovery template."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    template: Literal[RecoveryTemplate.STANDARD_PAYMENT_LINK] = (
        RecoveryTemplate.STANDARD_PAYMENT_LINK
    )
    template_version: Literal["standard_payment_link_v1"] = STANDARD_PAYMENT_LINK_TEMPLATE_VERSION
    effect: Literal[RecoveryEffect.CREATE_STANDARD_PAYMENT_LINK] = (
        RecoveryEffect.CREATE_STANDARD_PAYMENT_LINK
    )
    allowed_execution_targets: tuple[
        Literal[RecoveryExecutionTarget.DETERMINISTIC_FAKE],
        Literal[RecoveryExecutionTarget.RAZORPAY_TEST_MODE],
    ] = (
        RecoveryExecutionTarget.DETERMINISTIC_FAKE,
        RecoveryExecutionTarget.RAZORPAY_TEST_MODE,
    )
    preview_side_effect: Literal[SideEffectClass.NONE] = SideEffectClass.NONE
    approval_side_effect: Literal[SideEffectClass.DURABLE_INTERNAL_WRITE] = (
        SideEffectClass.DURABLE_INTERNAL_WRITE
    )
    preserve_verified_amount: Literal[True] = True
    external_notifications_enabled: Literal[False] = False
    requires_external_approval: Literal[True] = True
    production_execution_allowed: Literal[False] = False


class PolicyEvaluationStage(StrEnum):
    """Policy is evaluated during preview and repeated immediately before execution."""

    PREVIEW = "preview"
    EXECUTION = "execution"


class PolicyDecision(StrEnum):
    """Aggregate deterministic policy outcome."""

    ALLOW = "allow"
    DENY = "deny"


class PolicyRuleOutcome(StrEnum):
    """Per-rule result used to derive the aggregate decision."""

    SATISFIED = "pass"
    DENY = "deny"


class PolicyRule(StrEnum):
    """Complete P0 rule set; omitting any rule invalidates a policy result."""

    MERCHANT_SCOPE = "merchant_scope"
    INCIDENT_ACTION_ELIGIBILITY = "incident_action_eligibility"
    OPERATING_MODE = "operating_mode"
    TEMPLATE_ENABLED = "template_enabled"
    ORIGINAL_AMOUNT = "original_amount"
    CURRENCY = "currency"
    CONTACT_CONSENT = "contact_consent"
    CUSTOMER_OPT_OUT = "customer_opt_out"
    ATTEMPT_CAP = "attempt_cap"
    COOLDOWN = "cooldown"
    PLAN_EXPIRY = "plan_expiry"
    KILL_SWITCH = "kill_switch"
    ALREADY_RECOVERED = "already_recovered"


REQUIRED_POLICY_RULE_ORDER: tuple[PolicyRule, ...] = tuple(PolicyRule)


class PolicyReasonCode(StrEnum):
    """Allowlisted, machine-readable reason for every P0 rule outcome."""

    MERCHANT_SCOPE_MATCH = "POLICY_MERCHANT_SCOPE_MATCH"
    MERCHANT_SCOPE_MISMATCH = "POLICY_MERCHANT_SCOPE_MISMATCH"
    INCIDENT_ACTION_ELIGIBLE = "POLICY_INCIDENT_ACTION_ELIGIBLE"
    INCIDENT_ACTION_INELIGIBLE = "POLICY_INCIDENT_ACTION_INELIGIBLE"
    REVIEW_FIRST_ENABLED = "POLICY_REVIEW_FIRST_ENABLED"
    ANALYZE_ONLY_BLOCKS_MUTATION = "POLICY_ANALYZE_ONLY_BLOCKS_MUTATION"
    TEMPLATE_ENABLED = "POLICY_TEMPLATE_ENABLED"
    TEMPLATE_DISABLED = "POLICY_TEMPLATE_DISABLED"
    ORIGINAL_AMOUNT_MATCH = "POLICY_ORIGINAL_AMOUNT_MATCH"
    AMOUNT_CHANGED = "POLICY_AMOUNT_CHANGED"
    CURRENCY_MATCH = "POLICY_CURRENCY_MATCH"
    CURRENCY_MISMATCH = "POLICY_CURRENCY_MISMATCH"
    CONTACT_SAFE = "POLICY_CONTACT_NOT_REQUIRED_OR_CONSENT_VERIFIED"
    CONTACT_CONSENT_MISSING = "POLICY_CONTACT_CONSENT_MISSING"
    CUSTOMER_ELIGIBLE = "POLICY_CUSTOMER_NOT_OPTED_OUT"
    CUSTOMER_OPTED_OUT = "POLICY_CUSTOMER_OPTED_OUT"
    ATTEMPT_CAP_AVAILABLE = "POLICY_ATTEMPT_CAP_AVAILABLE"
    ATTEMPT_CAP_REACHED = "POLICY_ATTEMPT_CAP_REACHED"
    COOLDOWN_ELAPSED = "POLICY_COOLDOWN_ELAPSED"
    COOLDOWN_ACTIVE = "POLICY_COOLDOWN_ACTIVE"
    PLAN_ACTIVE = "POLICY_PLAN_ACTIVE"
    PLAN_EXPIRED = "POLICY_PLAN_EXPIRED"
    KILL_SWITCH_OFF = "POLICY_KILL_SWITCH_OFF"
    KILL_SWITCH_ON = "POLICY_KILL_SWITCH_ON"
    PAYMENT_UNRECOVERED = "POLICY_PAYMENT_UNRECOVERED"
    PAYMENT_ALREADY_RECOVERED = "POLICY_PAYMENT_ALREADY_RECOVERED"


_POLICY_REASON_BINDINGS: dict[
    PolicyRule,
    dict[PolicyRuleOutcome, PolicyReasonCode],
] = {
    PolicyRule.MERCHANT_SCOPE: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.MERCHANT_SCOPE_MATCH,
        PolicyRuleOutcome.DENY: PolicyReasonCode.MERCHANT_SCOPE_MISMATCH,
    },
    PolicyRule.INCIDENT_ACTION_ELIGIBILITY: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.INCIDENT_ACTION_ELIGIBLE,
        PolicyRuleOutcome.DENY: PolicyReasonCode.INCIDENT_ACTION_INELIGIBLE,
    },
    PolicyRule.OPERATING_MODE: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.REVIEW_FIRST_ENABLED,
        PolicyRuleOutcome.DENY: PolicyReasonCode.ANALYZE_ONLY_BLOCKS_MUTATION,
    },
    PolicyRule.TEMPLATE_ENABLED: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.TEMPLATE_ENABLED,
        PolicyRuleOutcome.DENY: PolicyReasonCode.TEMPLATE_DISABLED,
    },
    PolicyRule.ORIGINAL_AMOUNT: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.ORIGINAL_AMOUNT_MATCH,
        PolicyRuleOutcome.DENY: PolicyReasonCode.AMOUNT_CHANGED,
    },
    PolicyRule.CURRENCY: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.CURRENCY_MATCH,
        PolicyRuleOutcome.DENY: PolicyReasonCode.CURRENCY_MISMATCH,
    },
    PolicyRule.CONTACT_CONSENT: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.CONTACT_SAFE,
        PolicyRuleOutcome.DENY: PolicyReasonCode.CONTACT_CONSENT_MISSING,
    },
    PolicyRule.CUSTOMER_OPT_OUT: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.CUSTOMER_ELIGIBLE,
        PolicyRuleOutcome.DENY: PolicyReasonCode.CUSTOMER_OPTED_OUT,
    },
    PolicyRule.ATTEMPT_CAP: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.ATTEMPT_CAP_AVAILABLE,
        PolicyRuleOutcome.DENY: PolicyReasonCode.ATTEMPT_CAP_REACHED,
    },
    PolicyRule.COOLDOWN: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.COOLDOWN_ELAPSED,
        PolicyRuleOutcome.DENY: PolicyReasonCode.COOLDOWN_ACTIVE,
    },
    PolicyRule.PLAN_EXPIRY: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.PLAN_ACTIVE,
        PolicyRuleOutcome.DENY: PolicyReasonCode.PLAN_EXPIRED,
    },
    PolicyRule.KILL_SWITCH: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.KILL_SWITCH_OFF,
        PolicyRuleOutcome.DENY: PolicyReasonCode.KILL_SWITCH_ON,
    },
    PolicyRule.ALREADY_RECOVERED: {
        PolicyRuleOutcome.SATISFIED: PolicyReasonCode.PAYMENT_UNRECOVERED,
        PolicyRuleOutcome.DENY: PolicyReasonCode.PAYMENT_ALREADY_RECOVERED,
    },
}


def policy_reason_code(
    rule: PolicyRule,
    outcome: PolicyRuleOutcome,
) -> PolicyReasonCode:
    """Return the only reason code valid for a rule and outcome."""

    return _POLICY_REASON_BINDINGS[rule][outcome]


class PolicyContextSnapshot(StrictContract):
    """PII-free facts consumed by deterministic policy evaluation."""

    stage: PolicyEvaluationStage
    policy_version: Identifier
    evaluated_at: AwareDatetime
    merchant_id: Identifier
    resource_merchant_id: Identifier
    incident_id: Identifier
    plan_id: Identifier
    payment_id: Identifier
    incident_action_eligible: bool
    mode: OperatingMode
    template: RecoveryTemplate
    template_enabled: bool
    source_amount_subunits: int = Field(gt=0, le=100_000_000_000)
    proposed_amount_subunits: int = Field(gt=0, le=100_000_000_000)
    source_currency: Currency
    proposed_currency: Currency
    contact_required: bool
    contact_consent_verified: bool
    customer_opted_out: bool
    prior_action_attempts: int = Field(ge=0)
    maximum_attempts_per_payment: int = Field(gt=0, le=3)
    last_action_at: AwareDatetime | None = None
    cooldown_seconds: int = Field(ge=0, le=604_800)
    plan_expires_at: AwareDatetime
    merchant_kill_switch: bool
    already_recovered: bool
    execution_target: RecoveryExecutionTarget
    synthetic: bool

    @model_validator(mode="after")
    def validate_observation_times(self) -> Self:
        """Reject a future prior action rather than turning it into a policy fact."""

        if self.last_action_at is not None and self.last_action_at > self.evaluated_at:
            msg = "last action cannot be after policy evaluation"
            raise ValueError(msg)
        return self


class PolicyRuleResult(StrictContract):
    """One deterministic rule outcome with a reason bound to rule and polarity."""

    rule: PolicyRule
    outcome: PolicyRuleOutcome
    reason_code: PolicyReasonCode

    @model_validator(mode="after")
    def validate_reason_binding(self) -> Self:
        """Prevent a passing reason from being attached to a denied rule or vice versa."""

        expected = policy_reason_code(self.rule, self.outcome)
        if self.reason_code is not expected:
            msg = "policy reason does not match rule outcome"
            raise ValueError(msg)
        return self


class PolicyResultContract(StrictContract):
    """Complete policy record; it describes authority but cannot grant approval."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    policy_result_id: Identifier
    context: PolicyContextSnapshot
    decision: PolicyDecision
    rule_results: tuple[PolicyRuleResult, ...] = Field(
        min_length=len(REQUIRED_POLICY_RULE_ORDER),
        max_length=len(REQUIRED_POLICY_RULE_ORDER),
    )
    evaluation_side_effect: Literal[SideEffectClass.NONE] = SideEffectClass.NONE
    recording_side_effect: Literal[SideEffectClass.DURABLE_INTERNAL_WRITE] = (
        SideEffectClass.DURABLE_INTERNAL_WRITE
    )
    synthetic: bool

    @model_validator(mode="after")
    def validate_complete_decision(self) -> Self:
        """Reject skipped/reordered rules and aggregate decisions that hide a denial."""

        observed_order = tuple(item.rule for item in self.rule_results)
        if observed_order != REQUIRED_POLICY_RULE_ORDER:
            msg = "policy result must contain every required rule in canonical order"
            raise ValueError(msg)
        expected = (
            PolicyDecision.ALLOW
            if all(item.outcome is PolicyRuleOutcome.SATISFIED for item in self.rule_results)
            else PolicyDecision.DENY
        )
        if self.decision is not expected:
            msg = "policy decision does not match rule outcomes"
            raise ValueError(msg)
        if self.synthetic is not self.context.synthetic:
            msg = "policy result and context synthetic labels must match"
            raise ValueError(msg)
        return self


class ApprovalDecision(StrEnum):
    """Decision made by an authenticated merchant actor outside the model."""

    APPROVE = "approve"
    REJECT = "reject"


class ApprovalStatus(StrEnum):
    """Lifecycle of a hashed, short-lived, single-use approval credential."""

    ISSUED = "issued"
    CONSUMED = "consumed"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalRecordContract(StrictContract):
    """Durable approval fact that never contains the bearer token itself."""

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
    token_hash: Sha256Digest | None = None
    issued_at: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    consumed_at: AwareDatetime | None = None
    single_use: Literal[True] = True
    side_effect: Literal[SideEffectClass.DURABLE_INTERNAL_WRITE] = (
        SideEffectClass.DURABLE_INTERNAL_WRITE
    )
    synthetic: bool

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        """Bind decision, token material and timestamps to one valid lifecycle state."""

        if self.decision is ApprovalDecision.REJECT:
            self._validate_rejection()
        else:
            self._validate_approved_lifecycle()
        return self

    def _validate_rejection(self) -> None:
        """Require rejected decisions to remain token-free."""

        if self.status is not ApprovalStatus.REJECTED:
            msg = "rejected decisions require rejected status"
            raise ValueError(msg)
        token_fields = (self.token_hash, self.issued_at, self.expires_at, self.consumed_at)
        if any(value is not None for value in token_fields):
            msg = "rejected approvals cannot contain token lifecycle fields"
            raise ValueError(msg)

    def _validate_approved_lifecycle(self) -> None:
        """Validate issued, consumed and expired approved credentials."""

        if self.status is ApprovalStatus.REJECTED:
            msg = "approved decisions cannot have rejected status"
            raise ValueError(msg)
        issued_at, expires_at = self._approved_token_times()
        self._validate_approved_times(issued_at, expires_at)
        self._validate_consumption(issued_at, expires_at)

    def _approved_token_times(self) -> tuple[datetime, datetime]:
        """Return complete token timestamps for an approved decision."""

        token_fields = (self.token_hash, self.issued_at, self.expires_at)
        if any(value is None for value in token_fields):
            msg = "approved decisions require hashed token lifecycle fields"
            raise ValueError(msg)
        issued_at = self.issued_at
        expires_at = self.expires_at
        if issued_at is None or expires_at is None:  # pragma: no cover - type narrowing
            msg = "approved decisions require token timestamps"
            raise ValueError(msg)
        return issued_at, expires_at

    def _validate_approved_times(self, issued_at: datetime, expires_at: datetime) -> None:
        """Enforce decision ordering and the maximum credential lifetime."""

        if issued_at < self.decided_at:
            msg = "approval cannot be issued before the decision"
            raise ValueError(msg)
        if expires_at <= issued_at:
            msg = "approval expiry must be after issuance"
            raise ValueError(msg)
        if expires_at - issued_at > MAX_APPROVAL_TOKEN_LIFETIME:
            msg = "approval token lifetime cannot exceed fifteen minutes"
            raise ValueError(msg)

    def _validate_consumption(self, issued_at: datetime, expires_at: datetime) -> None:
        """Allow exactly one consumption timestamp within the credential lifetime."""

        if self.status is ApprovalStatus.CONSUMED:
            if self.consumed_at is None:
                msg = "consumed approvals require consumed_at"
                raise ValueError(msg)
            if self.consumed_at < issued_at or self.consumed_at >= expires_at:
                msg = "approval must be consumed after issuance and before expiry"
                raise ValueError(msg)
        elif self.consumed_at is not None:
            msg = "only consumed approvals may contain consumed_at"
            raise ValueError(msg)


class RecoveryActionActor(StrEnum):
    """Actors admitted to the M4/M5 action receipt state graph."""

    SYSTEM = "system"
    POLICY_ENGINE = "policy_engine"
    MERCHANT = "merchant"
    WORKER = "worker"
    DETERMINISTIC_FAKE = "deterministic_fake"
    RAZORPAY_TEST_MODE = "razorpay_test_mode"


class RecoveryActionErrorCategory(StrEnum):
    """Typed P0 execution failure categories without raw provider messages."""

    INVALID_INPUT = "invalid_input"
    UNAUTHORIZED = "unauthorized"
    RATE_LIMITED = "rate_limited"
    UPSTREAM_FAILURE = "upstream_failure"
    RECONCILIATION_REQUIRED = "reconciliation_required"


_ERROR_RETRY_RULES: dict[RecoveryActionErrorCategory, tuple[bool, bool]] = {
    RecoveryActionErrorCategory.INVALID_INPUT: (False, False),
    RecoveryActionErrorCategory.UNAUTHORIZED: (False, False),
    RecoveryActionErrorCategory.RATE_LIMITED: (True, False),
    RecoveryActionErrorCategory.UPSTREAM_FAILURE: (True, False),
    RecoveryActionErrorCategory.RECONCILIATION_REQUIRED: (False, True),
}


class RecoveryActionError(StrictContract):
    """Redacted action error with explicit retry and reconciliation semantics."""

    category: RecoveryActionErrorCategory
    reason_code: Identifier
    retry_permitted: bool
    reconciliation_required: bool

    @model_validator(mode="after")
    def validate_retry_semantics(self) -> Self:
        """Prevent blind retry from being enabled for an ambiguous outcome."""

        expected = _ERROR_RETRY_RULES[self.category]
        if (self.retry_permitted, self.reconciliation_required) != expected:
            msg = "action error retry semantics do not match its category"
            raise ValueError(msg)
        return self


class RecoveryActionTransition(StrictContract):
    """One append-only M4 action transition."""

    prior_state: ActionState | None
    new_state: ActionState
    occurred_at: AwareDatetime
    actor: RecoveryActionActor
    reason_code: Identifier


_ALLOWED_ACTION_TRANSITIONS: dict[ActionState | None, frozenset[ActionState]] = {
    None: frozenset({ActionState.PREVIEWED}),
    ActionState.PREVIEWED: frozenset({ActionState.AWAITING_APPROVAL}),
    ActionState.AWAITING_APPROVAL: frozenset(
        {ActionState.APPROVED, ActionState.REJECTED, ActionState.EXPIRED}
    ),
    ActionState.APPROVED: frozenset({ActionState.EXECUTING, ActionState.EXPIRED}),
    ActionState.EXECUTING: frozenset(
        {
            ActionState.SUCCEEDED,
            ActionState.FAILED,
            ActionState.RECONCILIATION_REQUIRED,
        }
    ),
    ActionState.RECONCILIATION_REQUIRED: frozenset({ActionState.SUCCEEDED, ActionState.FAILED}),
    ActionState.REJECTED: frozenset(),
    ActionState.EXPIRED: frozenset(),
    ActionState.SUCCEEDED: frozenset(),
    ActionState.FAILED: frozenset(),
}


class RecoveryActionContract(StrictContract):
    """Bounded action record joining preview, approval, execution and receipt evidence."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    action_id: Identifier
    plan_id: Identifier
    incident_id: Identifier
    merchant_id: Identifier
    payment_id: Identifier
    plan_sha256: Sha256Digest
    template: Literal[RecoveryTemplate.STANDARD_PAYMENT_LINK] = (
        RecoveryTemplate.STANDARD_PAYMENT_LINK
    )
    template_version: Literal["standard_payment_link_v1"] = STANDARD_PAYMENT_LINK_TEMPLATE_VERSION
    execution_target: RecoveryExecutionTarget
    execution_side_effect: SideEffectClass
    amount_subunits: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    reference_id: Identifier
    idempotency_key: Identifier
    preview_policy_result_id: Identifier
    approval_id: Identifier | None = None
    execution_policy_result_id: Identifier | None = None
    state: ActionState
    transitions: tuple[RecoveryActionTransition, ...] = Field(min_length=1)
    provider_action_id: Identifier | None = None
    verified_at: AwareDatetime | None = None
    error: RecoveryActionError | None = None
    external_notifications_enabled: Literal[False] = False
    synthetic: bool

    @model_validator(mode="after")
    def validate_action(self) -> Self:
        """Reject broken history, authority gaps and inconsistent provider outcomes."""

        self._validate_execution_target()
        self._validate_transition_chain()
        self._validate_authority_bindings()
        self._validate_outcome()
        return self

    def _validate_execution_target(self) -> None:
        """Keep target, side-effect classification and synthetic label aligned."""

        expected_side_effect = {
            RecoveryExecutionTarget.DETERMINISTIC_FAKE: (
                SideEffectClass.SIMULATED_EXTERNAL_MUTATION
            ),
            RecoveryExecutionTarget.RAZORPAY_TEST_MODE: (
                SideEffectClass.RAZORPAY_TEST_MODE_MUTATION
            ),
        }[self.execution_target]
        if self.execution_side_effect is not expected_side_effect:
            msg = "execution side effect does not match execution target"
            raise ValueError(msg)
        if (
            self.execution_target is RecoveryExecutionTarget.DETERMINISTIC_FAKE
            and not self.synthetic
        ):
            msg = "deterministic fake actions must be labelled synthetic"
            raise ValueError(msg)

    def _validate_transition_chain(self) -> None:
        """Require a complete, monotonic and actor-authorized transition chain."""

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
            self._validate_transition_actor(transition)
            previous_state = transition.new_state

        if previous_state is not self.state:
            msg = "action state must equal its last transition"
            raise ValueError(msg)

    def _validate_authority_bindings(self) -> None:
        """Require approval and fresh policy evidence exactly when their states do."""

        execution_states = {
            ActionState.EXECUTING,
            ActionState.SUCCEEDED,
            ActionState.FAILED,
            ActionState.RECONCILIATION_REQUIRED,
        }
        requires_approval = any(
            transition.new_state in {ActionState.APPROVED, ActionState.REJECTED}
            for transition in self.transitions
        )
        has_approval = self.approval_id is not None
        if requires_approval != has_approval:
            msg = "action approval binding does not match its state"
            raise ValueError(msg)
        requires_execution_policy = self.state in execution_states
        has_execution_policy = self.execution_policy_result_id is not None
        if requires_execution_policy != has_execution_policy:
            msg = "execution policy binding does not match action state"
            raise ValueError(msg)

    def _validate_outcome(self) -> None:
        """Require typed terminal evidence and prohibit premature provider outcomes."""

        if self.state is ActionState.SUCCEEDED:
            if self.provider_action_id is None or self.verified_at is None:
                msg = "succeeded actions require provider identity and verification time"
                raise ValueError(msg)
            if self.error is not None:
                msg = "succeeded actions cannot contain an error"
                raise ValueError(msg)
            if self.verified_at < self.transitions[-1].occurred_at:
                msg = "verified_at cannot precede the final transition"
                raise ValueError(msg)
        elif self.state is ActionState.FAILED:
            if self.error is None:
                msg = "failed actions require a typed error"
                raise ValueError(msg)
        elif self.state is ActionState.RECONCILIATION_REQUIRED:
            if (
                self.error is None
                or self.error.category is not RecoveryActionErrorCategory.RECONCILIATION_REQUIRED
            ):
                msg = "ambiguous actions require a reconciliation error"
                raise ValueError(msg)
        elif any(
            value is not None for value in (self.provider_action_id, self.verified_at, self.error)
        ):
            msg = "non-terminal actions cannot contain provider outcome fields"
            raise ValueError(msg)

    def _validate_transition_actor(self, transition: RecoveryActionTransition) -> None:
        """Bind security-sensitive transitions to the actor allowed to make them."""

        actor = transition.actor
        edge = (transition.prior_state, transition.new_state)
        if edge == (None, ActionState.PREVIEWED):
            allowed = {RecoveryActionActor.POLICY_ENGINE}
        elif edge == (ActionState.PREVIEWED, ActionState.AWAITING_APPROVAL):
            allowed = {RecoveryActionActor.SYSTEM}
        elif transition.prior_state is ActionState.AWAITING_APPROVAL:
            allowed = (
                {RecoveryActionActor.SYSTEM}
                if transition.new_state is ActionState.EXPIRED
                else {RecoveryActionActor.MERCHANT}
            )
        elif edge == (ActionState.APPROVED, ActionState.EXECUTING):
            allowed = {RecoveryActionActor.WORKER}
        elif edge == (ActionState.APPROVED, ActionState.EXPIRED):
            allowed = {RecoveryActionActor.SYSTEM}
        elif transition.prior_state is ActionState.EXECUTING:
            allowed = {self._provider_actor()}
        else:
            allowed = {RecoveryActionActor.WORKER, self._provider_actor()}
        if actor not in allowed:
            msg = "action transition actor is not authorized for the state change"
            raise ValueError(msg)

    def _provider_actor(self) -> RecoveryActionActor:
        """Return the only provider actor valid for this execution target."""

        if self.execution_target is RecoveryExecutionTarget.DETERMINISTIC_FAKE:
            return RecoveryActionActor.DETERMINISTIC_FAKE
        return RecoveryActionActor.RAZORPAY_TEST_MODE
