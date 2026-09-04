"""M4.1 contract tests for policy, approval and bounded recovery actions."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from retryrail.contracts.domain import ActionState, OperatingMode
from retryrail.contracts.recovery import (
    REQUIRED_POLICY_RULE_ORDER,
    ApprovalDecision,
    ApprovalRecordContract,
    ApprovalStatus,
    PolicyContextSnapshot,
    PolicyDecision,
    PolicyEvaluationStage,
    PolicyReasonCode,
    PolicyResultContract,
    PolicyRule,
    PolicyRuleOutcome,
    PolicyRuleResult,
    RecoveryActionActor,
    RecoveryActionContract,
    RecoveryActionError,
    RecoveryActionErrorCategory,
    RecoveryActionTransition,
    RecoveryExecutionTarget,
    RecoveryTemplateContract,
    SideEffectClass,
    policy_reason_code,
)

_NOW = datetime(2026, 9, 4, 10, 0, tzinfo=UTC)
_PLAN_DIGEST = "a" * 64
_POLICY_DIGEST = "b" * 64
_TOKEN_HASH = "c" * 64


def _policy_context(**updates: object) -> PolicyContextSnapshot:
    values: dict[str, object] = {
        "stage": PolicyEvaluationStage.PREVIEW,
        "policy_version": "policy_v1",
        "evaluated_at": _NOW,
        "merchant_id": "merchant_synthetic_001",
        "resource_merchant_id": "merchant_synthetic_001",
        "incident_id": "incident_synthetic_001",
        "plan_id": "plan_synthetic_001",
        "payment_id": "payment_synthetic_001",
        "incident_action_eligible": True,
        "mode": OperatingMode.REVIEW_FIRST,
        "template": "standard_payment_link",
        "template_enabled": True,
        "source_amount_subunits": 125_000,
        "proposed_amount_subunits": 125_000,
        "source_currency": "INR",
        "proposed_currency": "INR",
        "contact_required": False,
        "contact_consent_verified": False,
        "customer_opted_out": False,
        "prior_action_attempts": 0,
        "maximum_attempts_per_payment": 1,
        "last_action_at": None,
        "cooldown_seconds": 3_600,
        "plan_expires_at": _NOW + timedelta(hours=1),
        "merchant_kill_switch": False,
        "already_recovered": False,
        "execution_target": RecoveryExecutionTarget.DETERMINISTIC_FAKE,
        "synthetic": True,
    }
    values.update(updates)
    return PolicyContextSnapshot.model_validate(values)


def _policy_rules(
    denied_rule: PolicyRule | None = None,
) -> tuple[PolicyRuleResult, ...]:
    return tuple(
        PolicyRuleResult(
            rule=rule,
            outcome=(
                PolicyRuleOutcome.DENY if rule is denied_rule else PolicyRuleOutcome.SATISFIED
            ),
            reason_code=policy_reason_code(
                rule,
                PolicyRuleOutcome.DENY if rule is denied_rule else PolicyRuleOutcome.SATISFIED,
            ),
        )
        for rule in REQUIRED_POLICY_RULE_ORDER
    )


def _policy_result(
    *,
    denied_rule: PolicyRule | None = None,
    context: PolicyContextSnapshot | None = None,
) -> PolicyResultContract:
    return PolicyResultContract(
        policy_result_id="policy_result_synthetic_001",
        context=context or _policy_context(),
        decision=PolicyDecision.DENY if denied_rule is not None else PolicyDecision.ALLOW,
        rule_results=_policy_rules(denied_rule),
        synthetic=True,
    )


def _approval_values(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "approval_id": "approval_synthetic_001",
        "plan_id": "plan_synthetic_001",
        "incident_id": "incident_synthetic_001",
        "merchant_id": "merchant_synthetic_001",
        "policy_result_id": "policy_result_synthetic_001",
        "plan_sha256": _PLAN_DIGEST,
        "policy_result_sha256": _POLICY_DIGEST,
        "actor_id": "merchant_actor_001",
        "decision": ApprovalDecision.APPROVE,
        "status": ApprovalStatus.ISSUED,
        "decided_at": _NOW,
        "token_hash": _TOKEN_HASH,
        "issued_at": _NOW,
        "expires_at": _NOW + timedelta(minutes=5),
        "synthetic": True,
    }
    values.update(updates)
    return values


def _fake_success_transitions() -> tuple[RecoveryActionTransition, ...]:
    return (
        RecoveryActionTransition(
            prior_state=None,
            new_state=ActionState.PREVIEWED,
            occurred_at=_NOW,
            actor=RecoveryActionActor.POLICY_ENGINE,
            reason_code="policy_preview_allowed",
        ),
        RecoveryActionTransition(
            prior_state=ActionState.PREVIEWED,
            new_state=ActionState.AWAITING_APPROVAL,
            occurred_at=_NOW + timedelta(minutes=1),
            actor=RecoveryActionActor.SYSTEM,
            reason_code="merchant_approval_required",
        ),
        RecoveryActionTransition(
            prior_state=ActionState.AWAITING_APPROVAL,
            new_state=ActionState.APPROVED,
            occurred_at=_NOW + timedelta(minutes=2),
            actor=RecoveryActionActor.MERCHANT,
            reason_code="merchant_approved",
        ),
        RecoveryActionTransition(
            prior_state=ActionState.APPROVED,
            new_state=ActionState.EXECUTING,
            occurred_at=_NOW + timedelta(minutes=3),
            actor=RecoveryActionActor.WORKER,
            reason_code="execution_policy_allowed",
        ),
        RecoveryActionTransition(
            prior_state=ActionState.EXECUTING,
            new_state=ActionState.SUCCEEDED,
            occurred_at=_NOW + timedelta(minutes=4),
            actor=RecoveryActionActor.DETERMINISTIC_FAKE,
            reason_code="fake_provider_verified",
        ),
    )


def _action_values(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "action_id": "action_synthetic_001",
        "plan_id": "plan_synthetic_001",
        "incident_id": "incident_synthetic_001",
        "merchant_id": "merchant_synthetic_001",
        "payment_id": "payment_synthetic_001",
        "plan_sha256": _PLAN_DIGEST,
        "execution_target": RecoveryExecutionTarget.DETERMINISTIC_FAKE,
        "execution_side_effect": SideEffectClass.SIMULATED_EXTERNAL_MUTATION,
        "amount_subunits": 125_000,
        "currency": "INR",
        "reference_id": "recovery_synthetic_001",
        "idempotency_key": "action_synthetic_001_v1",
        "preview_policy_result_id": "policy_preview_synthetic_001",
        "approval_id": "approval_synthetic_001",
        "execution_policy_result_id": "policy_execute_synthetic_001",
        "state": ActionState.SUCCEEDED,
        "transitions": _fake_success_transitions(),
        "provider_action_id": "plink_fake_synthetic_001",
        "verified_at": _NOW + timedelta(minutes=5),
        "synthetic": True,
    }
    values.update(updates)
    return values


def test_template_contract_fixes_safe_p0_effects() -> None:
    template = RecoveryTemplateContract()

    assert template.external_notifications_enabled is False
    assert template.requires_external_approval is True
    assert template.production_execution_allowed is False
    assert template.allowed_execution_targets == (
        RecoveryExecutionTarget.DETERMINISTIC_FAKE,
        RecoveryExecutionTarget.RAZORPAY_TEST_MODE,
    )

    with pytest.raises(ValidationError):
        RecoveryTemplateContract.model_validate(
            {**template.model_dump(), "production_execution_allowed": True}
        )


def test_policy_result_accepts_complete_allow_and_machine_readable_deny() -> None:
    allowed = _policy_result()
    denied = _policy_result(denied_rule=PolicyRule.KILL_SWITCH)

    assert allowed.decision is PolicyDecision.ALLOW
    assert denied.decision is PolicyDecision.DENY
    assert denied.rule_results[11].reason_code is PolicyReasonCode.KILL_SWITCH_ON
    assert allowed.evaluation_side_effect is SideEffectClass.NONE


def test_policy_result_rejects_missing_reordered_or_hidden_denials() -> None:
    allowed = _policy_result()
    reversed_rules = tuple(reversed(allowed.rule_results))

    with pytest.raises(ValidationError, match="every required rule"):
        PolicyResultContract.model_validate(
            {**allowed.model_dump(), "rule_results": reversed_rules}
        )

    denied_rules = _policy_rules(PolicyRule.CUSTOMER_OPT_OUT)
    with pytest.raises(ValidationError, match="decision does not match"):
        PolicyResultContract.model_validate(
            {**allowed.model_dump(), "decision": "allow", "rule_results": denied_rules}
        )


def test_policy_rule_rejects_reason_with_wrong_polarity() -> None:
    with pytest.raises(ValidationError, match="reason does not match"):
        PolicyRuleResult(
            rule=PolicyRule.CURRENCY,
            outcome=PolicyRuleOutcome.DENY,
            reason_code=PolicyReasonCode.CURRENCY_MATCH,
        )


def test_policy_context_and_result_reject_invalid_provenance() -> None:
    with pytest.raises(ValidationError, match="last action cannot be after"):
        _policy_context(last_action_at=_NOW + timedelta(seconds=1))

    allowed = _policy_result()
    with pytest.raises(ValidationError, match="synthetic labels must match"):
        PolicyResultContract.model_validate({**allowed.model_dump(), "synthetic": False})


def test_approval_contract_never_contains_raw_bearer_token() -> None:
    issued = ApprovalRecordContract.model_validate(_approval_values())

    assert issued.status is ApprovalStatus.ISSUED
    assert issued.single_use is True
    assert "token" not in issued.model_dump()

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ApprovalRecordContract.model_validate(
            {**_approval_values(), "token": "rr_approval_raw_secret"}
        )


def test_approval_contract_accepts_consumed_and_rejected_terminal_states() -> None:
    maximum_lifetime = ApprovalRecordContract.model_validate(
        _approval_values(expires_at=_NOW + timedelta(minutes=15))
    )
    consumed = ApprovalRecordContract.model_validate(
        _approval_values(
            status=ApprovalStatus.CONSUMED,
            consumed_at=_NOW + timedelta(minutes=1),
        )
    )
    rejected = ApprovalRecordContract.model_validate(
        _approval_values(
            decision=ApprovalDecision.REJECT,
            status=ApprovalStatus.REJECTED,
            token_hash=None,
            issued_at=None,
            expires_at=None,
        )
    )

    assert maximum_lifetime.expires_at == _NOW + timedelta(minutes=15)
    assert consumed.consumed_at == _NOW + timedelta(minutes=1)
    assert rejected.token_hash is None


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        (
            {"expires_at": _NOW + timedelta(minutes=16)},
            "cannot exceed fifteen minutes",
        ),
        (
            {"issued_at": _NOW - timedelta(seconds=1)},
            "cannot be issued before the decision",
        ),
        (
            {"expires_at": _NOW},
            "expiry must be after issuance",
        ),
        (
            {"status": ApprovalStatus.CONSUMED, "consumed_at": None},
            "require consumed_at",
        ),
        (
            {
                "status": ApprovalStatus.CONSUMED,
                "consumed_at": _NOW + timedelta(minutes=5),
            },
            "before expiry",
        ),
        (
            {"status": ApprovalStatus.EXPIRED, "consumed_at": _NOW},
            "only consumed approvals",
        ),
        (
            {"decision": ApprovalDecision.REJECT},
            "require rejected status",
        ),
        (
            {"decision": ApprovalDecision.REJECT, "status": ApprovalStatus.REJECTED},
            "cannot contain token lifecycle fields",
        ),
        (
            {
                "decision": ApprovalDecision.APPROVE,
                "status": ApprovalStatus.REJECTED,
            },
            "approved decisions cannot have rejected status",
        ),
        (
            {"token_hash": None},
            "require hashed token",
        ),
    ],
)
def test_approval_contract_rejects_unsafe_lifecycle_combinations(
    updates: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        ApprovalRecordContract.model_validate(_approval_values(**updates))


def test_recovery_action_accepts_complete_fake_provider_receipt() -> None:
    action = RecoveryActionContract.model_validate(_action_values())

    assert action.state is ActionState.SUCCEEDED
    assert action.external_notifications_enabled is False
    assert action.execution_target is RecoveryExecutionTarget.DETERMINISTIC_FAKE


def test_recovery_action_accepts_typed_known_failure() -> None:
    transitions = (*_fake_success_transitions()[:-1],)
    transitions += (
        RecoveryActionTransition(
            prior_state=ActionState.EXECUTING,
            new_state=ActionState.FAILED,
            occurred_at=_NOW + timedelta(minutes=4),
            actor=RecoveryActionActor.DETERMINISTIC_FAKE,
            reason_code="fake_provider_rate_limited",
        ),
    )
    error = RecoveryActionError(
        category=RecoveryActionErrorCategory.RATE_LIMITED,
        reason_code="ACTION_RATE_LIMITED",
        retry_permitted=True,
        reconciliation_required=False,
    )

    action = RecoveryActionContract.model_validate(
        _action_values(
            state=ActionState.FAILED,
            transitions=transitions,
            provider_action_id=None,
            verified_at=None,
            error=error,
        )
    )

    assert action.error == error


def test_recovery_action_accepts_plan_expiry_before_merchant_decision() -> None:
    transitions = (
        *_fake_success_transitions()[:2],
        RecoveryActionTransition(
            prior_state=ActionState.AWAITING_APPROVAL,
            new_state=ActionState.EXPIRED,
            occurred_at=_NOW + timedelta(minutes=2),
            actor=RecoveryActionActor.SYSTEM,
            reason_code="plan_expired_before_approval",
        ),
    )

    action = RecoveryActionContract.model_validate(
        _action_values(
            state=ActionState.EXPIRED,
            transitions=transitions,
            approval_id=None,
            execution_policy_result_id=None,
            provider_action_id=None,
            verified_at=None,
        )
    )

    assert action.approval_id is None


def test_recovery_action_accepts_approval_expiry_before_execution() -> None:
    transitions = (
        *_fake_success_transitions()[:3],
        RecoveryActionTransition(
            prior_state=ActionState.APPROVED,
            new_state=ActionState.EXPIRED,
            occurred_at=_NOW + timedelta(minutes=3),
            actor=RecoveryActionActor.SYSTEM,
            reason_code="approval_expired_before_execution",
        ),
    )

    action = RecoveryActionContract.model_validate(
        _action_values(
            state=ActionState.EXPIRED,
            transitions=transitions,
            execution_policy_result_id=None,
            provider_action_id=None,
            verified_at=None,
        )
    )

    assert action.approval_id == "approval_synthetic_001"


def test_recovery_action_accepts_test_mode_reconciliation_and_resolution() -> None:
    ambiguous_transitions = (
        *_fake_success_transitions()[:4],
        RecoveryActionTransition(
            prior_state=ActionState.EXECUTING,
            new_state=ActionState.RECONCILIATION_REQUIRED,
            occurred_at=_NOW + timedelta(minutes=4),
            actor=RecoveryActionActor.RAZORPAY_TEST_MODE,
            reason_code="test_mode_outcome_ambiguous",
        ),
    )
    ambiguous_error = RecoveryActionError(
        category=RecoveryActionErrorCategory.RECONCILIATION_REQUIRED,
        reason_code="ACTION_OUTCOME_AMBIGUOUS",
        retry_permitted=False,
        reconciliation_required=True,
    )
    ambiguous = RecoveryActionContract.model_validate(
        _action_values(
            execution_target=RecoveryExecutionTarget.RAZORPAY_TEST_MODE,
            execution_side_effect=SideEffectClass.RAZORPAY_TEST_MODE_MUTATION,
            state=ActionState.RECONCILIATION_REQUIRED,
            transitions=ambiguous_transitions,
            provider_action_id=None,
            verified_at=None,
            error=ambiguous_error,
        )
    )

    resolved_transitions = (
        *ambiguous_transitions,
        RecoveryActionTransition(
            prior_state=ActionState.RECONCILIATION_REQUIRED,
            new_state=ActionState.SUCCEEDED,
            occurred_at=_NOW + timedelta(minutes=5),
            actor=RecoveryActionActor.WORKER,
            reason_code="test_mode_reference_reconciled",
        ),
    )
    resolved = RecoveryActionContract.model_validate(
        _action_values(
            execution_target=RecoveryExecutionTarget.RAZORPAY_TEST_MODE,
            execution_side_effect=SideEffectClass.RAZORPAY_TEST_MODE_MUTATION,
            transitions=resolved_transitions,
            provider_action_id="plink_test_synthetic_001",
            verified_at=_NOW + timedelta(minutes=5),
        )
    )

    assert ambiguous.error == ambiguous_error
    assert resolved.state is ActionState.SUCCEEDED


def test_recovery_action_rejects_skipped_approval_and_wrong_provider_actor() -> None:
    transitions = list(_fake_success_transitions())
    transitions[2] = RecoveryActionTransition(
        prior_state=ActionState.AWAITING_APPROVAL,
        new_state=ActionState.EXECUTING,
        occurred_at=_NOW + timedelta(minutes=2),
        actor=RecoveryActionActor.WORKER,
        reason_code="approval_skipped",
    )
    with pytest.raises(ValidationError, match="is not allowed"):
        RecoveryActionContract.model_validate(_action_values(transitions=tuple(transitions[:3])))

    wrong_actor = list(_fake_success_transitions())
    wrong_actor[-1] = wrong_actor[-1].model_copy(
        update={"actor": RecoveryActionActor.RAZORPAY_TEST_MODE}
    )
    with pytest.raises(ValidationError, match="actor is not authorized"):
        RecoveryActionContract.model_validate(_action_values(transitions=tuple(wrong_actor)))

    wrong_expiry_actor = (
        *_fake_success_transitions()[:3],
        RecoveryActionTransition(
            prior_state=ActionState.APPROVED,
            new_state=ActionState.EXPIRED,
            occurred_at=_NOW + timedelta(minutes=3),
            actor=RecoveryActionActor.WORKER,
            reason_code="worker_cannot_expire_approval",
        ),
    )
    with pytest.raises(ValidationError, match="actor is not authorized"):
        RecoveryActionContract.model_validate(
            _action_values(
                state=ActionState.EXPIRED,
                transitions=wrong_expiry_actor,
                execution_policy_result_id=None,
                provider_action_id=None,
                verified_at=None,
            )
        )


def test_recovery_action_rejects_broken_or_nonmonotonic_history() -> None:
    broken_chain = list(_fake_success_transitions())
    broken_chain[1] = broken_chain[1].model_copy(update={"prior_state": None})
    with pytest.raises(ValidationError, match="does not continue"):
        RecoveryActionContract.model_validate(_action_values(transitions=tuple(broken_chain)))

    nonmonotonic = list(_fake_success_transitions())
    nonmonotonic[1] = nonmonotonic[1].model_copy(
        update={"occurred_at": _NOW - timedelta(seconds=1)}
    )
    with pytest.raises(ValidationError, match="timestamps must be monotonic"):
        RecoveryActionContract.model_validate(_action_values(transitions=tuple(nonmonotonic)))

    with pytest.raises(ValidationError, match="state must equal its last transition"):
        RecoveryActionContract.model_validate(_action_values(state=ActionState.FAILED))


def test_recovery_action_rejects_incomplete_or_premature_outcome_evidence() -> None:
    with pytest.raises(ValidationError, match="verified_at cannot precede"):
        RecoveryActionContract.model_validate(
            _action_values(verified_at=_NOW + timedelta(minutes=3))
        )

    failed_transitions = (
        *_fake_success_transitions()[:4],
        RecoveryActionTransition(
            prior_state=ActionState.EXECUTING,
            new_state=ActionState.FAILED,
            occurred_at=_NOW + timedelta(minutes=4),
            actor=RecoveryActionActor.DETERMINISTIC_FAKE,
            reason_code="fake_provider_failed",
        ),
    )
    with pytest.raises(ValidationError, match="failed actions require a typed error"):
        RecoveryActionContract.model_validate(
            _action_values(
                state=ActionState.FAILED,
                transitions=failed_transitions,
                provider_action_id=None,
                verified_at=None,
            )
        )

    ambiguous_transitions = (
        *_fake_success_transitions()[:4],
        RecoveryActionTransition(
            prior_state=ActionState.EXECUTING,
            new_state=ActionState.RECONCILIATION_REQUIRED,
            occurred_at=_NOW + timedelta(minutes=4),
            actor=RecoveryActionActor.DETERMINISTIC_FAKE,
            reason_code="fake_provider_ambiguous",
        ),
    )
    with pytest.raises(ValidationError, match="require a reconciliation error"):
        RecoveryActionContract.model_validate(
            _action_values(
                state=ActionState.RECONCILIATION_REQUIRED,
                transitions=ambiguous_transitions,
                provider_action_id=None,
                verified_at=None,
            )
        )

    with pytest.raises(ValidationError, match="non-terminal actions cannot contain"):
        RecoveryActionContract.model_validate(
            _action_values(
                state=ActionState.PREVIEWED,
                transitions=_fake_success_transitions()[:1],
                approval_id=None,
                execution_policy_result_id=None,
            )
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        (
            {"execution_side_effect": SideEffectClass.RAZORPAY_TEST_MODE_MUTATION},
            "side effect does not match",
        ),
        ({"synthetic": False}, "must be labelled synthetic"),
        ({"approval_id": None}, "approval binding"),
        ({"execution_policy_result_id": None}, "execution policy binding"),
        ({"provider_action_id": None}, "require provider identity"),
        (
            {
                "error": RecoveryActionError(
                    category=RecoveryActionErrorCategory.UPSTREAM_FAILURE,
                    reason_code="ACTION_UPSTREAM_FAILED",
                    retry_permitted=True,
                    reconciliation_required=False,
                )
            },
            "cannot contain an error",
        ),
    ],
)
def test_recovery_action_rejects_inconsistent_authority_and_outcomes(
    updates: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        RecoveryActionContract.model_validate(_action_values(**updates))


def test_action_error_rejects_blind_retry_for_ambiguous_outcome() -> None:
    with pytest.raises(ValidationError, match="retry semantics"):
        RecoveryActionError(
            category=RecoveryActionErrorCategory.RECONCILIATION_REQUIRED,
            reason_code="ACTION_OUTCOME_AMBIGUOUS",
            retry_permitted=True,
            reconciliation_required=True,
        )


@pytest.mark.parametrize(
    ("category", "semantics"),
    [
        (RecoveryActionErrorCategory.INVALID_INPUT, (False, False)),
        (RecoveryActionErrorCategory.UNAUTHORIZED, (False, False)),
        (RecoveryActionErrorCategory.RATE_LIMITED, (True, False)),
        (RecoveryActionErrorCategory.UPSTREAM_FAILURE, (True, False)),
        (RecoveryActionErrorCategory.RECONCILIATION_REQUIRED, (False, True)),
    ],
)
def test_action_error_accepts_only_category_specific_retry_semantics(
    category: RecoveryActionErrorCategory,
    semantics: tuple[bool, bool],
) -> None:
    retry_permitted, reconciliation_required = semantics
    error = RecoveryActionError(
        category=category,
        reason_code="ACTION_TYPED_FAILURE",
        retry_permitted=retry_permitted,
        reconciliation_required=reconciliation_required,
    )

    assert error.category is category
