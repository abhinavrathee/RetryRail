"""M4.2 allow/deny, boundary and determinism tests for every policy rule."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from retryrail.contracts.domain import OperatingMode
from retryrail.contracts.recovery import (
    REQUIRED_POLICY_RULE_ORDER,
    PolicyContextSnapshot,
    PolicyDecision,
    PolicyEvaluationStage,
    PolicyReasonCode,
    PolicyRule,
    PolicyRuleOutcome,
    RecoveryExecutionTarget,
    SideEffectClass,
)
from retryrail.policy import (
    DETERMINISTIC_POLICY_VERSION,
    DeterministicPolicyEngine,
    NonUtcPolicyTimestampError,
    UnsupportedPolicyVersionError,
    evaluate_policy,
)

_NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
_IST = timezone(timedelta(hours=5, minutes=30))


def _context(**updates: object) -> PolicyContextSnapshot:
    values: dict[str, object] = {
        "stage": PolicyEvaluationStage.PREVIEW,
        "policy_version": DETERMINISTIC_POLICY_VERSION,
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


_DENY_CASES: tuple[
    tuple[PolicyRule, PolicyReasonCode, dict[str, object]],
    ...,
] = (
    (
        PolicyRule.MERCHANT_SCOPE,
        PolicyReasonCode.MERCHANT_SCOPE_MISMATCH,
        {"resource_merchant_id": "merchant_synthetic_002"},
    ),
    (
        PolicyRule.INCIDENT_ACTION_ELIGIBILITY,
        PolicyReasonCode.INCIDENT_ACTION_INELIGIBLE,
        {"incident_action_eligible": False},
    ),
    (
        PolicyRule.OPERATING_MODE,
        PolicyReasonCode.ANALYZE_ONLY_BLOCKS_MUTATION,
        {"mode": OperatingMode.ANALYZE_ONLY},
    ),
    (
        PolicyRule.TEMPLATE_ENABLED,
        PolicyReasonCode.TEMPLATE_DISABLED,
        {"template_enabled": False},
    ),
    (
        PolicyRule.ORIGINAL_AMOUNT,
        PolicyReasonCode.AMOUNT_CHANGED,
        {"proposed_amount_subunits": 124_999},
    ),
    (
        PolicyRule.CURRENCY,
        PolicyReasonCode.CURRENCY_MISMATCH,
        {"proposed_currency": "USD"},
    ),
    (
        PolicyRule.CONTACT_CONSENT,
        PolicyReasonCode.CONTACT_CONSENT_MISSING,
        {"contact_required": True, "contact_consent_verified": False},
    ),
    (
        PolicyRule.CUSTOMER_OPT_OUT,
        PolicyReasonCode.CUSTOMER_OPTED_OUT,
        {"customer_opted_out": True},
    ),
    (
        PolicyRule.ATTEMPT_CAP,
        PolicyReasonCode.ATTEMPT_CAP_REACHED,
        {"prior_action_attempts": 1},
    ),
    (
        PolicyRule.COOLDOWN,
        PolicyReasonCode.COOLDOWN_ACTIVE,
        {"last_action_at": _NOW - timedelta(seconds=3_599)},
    ),
    (
        PolicyRule.PLAN_EXPIRY,
        PolicyReasonCode.PLAN_EXPIRED,
        {"plan_expires_at": _NOW},
    ),
    (
        PolicyRule.KILL_SWITCH,
        PolicyReasonCode.KILL_SWITCH_ON,
        {"merchant_kill_switch": True},
    ),
    (
        PolicyRule.ALREADY_RECOVERED,
        PolicyReasonCode.PAYMENT_ALREADY_RECOVERED,
        {"already_recovered": True},
    ),
)


def _result_for_rule(
    result_rule: PolicyRule,
    context: PolicyContextSnapshot,
) -> tuple[PolicyRuleOutcome, PolicyReasonCode]:
    result = evaluate_policy(context)
    rule_result = next(item for item in result.rule_results if item.rule is result_rule)
    return rule_result.outcome, rule_result.reason_code


def test_review_first_context_allows_every_rule_without_side_effects() -> None:
    context = _context()

    result = evaluate_policy(context)

    assert result.decision is PolicyDecision.ALLOW
    assert tuple(item.rule for item in result.rule_results) == REQUIRED_POLICY_RULE_ORDER
    assert all(item.outcome is PolicyRuleOutcome.SATISFIED for item in result.rule_results)
    assert result.evaluation_side_effect is SideEffectClass.NONE
    assert context == _context()


@pytest.mark.parametrize(("rule", "reason_code", "updates"), _DENY_CASES)
def test_every_rule_has_an_explicit_allow_and_deny_result(
    rule: PolicyRule,
    reason_code: PolicyReasonCode,
    updates: dict[str, object],
) -> None:
    allowed_outcome, allowed_reason = _result_for_rule(rule, _context())
    denied = evaluate_policy(_context(**updates))
    denied_rule = next(item for item in denied.rule_results if item.rule is rule)

    assert allowed_outcome is PolicyRuleOutcome.SATISFIED
    assert allowed_reason is not reason_code
    assert denied.decision is PolicyDecision.DENY
    assert denied_rule.outcome is PolicyRuleOutcome.DENY
    assert denied_rule.reason_code is reason_code
    assert sum(item.outcome is PolicyRuleOutcome.DENY for item in denied.rule_results) == 1


def test_engine_collects_every_denial_without_short_circuiting() -> None:
    result = evaluate_policy(
        _context(
            incident_action_eligible=False,
            mode=OperatingMode.ANALYZE_ONLY,
            proposed_amount_subunits=100_000,
            merchant_kill_switch=True,
            already_recovered=True,
        )
    )

    denied_rules = tuple(
        item.rule for item in result.rule_results if item.outcome is PolicyRuleOutcome.DENY
    )
    assert denied_rules == (
        PolicyRule.INCIDENT_ACTION_ELIGIBILITY,
        PolicyRule.OPERATING_MODE,
        PolicyRule.ORIGINAL_AMOUNT,
        PolicyRule.KILL_SWITCH,
        PolicyRule.ALREADY_RECOVERED,
    )


def test_cooldown_and_plan_expiry_boundaries_are_fail_closed() -> None:
    cooldown_boundary = _context(last_action_at=_NOW - timedelta(seconds=3_600))
    active_until_next_microsecond = _context(plan_expires_at=_NOW + timedelta(microseconds=1))

    assert _result_for_rule(PolicyRule.COOLDOWN, cooldown_boundary)[0] is (
        PolicyRuleOutcome.SATISFIED
    )
    assert _result_for_rule(PolicyRule.PLAN_EXPIRY, active_until_next_microsecond)[0] is (
        PolicyRuleOutcome.SATISFIED
    )
    assert _result_for_rule(PolicyRule.PLAN_EXPIRY, _context(plan_expires_at=_NOW))[0] is (
        PolicyRuleOutcome.DENY
    )


def test_verified_consent_allows_required_contact() -> None:
    result = _result_for_rule(
        PolicyRule.CONTACT_CONSENT,
        _context(contact_required=True, contact_consent_verified=True),
    )

    assert result == (PolicyRuleOutcome.SATISFIED, PolicyReasonCode.CONTACT_SAFE)


@given(
    source_amount=st.integers(min_value=1, max_value=100_000_000_000),
    proposed_amount=st.integers(min_value=1, max_value=100_000_000_000),
)
def test_amount_rule_matches_integer_subunits_exactly(
    source_amount: int,
    proposed_amount: int,
) -> None:
    outcome = _result_for_rule(
        PolicyRule.ORIGINAL_AMOUNT,
        _context(
            source_amount_subunits=source_amount,
            proposed_amount_subunits=proposed_amount,
        ),
    )[0]

    assert (outcome is PolicyRuleOutcome.SATISFIED) is (source_amount == proposed_amount)


@given(
    prior_attempts=st.integers(min_value=0, max_value=10),
    maximum_attempts=st.integers(min_value=1, max_value=3),
)
def test_attempt_rule_uses_a_strict_upper_bound(
    prior_attempts: int,
    maximum_attempts: int,
) -> None:
    outcome = _result_for_rule(
        PolicyRule.ATTEMPT_CAP,
        _context(
            prior_action_attempts=prior_attempts,
            maximum_attempts_per_payment=maximum_attempts,
        ),
    )[0]

    assert (outcome is PolicyRuleOutcome.SATISFIED) is (prior_attempts < maximum_attempts)


@given(
    cooldown_seconds=st.integers(min_value=0, max_value=604_800),
    elapsed_seconds=st.integers(min_value=0, max_value=604_801),
)
def test_cooldown_rule_matches_elapsed_duration(
    cooldown_seconds: int,
    elapsed_seconds: int,
) -> None:
    outcome = _result_for_rule(
        PolicyRule.COOLDOWN,
        _context(
            last_action_at=_NOW - timedelta(seconds=elapsed_seconds),
            cooldown_seconds=cooldown_seconds,
        ),
    )[0]

    assert (outcome is PolicyRuleOutcome.SATISFIED) is (elapsed_seconds >= cooldown_seconds)


def test_preview_and_execution_are_both_evaluated_and_content_addressed() -> None:
    preview_context = _context()
    execution_context = _context(stage=PolicyEvaluationStage.EXECUTION)

    first_preview = evaluate_policy(preview_context)
    second_preview = evaluate_policy(preview_context)
    execution = evaluate_policy(execution_context)

    assert first_preview == second_preview
    assert first_preview.policy_result_id == (
        "policy_3702e8db56746ecf975eedec23367a6ceb6a2ebc17a716ea2f5afbd029df546b"
    )
    assert execution.decision is PolicyDecision.ALLOW
    assert execution.context.stage is PolicyEvaluationStage.EXECUTION
    assert execution.policy_result_id != first_preview.policy_result_id


def test_engine_rejects_unrecognized_policy_version_before_evaluation() -> None:
    engine = DeterministicPolicyEngine()

    with pytest.raises(UnsupportedPolicyVersionError, match="unsupported policy version"):
        engine.evaluate(_context(policy_version="deterministic_policy_v0_9_0"))


@pytest.mark.parametrize(
    ("field_name", "timestamp"),
    [
        ("evaluated_at", _NOW.astimezone(_IST)),
        ("last_action_at", (_NOW - timedelta(hours=2)).astimezone(_IST)),
        ("plan_expires_at", (_NOW + timedelta(hours=1)).astimezone(_IST)),
    ],
)
def test_engine_rejects_non_utc_policy_facts(
    field_name: str,
    timestamp: datetime,
) -> None:
    with pytest.raises(NonUtcPolicyTimestampError, match=field_name):
        evaluate_policy(_context(**{field_name: timestamp}))
