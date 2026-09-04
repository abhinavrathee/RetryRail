"""Pure, fail-closed M4.2 recovery policy evaluation."""

import hashlib
import json
from collections.abc import Callable
from datetime import timedelta
from typing import Final

from retryrail.contracts.domain import OperatingMode
from retryrail.contracts.recovery import (
    PolicyContextSnapshot,
    PolicyDecision,
    PolicyResultContract,
    PolicyRule,
    PolicyRuleOutcome,
    PolicyRuleResult,
    policy_reason_code,
)

DETERMINISTIC_POLICY_VERSION: Final = "deterministic_policy_v1_0_0"


class UnsupportedPolicyVersionError(ValueError):
    """The supplied context does not target this frozen evaluator version."""


class NonUtcPolicyTimestampError(ValueError):
    """A policy timestamp is aware but not represented in UTC."""


RuleEvaluator = Callable[[PolicyContextSnapshot], bool]


def _merchant_scope_matches(context: PolicyContextSnapshot) -> bool:
    return context.merchant_id == context.resource_merchant_id


def _incident_is_action_eligible(context: PolicyContextSnapshot) -> bool:
    return context.incident_action_eligible


def _review_first_is_enabled(context: PolicyContextSnapshot) -> bool:
    return context.mode is OperatingMode.REVIEW_FIRST


def _template_is_enabled(context: PolicyContextSnapshot) -> bool:
    return context.template_enabled


def _amount_is_unchanged(context: PolicyContextSnapshot) -> bool:
    return context.source_amount_subunits == context.proposed_amount_subunits


def _currency_is_unchanged(context: PolicyContextSnapshot) -> bool:
    return context.source_currency == context.proposed_currency


def _contact_is_safe(context: PolicyContextSnapshot) -> bool:
    return not context.contact_required or context.contact_consent_verified


def _customer_is_not_opted_out(context: PolicyContextSnapshot) -> bool:
    return not context.customer_opted_out


def _attempt_cap_is_available(context: PolicyContextSnapshot) -> bool:
    return context.prior_action_attempts < context.maximum_attempts_per_payment


def _cooldown_has_elapsed(context: PolicyContextSnapshot) -> bool:
    if context.last_action_at is None:
        return True
    elapsed = context.evaluated_at - context.last_action_at
    return elapsed >= timedelta(seconds=context.cooldown_seconds)


def _plan_is_active(context: PolicyContextSnapshot) -> bool:
    return context.evaluated_at < context.plan_expires_at


def _kill_switch_is_off(context: PolicyContextSnapshot) -> bool:
    return not context.merchant_kill_switch


def _payment_is_unrecovered(context: PolicyContextSnapshot) -> bool:
    return not context.already_recovered


_RULE_EVALUATORS: Final[tuple[tuple[PolicyRule, RuleEvaluator], ...]] = (
    (PolicyRule.MERCHANT_SCOPE, _merchant_scope_matches),
    (PolicyRule.INCIDENT_ACTION_ELIGIBILITY, _incident_is_action_eligible),
    (PolicyRule.OPERATING_MODE, _review_first_is_enabled),
    (PolicyRule.TEMPLATE_ENABLED, _template_is_enabled),
    (PolicyRule.ORIGINAL_AMOUNT, _amount_is_unchanged),
    (PolicyRule.CURRENCY, _currency_is_unchanged),
    (PolicyRule.CONTACT_CONSENT, _contact_is_safe),
    (PolicyRule.CUSTOMER_OPT_OUT, _customer_is_not_opted_out),
    (PolicyRule.ATTEMPT_CAP, _attempt_cap_is_available),
    (PolicyRule.COOLDOWN, _cooldown_has_elapsed),
    (PolicyRule.PLAN_EXPIRY, _plan_is_active),
    (PolicyRule.KILL_SWITCH, _kill_switch_is_off),
    (PolicyRule.ALREADY_RECOVERED, _payment_is_unrecovered),
)


def _canonical_context_bytes(context: PolicyContextSnapshot) -> bytes:
    serialized = json.dumps(
        context.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return serialized.encode("utf-8")


def _policy_result_id(context: PolicyContextSnapshot) -> str:
    digest = hashlib.sha256(_canonical_context_bytes(context)).hexdigest()
    return f"policy_{digest}"


def _validate_utc_timestamps(context: PolicyContextSnapshot) -> None:
    timestamps = (
        ("evaluated_at", context.evaluated_at),
        ("last_action_at", context.last_action_at),
        ("plan_expires_at", context.plan_expires_at),
    )
    for field_name, timestamp in timestamps:
        if timestamp is not None and timestamp.utcoffset() != timedelta(0):
            msg = f"policy context timestamp {field_name!r} must be UTC"
            raise NonUtcPolicyTimestampError(msg)


class DeterministicPolicyEngine:
    """Evaluate the complete frozen rule set without I/O or side effects."""

    __slots__ = ()

    policy_version: Final = DETERMINISTIC_POLICY_VERSION

    def evaluate(self, context: PolicyContextSnapshot) -> PolicyResultContract:
        """Return all rule outcomes in canonical order or reject version drift."""

        if context.policy_version != self.policy_version:
            msg = (
                f"unsupported policy version {context.policy_version!r}; "
                f"expected {self.policy_version!r}"
            )
            raise UnsupportedPolicyVersionError(msg)
        _validate_utc_timestamps(context)

        rule_results = tuple(
            self._evaluate_rule(rule, evaluator, context) for rule, evaluator in _RULE_EVALUATORS
        )
        decision = (
            PolicyDecision.ALLOW
            if all(result.outcome is PolicyRuleOutcome.SATISFIED for result in rule_results)
            else PolicyDecision.DENY
        )
        return PolicyResultContract(
            policy_result_id=_policy_result_id(context),
            context=context,
            decision=decision,
            rule_results=rule_results,
            synthetic=context.synthetic,
        )

    @staticmethod
    def _evaluate_rule(
        rule: PolicyRule,
        evaluator: RuleEvaluator,
        context: PolicyContextSnapshot,
    ) -> PolicyRuleResult:
        outcome = PolicyRuleOutcome.SATISFIED if evaluator(context) else PolicyRuleOutcome.DENY
        return PolicyRuleResult(
            rule=rule,
            outcome=outcome,
            reason_code=policy_reason_code(rule, outcome),
        )


_DEFAULT_ENGINE = DeterministicPolicyEngine()


def evaluate_policy(context: PolicyContextSnapshot) -> PolicyResultContract:
    """Evaluate policy through the stateless default engine."""

    return _DEFAULT_ENGINE.evaluate(context)
