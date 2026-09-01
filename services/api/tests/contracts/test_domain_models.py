"""Failure-path tests for contracts that later milestones must implement."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from retryrail.contracts.domain import (
    ActionActor,
    ActionReceiptContract,
    ActionState,
    ActionTransition,
    CohortDimension,
    CohortPredicate,
    IncidentContract,
    IncidentEvidence,
    IncidentStatus,
    OperatingMode,
    RecoveryEligibility,
    RecoveryPlanContract,
    RecoveryStoppingRules,
    RecoveryTemplate,
)
from retryrail.events.models import PaymentMethod
from retryrail.synthetic.models import (
    BodyMode,
    ExpectedDeliveryDisposition,
    ExperimentDesign,
    SignatureMode,
    WebhookDeliveryInstruction,
)

_NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _incident_evidence(**updates: int) -> IncidentEvidence:
    values = {
        "baseline_attempts": 100,
        "baseline_successes": 92,
        "current_attempts": 50,
        "current_successes": 25,
        "minimum_attempts": 20,
        "observed_success_rate_drop_bps": 4_200,
        "confidence_ppm": 990_000,
        "excess_failures": 21,
    }
    values.update(updates)
    return IncidentEvidence(**values)


def _eligibility(currency: str = "INR") -> RecoveryEligibility:
    return RecoveryEligibility(
        currency=currency,
        methods=(PaymentMethod.CARD,),
        minimum_amount_subunits=100,
        maximum_amount_subunits=1_000_000,
    )


def _stopping_rules(expires_at: datetime | None = None) -> RecoveryStoppingRules:
    return RecoveryStoppingRules(
        maximum_actions=100,
        maximum_attempts_per_payment=1,
        cooldown_seconds=3_600,
        expires_at=expires_at or _NOW + timedelta(hours=24),
    )


def test_incident_contract_accepts_grounded_open_incident() -> None:
    incident = IncidentContract(
        incident_id="incident_synthetic_001",
        merchant_id="merchant_synthetic_001",
        status=IncidentStatus.OPEN,
        detector_version="detector_v1",
        opened_at=_NOW,
        last_observed_at=_NOW + timedelta(minutes=15),
        affected_cohort=(
            CohortPredicate(dimension=CohortDimension.METHOD, value="card"),
        ),
        evidence_event_ids=("event_synthetic_001",),
        evidence=_incident_evidence(),
        likely_error_sources=("bank",),
        gmv_at_risk_subunits=2_500_000,
        currency="INR",
        synthetic=True,
    )

    assert incident.resolved_at is None
    assert incident.evidence.excess_failures == 21


@pytest.mark.parametrize(
    "updates",
    [
        {"baseline_successes": 101},
        {"current_successes": 51},
    ],
)
def test_incident_evidence_rejects_impossible_counts(updates: dict[str, int]) -> None:
    with pytest.raises(ValidationError, match="successes cannot exceed"):
        _incident_evidence(**updates)


def test_incident_lifecycle_rejects_missing_or_invalid_resolution_times() -> None:
    common = {
        "incident_id": "incident_synthetic_001",
        "merchant_id": "merchant_synthetic_001",
        "detector_version": "detector_v1",
        "opened_at": _NOW,
        "last_observed_at": _NOW + timedelta(minutes=10),
        "affected_cohort": (
            CohortPredicate(dimension=CohortDimension.METHOD, value="upi"),
        ),
        "evidence_event_ids": ("event_synthetic_001",),
        "evidence": _incident_evidence(),
        "likely_error_sources": ("gateway",),
        "gmv_at_risk_subunits": 100_000,
        "currency": "INR",
        "synthetic": True,
    }
    with pytest.raises(ValidationError, match="require resolved_at"):
        IncidentContract(status=IncidentStatus.RESOLVED, **common)
    with pytest.raises(ValidationError, match="open incidents cannot"):
        IncidentContract(
            status=IncidentStatus.OPEN,
            resolved_at=_NOW + timedelta(minutes=20),
            **common,
        )


def test_recovery_plan_freezes_review_first_policy_and_currency() -> None:
    plan = RecoveryPlanContract(
        plan_id="plan_synthetic_001",
        incident_id="incident_synthetic_001",
        merchant_id="merchant_synthetic_001",
        mode=OperatingMode.REVIEW_FIRST,
        template=RecoveryTemplate.STANDARD_PAYMENT_LINK,
        policy_version="policy_v1",
        created_at=_NOW,
        eligibility=_eligibility(),
        stopping_rules=_stopping_rules(),
        eligible_payment_count=25,
        eligible_gmv_subunits=2_000_000,
        currency="INR",
        synthetic=True,
    )

    assert plan.requires_external_approval is True
    with pytest.raises(ValidationError, match="currencies must match"):
        plan.model_copy(update={"currency": "USD"}).model_validate(
            {**plan.model_dump(), "currency": "USD"}
        )


def test_recovery_contract_rejects_inverted_amount_and_expiry_ranges() -> None:
    with pytest.raises(ValidationError, match="maximum amount"):
        RecoveryEligibility(
            currency="INR",
            methods=(PaymentMethod.UPI,),
            minimum_amount_subunits=1_000,
            maximum_amount_subunits=999,
        )

    with pytest.raises(ValidationError, match="expiry must be after"):
        RecoveryPlanContract(
            plan_id="plan_synthetic_001",
            incident_id="incident_synthetic_001",
            merchant_id="merchant_synthetic_001",
            mode=OperatingMode.ANALYZE_ONLY,
            template=RecoveryTemplate.STANDARD_PAYMENT_LINK,
            policy_version="policy_v1",
            created_at=_NOW,
            eligibility=_eligibility(),
            stopping_rules=_stopping_rules(_NOW),
            eligible_payment_count=0,
            eligible_gmv_subunits=0,
            currency="INR",
            synthetic=True,
        )


def test_action_receipt_requires_a_complete_monotonic_chain() -> None:
    transitions = (
        ActionTransition(
            prior_state=None,
            new_state=ActionState.PREVIEWED,
            occurred_at=_NOW,
            actor=ActionActor.SYSTEM,
            reason_code="policy_preview_passed",
        ),
        ActionTransition(
            prior_state=ActionState.PREVIEWED,
            new_state=ActionState.AWAITING_APPROVAL,
            occurred_at=_NOW + timedelta(minutes=1),
            actor=ActionActor.SYSTEM,
            reason_code="external_approval_required",
        ),
        ActionTransition(
            prior_state=ActionState.AWAITING_APPROVAL,
            new_state=ActionState.APPROVED,
            occurred_at=_NOW + timedelta(minutes=2),
            actor=ActionActor.MERCHANT,
            reason_code="merchant_approved",
        ),
        ActionTransition(
            prior_state=ActionState.APPROVED,
            new_state=ActionState.EXECUTING,
            occurred_at=_NOW + timedelta(minutes=3),
            actor=ActionActor.WORKER,
            reason_code="policy_revalidated",
        ),
        ActionTransition(
            prior_state=ActionState.EXECUTING,
            new_state=ActionState.SUCCEEDED,
            occurred_at=_NOW + timedelta(minutes=4),
            actor=ActionActor.RAZORPAY_TEST_MODE,
            reason_code="provider_verified",
        ),
    )
    receipt = ActionReceiptContract(
        action_id="action_synthetic_001",
        plan_id="plan_synthetic_001",
        incident_id="incident_synthetic_001",
        merchant_id="merchant_synthetic_001",
        idempotency_key="idempotency_synthetic_001",
        state=ActionState.SUCCEEDED,
        transitions=transitions,
        external_reference="plink_synthetic_001",
        verified_at=_NOW + timedelta(minutes=5),
        synthetic=True,
    )
    assert receipt.state is ActionState.SUCCEEDED

    broken = [transition.model_dump() for transition in transitions]
    broken[2]["prior_state"] = ActionState.PREVIEWED
    with pytest.raises(ValidationError, match="does not continue"):
        ActionReceiptContract.model_validate({**receipt.model_dump(), "transitions": broken})

    illegal = [transition.model_dump() for transition in transitions[:2]]
    illegal.append(
        ActionTransition(
            prior_state=ActionState.AWAITING_APPROVAL,
            new_state=ActionState.EXECUTING,
            occurred_at=_NOW + timedelta(minutes=2),
            actor=ActionActor.WORKER,
            reason_code="approval_was_skipped",
        ).model_dump()
    )
    with pytest.raises(ValidationError, match="is not allowed"):
        ActionReceiptContract.model_validate(
            {
                **receipt.model_dump(),
                "state": ActionState.EXECUTING,
                "transitions": illegal,
                "external_reference": None,
                "verified_at": None,
            }
        )

    with pytest.raises(ValidationError, match="external reference"):
        ActionReceiptContract.model_validate(
            {
                **receipt.model_dump(),
                "external_reference": None,
                "verified_at": None,
            }
        )


def test_delivery_contract_rejects_authentic_rejection_and_unauthentic_acceptance() -> None:
    common = {
        "sequence": 1,
        "delivery_id": "delivery_synthetic_001",
        "merchant_id": "merchant_synthetic_001",
        "razorpay_event_id": "event_synthetic_001",
        "delivery_attempt": 1,
        "delivered_at": _NOW,
    }
    with pytest.raises(ValidationError, match="authentic deliveries"):
        WebhookDeliveryInstruction(
            signature_mode=SignatureMode.VALID,
            body_mode=BodyMode.UNMODIFIED,
            expected_disposition=ExpectedDeliveryDisposition.REJECTED_SIGNATURE,
            **common,
        )
    with pytest.raises(ValidationError, match="unauthentic deliveries"):
        WebhookDeliveryInstruction(
            signature_mode=SignatureMode.INVALID,
            body_mode=BodyMode.UNMODIFIED,
            expected_disposition=ExpectedDeliveryDisposition.ACCEPTED,
            **common,
        )


@pytest.mark.parametrize(
    ("treatment", "control", "assignment_namespace", "outcome_namespace", "message"),
    [
        (7_000, 2_000, "assignment_v1", "outcome_v1", "total 10,000"),
        (8_000, 2_000, "same_namespace", "same_namespace", "independent"),
    ],
)
def test_experiment_design_rejects_post_hoc_or_incomplete_rules(
    treatment: int,
    control: int,
    assignment_namespace: str,
    outcome_namespace: str,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        ExperimentDesign(
            design_id="experiment_design_v1",
            frozen_at=_NOW,
            assignment_namespace=assignment_namespace,
            outcome_namespace=outcome_namespace,
            treatment_allocation_bps=treatment,
            control_allocation_bps=control,
            strata=("method",),
            control_recovery_rate_bps=1_500,
            treatment_recovery_rate_bps=4_500,
            attribution_window_seconds=86_400,
        )
