"""Deterministic M4 audit-completeness verification across recovery facts."""

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from retryrail.config import Settings
from retryrail.contracts.domain import ActionState
from retryrail.db.session import Database
from retryrail.db.tables import (
    ApprovalDecisionRecord,
    ApprovalTokenConsumptionRecord,
    IncidentRecord,
    PaymentEventRecord,
    PaymentRecoveryControlRecord,
    PolicyResultRecord,
    RecoveryActionRecord,
    RecoveryActionTransitionRecord,
    RecoveryPlanRecord,
    RecoveryProviderDispatchRecord,
    RecoveryProviderReceiptRecord,
    RecoveryReconciliationRecord,
    RulesBasedIncidentBriefRecord,
)
from retryrail.recovery.execution import RecoveryActionNotFoundError, RecoveryExecutionService
from retryrail.recovery.models import RecoveryAuditCompletenessReport
from retryrail.recovery.workflow import MerchantScopeError, RecoveryPersistenceError

_BASE_REQUIRED_FACTS = (
    "source_payment_event",
    "incident",
    "rules_based_brief",
    "recovery_plan",
    "preview_policy",
    "merchant_approval",
    "approval_consumption",
    "execution_policy",
    "action_receipt_contract",
    "provider_terminal_transition",
    "provider_dispatch",
    "recovery_control_attempt",
)


class RecoveryAuditVerifier:
    """Prove that one action can be reconstructed without trusting logs."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        execution: RecoveryExecutionService,
    ) -> None:
        self._database = database
        self._settings = settings
        self._execution = execution

    async def verify_action(
        self,
        *,
        merchant_id: str,
        action_id: str,
    ) -> RecoveryAuditCompletenessReport:
        """Return every absent or inconsistent fact for one terminal action."""

        if merchant_id != self._settings.merchant_id:
            raise MerchantScopeError
        receipt = await self._execution.get_receipt(
            merchant_id=merchant_id,
            action_id=action_id,
        )
        try:
            async with self._database.sessions() as session:
                action = await session.scalar(
                    select(RecoveryActionRecord).where(
                        RecoveryActionRecord.action_id == action_id,
                        RecoveryActionRecord.merchant_id == merchant_id,
                    )
                )
                if action is None:
                    raise RecoveryActionNotFoundError
                required = list(_BASE_REQUIRED_FACTS)
                reconciled = any(
                    item.new_state is ActionState.RECONCILIATION_REQUIRED
                    for item in receipt.transitions
                )
                if reconciled:
                    required.append("reconciliation_receipt")
                if receipt.state is ActionState.SUCCEEDED:
                    required.append("provider_receipt")
                observed = await _observed_facts(session, action=action)
        except SQLAlchemyError as error:
            raise RecoveryPersistenceError from error
        missing = tuple(item for item in required if item not in observed)
        return RecoveryAuditCompletenessReport(
            action_id=receipt.action_id,
            incident_id=receipt.incident_id,
            plan_id=receipt.plan_id,
            merchant_id=receipt.merchant_id,
            complete=not missing,
            required_facts=tuple(required),
            missing_facts=missing,
            transition_count=len(receipt.transitions),
            terminal_state=receipt.state,
            synthetic=receipt.synthetic,
        )


async def _observed_facts(
    session: AsyncSession,
    *,
    action: RecoveryActionRecord,
) -> set[str]:
    observed = {"action_receipt_contract"}
    observed.update(await _source_and_incident_facts(session, action=action))
    observed.update(await _authority_facts(session, action=action))
    observed.update(await _outcome_facts(session, action=action))
    return observed


async def _source_and_incident_facts(
    session: AsyncSession,
    *,
    action: RecoveryActionRecord,
) -> set[str]:
    observed: set[str] = set()
    plan = await session.scalar(
        select(RecoveryPlanRecord).where(
            RecoveryPlanRecord.plan_id == action.plan_id,
            RecoveryPlanRecord.incident_id == action.incident_id,
            RecoveryPlanRecord.merchant_id == action.merchant_id,
        )
    )
    if plan is not None:
        observed.add("recovery_plan")
        source_id = plan.source_evidence_document.get("source_event_internal_id")
        source = await session.scalar(
            select(PaymentEventRecord).where(
                PaymentEventRecord.internal_id == source_id,
                PaymentEventRecord.merchant_id == action.merchant_id,
                PaymentEventRecord.payment_id == action.payment_id,
            )
        )
        if source is not None and source.signature_status == "verified":
            observed.add("source_payment_event")
    incident = await session.scalar(
        select(IncidentRecord).where(
            IncidentRecord.incident_id == action.incident_id,
            IncidentRecord.merchant_id == action.merchant_id,
        )
    )
    if incident is not None:
        observed.add("incident")
    brief = await session.scalar(
        select(RulesBasedIncidentBriefRecord).where(
            RulesBasedIncidentBriefRecord.incident_id == action.incident_id,
            RulesBasedIncidentBriefRecord.merchant_id == action.merchant_id,
            RulesBasedIncidentBriefRecord.created_at <= action.created_at,
        )
    )
    if brief is not None:
        observed.add("rules_based_brief")
    return observed


async def _authority_facts(
    session: AsyncSession,
    *,
    action: RecoveryActionRecord,
) -> set[str]:
    observed: set[str] = set()
    preview_policy = await session.scalar(
        select(PolicyResultRecord).where(
            PolicyResultRecord.policy_result_id == action.preview_policy_result_id,
            PolicyResultRecord.plan_id == action.plan_id,
            PolicyResultRecord.merchant_id == action.merchant_id,
            PolicyResultRecord.stage == "preview",
        )
    )
    if preview_policy is not None:
        observed.add("preview_policy")
    approval = await session.scalar(
        select(ApprovalDecisionRecord).where(
            ApprovalDecisionRecord.approval_id == action.approval_id,
            ApprovalDecisionRecord.plan_id == action.plan_id,
            ApprovalDecisionRecord.merchant_id == action.merchant_id,
        )
    )
    if approval is not None and approval.decision == "approve":
        observed.add("merchant_approval")
    consumption = await session.scalar(
        select(ApprovalTokenConsumptionRecord).where(
            ApprovalTokenConsumptionRecord.approval_id == action.approval_id,
            ApprovalTokenConsumptionRecord.plan_id == action.plan_id,
            ApprovalTokenConsumptionRecord.merchant_id == action.merchant_id,
        )
    )
    if consumption is not None:
        observed.add("approval_consumption")
    execution_policy = await session.scalar(
        select(PolicyResultRecord).where(
            PolicyResultRecord.policy_result_id == action.execution_policy_result_id,
            PolicyResultRecord.plan_id == action.plan_id,
            PolicyResultRecord.merchant_id == action.merchant_id,
            PolicyResultRecord.stage == "execution",
        )
    )
    if execution_policy is not None:
        observed.add("execution_policy")
    return observed


async def _outcome_facts(
    session: AsyncSession,
    *,
    action: RecoveryActionRecord,
) -> set[str]:
    observed: set[str] = set()
    dispatch = await session.scalar(
        select(RecoveryProviderDispatchRecord).where(
            RecoveryProviderDispatchRecord.action_id == action.action_id,
            RecoveryProviderDispatchRecord.merchant_id == action.merchant_id,
        )
    )
    if dispatch is not None:
        observed.add("provider_dispatch")
    provider_receipt = await session.scalar(
        select(RecoveryProviderReceiptRecord).where(
            RecoveryProviderReceiptRecord.action_id == action.action_id,
            RecoveryProviderReceiptRecord.merchant_id == action.merchant_id,
        )
    )
    if provider_receipt is not None:
        observed.add("provider_receipt")
    transitions = tuple(
        (
            await session.scalars(
                select(RecoveryActionTransitionRecord).where(
                    RecoveryActionTransitionRecord.action_id == action.action_id,
                    RecoveryActionTransitionRecord.merchant_id == action.merchant_id,
                )
            )
        ).all()
    )
    terminal = next(
        (
            item
            for item in transitions
            if item.new_state in {ActionState.SUCCEEDED.value, ActionState.FAILED.value}
        ),
        None,
    )
    if terminal is not None:
        observed.add("provider_terminal_transition")
    controls = await session.scalar(
        select(PaymentRecoveryControlRecord).where(
            PaymentRecoveryControlRecord.merchant_id == action.merchant_id,
            PaymentRecoveryControlRecord.payment_id == action.payment_id,
        )
    )
    if controls is not None and controls.prior_action_attempts >= 1:
        observed.add("recovery_control_attempt")
    reconciliation = await session.scalar(
        select(RecoveryReconciliationRecord).where(
            RecoveryReconciliationRecord.action_id == action.action_id,
            RecoveryReconciliationRecord.merchant_id == action.merchant_id,
        )
    )
    if reconciliation is not None:
        observed.add("reconciliation_receipt")
    return observed
