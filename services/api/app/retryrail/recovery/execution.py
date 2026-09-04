"""Crash-safe execute-once recovery state machine and append-only receipt ledger."""

import asyncio
import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from retryrail.config import Settings
from retryrail.contracts.domain import ActionState, RecoveryTemplate
from retryrail.contracts.recovery import (
    ApprovalDecision,
    ApprovalStatus,
    PolicyContextSnapshot,
    PolicyDecision,
    PolicyEvaluationStage,
    PolicyResultContract,
    RecoveryActionActor,
    RecoveryActionContract,
    RecoveryActionError,
    RecoveryActionErrorCategory,
    RecoveryActionTransition,
    RecoveryExecutionTarget,
    SideEffectClass,
)
from retryrail.db.session import Database
from retryrail.db.tables import (
    ApprovalDecisionRecord,
    ApprovalTokenConsumptionRecord,
    IncidentRecord,
    PaymentEventRecord,
    PaymentProjectionRecord,
    PaymentRecoveryControlRecord,
    PolicyResultRecord,
    RecoveryActionRecord,
    RecoveryActionTransitionRecord,
    RecoveryPlanRecord,
    RecoveryProviderDispatchRecord,
    RecoveryProviderReceiptRecord,
    RecoveryReconciliationRecord,
)
from retryrail.detection.runtime_activation import load_detector_v4_activation
from retryrail.events.models import NormalizedPaymentEvent, PaymentEventType, PaymentStatus
from retryrail.observability.metrics import PipelineMetrics
from retryrail.policy import DETERMINISTIC_POLICY_VERSION, DeterministicPolicyEngine
from retryrail.recovery.adapter import (
    PaymentLinkCreateRequest,
    PaymentLinkResult,
    ProviderError,
    ProviderOutcomeAmbiguousError,
    RecoveryProvider,
)
from retryrail.recovery.integrity import canonical_sha256, stable_identifier
from retryrail.recovery.models import (
    ApprovalTokenBinding,
    ProviderVerificationSource,
    RecoveryExecutionDisposition,
    RecoveryExecutionResponse,
    RecoveryPlanPreview,
    RecoveryProviderReceipt,
    RecoveryReconciliationResponse,
)
from retryrail.recovery.workflow import (
    ApprovalTokenAlreadyUsedError,
    ApprovalTokenInvalidError,
    MerchantScopeError,
    PlanNotFoundError,
    RecoveryEvidenceInvalidError,
    RecoveryIdempotencyConflictError,
    RecoveryPersistenceError,
    RecoveryWorkflowError,
    RecoveryWorkflowService,
    approval_matches_binding,
    materialize_preview,
)

LOGGER = structlog.get_logger(__name__)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class RecoveryActionNotFoundError(RecoveryWorkflowError):
    """No action exists in the configured merchant scope."""

    reason_code = "RECOVERY_ACTION_NOT_FOUND"


class RecoveryActionNotReconciliationRequiredError(RecoveryWorkflowError):
    """Only an ambiguous action may enter the reconciliation boundary."""

    reason_code = "RECOVERY_ACTION_NOT_RECONCILIABLE"


class RecoveryFakeTargetRequiresSyntheticError(RecoveryWorkflowError):
    """M4's deterministic fake is never used for an unlabeled real payment."""

    reason_code = "RECOVERY_FAKE_TARGET_REQUIRES_SYNTHETIC_PAYMENT"


class RecoveryExecutionRequiresSyntheticError(RecoveryWorkflowError):
    """P0 provider execution is limited to explicitly synthetic Test Mode evidence."""

    reason_code = "RECOVERY_EXECUTION_REQUIRES_SYNTHETIC_PAYMENT"


class RecoveryProviderLookupUnavailableError(RecoveryWorkflowError):
    """A lookup failed safely and the action remains eligible for reconciliation."""

    reason_code = "RECOVERY_PROVIDER_LOOKUP_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class _ExecutionResources:
    plan_record: RecoveryPlanRecord
    preview_policy_record: PolicyResultRecord
    approval: ApprovalDecisionRecord
    preview: RecoveryPlanPreview


@dataclass(frozen=True, slots=True)
class _PreparedExecution:
    response: RecoveryExecutionResponse | None
    action_id: str | None
    request: PaymentLinkCreateRequest | None
    approval_consumed: bool


@dataclass(frozen=True, slots=True)
class _PreparedReconciliation:
    response: RecoveryReconciliationResponse | None
    reference_id: str | None


class RecoveryExecutionService:
    """Join fresh authority to one durable provider dispatch and verified outcome."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        metrics: PipelineMetrics,
        workflow: RecoveryWorkflowService,
        provider: RecoveryProvider,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._database = database
        self._settings = settings
        self._metrics = metrics
        self._workflow = workflow
        self._provider = provider
        self._clock = clock
        self._policy = DeterministicPolicyEngine()
        self._detector_activation = load_detector_v4_activation()
        self._operation_locks: dict[str, asyncio.Lock] = {}

    async def execute(
        self,
        *,
        merchant_id: str,
        plan_id: str,
        raw_approval_token: str | None,
        idempotency_key: str,
    ) -> RecoveryExecutionResponse:
        """Revalidate, durably dispatch and create at most one logical action."""

        self._require_merchant(merchant_id)
        token_hash = self._workflow.validated_token_hash(raw_approval_token)
        async with self._operation_lock(f"execute:{merchant_id}:{plan_id}"):
            try:
                now = self._clock_utc()
                async with self._database.sessions() as session, session.begin():
                    prepared = await self._prepare_execution_in_session(
                        session,
                        merchant_id=merchant_id,
                        plan_id=plan_id,
                        token_hash=token_hash,
                        idempotency_key=idempotency_key,
                        now=now,
                    )
            except SQLAlchemyError as error:
                self._log_execution_persistence_failure(merchant_id, plan_id)
                raise RecoveryPersistenceError from error

            if prepared.response is not None:
                response = prepared.response
                provider_called = False
            else:
                if prepared.action_id is None or prepared.request is None:
                    raise RecoveryEvidenceInvalidError
                provider_called = True
                provider_target = self._settings.recovery_execution_target
                self._metrics.recovery_provider_dispatches.labels(
                    target=provider_target
                ).inc()
                provider_result: PaymentLinkResult | None = None
                provider_error: ProviderError | None = None
                try:
                    provider_result = await self._provider.create_standard_payment_link(
                        prepared.request
                    )
                except ProviderError as error:
                    provider_error = error
                provider_result_label = "succeeded"
                if isinstance(provider_error, ProviderOutcomeAmbiguousError):
                    provider_result_label = "ambiguous"
                elif provider_error is not None:
                    provider_result_label = "known_failure"
                self._metrics.recovery_provider_outcomes.labels(
                    target=provider_target,
                    result=provider_result_label,
                ).inc()
                try:
                    async with self._database.sessions() as session, session.begin():
                        response = await self._record_provider_outcome_in_session(
                            session,
                            merchant_id=merchant_id,
                            action_id=prepared.action_id,
                            request=prepared.request,
                            result=provider_result,
                            error=provider_error,
                        )
                except SQLAlchemyError as error:
                    self._log_execution_persistence_failure(merchant_id, plan_id)
                    raise RecoveryPersistenceError from error

        if prepared.approval_consumed:
            self._metrics.approval_token_consumptions.labels(result="consumed").inc()
        self._metrics.recovery_action_executions.labels(
            result=response.disposition.value,
            state=(response.receipt.state.value if response.receipt else "blocked"),
        ).inc()
        LOGGER.info(
            "recovery_execution_completed",
            disposition=response.disposition.value,
            merchant_id=merchant_id,
            plan_id=plan_id,
            action_id=(response.receipt.action_id if response.receipt else None),
            state=(response.receipt.state.value if response.receipt else "blocked"),
            provider_called=provider_called,
        )
        return response

    async def reconcile(
        self,
        *,
        merchant_id: str,
        action_id: str,
        idempotency_key: str,
    ) -> RecoveryReconciliationResponse:
        """Resolve one ambiguous result by reference without retrying creation."""

        self._require_merchant(merchant_id)
        async with self._operation_lock(f"reconcile:{merchant_id}:{action_id}"):
            try:
                now = self._clock_utc()
                async with self._database.sessions() as session, session.begin():
                    prepared = await self._prepare_reconciliation_in_session(
                        session,
                        merchant_id=merchant_id,
                        action_id=action_id,
                        idempotency_key=idempotency_key,
                    )
            except SQLAlchemyError as error:
                self._log_reconciliation_persistence_failure(merchant_id, action_id)
                raise RecoveryPersistenceError from error

            if prepared.response is not None:
                response = prepared.response
            else:
                if prepared.reference_id is None:
                    raise RecoveryEvidenceInvalidError
                try:
                    provider_result = await self._provider.reconcile(prepared.reference_id)
                except ProviderError as error:
                    self._metrics.recovery_provider_lookups.labels(
                        target=self._settings.recovery_execution_target,
                        result="unavailable",
                    ).inc()
                    LOGGER.warning(
                        "recovery_provider_lookup_unavailable",
                        merchant_id=merchant_id,
                        action_id=action_id,
                        reason_code=RecoveryProviderLookupUnavailableError.reason_code,
                        provider_reason_code=error.error.reason_code,
                    )
                    raise RecoveryProviderLookupUnavailableError from error
                self._metrics.recovery_provider_lookups.labels(
                    target=self._settings.recovery_execution_target,
                    result="found" if provider_result is not None else "absent",
                ).inc()
                try:
                    async with self._database.sessions() as session, session.begin():
                        response = await self._record_reconciliation_in_session(
                            session,
                            merchant_id=merchant_id,
                            action_id=action_id,
                            idempotency_key=idempotency_key,
                            now=now,
                            provider_result=provider_result,
                        )
                except SQLAlchemyError as error:
                    self._log_reconciliation_persistence_failure(merchant_id, action_id)
                    raise RecoveryPersistenceError from error

        self._metrics.recovery_action_reconciliations.labels(
            result=response.disposition,
            state=response.receipt.state.value,
        ).inc()
        return response

    async def get_receipt(
        self,
        *,
        merchant_id: str,
        action_id: str,
    ) -> RecoveryActionContract:
        """Read and fully revalidate one immutable action history."""

        self._require_merchant(merchant_id)
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
                return await self._materialize_action(session, action)
        except SQLAlchemyError as error:
            raise RecoveryPersistenceError from error

    async def _prepare_execution_in_session(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        plan_id: str,
        token_hash: str,
        idempotency_key: str,
        now: datetime,
    ) -> _PreparedExecution:
        resources = await self._load_execution_resources(
            session,
            merchant_id=merchant_id,
            plan_id=plan_id,
            token_hash=token_hash,
        )
        request = self._provider_request(resources)
        existing = await self._existing_action(
            session,
            merchant_id=merchant_id,
            plan_id=plan_id,
            idempotency_key=idempotency_key,
        )
        if existing is not None:
            response = await self._replay_action(
                session,
                action=existing,
                approval=resources.approval,
                request=request,
                idempotency_key=idempotency_key,
            )
            return _PreparedExecution(
                response=response,
                action_id=None,
                request=None,
                approval_consumed=False,
            )

        binding = self._approval_binding(resources, idempotency_key=idempotency_key)
        if not approval_matches_binding(resources.approval, binding):
            raise ApprovalTokenInvalidError
        if self._is_expired(resources, now=now):
            action = await self._persist_expired_action(
                session,
                resources=resources,
                request=request,
                idempotency_key=idempotency_key,
                now=now,
            )
            response = await self._execution_response(
                session,
                action,
                disposition=RecoveryExecutionDisposition.CREATED,
            )
            return _PreparedExecution(
                response=response,
                action_id=None,
                request=None,
                approval_consumed=False,
            )

        prior_consumption = await session.scalar(
            select(ApprovalTokenConsumptionRecord).where(
                ApprovalTokenConsumptionRecord.approval_id == resources.approval.approval_id
            )
        )
        if prior_consumption is not None:
            raise ApprovalTokenAlreadyUsedError

        execution_policy = await self._load_or_create_execution_policy(
            session,
            resources=resources,
            now=now,
        )
        if execution_policy.decision is PolicyDecision.DENY:
            return _PreparedExecution(
                response=RecoveryExecutionResponse(
                    disposition=RecoveryExecutionDisposition.BLOCKED,
                    execution_policy_result=execution_policy,
                    execution_policy_result_sha256=canonical_sha256(execution_policy),
                    synthetic=execution_policy.synthetic,
                ),
                action_id=None,
                request=None,
                approval_consumed=False,
            )

        await self._workflow.consume_approval_token_in_session(
            session,
            approval=resources.approval,
            binding=binding,
            now=now,
        )
        action = await self._persist_executing_action(
            session,
            resources=resources,
            request=request,
            execution_policy=execution_policy,
            idempotency_key=idempotency_key,
            now=now,
        )
        await self._record_provider_attempt(session, resources=resources, now=now)
        await self._persist_provider_dispatch(
            session,
            action=action,
            request=request,
            prepared_at=now,
        )
        return _PreparedExecution(
            response=None,
            action_id=action.action_id,
            request=request,
            approval_consumed=True,
        )

    async def _load_execution_resources(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        plan_id: str,
        token_hash: str,
    ) -> _ExecutionResources:
        plan = await session.scalar(
            select(RecoveryPlanRecord)
            .where(
                RecoveryPlanRecord.plan_id == plan_id,
                RecoveryPlanRecord.merchant_id == merchant_id,
            )
            .with_for_update()
        )
        if plan is None:
            raise PlanNotFoundError
        preview_policy = await session.scalar(
            select(PolicyResultRecord).where(
                PolicyResultRecord.plan_id == plan_id,
                PolicyResultRecord.merchant_id == merchant_id,
                PolicyResultRecord.stage == PolicyEvaluationStage.PREVIEW.value,
            )
        )
        if preview_policy is None:
            raise RecoveryEvidenceInvalidError
        preview = materialize_preview(plan, preview_policy)
        approval = await session.scalar(
            select(ApprovalDecisionRecord)
            .where(ApprovalDecisionRecord.token_hash == token_hash)
            .with_for_update()
        )
        if (
            approval is None
            or approval.plan_id != plan_id
            or approval.merchant_id != merchant_id
            or approval.decision != ApprovalDecision.APPROVE.value
            or approval.initial_status != ApprovalStatus.ISSUED.value
        ):
            raise ApprovalTokenInvalidError
        return _ExecutionResources(plan, preview_policy, approval, preview)

    async def _existing_action(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        plan_id: str,
        idempotency_key: str,
    ) -> RecoveryActionRecord | None:
        by_plan = await session.scalar(
            select(RecoveryActionRecord).where(
                RecoveryActionRecord.plan_id == plan_id,
                RecoveryActionRecord.merchant_id == merchant_id,
            )
        )
        by_idempotency = await session.scalar(
            select(RecoveryActionRecord).where(
                RecoveryActionRecord.merchant_id == merchant_id,
                RecoveryActionRecord.idempotency_key == idempotency_key,
            )
        )
        if by_plan is not None and by_idempotency is not None:
            if by_plan.action_id != by_idempotency.action_id:
                raise RecoveryIdempotencyConflictError
            return by_plan
        if by_plan is not None:
            raise RecoveryIdempotencyConflictError
        if by_idempotency is not None:
            raise RecoveryIdempotencyConflictError
        return None

    async def _replay_action(
        self,
        session: AsyncSession,
        *,
        action: RecoveryActionRecord,
        approval: ApprovalDecisionRecord,
        request: PaymentLinkCreateRequest,
        idempotency_key: str,
    ) -> RecoveryExecutionResponse:
        if (
            action.approval_id != approval.approval_id
            or action.idempotency_key != idempotency_key
            or not hmac.compare_digest(action.request_sha256, canonical_sha256(request))
            or action.request_document != request.model_dump(mode="json")
        ):
            raise RecoveryIdempotencyConflictError
        return await self._execution_response(
            session,
            action,
            disposition=RecoveryExecutionDisposition.REPLAYED,
        )

    def _approval_binding(
        self,
        resources: _ExecutionResources,
        *,
        idempotency_key: str,
    ) -> ApprovalTokenBinding:
        preview = resources.preview
        return ApprovalTokenBinding(
            merchant_id=preview.plan.merchant_id,
            incident_id=preview.plan.incident_id,
            plan_id=preview.plan.plan_id,
            policy_result_id=preview.policy_result.policy_result_id,
            plan_sha256=preview.plan_sha256,
            policy_result_sha256=preview.policy_result_sha256,
            consumption_idempotency_key=idempotency_key,
        )

    @staticmethod
    def _is_expired(resources: _ExecutionResources, *, now: datetime) -> bool:
        approval_expiry = resources.approval.expires_at
        return (
            approval_expiry is None
            or now >= approval_expiry
            or now >= resources.preview.plan.stopping_rules.expires_at
        )

    async def _load_or_create_execution_policy(
        self,
        session: AsyncSession,
        *,
        resources: _ExecutionResources,
        now: datetime,
    ) -> PolicyResultContract:
        existing = await session.scalar(
            select(PolicyResultRecord).where(
                PolicyResultRecord.plan_id == resources.plan_record.plan_id,
                PolicyResultRecord.merchant_id == resources.plan_record.merchant_id,
                PolicyResultRecord.stage == PolicyEvaluationStage.EXECUTION.value,
            )
        )
        if existing is not None:
            return _materialize_policy(existing, resources.plan_record)
        context = await self._build_execution_context(session, resources=resources, now=now)
        result = self._policy.evaluate(context)
        record = PolicyResultRecord(
            policy_result_id=result.policy_result_id,
            plan_id=resources.plan_record.plan_id,
            merchant_id=resources.plan_record.merchant_id,
            stage=PolicyEvaluationStage.EXECUTION.value,
            policy_result_sha256=canonical_sha256(result),
            result_document=result.model_dump(mode="json"),
            created_at=now,
        )
        session.add(record)
        await session.flush()
        self._metrics.recovery_policy_decisions.labels(
            stage=PolicyEvaluationStage.EXECUTION.value,
            decision=result.decision.value,
        ).inc()
        return result

    async def _build_execution_context(
        self,
        session: AsyncSession,
        *,
        resources: _ExecutionResources,
        now: datetime,
    ) -> PolicyContextSnapshot:
        preview = resources.preview
        incident = await session.scalar(
            select(IncidentRecord)
            .where(
                IncidentRecord.incident_id == preview.plan.incident_id,
                IncidentRecord.merchant_id == preview.plan.merchant_id,
            )
            .with_for_update()
        )
        payment = await session.scalar(
            select(PaymentProjectionRecord)
            .where(
                PaymentProjectionRecord.merchant_id == preview.plan.merchant_id,
                PaymentProjectionRecord.payment_id == preview.payment_id,
            )
            .with_for_update()
        )
        controls = await session.scalar(
            select(PaymentRecoveryControlRecord)
            .where(
                PaymentRecoveryControlRecord.merchant_id == preview.plan.merchant_id,
                PaymentRecoveryControlRecord.payment_id == preview.payment_id,
            )
            .with_for_update()
        )
        if incident is None or payment is None or controls is None:
            raise RecoveryEvidenceInvalidError
        await self._validate_execution_sources(
            session,
            resources=resources,
            incident=incident,
            payment=payment,
            controls=controls,
        )
        return PolicyContextSnapshot(
            stage=PolicyEvaluationStage.EXECUTION,
            policy_version=DETERMINISTIC_POLICY_VERSION,
            evaluated_at=now,
            merchant_id=preview.plan.merchant_id,
            resource_merchant_id=payment.merchant_id,
            incident_id=preview.plan.incident_id,
            plan_id=preview.plan.plan_id,
            payment_id=preview.payment_id,
            incident_action_eligible=self._detector_activation.allows_incident(incident),
            mode=preview.plan.mode,
            template=preview.plan.template,
            template_enabled=self._settings.recovery_template_enabled,
            source_amount_subunits=preview.amount_subunits,
            proposed_amount_subunits=preview.amount_subunits,
            source_currency=preview.currency,
            proposed_currency=preview.currency,
            contact_required=False,
            contact_consent_verified=controls.contact_consent_verified,
            customer_opted_out=controls.customer_opted_out,
            prior_action_attempts=controls.prior_action_attempts,
            maximum_attempts_per_payment=(preview.plan.stopping_rules.maximum_attempts_per_payment),
            last_action_at=controls.last_action_at,
            cooldown_seconds=preview.plan.stopping_rules.cooldown_seconds,
            plan_expires_at=preview.plan.stopping_rules.expires_at,
            merchant_kill_switch=self._settings.recovery_kill_switch,
            already_recovered=(
                controls.already_recovered or payment.status != PaymentStatus.FAILED.value
            ),
            execution_target=preview.execution_target,
            synthetic=preview.synthetic,
        )

    async def _validate_execution_sources(
        self,
        session: AsyncSession,
        *,
        resources: _ExecutionResources,
        incident: IncidentRecord,
        payment: PaymentProjectionRecord,
        controls: PaymentRecoveryControlRecord,
    ) -> None:
        preview = resources.preview
        evidence = preview.source_evidence
        if not preview.synthetic:
            if preview.execution_target is RecoveryExecutionTarget.DETERMINISTIC_FAKE:
                raise RecoveryFakeTargetRequiresSyntheticError
            raise RecoveryExecutionRequiresSyntheticError
        if (
            incident.detector_version != evidence.detector_version
            or incident.detector_config_sha256 != evidence.detector_config_sha256
            or incident.synthetic is not preview.synthetic
            or payment.synthetic is not preview.synthetic
            or payment.amount_subunits != preview.amount_subunits
            or payment.currency != preview.currency
            or controls.source != "synthetic_fixture_default"
            or controls.version < evidence.recovery_control_version
        ):
            raise RecoveryEvidenceInvalidError
        event_record = await session.scalar(
            select(PaymentEventRecord).where(
                PaymentEventRecord.internal_id == evidence.source_event_internal_id,
                PaymentEventRecord.merchant_id == preview.plan.merchant_id,
                PaymentEventRecord.payment_id == preview.payment_id,
            )
        )
        if event_record is None:
            raise RecoveryEvidenceInvalidError
        try:
            event = NormalizedPaymentEvent.model_validate(event_record.normalized_event)
        except ValidationError as error:
            raise RecoveryEvidenceInvalidError from error
        if (
            event_record.signature_status != "verified"
            or event.event_type is not PaymentEventType.FAILED
            or event.razorpay_event_id != evidence.source_razorpay_event_id
            or event.payment.amount_subunits != preview.amount_subunits
            or event.payment.currency != preview.currency
            or event.synthetic is not preview.synthetic
        ):
            raise RecoveryEvidenceInvalidError

    def _provider_request(self, resources: _ExecutionResources) -> PaymentLinkCreateRequest:
        preview = resources.preview
        return PaymentLinkCreateRequest(
            amount_subunits=preview.amount_subunits,
            currency=preview.currency,
            reference_id=_reference_id(
                preview.plan.merchant_id,
                preview.payment_id,
                preview.plan.plan_id,
            ),
            expires_at=preview.plan.stopping_rules.expires_at,
            external_notifications_enabled=False,
            synthetic=preview.synthetic,
        )

    async def _persist_expired_action(
        self,
        session: AsyncSession,
        *,
        resources: _ExecutionResources,
        request: PaymentLinkCreateRequest,
        idempotency_key: str,
        now: datetime,
    ) -> RecoveryActionRecord:
        action = self._action_record(
            resources=resources,
            request=request,
            idempotency_key=idempotency_key,
            execution_policy_result_id=None,
            created_at=now,
        )
        session.add(action)
        await session.flush()
        for transition in self._initial_transition_values(resources, now=now)[:3]:
            self._add_transition(session, action=action, **transition)
        reason = (
            "plan_expired_before_execution"
            if now >= resources.preview.plan.stopping_rules.expires_at
            else "approval_expired_before_execution"
        )
        self._add_transition(
            session,
            action=action,
            sequence=4,
            prior_state=ActionState.APPROVED,
            new_state=ActionState.EXPIRED,
            occurred_at=now,
            actor=RecoveryActionActor.SYSTEM,
            reason_code=reason,
        )
        await session.flush()
        return action

    async def _persist_executing_action(
        self,
        session: AsyncSession,
        *,
        resources: _ExecutionResources,
        request: PaymentLinkCreateRequest,
        execution_policy: PolicyResultContract,
        idempotency_key: str,
        now: datetime,
    ) -> RecoveryActionRecord:
        action = self._action_record(
            resources=resources,
            request=request,
            idempotency_key=idempotency_key,
            execution_policy_result_id=execution_policy.policy_result_id,
            created_at=now,
        )
        session.add(action)
        await session.flush()
        for transition in self._initial_transition_values(resources, now=now):
            self._add_transition(session, action=action, **transition)
        await session.flush()
        return action

    def _action_record(
        self,
        *,
        resources: _ExecutionResources,
        request: PaymentLinkCreateRequest,
        idempotency_key: str,
        execution_policy_result_id: str | None,
        created_at: datetime,
    ) -> RecoveryActionRecord:
        preview = resources.preview
        return RecoveryActionRecord(
            action_id=stable_identifier("action", preview.plan.merchant_id, preview.plan.plan_id),
            plan_id=preview.plan.plan_id,
            incident_id=preview.plan.incident_id,
            merchant_id=preview.plan.merchant_id,
            payment_id=preview.payment_id,
            approval_id=resources.approval.approval_id,
            preview_policy_result_id=preview.policy_result.policy_result_id,
            execution_policy_result_id=execution_policy_result_id,
            plan_sha256=preview.plan_sha256,
            template=RecoveryTemplate.STANDARD_PAYMENT_LINK.value,
            template_version="standard_payment_link_v1",
            execution_target=preview.execution_target.value,
            execution_side_effect=(
                SideEffectClass.SIMULATED_EXTERNAL_MUTATION.value
                if preview.execution_target is RecoveryExecutionTarget.DETERMINISTIC_FAKE
                else SideEffectClass.RAZORPAY_TEST_MODE_MUTATION.value
            ),
            amount_subunits=request.amount_subunits,
            currency=request.currency,
            reference_id=request.reference_id,
            idempotency_key=idempotency_key,
            request_sha256=canonical_sha256(request),
            request_document=request.model_dump(mode="json"),
            external_notifications_enabled=False,
            synthetic=preview.synthetic,
            created_at=created_at,
        )

    def _initial_transition_values(
        self,
        resources: _ExecutionResources,
        *,
        now: datetime,
    ) -> tuple[dict[str, Any], ...]:
        preview = resources.preview
        return (
            {
                "sequence": 1,
                "prior_state": None,
                "new_state": ActionState.PREVIEWED,
                "occurred_at": preview.plan.created_at,
                "actor": RecoveryActionActor.POLICY_ENGINE,
                "reason_code": "preview_policy_allowed",
            },
            {
                "sequence": 2,
                "prior_state": ActionState.PREVIEWED,
                "new_state": ActionState.AWAITING_APPROVAL,
                "occurred_at": preview.plan.created_at,
                "actor": RecoveryActionActor.SYSTEM,
                "reason_code": "merchant_approval_required",
            },
            {
                "sequence": 3,
                "prior_state": ActionState.AWAITING_APPROVAL,
                "new_state": ActionState.APPROVED,
                "occurred_at": resources.approval.decided_at,
                "actor": RecoveryActionActor.MERCHANT,
                "reason_code": "merchant_approved",
            },
            {
                "sequence": 4,
                "prior_state": ActionState.APPROVED,
                "new_state": ActionState.EXECUTING,
                "occurred_at": now,
                "actor": RecoveryActionActor.WORKER,
                "reason_code": "execution_policy_allowed",
            },
        )

    async def _record_provider_attempt(
        self,
        session: AsyncSession,
        *,
        resources: _ExecutionResources,
        now: datetime,
    ) -> None:
        controls = await session.scalar(
            select(PaymentRecoveryControlRecord)
            .where(
                PaymentRecoveryControlRecord.merchant_id == resources.plan_record.merchant_id,
                PaymentRecoveryControlRecord.payment_id == resources.plan_record.payment_id,
            )
            .with_for_update()
        )
        if controls is None:
            raise RecoveryEvidenceInvalidError
        controls.prior_action_attempts += 1
        controls.last_action_at = now
        controls.version += 1
        controls.updated_at = now

    async def _persist_provider_dispatch(
        self,
        session: AsyncSession,
        *,
        action: RecoveryActionRecord,
        request: PaymentLinkCreateRequest,
        prepared_at: datetime,
    ) -> None:
        """Flush an immutable intent record inside the pre-network transaction."""

        request_sha256 = canonical_sha256(request)
        if (
            not hmac.compare_digest(action.request_sha256, request_sha256)
            or action.request_document != request.model_dump(mode="json")
            or action.reference_id != request.reference_id
        ):
            raise RecoveryEvidenceInvalidError
        session.add(
            RecoveryProviderDispatchRecord(
                dispatch_id=stable_identifier("dispatch", action.merchant_id, action.action_id),
                action_id=action.action_id,
                plan_id=action.plan_id,
                incident_id=action.incident_id,
                merchant_id=action.merchant_id,
                provider_target=action.execution_target,
                reference_id=action.reference_id,
                request_sha256=request_sha256,
                request_document=request.model_dump(mode="json"),
                external_notifications_enabled=False,
                synthetic=action.synthetic,
                prepared_at=prepared_at,
            )
        )
        await session.flush()

    async def _record_provider_outcome_in_session(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        action_id: str,
        request: PaymentLinkCreateRequest,
        result: PaymentLinkResult | None,
        error: ProviderError | None,
    ) -> RecoveryExecutionResponse:
        """Record a provider outcome after the durable dispatch transaction commits."""

        action = await session.scalar(
            select(RecoveryActionRecord)
            .where(
                RecoveryActionRecord.action_id == action_id,
                RecoveryActionRecord.merchant_id == merchant_id,
            )
            .with_for_update()
        )
        dispatch = await session.scalar(
            select(RecoveryProviderDispatchRecord).where(
                RecoveryProviderDispatchRecord.action_id == action_id,
                RecoveryProviderDispatchRecord.merchant_id == merchant_id,
            )
        )
        if action is None or dispatch is None:
            raise RecoveryEvidenceInvalidError
        if (
            not hmac.compare_digest(dispatch.request_sha256, canonical_sha256(request))
            or dispatch.request_document != request.model_dump(mode="json")
            or dispatch.reference_id != action.reference_id
            or dispatch.provider_target != action.execution_target
        ):
            raise RecoveryEvidenceInvalidError
        current = await self._materialize_action(session, action)
        if current.state is not ActionState.EXECUTING:
            return await self._execution_response(
                session,
                action,
                disposition=RecoveryExecutionDisposition.CREATED,
            )
        if (result is None) == (error is None):
            raise RecoveryEvidenceInvalidError

        actor = self._provider_actor(action)
        if error is not None and isinstance(error, ProviderOutcomeAmbiguousError):
            self._add_transition(
                session,
                action=action,
                sequence=5,
                prior_state=ActionState.EXECUTING,
                new_state=ActionState.RECONCILIATION_REQUIRED,
                occurred_at=self._clock_utc(),
                actor=actor,
                reason_code="provider_outcome_ambiguous",
                error=error.error,
            )
        elif error is not None:
            self._add_transition(
                session,
                action=action,
                sequence=5,
                prior_state=ActionState.EXECUTING,
                new_state=ActionState.FAILED,
                occurred_at=self._clock_utc(),
                actor=actor,
                reason_code="provider_known_failure",
                error=error.error,
            )
        else:
            if result is None:
                raise RecoveryEvidenceInvalidError
            await self._add_success_transition(
                session,
                action=action,
                dispatch=dispatch,
                sequence=5,
                prior_state=ActionState.EXECUTING,
                result=result,
                actor=actor,
                reason_code="provider_created",
                verification_source=ProviderVerificationSource.CREATE_RESPONSE,
            )
        await session.flush()
        return await self._execution_response(
            session,
            action,
            disposition=RecoveryExecutionDisposition.CREATED,
        )

    async def _prepare_reconciliation_in_session(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        action_id: str,
        idempotency_key: str,
    ) -> _PreparedReconciliation:
        action = await session.scalar(
            select(RecoveryActionRecord)
            .where(
                RecoveryActionRecord.action_id == action_id,
                RecoveryActionRecord.merchant_id == merchant_id,
            )
            .with_for_update()
        )
        if action is None:
            raise RecoveryActionNotFoundError
        request_sha256 = canonical_sha256({"merchant_id": merchant_id, "action_id": action_id})
        existing = await session.scalar(
            select(RecoveryReconciliationRecord).where(
                RecoveryReconciliationRecord.action_id == action_id
            )
        )
        by_key = await session.scalar(
            select(RecoveryReconciliationRecord).where(
                RecoveryReconciliationRecord.merchant_id == merchant_id,
                RecoveryReconciliationRecord.idempotency_key == idempotency_key,
            )
        )
        if existing is not None or by_key is not None:
            if (
                existing is None
                or by_key is None
                or existing.reconciliation_id != by_key.reconciliation_id
                or existing.idempotency_key != idempotency_key
                or not hmac.compare_digest(existing.request_sha256, request_sha256)
            ):
                raise RecoveryIdempotencyConflictError
            receipt = await self._materialize_action(session, action)
            provider_receipt = await self._materialize_provider_receipt(session, action)
            return _PreparedReconciliation(
                response=RecoveryReconciliationResponse(
                    disposition="replayed",
                    receipt=receipt,
                    provider_receipt=provider_receipt,
                ),
                reference_id=None,
            )
        receipt = await self._materialize_action(session, action)
        if receipt.state not in {
            ActionState.EXECUTING,
            ActionState.RECONCILIATION_REQUIRED,
        }:
            raise RecoveryActionNotReconciliationRequiredError
        dispatch = await session.scalar(
            select(RecoveryProviderDispatchRecord).where(
                RecoveryProviderDispatchRecord.action_id == action.action_id,
                RecoveryProviderDispatchRecord.merchant_id == merchant_id,
            )
        )
        if dispatch is None or dispatch.reference_id != action.reference_id:
            raise RecoveryEvidenceInvalidError
        return _PreparedReconciliation(response=None, reference_id=action.reference_id)

    async def _record_reconciliation_in_session(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        action_id: str,
        idempotency_key: str,
        now: datetime,
        provider_result: PaymentLinkResult | None,
    ) -> RecoveryReconciliationResponse:
        action = await session.scalar(
            select(RecoveryActionRecord)
            .where(
                RecoveryActionRecord.action_id == action_id,
                RecoveryActionRecord.merchant_id == merchant_id,
            )
            .with_for_update()
        )
        if action is None:
            raise RecoveryActionNotFoundError
        request_sha256 = canonical_sha256({"merchant_id": merchant_id, "action_id": action_id})
        existing = await session.scalar(
            select(RecoveryReconciliationRecord).where(
                RecoveryReconciliationRecord.action_id == action_id
            )
        )
        by_key = await session.scalar(
            select(RecoveryReconciliationRecord).where(
                RecoveryReconciliationRecord.merchant_id == merchant_id,
                RecoveryReconciliationRecord.idempotency_key == idempotency_key,
            )
        )
        if existing is not None or by_key is not None:
            if (
                existing is None
                or by_key is None
                or existing.reconciliation_id != by_key.reconciliation_id
                or existing.idempotency_key != idempotency_key
                or not hmac.compare_digest(existing.request_sha256, request_sha256)
            ):
                raise RecoveryIdempotencyConflictError
            receipt = await self._materialize_action(session, action)
            return RecoveryReconciliationResponse(
                disposition="replayed",
                receipt=receipt,
                provider_receipt=await self._materialize_provider_receipt(session, action),
            )
        receipt = await self._materialize_action(session, action)
        if receipt.state not in {
            ActionState.EXECUTING,
            ActionState.RECONCILIATION_REQUIRED,
            ActionState.SUCCEEDED,
        }:
            raise RecoveryActionNotReconciliationRequiredError
        dispatch = await session.scalar(
            select(RecoveryProviderDispatchRecord).where(
                RecoveryProviderDispatchRecord.action_id == action.action_id,
                RecoveryProviderDispatchRecord.merchant_id == merchant_id,
            )
        )
        if dispatch is None:
            raise RecoveryEvidenceInvalidError
        session.add(
            RecoveryReconciliationRecord(
                reconciliation_id=stable_identifier(
                    "reconcile",
                    merchant_id,
                    idempotency_key,
                ),
                action_id=action.action_id,
                plan_id=action.plan_id,
                incident_id=action.incident_id,
                merchant_id=action.merchant_id,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
                created_at=now,
            )
        )
        await session.flush()
        if receipt.state is ActionState.SUCCEEDED:
            if provider_result is not None and (
                provider_result.provider_action_id != receipt.provider_action_id
                or provider_result.reference_id != receipt.reference_id
            ):
                raise RecoveryEvidenceInvalidError
        elif provider_result is None:
            self._add_transition(
                session,
                action=action,
                sequence=len(receipt.transitions) + 1,
                prior_state=receipt.state,
                new_state=ActionState.FAILED,
                occurred_at=self._clock_utc(),
                actor=self._provider_actor(action),
                reason_code="provider_absence_reconciled",
                error=RecoveryActionError(
                    category=RecoveryActionErrorCategory.UPSTREAM_FAILURE,
                    reason_code=(
                        "FAKE_PROVIDER_CONFIRMED_NOT_CREATED"
                        if action.execution_target
                        == RecoveryExecutionTarget.DETERMINISTIC_FAKE.value
                        else "RAZORPAY_TEST_MODE_CONFIRMED_NOT_CREATED"
                    ),
                    retry_permitted=True,
                    reconciliation_required=False,
                ),
            )
        else:
            verified_result = provider_result.model_copy(update={"verified_at": self._clock_utc()})
            await self._add_success_transition(
                session,
                action=action,
                dispatch=dispatch,
                sequence=len(receipt.transitions) + 1,
                prior_state=receipt.state,
                result=verified_result,
                actor=self._provider_actor(action),
                reason_code="provider_reference_reconciled",
                verification_source=ProviderVerificationSource.REFERENCE_LOOKUP,
            )
        await session.flush()
        terminal = await self._materialize_action(session, action)
        return RecoveryReconciliationResponse(
            disposition="created",
            receipt=terminal,
            provider_receipt=await self._materialize_provider_receipt(session, action),
        )

    async def _add_success_transition(
        self,
        session: AsyncSession,
        *,
        action: RecoveryActionRecord,
        dispatch: RecoveryProviderDispatchRecord,
        sequence: int,
        prior_state: ActionState,
        result: PaymentLinkResult,
        actor: RecoveryActionActor,
        reason_code: str,
        verification_source: ProviderVerificationSource,
    ) -> None:
        if (
            result.reference_id != action.reference_id
            or result.amount_subunits != action.amount_subunits
            or result.currency != action.currency
            or result.synthetic is not action.synthetic
            or dispatch.action_id != action.action_id
            or dispatch.provider_target != action.execution_target
            or not hmac.compare_digest(dispatch.request_sha256, action.request_sha256)
        ):
            raise RecoveryEvidenceInvalidError
        response_document = result.model_dump(mode="json")
        response_sha256 = canonical_sha256(result)
        session.add(
            RecoveryProviderReceiptRecord(
                provider_receipt_id=stable_identifier(
                    "provider",
                    action.merchant_id,
                    action.action_id,
                ),
                dispatch_id=dispatch.dispatch_id,
                action_id=action.action_id,
                plan_id=action.plan_id,
                incident_id=action.incident_id,
                merchant_id=action.merchant_id,
                provider_target=action.execution_target,
                provider_action_id=result.provider_action_id,
                reference_id=result.reference_id,
                status=result.status.value,
                amount_subunits=result.amount_subunits,
                currency=result.currency,
                short_url=str(result.short_url) if result.short_url is not None else None,
                provider_created_at=result.provider_created_at,
                verified_at=result.verified_at,
                verification_source=verification_source.value,
                request_sha256=dispatch.request_sha256,
                response_sha256=response_sha256,
                response_document=response_document,
                external_notifications_enabled=False,
                synthetic=result.synthetic,
                created_at=result.verified_at,
            )
        )
        self._add_transition(
            session,
            action=action,
            sequence=sequence,
            prior_state=prior_state,
            new_state=ActionState.SUCCEEDED,
            occurred_at=result.verified_at,
            actor=actor,
            reason_code=reason_code,
            provider_action_id=result.provider_action_id,
            verified_at=result.verified_at,
            response=response_document,
        )

    def _add_transition(
        self,
        session: AsyncSession,
        *,
        action: RecoveryActionRecord,
        sequence: int,
        prior_state: ActionState | None,
        new_state: ActionState,
        occurred_at: datetime,
        actor: RecoveryActionActor,
        reason_code: str,
        provider_action_id: str | None = None,
        verified_at: datetime | None = None,
        error: RecoveryActionError | None = None,
        response: dict[str, object] | None = None,
    ) -> None:
        session.add(
            RecoveryActionTransitionRecord(
                transition_id=stable_identifier(
                    "transition",
                    action.merchant_id,
                    f"{action.action_id}:{sequence}",
                ),
                action_id=action.action_id,
                plan_id=action.plan_id,
                incident_id=action.incident_id,
                merchant_id=action.merchant_id,
                sequence=sequence,
                prior_state=prior_state.value if prior_state is not None else None,
                new_state=new_state.value,
                occurred_at=occurred_at,
                actor=actor.value,
                reason_code=reason_code,
                provider_action_id=provider_action_id,
                verified_at=verified_at,
                error_document=error.model_dump(mode="json") if error is not None else None,
                response_document=response,
                created_at=occurred_at,
            )
        )

    async def _execution_response(
        self,
        session: AsyncSession,
        action: RecoveryActionRecord,
        *,
        disposition: RecoveryExecutionDisposition,
    ) -> RecoveryExecutionResponse:
        receipt = await self._materialize_action(session, action)
        policy: PolicyResultContract | None = None
        policy_sha256: str | None = None
        if action.execution_policy_result_id is not None:
            record = await session.scalar(
                select(PolicyResultRecord).where(
                    PolicyResultRecord.policy_result_id == action.execution_policy_result_id,
                    PolicyResultRecord.plan_id == action.plan_id,
                    PolicyResultRecord.merchant_id == action.merchant_id,
                    PolicyResultRecord.stage == PolicyEvaluationStage.EXECUTION.value,
                )
            )
            if record is None:
                raise RecoveryEvidenceInvalidError
            policy = _materialize_policy_record(record)
            policy_sha256 = record.policy_result_sha256
        return RecoveryExecutionResponse(
            disposition=disposition,
            receipt=receipt,
            provider_receipt=await self._materialize_provider_receipt(session, action),
            execution_policy_result=policy,
            execution_policy_result_sha256=policy_sha256,
            synthetic=action.synthetic,
        )

    async def _materialize_action(
        self,
        session: AsyncSession,
        action: RecoveryActionRecord,
    ) -> RecoveryActionContract:
        rows = tuple(
            (
                await session.scalars(
                    select(RecoveryActionTransitionRecord)
                    .where(
                        RecoveryActionTransitionRecord.action_id == action.action_id,
                        RecoveryActionTransitionRecord.merchant_id == action.merchant_id,
                    )
                    .order_by(RecoveryActionTransitionRecord.sequence)
                )
            ).all()
        )
        if not rows or not hmac.compare_digest(
            action.request_sha256,
            canonical_sha256(action.request_document),
        ):
            raise RecoveryEvidenceInvalidError
        try:
            transitions = tuple(
                RecoveryActionTransition(
                    prior_state=(
                        ActionState(row.prior_state) if row.prior_state is not None else None
                    ),
                    new_state=ActionState(row.new_state),
                    occurred_at=row.occurred_at,
                    actor=RecoveryActionActor(row.actor),
                    reason_code=row.reason_code,
                )
                for row in rows
            )
            latest = rows[-1]
            error = (
                RecoveryActionError.model_validate(latest.error_document)
                if latest.error_document is not None
                else None
            )
            return RecoveryActionContract(
                action_id=action.action_id,
                plan_id=action.plan_id,
                incident_id=action.incident_id,
                merchant_id=action.merchant_id,
                payment_id=action.payment_id,
                plan_sha256=action.plan_sha256,
                template=RecoveryTemplate(action.template),
                template_version=action.template_version,
                execution_target=RecoveryExecutionTarget(action.execution_target),
                execution_side_effect=SideEffectClass(action.execution_side_effect),
                amount_subunits=action.amount_subunits,
                currency=action.currency,
                reference_id=action.reference_id,
                idempotency_key=action.idempotency_key,
                preview_policy_result_id=action.preview_policy_result_id,
                approval_id=action.approval_id,
                execution_policy_result_id=action.execution_policy_result_id,
                state=ActionState(latest.new_state),
                transitions=transitions,
                provider_action_id=latest.provider_action_id,
                verified_at=latest.verified_at,
                error=error,
                external_notifications_enabled=action.external_notifications_enabled,
                synthetic=action.synthetic,
            )
        except (ValidationError, ValueError) as error:
            raise RecoveryEvidenceInvalidError from error

    async def _materialize_provider_receipt(
        self,
        session: AsyncSession,
        action: RecoveryActionRecord,
    ) -> RecoveryProviderReceipt | None:
        record = await session.scalar(
            select(RecoveryProviderReceiptRecord).where(
                RecoveryProviderReceiptRecord.action_id == action.action_id,
                RecoveryProviderReceiptRecord.merchant_id == action.merchant_id,
            )
        )
        if record is None:
            return None
        dispatch = await session.scalar(
            select(RecoveryProviderDispatchRecord).where(
                RecoveryProviderDispatchRecord.dispatch_id == record.dispatch_id,
                RecoveryProviderDispatchRecord.action_id == action.action_id,
            )
        )
        if dispatch is None:
            raise RecoveryEvidenceInvalidError
        try:
            result = PaymentLinkResult.model_validate(record.response_document)
            receipt = RecoveryProviderReceipt(
                provider_receipt_id=record.provider_receipt_id,
                dispatch_id=record.dispatch_id,
                action_id=record.action_id,
                plan_id=record.plan_id,
                incident_id=record.incident_id,
                merchant_id=record.merchant_id,
                execution_target=RecoveryExecutionTarget(record.provider_target),
                provider_action_id=record.provider_action_id,
                reference_id=record.reference_id,
                status=result.status,
                amount_subunits=record.amount_subunits,
                currency=record.currency,
                short_url=result.short_url,
                provider_created_at=record.provider_created_at,
                verified_at=record.verified_at,
                verification_source=ProviderVerificationSource(record.verification_source),
                request_sha256=record.request_sha256,
                response_sha256=record.response_sha256,
                external_notifications_enabled=record.external_notifications_enabled,
                synthetic=record.synthetic,
            )
        except (ValidationError, ValueError) as error:
            raise RecoveryEvidenceInvalidError from error
        if (
            record.action_id != action.action_id
            or record.plan_id != action.plan_id
            or record.incident_id != action.incident_id
            or record.merchant_id != action.merchant_id
            or record.provider_target != action.execution_target
            or record.provider_action_id != result.provider_action_id
            or not (record.reference_id == action.reference_id == result.reference_id)
            or not (
                record.amount_subunits == action.amount_subunits == result.amount_subunits
            )
            or not (record.currency == action.currency == result.currency)
            or record.provider_created_at != result.provider_created_at
            or record.verified_at != result.verified_at
            or record.synthetic is not action.synthetic
            or dispatch.provider_target != action.execution_target
            or not hmac.compare_digest(record.request_sha256, action.request_sha256)
            or not hmac.compare_digest(record.request_sha256, dispatch.request_sha256)
            or not hmac.compare_digest(record.response_sha256, canonical_sha256(result))
        ):
            raise RecoveryEvidenceInvalidError
        return receipt

    def _require_merchant(self, merchant_id: str) -> None:
        if merchant_id != self._settings.merchant_id:
            raise MerchantScopeError

    @staticmethod
    def _provider_actor(action: RecoveryActionRecord) -> RecoveryActionActor:
        target = RecoveryExecutionTarget(action.execution_target)
        if target is RecoveryExecutionTarget.DETERMINISTIC_FAKE:
            return RecoveryActionActor.DETERMINISTIC_FAKE
        return RecoveryActionActor.RAZORPAY_TEST_MODE

    @staticmethod
    def _log_execution_persistence_failure(merchant_id: str, plan_id: str) -> None:
        LOGGER.warning(
            "recovery_execution_persistence_failed",
            merchant_id=merchant_id,
            plan_id=plan_id,
            reason_code=RecoveryPersistenceError.reason_code,
        )

    @staticmethod
    def _log_reconciliation_persistence_failure(
        merchant_id: str,
        action_id: str,
    ) -> None:
        LOGGER.warning(
            "recovery_reconciliation_persistence_failed",
            merchant_id=merchant_id,
            action_id=action_id,
            reason_code=RecoveryPersistenceError.reason_code,
        )

    def _operation_lock(self, key: str) -> asyncio.Lock:
        """Coalesce same-process duplicates; database constraints remain authoritative."""

        return self._operation_locks.setdefault(key, asyncio.Lock())

    def _clock_utc(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RecoveryEvidenceInvalidError
        return now.astimezone(UTC)


def _materialize_policy(
    record: PolicyResultRecord,
    plan: RecoveryPlanRecord,
) -> PolicyResultContract:
    result = _materialize_policy_record(record)
    if (
        result.context.stage is not PolicyEvaluationStage.EXECUTION
        or result.context.plan_id != plan.plan_id
        or result.context.merchant_id != plan.merchant_id
        or record.plan_id != plan.plan_id
        or record.merchant_id != plan.merchant_id
    ):
        raise RecoveryEvidenceInvalidError
    return result


def _materialize_policy_record(record: PolicyResultRecord) -> PolicyResultContract:
    try:
        result = PolicyResultContract.model_validate(record.result_document)
    except ValidationError as error:
        raise RecoveryEvidenceInvalidError from error
    if (
        result.policy_result_id != record.policy_result_id
        or record.stage != result.context.stage.value
        or not hmac.compare_digest(
            record.policy_result_sha256,
            canonical_sha256(result),
        )
    ):
        raise RecoveryEvidenceInvalidError
    return result


def _reference_id(merchant_id: str, payment_id: str, plan_id: str) -> str:
    material = f"{merchant_id}\x1f{payment_id}\x1f{plan_id}".encode()
    return f"rr_{hashlib.sha256(material).hexdigest()[:32]}"
