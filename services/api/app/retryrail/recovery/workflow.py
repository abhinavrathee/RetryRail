"""Authoritative, idempotent M4.3 recovery preview and approval workflow."""

import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import structlog
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from retryrail.config import Settings
from retryrail.contracts.domain import (
    CohortPredicate,
    OperatingMode,
    RecoveryEligibility,
    RecoveryPlanContract,
    RecoveryStoppingRules,
    RecoveryTemplate,
)
from retryrail.contracts.recovery import (
    ApprovalDecision,
    ApprovalRecordContract,
    ApprovalStatus,
    PolicyContextSnapshot,
    PolicyDecision,
    PolicyEvaluationStage,
    PolicyResultContract,
    RecoveryExecutionTarget,
    RecoveryTemplateContract,
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
    RecoveryPlanRecord,
)
from retryrail.detection.runtime_activation import load_detector_v4_activation
from retryrail.events.models import (
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentStatus,
)
from retryrail.observability.metrics import PipelineMetrics
from retryrail.policy import DETERMINISTIC_POLICY_VERSION, DeterministicPolicyEngine
from retryrail.recovery.integrity import (
    canonical_sha256,
    payment_link_reference_id,
    stable_identifier,
)
from retryrail.recovery.models import (
    ApprovalBearer,
    ApprovalDecisionResponse,
    ApprovalTokenBinding,
    PreviewPersistenceDisposition,
    PublicApprovalRecord,
    RecoveryPlanPreview,
    RecoveryPlanPreviewResponse,
    RecoverySourceEvidence,
    TokenDelivery,
)

LOGGER = structlog.get_logger(__name__)
_APPROVAL_BEARER_ADAPTER: Final = TypeAdapter(ApprovalBearer)
_COHORT_PREDICATE_ADAPTER: Final = TypeAdapter(CohortPredicate)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _new_approval_bearer() -> str:
    return f"rr_apv_{secrets.token_urlsafe(32)}"


class RecoveryWorkflowError(RuntimeError):
    """Base for bounded errors safe to map to a machine-readable API reason."""

    reason_code = "RECOVERY_WORKFLOW_FAILED"


class MerchantScopeError(RecoveryWorkflowError):
    """The requested merchant does not match the configured tenant."""

    reason_code = "MERCHANT_NOT_FOUND"


class IncidentNotFoundError(RecoveryWorkflowError):
    """No incident exists within the configured merchant scope."""

    reason_code = "INCIDENT_NOT_FOUND"


class PaymentNotFoundError(RecoveryWorkflowError):
    """No payment projection exists within the configured merchant scope."""

    reason_code = "PAYMENT_NOT_FOUND"


class PaymentNotEligibleError(RecoveryWorkflowError):
    """The payment is not a failed member of the incident cohort."""

    reason_code = "PAYMENT_NOT_ELIGIBLE_FOR_INCIDENT"


class RecoveryControlsMissingError(RecoveryWorkflowError):
    """Current consent, opt-out and recovery controls are unavailable."""

    reason_code = "RECOVERY_CONTROLS_MISSING"


class RecoveryEvidenceInvalidError(RecoveryWorkflowError):
    """Persisted evidence failed its typed or cryptographic integrity checks."""

    reason_code = "RECOVERY_EVIDENCE_INVALID"


class RecoveryIdempotencyConflictError(RecoveryWorkflowError):
    """An idempotency key was reused for a different logical request."""

    reason_code = "RECOVERY_IDEMPOTENCY_CONFLICT"


class PlanNotFoundError(RecoveryWorkflowError):
    """No recovery plan exists within the configured merchant scope."""

    reason_code = "RECOVERY_PLAN_NOT_FOUND"


class PlanPolicyDeniedError(RecoveryWorkflowError):
    """The complete persisted preview policy did not allow approval."""

    reason_code = "RECOVERY_PLAN_POLICY_DENIED"


class PlanExpiredError(RecoveryWorkflowError):
    """The merchant decision occurred at or after plan expiry."""

    reason_code = "RECOVERY_PLAN_EXPIRED"


class ApprovalAlreadyDecidedError(RecoveryWorkflowError):
    """A plan already has a durable merchant decision."""

    reason_code = "RECOVERY_PLAN_ALREADY_DECIDED"


class ApprovalActorError(RecoveryWorkflowError):
    """The service caller did not supply the configured authenticated actor."""

    reason_code = "RECOVERY_APPROVAL_ACTOR_INVALID"


class ApprovalTokenInvalidError(RecoveryWorkflowError):
    """The bearer is missing, malformed, unknown or bound to another resource."""

    reason_code = "APPROVAL_TOKEN_INVALID"


class ApprovalTokenExpiredError(RecoveryWorkflowError):
    """The bearer reached its strict expiry boundary before consumption."""

    reason_code = "APPROVAL_TOKEN_EXPIRED"


class ApprovalTokenAlreadyUsedError(RecoveryWorkflowError):
    """The append-only consumption fact proves that the bearer was already used."""

    reason_code = "APPROVAL_TOKEN_ALREADY_USED"


class RecoveryPersistenceError(RecoveryWorkflowError):
    """A database failure was converted to a bounded, redacted error."""

    reason_code = "RECOVERY_PERSISTENCE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class _AuthoritativeFacts:
    incident: IncidentRecord
    payment: PaymentProjectionRecord
    controls: PaymentRecoveryControlRecord
    source_event: NormalizedPaymentEvent
    payment_method: PaymentMethod


class RecoveryWorkflowService:
    """Own the durable boundary; it cannot execute or call an external provider."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        metrics: PipelineMetrics,
        *,
        clock: Callable[[], datetime] = _utc_now,
        token_factory: Callable[[], str] = _new_approval_bearer,
    ) -> None:
        self._database = database
        self._settings = settings
        self._metrics = metrics
        self._clock = clock
        self._token_factory = token_factory
        self._policy = DeterministicPolicyEngine()
        self._detector_activation = load_detector_v4_activation()

    async def create_preview(
        self,
        *,
        merchant_id: str,
        incident_id: str,
        payment_id: str,
        idempotency_key: str,
    ) -> RecoveryPlanPreviewResponse:
        """Persist one content-bound plan/policy pair or replay the exact pair."""

        self._require_merchant(merchant_id)
        request_sha256 = canonical_sha256(
            {
                "merchant_id": merchant_id,
                "incident_id": incident_id,
                "payment_id": payment_id,
            }
        )
        plan_id = stable_identifier("plan", merchant_id, idempotency_key)
        try:
            async with self._database.sessions() as session, session.begin():
                existing = await self._plan_by_idempotency(
                    session,
                    merchant_id=merchant_id,
                    idempotency_key=idempotency_key,
                )
                if existing is not None:
                    response = await self._replay_preview(
                        session,
                        existing=existing,
                        expected_request_sha256=request_sha256,
                    )
                else:
                    facts = await self._load_authoritative_facts(
                        session,
                        merchant_id=merchant_id,
                        incident_id=incident_id,
                        payment_id=payment_id,
                    )
                    created_at = self._clock_utc()
                    try:
                        plan, policy_result, source_evidence = self._build_preview(
                            facts=facts,
                            plan_id=plan_id,
                            created_at=created_at,
                        )
                    except (ValidationError, ValueError) as error:
                        raise RecoveryEvidenceInvalidError from error
                    plan_sha256 = canonical_sha256(plan)
                    policy_result_sha256 = canonical_sha256(policy_result)
                    source_evidence_sha256 = canonical_sha256(source_evidence)
                    plan_record = RecoveryPlanRecord(
                        plan_id=plan.plan_id,
                        incident_id=plan.incident_id,
                        merchant_id=plan.merchant_id,
                        payment_id=payment_id,
                        idempotency_key=idempotency_key,
                        request_sha256=request_sha256,
                        plan_sha256=plan_sha256,
                        plan_document=plan.model_dump(mode="json"),
                        source_evidence_sha256=source_evidence_sha256,
                        source_evidence_document=source_evidence.model_dump(mode="json"),
                        created_at=created_at,
                    )
                    policy_record = PolicyResultRecord(
                        policy_result_id=policy_result.policy_result_id,
                        plan_id=plan.plan_id,
                        merchant_id=plan.merchant_id,
                        stage=PolicyEvaluationStage.PREVIEW.value,
                        policy_result_sha256=policy_result_sha256,
                        result_document=policy_result.model_dump(mode="json"),
                        created_at=created_at,
                    )
                    try:
                        async with session.begin_nested():
                            # There are deliberately no ORM relationships on these
                            # narrow evidence mappers. Flush the parent explicitly so
                            # SQLite and PostgreSQL enforce the same FK order.
                            session.add(plan_record)
                            await session.flush()
                            session.add(policy_record)
                            await session.flush()
                    except IntegrityError:
                        existing = await self._plan_by_idempotency(
                            session,
                            merchant_id=merchant_id,
                            idempotency_key=idempotency_key,
                        )
                        if existing is None:
                            raise
                        response = await self._replay_preview(
                            session,
                            existing=existing,
                            expected_request_sha256=request_sha256,
                        )
                    else:
                        response = RecoveryPlanPreviewResponse(
                            disposition=PreviewPersistenceDisposition.CREATED,
                            preview=materialize_preview(plan_record, policy_record),
                        )
        except SQLAlchemyError as error:
            LOGGER.warning(
                "recovery_preview_persistence_failed",
                merchant_id=merchant_id,
                incident_id=incident_id,
                plan_id=plan_id,
                reason_code=RecoveryPersistenceError.reason_code,
            )
            raise RecoveryPersistenceError from error

        decision = response.preview.policy_result.decision.value
        self._metrics.recovery_plan_previews.labels(result=response.disposition.value).inc()
        if response.disposition is PreviewPersistenceDisposition.CREATED:
            self._metrics.recovery_policy_decisions.labels(
                stage=PolicyEvaluationStage.PREVIEW.value,
                decision=decision,
            ).inc()
        LOGGER.info(
            "recovery_preview_recorded",
            disposition=response.disposition.value,
            merchant_id=merchant_id,
            incident_id=incident_id,
            payment_id=payment_id,
            plan_id=response.preview.plan.plan_id,
            policy_result_id=response.preview.policy_result.policy_result_id,
            decision=decision,
        )
        return response

    async def get_preview(
        self,
        *,
        merchant_id: str,
        plan_id: str,
    ) -> RecoveryPlanPreviewResponse:
        """Read and revalidate the exact immutable preview without writing."""

        self._require_merchant(merchant_id)
        try:
            async with self._database.sessions() as session:
                plan_record = await session.scalar(
                    select(RecoveryPlanRecord).where(
                        RecoveryPlanRecord.plan_id == plan_id,
                        RecoveryPlanRecord.merchant_id == merchant_id,
                    )
                )
                if plan_record is None:
                    raise PlanNotFoundError
                policy_record = await self._policy_for_plan(session, plan_record)
                preview = materialize_preview(plan_record, policy_record)
        except SQLAlchemyError as error:
            raise RecoveryPersistenceError from error
        return RecoveryPlanPreviewResponse(
            disposition=PreviewPersistenceDisposition.RETRIEVED,
            preview=preview,
        )

    async def decide(
        self,
        *,
        merchant_id: str,
        plan_id: str,
        actor_id: str,
        decision: ApprovalDecision,
        idempotency_key: str,
    ) -> ApprovalDecisionResponse:
        """Record one authenticated merchant decision and return a bearer once."""

        self._require_merchant(merchant_id)
        if actor_id != self._settings.merchant_approver_id:
            raise ApprovalActorError
        request_sha256 = canonical_sha256(
            {
                "merchant_id": merchant_id,
                "plan_id": plan_id,
                "actor_id": actor_id,
                "decision": decision.value,
            }
        )
        now = self._clock_utc()
        try:
            async with self._database.sessions() as session, session.begin():
                existing = await self._decision_by_idempotency(
                    session,
                    merchant_id=merchant_id,
                    idempotency_key=idempotency_key,
                )
                if existing is not None:
                    response = await self._replay_decision(
                        session,
                        existing=existing,
                        expected_request_sha256=request_sha256,
                        now=now,
                    )
                else:
                    plan_record = await session.scalar(
                        select(RecoveryPlanRecord)
                        .where(
                            RecoveryPlanRecord.plan_id == plan_id,
                            RecoveryPlanRecord.merchant_id == merchant_id,
                        )
                        .with_for_update()
                    )
                    if plan_record is None:
                        raise PlanNotFoundError
                    policy_record = await self._policy_for_plan(session, plan_record)
                    preview = materialize_preview(plan_record, policy_record)
                    prior_decision = await session.scalar(
                        select(ApprovalDecisionRecord).where(
                            ApprovalDecisionRecord.plan_id == plan_id
                        )
                    )
                    if prior_decision is not None:
                        if prior_decision.idempotency_key != idempotency_key:
                            raise ApprovalAlreadyDecidedError
                        response = await self._replay_decision(
                            session,
                            existing=prior_decision,
                            expected_request_sha256=request_sha256,
                            now=now,
                        )
                    else:
                        if decision is ApprovalDecision.APPROVE:
                            if preview.policy_result.decision is not PolicyDecision.ALLOW:
                                raise PlanPolicyDeniedError
                            if now >= preview.plan.stopping_rules.expires_at:
                                raise PlanExpiredError
                        response = await self._persist_decision(
                            session,
                            preview=preview,
                            actor_id=actor_id,
                            decision=decision,
                            idempotency_key=idempotency_key,
                            request_sha256=request_sha256,
                            decided_at=now,
                        )
        except SQLAlchemyError as error:
            LOGGER.warning(
                "recovery_approval_persistence_failed",
                merchant_id=merchant_id,
                plan_id=plan_id,
                decision=decision.value,
                reason_code=RecoveryPersistenceError.reason_code,
            )
            raise RecoveryPersistenceError from error

        self._metrics.recovery_approval_decisions.labels(
            decision=decision.value,
            result=response.disposition,
        ).inc()
        LOGGER.info(
            "recovery_approval_decided",
            disposition=response.disposition,
            merchant_id=merchant_id,
            incident_id=response.approval.incident_id,
            plan_id=plan_id,
            approval_id=response.approval.approval_id,
            decision=decision.value,
            status=response.approval.status.value,
        )
        return response

    async def consume_approval_token(
        self,
        *,
        raw_token: str | None,
        binding: ApprovalTokenBinding,
    ) -> ApprovalRecordContract:
        """Atomically append the sole consumption fact for a fully bound bearer."""

        self._require_merchant(binding.merchant_id)
        token_hash = self.validated_token_hash(raw_token)
        now = self._clock_utc()
        try:
            async with self._database.sessions() as session, session.begin():
                approval = await session.scalar(
                    select(ApprovalDecisionRecord)
                    .where(ApprovalDecisionRecord.token_hash == token_hash)
                    .with_for_update()
                )
                if approval is None:
                    raise ApprovalTokenInvalidError
                result = await self.consume_approval_token_in_session(
                    session,
                    approval=approval,
                    binding=binding,
                    now=now,
                )
        except SQLAlchemyError as error:
            raise RecoveryPersistenceError from error

        self._metrics.approval_token_consumptions.labels(result="consumed").inc()
        LOGGER.info(
            "approval_token_consumed",
            merchant_id=binding.merchant_id,
            incident_id=binding.incident_id,
            plan_id=binding.plan_id,
            approval_id=result.approval_id,
        )
        return result

    async def consume_approval_token_in_session(
        self,
        session: AsyncSession,
        *,
        approval: ApprovalDecisionRecord,
        binding: ApprovalTokenBinding,
        now: datetime,
    ) -> ApprovalRecordContract:
        """Append consumption inside an execution-owned transaction."""

        if not approval_matches_binding(approval, binding):
            raise ApprovalTokenInvalidError
        existing = await session.scalar(
            select(ApprovalTokenConsumptionRecord).where(
                ApprovalTokenConsumptionRecord.approval_id == approval.approval_id
            )
        )
        if existing is not None:
            raise ApprovalTokenAlreadyUsedError
        if approval.expires_at is None or now >= approval.expires_at:
            raise ApprovalTokenExpiredError
        preview = await self._preview_for_approval(session, approval)
        if now >= preview.plan.stopping_rules.expires_at:
            raise ApprovalTokenExpiredError
        request_sha256 = canonical_sha256(binding)
        conflicting_consumption = await self._consumption_by_idempotency(
            session,
            merchant_id=binding.merchant_id,
            idempotency_key=binding.consumption_idempotency_key,
        )
        if conflicting_consumption is not None:
            if conflicting_consumption.approval_id == approval.approval_id:
                raise ApprovalTokenAlreadyUsedError
            raise RecoveryIdempotencyConflictError
        consumption = ApprovalTokenConsumptionRecord(
            consumption_id=stable_identifier(
                "consume",
                binding.merchant_id,
                binding.consumption_idempotency_key,
            ),
            approval_id=approval.approval_id,
            plan_id=approval.plan_id,
            merchant_id=approval.merchant_id,
            idempotency_key=binding.consumption_idempotency_key,
            request_sha256=request_sha256,
            consumed_at=now,
            created_at=now,
        )
        try:
            async with session.begin_nested():
                session.add(consumption)
                await session.flush()
        except IntegrityError as error:
            conflicting_consumption = await self._consumption_by_idempotency(
                session,
                merchant_id=binding.merchant_id,
                idempotency_key=binding.consumption_idempotency_key,
            )
            if (
                conflicting_consumption is not None
                and conflicting_consumption.approval_id != approval.approval_id
            ):
                raise RecoveryIdempotencyConflictError from error
            raise ApprovalTokenAlreadyUsedError from error
        return materialize_approval(approval, consumed_at=now, now=now)

    async def _replay_preview(
        self,
        session: AsyncSession,
        *,
        existing: RecoveryPlanRecord,
        expected_request_sha256: str,
    ) -> RecoveryPlanPreviewResponse:
        if existing.request_sha256 != expected_request_sha256:
            raise RecoveryIdempotencyConflictError
        policy_record = await self._policy_for_plan(session, existing)
        return RecoveryPlanPreviewResponse(
            disposition=PreviewPersistenceDisposition.REPLAYED,
            preview=materialize_preview(existing, policy_record),
        )

    async def _persist_decision(
        self,
        session: AsyncSession,
        *,
        preview: RecoveryPlanPreview,
        actor_id: str,
        decision: ApprovalDecision,
        idempotency_key: str,
        request_sha256: str,
        decided_at: datetime,
    ) -> ApprovalDecisionResponse:
        approval_id = stable_identifier(
            "approval",
            preview.plan.merchant_id,
            idempotency_key,
        )
        token: str | None = None
        token_hash: str | None = None
        issued_at: datetime | None = None
        expires_at: datetime | None = None
        initial_status = ApprovalStatus.REJECTED
        if decision is ApprovalDecision.APPROVE:
            token = self._new_validated_token()
            token_hash = self.token_hash(token)
            issued_at = decided_at
            expires_at = min(
                decided_at + timedelta(seconds=self._settings.approval_token_lifetime_seconds),
                preview.plan.stopping_rules.expires_at,
            )
            initial_status = ApprovalStatus.ISSUED
        record = ApprovalDecisionRecord(
            approval_id=approval_id,
            plan_id=preview.plan.plan_id,
            incident_id=preview.plan.incident_id,
            merchant_id=preview.plan.merchant_id,
            policy_result_id=preview.policy_result.policy_result_id,
            plan_sha256=preview.plan_sha256,
            policy_result_sha256=preview.policy_result_sha256,
            actor_id=actor_id,
            actor_type="merchant",
            decision=decision.value,
            initial_status=initial_status.value,
            token_hash=token_hash,
            decided_at=decided_at,
            issued_at=issued_at,
            expires_at=expires_at,
            idempotency_key=idempotency_key,
            request_sha256=request_sha256,
            synthetic=preview.synthetic,
            created_at=decided_at,
        )
        try:
            async with session.begin_nested():
                session.add(record)
                await session.flush()
        except IntegrityError:
            existing = await self._decision_by_idempotency(
                session,
                merchant_id=preview.plan.merchant_id,
                idempotency_key=idempotency_key,
            )
            if existing is None:
                raise ApprovalAlreadyDecidedError from None
            return await self._replay_decision(
                session,
                existing=existing,
                expected_request_sha256=request_sha256,
                now=decided_at,
            )
        internal = materialize_approval(record, consumed_at=None, now=decided_at)
        return ApprovalDecisionResponse(
            disposition="created",
            approval=PublicApprovalRecord.from_internal(internal),
            approval_token=token,
            token_delivery=(
                TokenDelivery.ISSUED_ONCE if token is not None else TokenDelivery.NOT_APPLICABLE
            ),
        )

    async def _replay_decision(
        self,
        session: AsyncSession,
        *,
        existing: ApprovalDecisionRecord,
        expected_request_sha256: str,
        now: datetime,
    ) -> ApprovalDecisionResponse:
        if existing.request_sha256 != expected_request_sha256:
            raise RecoveryIdempotencyConflictError
        consumption = await session.scalar(
            select(ApprovalTokenConsumptionRecord).where(
                ApprovalTokenConsumptionRecord.approval_id == existing.approval_id
            )
        )
        internal = materialize_approval(
            existing,
            consumed_at=consumption.consumed_at if consumption is not None else None,
            now=now,
        )
        return ApprovalDecisionResponse(
            disposition="replayed",
            approval=PublicApprovalRecord.from_internal(internal),
            approval_token=None,
            token_delivery=(
                TokenDelivery.NOT_REPEATED
                if internal.decision is ApprovalDecision.APPROVE
                else TokenDelivery.NOT_APPLICABLE
            ),
        )

    async def _load_authoritative_facts(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        incident_id: str,
        payment_id: str,
    ) -> _AuthoritativeFacts:
        incident = await session.scalar(
            select(IncidentRecord)
            .where(
                IncidentRecord.incident_id == incident_id,
                IncidentRecord.merchant_id == merchant_id,
            )
            .with_for_update()
        )
        if incident is None:
            raise IncidentNotFoundError
        payment = await session.scalar(
            select(PaymentProjectionRecord)
            .where(
                PaymentProjectionRecord.merchant_id == merchant_id,
                PaymentProjectionRecord.payment_id == payment_id,
            )
            .with_for_update()
        )
        if payment is None:
            raise PaymentNotFoundError
        if payment.status != PaymentStatus.FAILED.value:
            raise PaymentNotEligibleError
        controls = await session.scalar(
            select(PaymentRecoveryControlRecord)
            .where(
                PaymentRecoveryControlRecord.merchant_id == merchant_id,
                PaymentRecoveryControlRecord.payment_id == payment_id,
            )
            .with_for_update()
        )
        if controls is None:
            raise RecoveryControlsMissingError
        source_event, payment_method = await self._load_source_event(
            session,
            merchant_id=merchant_id,
            payment_id=payment_id,
            payment=payment,
        )
        _validate_authoritative_bindings(
            incident=incident,
            payment=payment,
            controls=controls,
            source_event=source_event,
        )
        return _AuthoritativeFacts(
            incident=incident,
            payment=payment,
            controls=controls,
            source_event=source_event,
            payment_method=payment_method,
        )

    async def _load_source_event(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        payment_id: str,
        payment: PaymentProjectionRecord,
    ) -> tuple[NormalizedPaymentEvent, PaymentMethod]:
        event_record = await session.scalar(
            select(PaymentEventRecord).where(
                PaymentEventRecord.internal_id == payment.last_event_internal_id,
                PaymentEventRecord.merchant_id == merchant_id,
                PaymentEventRecord.payment_id == payment_id,
            )
        )
        if event_record is None:
            raise RecoveryEvidenceInvalidError
        try:
            source_event = NormalizedPaymentEvent.model_validate(event_record.normalized_event)
            payment_method = PaymentMethod(payment.method)
        except (ValidationError, ValueError) as error:
            raise RecoveryEvidenceInvalidError from error
        if not _event_matches_projection(event_record, source_event, payment):
            raise RecoveryEvidenceInvalidError
        if source_event.event_type is not PaymentEventType.FAILED:
            raise RecoveryEvidenceInvalidError
        return source_event, payment_method

    def _build_preview(
        self,
        *,
        facts: _AuthoritativeFacts,
        plan_id: str,
        created_at: datetime,
    ) -> tuple[
        RecoveryPlanContract,
        PolicyResultContract,
        RecoverySourceEvidence,
    ]:
        payment = facts.payment
        incident = facts.incident
        controls = facts.controls
        expires_at = created_at + timedelta(seconds=self._settings.recovery_plan_lifetime_seconds)
        plan = RecoveryPlanContract(
            plan_id=plan_id,
            incident_id=incident.incident_id,
            merchant_id=incident.merchant_id,
            mode=OperatingMode(self._settings.recovery_mode),
            template=RecoveryTemplate.STANDARD_PAYMENT_LINK,
            policy_version=DETERMINISTIC_POLICY_VERSION,
            created_at=created_at,
            eligibility=RecoveryEligibility(
                currency=payment.currency,
                methods=(facts.payment_method,),
                minimum_amount_subunits=payment.amount_subunits,
                maximum_amount_subunits=payment.amount_subunits,
            ),
            stopping_rules=RecoveryStoppingRules(
                maximum_actions=1,
                maximum_attempts_per_payment=(self._settings.recovery_maximum_attempts_per_payment),
                cooldown_seconds=self._settings.recovery_cooldown_seconds,
                expires_at=expires_at,
            ),
            eligible_payment_count=1,
            eligible_gmv_subunits=payment.amount_subunits,
            currency=payment.currency,
            synthetic=payment.synthetic,
        )
        context = PolicyContextSnapshot(
            stage=PolicyEvaluationStage.PREVIEW,
            policy_version=DETERMINISTIC_POLICY_VERSION,
            evaluated_at=created_at,
            merchant_id=incident.merchant_id,
            resource_merchant_id=payment.merchant_id,
            incident_id=incident.incident_id,
            plan_id=plan.plan_id,
            payment_id=payment.payment_id,
            incident_action_eligible=self._detector_activation.allows_incident(incident),
            mode=plan.mode,
            template=plan.template,
            template_enabled=self._settings.recovery_template_enabled,
            source_amount_subunits=payment.amount_subunits,
            proposed_amount_subunits=payment.amount_subunits,
            source_currency=payment.currency,
            proposed_currency=payment.currency,
            contact_required=False,
            contact_consent_verified=controls.contact_consent_verified,
            customer_opted_out=controls.customer_opted_out,
            prior_action_attempts=controls.prior_action_attempts,
            maximum_attempts_per_payment=plan.stopping_rules.maximum_attempts_per_payment,
            last_action_at=controls.last_action_at,
            cooldown_seconds=plan.stopping_rules.cooldown_seconds,
            plan_expires_at=plan.stopping_rules.expires_at,
            merchant_kill_switch=self._settings.recovery_kill_switch,
            already_recovered=controls.already_recovered,
            execution_target=RecoveryExecutionTarget(
                self._settings.recovery_execution_target
            ),
            synthetic=payment.synthetic,
        )
        source_evidence = RecoverySourceEvidence(
            merchant_id=incident.merchant_id,
            incident_id=incident.incident_id,
            payment_id=payment.payment_id,
            source_event_internal_id=payment.last_event_internal_id,
            source_razorpay_event_id=facts.source_event.razorpay_event_id,
            payment_projection_version=payment.version,
            recovery_control_version=controls.version,
            detector_version=incident.detector_version,
            detector_config_sha256=incident.detector_config_sha256,
            incident_last_observed_at=incident.last_observed_at,
            synthetic=payment.synthetic,
        )
        return plan, self._policy.evaluate(context), source_evidence

    async def _plan_by_idempotency(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        idempotency_key: str,
    ) -> RecoveryPlanRecord | None:
        result: RecoveryPlanRecord | None = await session.scalar(
            select(RecoveryPlanRecord).where(
                RecoveryPlanRecord.merchant_id == merchant_id,
                RecoveryPlanRecord.idempotency_key == idempotency_key,
            )
        )
        return result

    async def _decision_by_idempotency(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        idempotency_key: str,
    ) -> ApprovalDecisionRecord | None:
        result: ApprovalDecisionRecord | None = await session.scalar(
            select(ApprovalDecisionRecord).where(
                ApprovalDecisionRecord.merchant_id == merchant_id,
                ApprovalDecisionRecord.idempotency_key == idempotency_key,
            )
        )
        return result

    async def _consumption_by_idempotency(
        self,
        session: AsyncSession,
        *,
        merchant_id: str,
        idempotency_key: str,
    ) -> ApprovalTokenConsumptionRecord | None:
        result: ApprovalTokenConsumptionRecord | None = await session.scalar(
            select(ApprovalTokenConsumptionRecord).where(
                ApprovalTokenConsumptionRecord.merchant_id == merchant_id,
                ApprovalTokenConsumptionRecord.idempotency_key == idempotency_key,
            )
        )
        return result

    async def _policy_for_plan(
        self,
        session: AsyncSession,
        plan: RecoveryPlanRecord,
    ) -> PolicyResultRecord:
        policy = await session.scalar(
            select(PolicyResultRecord).where(
                PolicyResultRecord.plan_id == plan.plan_id,
                PolicyResultRecord.merchant_id == plan.merchant_id,
                PolicyResultRecord.stage == PolicyEvaluationStage.PREVIEW.value,
            )
        )
        if policy is None:
            raise RecoveryEvidenceInvalidError
        return policy

    async def _preview_for_approval(
        self,
        session: AsyncSession,
        approval: ApprovalDecisionRecord,
    ) -> RecoveryPlanPreview:
        plan = await session.scalar(
            select(RecoveryPlanRecord).where(
                RecoveryPlanRecord.plan_id == approval.plan_id,
                RecoveryPlanRecord.merchant_id == approval.merchant_id,
            )
        )
        if plan is None:
            raise RecoveryEvidenceInvalidError
        policy = await self._policy_for_plan(session, plan)
        preview = materialize_preview(plan, policy)
        if (
            preview.plan_sha256 != approval.plan_sha256
            or preview.policy_result_sha256 != approval.policy_result_sha256
            or preview.policy_result.policy_result_id != approval.policy_result_id
            or preview.plan.incident_id != approval.incident_id
        ):
            raise RecoveryEvidenceInvalidError
        return preview

    def _new_validated_token(self) -> str:
        try:
            return _APPROVAL_BEARER_ADAPTER.validate_python(self._token_factory())
        except ValidationError as error:
            raise RecoveryEvidenceInvalidError from error

    def validated_token_hash(self, raw_token: str | None) -> str:
        """Validate one raw bearer and return its separate-key digest."""

        try:
            token = _APPROVAL_BEARER_ADAPTER.validate_python(raw_token)
        except ValidationError as error:
            self._metrics.approval_token_consumptions.labels(result="invalid").inc()
            raise ApprovalTokenInvalidError from error
        return self.token_hash(token)

    def token_hash(self, token: str) -> str:
        """Digest a validated bearer without persisting or logging it."""

        key = self._settings.approval_token_hmac_key.get_secret_value().encode()
        return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()

    def _require_merchant(self, merchant_id: str) -> None:
        if merchant_id != self._settings.merchant_id:
            raise MerchantScopeError

    def _clock_utc(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RecoveryEvidenceInvalidError
        return now.astimezone(UTC)


def _event_matches_projection(
    event_record: PaymentEventRecord,
    event: NormalizedPaymentEvent,
    payment: PaymentProjectionRecord,
) -> bool:
    snapshot = event.payment
    return (
        event_record.signature_status == "verified"
        and event_record.schema_version == event.schema_version
        and event_record.event_type == event.event_type.value
        and event_record.merchant_id == event.merchant_id == payment.merchant_id
        and event_record.payment_id == snapshot.payment_id == payment.payment_id
        and event_record.occurred_at == event.occurred_at
        and event_record.received_at == event.received_at
        and event_record.synthetic is event.synthetic is payment.synthetic
        and snapshot.status.value == payment.status
        and snapshot.amount_subunits == payment.amount_subunits
        and snapshot.currency == payment.currency
        and snapshot.method.value == payment.method
        and snapshot.issuer == payment.issuer
    )


def _validate_authoritative_bindings(
    *,
    incident: IncidentRecord,
    payment: PaymentProjectionRecord,
    controls: PaymentRecoveryControlRecord,
    source_event: NormalizedPaymentEvent,
) -> None:
    if (
        incident.currency != payment.currency
        or incident.synthetic is not payment.synthetic
        or controls.source != "synthetic_fixture_default"
        or controls.merchant_id != payment.merchant_id
        or controls.payment_id != payment.payment_id
    ):
        raise RecoveryEvidenceInvalidError
    if not _is_incident_member(incident.affected_cohort, source_event):
        raise PaymentNotEligibleError


def _is_incident_member(
    affected_cohort: list[dict[str, Any]],
    event: NormalizedPaymentEvent,
) -> bool:
    error = event.payment.error
    dimensions: dict[str, str | None] = {
        "method": event.payment.method.value,
        "issuer": event.payment.issuer,
        "error_source": error.source if error is not None else None,
        "error_step": error.step if error is not None else None,
        "error_reason": error.reason if error is not None else None,
    }
    try:
        predicates = tuple(
            _COHORT_PREDICATE_ADAPTER.validate_python(item) for item in affected_cohort
        )
    except ValidationError as validation_error:
        raise RecoveryEvidenceInvalidError from validation_error
    return bool(predicates) and all(
        dimensions[predicate.dimension.value] == predicate.value for predicate in predicates
    )


def materialize_preview(
    plan_record: RecoveryPlanRecord,
    policy_record: PolicyResultRecord,
) -> RecoveryPlanPreview:
    try:
        plan = RecoveryPlanContract.model_validate(plan_record.plan_document)
        policy = PolicyResultContract.model_validate(policy_record.result_document)
        source_evidence = RecoverySourceEvidence.model_validate(
            plan_record.source_evidence_document
        )
    except ValidationError as error:
        raise RecoveryEvidenceInvalidError from error
    plan_sha256 = canonical_sha256(plan)
    policy_sha256 = canonical_sha256(policy)
    source_evidence_sha256 = canonical_sha256(source_evidence)
    if (
        plan_sha256 != plan_record.plan_sha256
        or policy_sha256 != policy_record.policy_result_sha256
        or source_evidence_sha256 != plan_record.source_evidence_sha256
        or plan.plan_id != plan_record.plan_id
        or plan.incident_id != plan_record.incident_id
        or plan.merchant_id != plan_record.merchant_id
        or policy.policy_result_id != policy_record.policy_result_id
        or policy.context.plan_id != plan_record.plan_id
        or policy.context.payment_id != plan_record.payment_id
        or policy_record.plan_id != plan_record.plan_id
        or policy_record.merchant_id != plan_record.merchant_id
        or source_evidence.merchant_id != plan_record.merchant_id
        or source_evidence.incident_id != plan_record.incident_id
        or source_evidence.payment_id != plan_record.payment_id
    ):
        raise RecoveryEvidenceInvalidError
    template = RecoveryTemplateContract()
    try:
        return RecoveryPlanPreview(
            plan=plan,
            payment_id=plan_record.payment_id,
            amount_subunits=policy.context.proposed_amount_subunits,
            currency=policy.context.proposed_currency,
            template=template,
            execution_target=policy.context.execution_target,
            provider_reference_id=payment_link_reference_id(
                plan.merchant_id,
                plan_record.payment_id,
                plan.plan_id,
            ),
            effect=template.effect,
            plan_sha256=plan_sha256,
            source_evidence=source_evidence,
            source_evidence_sha256=source_evidence_sha256,
            policy_result=policy,
            policy_result_sha256=policy_sha256,
            preview_policy_allowed=policy.decision is PolicyDecision.ALLOW,
            persisted_at=plan_record.created_at,
            synthetic=plan.synthetic,
        )
    except ValidationError as error:
        raise RecoveryEvidenceInvalidError from error


def materialize_approval(
    record: ApprovalDecisionRecord,
    *,
    consumed_at: datetime | None,
    now: datetime,
) -> ApprovalRecordContract:
    try:
        decision = ApprovalDecision(record.decision)
        if decision is ApprovalDecision.REJECT:
            status = ApprovalStatus.REJECTED
        elif consumed_at is not None:
            status = ApprovalStatus.CONSUMED
        elif record.expires_at is not None and now >= record.expires_at:
            status = ApprovalStatus.EXPIRED
        else:
            status = ApprovalStatus.ISSUED
        return ApprovalRecordContract(
            approval_id=record.approval_id,
            plan_id=record.plan_id,
            incident_id=record.incident_id,
            merchant_id=record.merchant_id,
            policy_result_id=record.policy_result_id,
            plan_sha256=record.plan_sha256,
            policy_result_sha256=record.policy_result_sha256,
            actor_id=record.actor_id,
            decision=decision,
            status=status,
            decided_at=record.decided_at,
            token_hash=record.token_hash,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
            consumed_at=consumed_at,
            synthetic=record.synthetic,
        )
    except (ValidationError, ValueError) as error:
        raise RecoveryEvidenceInvalidError from error


def approval_matches_binding(
    approval: ApprovalDecisionRecord,
    binding: ApprovalTokenBinding,
) -> bool:
    return (
        approval.decision == ApprovalDecision.APPROVE.value
        and approval.initial_status == ApprovalStatus.ISSUED.value
        and approval.merchant_id == binding.merchant_id
        and approval.incident_id == binding.incident_id
        and approval.plan_id == binding.plan_id
        and approval.policy_result_id == binding.policy_result_id
        and hmac.compare_digest(approval.plan_sha256, binding.plan_sha256)
        and hmac.compare_digest(
            approval.policy_result_sha256,
            binding.policy_result_sha256,
        )
    )
