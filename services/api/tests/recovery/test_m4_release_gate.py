"""M4 model-unavailable release gate from qualified detection to receipt."""

import asyncio
import hashlib
import uuid
from datetime import timedelta

from sqlalchemy import select

from retryrail.config import Settings
from retryrail.contracts.domain import ActionState
from retryrail.contracts.recovery import ApprovalDecision, PolicyDecision
from retryrail.db.session import Database
from retryrail.db.tables import (
    IncidentRecord,
    OutboxMessageRecord,
    PaymentEventRecord,
    TraceLinkRecord,
)
from retryrail.detection.runtime_activation import load_detector_v4_activation
from retryrail.detection.service import DetectionService
from retryrail.events.ingestion import PROJECT_PAYMENT_TOPIC
from retryrail.events.models import NormalizedPaymentEvent, PaymentEventType
from retryrail.events.projector import PaymentProjector
from retryrail.observability.metrics import PipelineMetrics
from retryrail.recovery.adapter import DeterministicFakeRazorpayAdapter
from retryrail.recovery.analysis import RulesBasedIncidentAnalyst
from retryrail.recovery.audit import RecoveryAuditVerifier
from retryrail.recovery.execution import RecoveryExecutionService
from retryrail.recovery.workflow import RecoveryWorkflowService
from retryrail.synthetic.v2_generator import build_development_dataset


def _open_incident_events() -> tuple[NormalizedPaymentEvent, ...]:
    dataset = build_development_dataset()
    cutoff = dataset.manifest.starts_at + timedelta(hours=5)
    return tuple(
        event
        for line in dataset.event_artifact.content.splitlines()
        if (event := NormalizedPaymentEvent.model_validate_json(line)).occurred_at < cutoff
    )


async def _persist_completed_events(
    database: Database,
    events: tuple[NormalizedPaymentEvent, ...],
) -> None:
    async with database.sessions() as session, session.begin():
        identities: list[tuple[NormalizedPaymentEvent, str]] = []
        for event in events:
            internal_id = str(uuid.uuid5(uuid.NAMESPACE_URL, event.razorpay_event_id))
            identities.append((event, internal_id))
            payload_sha256 = hashlib.sha256(event.model_dump_json().encode()).hexdigest()
            session.add(
                PaymentEventRecord(
                    internal_id=internal_id,
                    merchant_id=event.merchant_id,
                    razorpay_event_id=event.razorpay_event_id,
                    schema_version=event.schema_version,
                    signature_status="verified",
                    event_type=event.event_type.value,
                    payment_id=event.payment.payment_id,
                    occurred_at=event.occurred_at,
                    received_at=event.received_at,
                    payload_sha256=payload_sha256,
                    sanitized_payload={"synthetic": True},
                    normalized_event=event.model_dump(mode="json"),
                    synthetic=True,
                    created_at=event.received_at,
                )
            )
        await session.flush()
        for event, internal_id in identities:
            session.add(
                OutboxMessageRecord(
                    outbox_id=str(uuid.uuid5(uuid.NAMESPACE_OID, event.razorpay_event_id)),
                    merchant_id=event.merchant_id,
                    event_internal_id=internal_id,
                    topic=PROJECT_PAYMENT_TOPIC,
                    payload={
                        "schema_version": "1.0.0",
                        "event_internal_id": internal_id,
                        "merchant_id": event.merchant_id,
                    },
                    idempotency_key=f"project:{internal_id}",
                    status="completed",
                    attempts=1,
                    max_attempts=5,
                    available_at=event.received_at,
                    completed_at=event.received_at,
                    created_at=event.received_at,
                )
            )


async def _project_failed_evidence_payment(
    database: Database,
    incident: IncidentRecord,
) -> PaymentEventRecord:
    async with database.sessions() as session, session.begin():
        source = await session.scalar(
            select(PaymentEventRecord)
            .where(
                PaymentEventRecord.merchant_id == incident.merchant_id,
                PaymentEventRecord.razorpay_event_id.in_(incident.evidence_event_ids),
                PaymentEventRecord.event_type == PaymentEventType.FAILED.value,
            )
            .order_by(PaymentEventRecord.occurred_at)
            .limit(1)
        )
        assert source is not None
        await PaymentProjector().apply(
            session,
            source,
            processed_at=incident.last_observed_at + timedelta(seconds=1),
        )
        return source


async def _assert_trace_lineage(
    database: Database,
    *,
    incident_id: str,
    plan_id: str,
    action_id: str,
) -> None:
    async with database.sessions() as session:
        incident_trace = await session.scalar(
            select(TraceLinkRecord).where(
                TraceLinkRecord.entity_type == "incident",
                TraceLinkRecord.entity_id == incident_id,
            )
        )
        plan_trace = await session.scalar(
            select(TraceLinkRecord).where(
                TraceLinkRecord.entity_type == "plan",
                TraceLinkRecord.entity_id == plan_id,
            )
        )
        action_trace = await session.scalar(
            select(TraceLinkRecord).where(
                TraceLinkRecord.entity_type == "action",
                TraceLinkRecord.entity_id == action_id,
            )
        )
        assert incident_trace is not None
        assert plan_trace is not None
        assert action_trace is not None
        event_trace = await session.scalar(
            select(TraceLinkRecord).where(
                TraceLinkRecord.entity_type == "event",
                TraceLinkRecord.span_id == incident_trace.parent_span_id,
            )
        )
    assert event_trace is not None
    assert {
        event_trace.trace_id,
        incident_trace.trace_id,
        plan_trace.trace_id,
        action_trace.trace_id,
    } == {incident_trace.trace_id}
    assert plan_trace.parent_span_id == incident_trace.span_id
    assert action_trace.parent_span_id == plan_trace.span_id


def test_m4_model_unavailable_detect_to_audited_receipt_release_gate(
    settings: Settings,
) -> None:
    """Prove the literal M4 exit path without a model or real provider."""

    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        activation = load_detector_v4_activation()
        try:
            events = _open_incident_events()
            await _persist_completed_events(database, events)
            detection = await DetectionService(
                database,
                metrics,
                runtime_version="v4",
            ).refresh(settings.merchant_id)
            assert detection.incidents == detection.active_incidents == 1

            async with database.sessions() as session:
                incident = await session.scalar(
                    select(IncidentRecord).where(
                        IncidentRecord.merchant_id == settings.merchant_id,
                        IncidentRecord.status == "open",
                    )
                )
            assert incident is not None
            assert incident.detector_version == activation.detector_version
            assert incident.detector_config_sha256 == activation.detector_config_sha256
            assert activation.allows_incident(incident)
            source = await _project_failed_evidence_payment(database, incident)

            now = incident.last_observed_at + timedelta(minutes=5)
            analyst = RulesBasedIncidentAnalyst(
                database,
                settings,
                metrics,
                clock=lambda: now,
            )
            analysis = await analyst.analyze(
                merchant_id=settings.merchant_id,
                incident_id=incident.incident_id,
            )
            assert analysis.model_status == "unavailable"
            assert analysis.fallback_used is True
            assert analysis.plan_fallback.can_create_plan is True
            assert "actionable failure-rate increase" in (
                analysis.brief.verified_evidence[0].statement
            )

            workflow = RecoveryWorkflowService(
                database,
                settings,
                metrics,
                clock=lambda: now,
            )
            preview = await workflow.create_preview(
                merchant_id=settings.merchant_id,
                incident_id=incident.incident_id,
                payment_id=source.payment_id,
                idempotency_key="m4_release_preview_v1",
            )
            assert preview.preview.policy_result.decision is PolicyDecision.ALLOW
            approval = await workflow.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key="m4_release_approval_v1",
            )
            assert approval.approval_token is not None

            provider = DeterministicFakeRazorpayAdapter(clock=lambda: now)
            executor = RecoveryExecutionService(
                database,
                settings,
                metrics,
                workflow,
                provider,
                clock=lambda: now,
            )
            execution = await executor.execute(
                merchant_id=settings.merchant_id,
                plan_id=preview.preview.plan.plan_id,
                raw_approval_token=approval.approval_token,
                idempotency_key="m4_release_execution_v1",
            )
            assert execution.receipt is not None
            assert execution.receipt.state is ActionState.SUCCEEDED
            assert execution.receipt.external_notifications_enabled is False
            assert provider.create_calls == 1

            audit = await RecoveryAuditVerifier(database, settings, executor).verify_action(
                merchant_id=settings.merchant_id,
                action_id=execution.receipt.action_id,
            )
            assert audit.complete is True
            assert audit.missing_facts == ()
            assert audit.terminal_state is ActionState.SUCCEEDED

            await _assert_trace_lineage(
                database,
                incident_id=incident.incident_id,
                plan_id=preview.preview.plan.plan_id,
                action_id=execution.receipt.action_id,
            )
        finally:
            await database.dispose()

    asyncio.run(exercise())
