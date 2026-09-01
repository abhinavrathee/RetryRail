"""Database-backed aggregate, incident, API and immutable-evidence tests."""

import asyncio
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError

from retryrail.config import Settings
from retryrail.contracts.domain import DatasetSplit
from retryrail.db.session import Database
from retryrail.db.tables import (
    AggregateWindowRecord,
    DetectionRunRecord,
    IncidentObservationRecord,
    IncidentRecord,
    OutboxMessageRecord,
    PaymentEventRecord,
)
from retryrail.detection.config import DetectorArtifactMismatchError, load_detector_config
from retryrail.detection.service import DetectionPersistenceError, DetectionService
from retryrail.events.models import (
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.main import create_app
from retryrail.observability.metrics import PipelineMetrics
from retryrail.synthetic.generator import build_dataset


def _partition_events(split: DatasetSplit) -> tuple[NormalizedPaymentEvent, ...]:
    dataset = build_dataset()
    partition = next(item for item in dataset.manifest.partitions if item.split is split)
    artifact = next(
        item for item in dataset.artifacts if item.path == partition.event_artifact
    )
    return tuple(
        NormalizedPaymentEvent.model_validate_json(line)
        for line in artifact.content.splitlines()
    )


async def _persist_completed_events(
    database: Database,
    events: tuple[NormalizedPaymentEvent, ...],
) -> None:
    identities: list[tuple[NormalizedPaymentEvent, str]] = []
    async with database.sessions() as session, session.begin():
        for event in events:
            internal_id = str(uuid.uuid5(uuid.NAMESPACE_URL, event.razorpay_event_id))
            identities.append((event, internal_id))
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
                    payload_sha256="0" * 64,
                    sanitized_payload={"synthetic": True},
                    normalized_event=event.model_dump(mode="json"),
                    synthetic=True,
                    created_at=event.received_at,
                )
            )
        await session.flush()
        for event, internal_id in identities:
            outbox_id = str(uuid.uuid5(uuid.NAMESPACE_OID, event.razorpay_event_id))
            session.add(
                OutboxMessageRecord(
                    outbox_id=outbox_id,
                    merchant_id=event.merchant_id,
                    event_internal_id=internal_id,
                    topic="payment.project.v1",
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


async def _assert_persisted_detection(database: Database) -> tuple[str, str]:
    async with database.sessions() as session:
        incidents = tuple(
            (
                await session.scalars(
                    select(IncidentRecord).order_by(IncidentRecord.opened_at)
                )
            ).all()
        )
        aggregate_records = tuple(
            (
                await session.scalars(
                    select(AggregateWindowRecord).where(
                        AggregateWindowRecord.detector_version == "detector_v1_0_0"
                    )
                )
            ).all()
        )
        observation_count = int(
            await session.scalar(
                select(func.count()).select_from(IncidentObservationRecord)
            )
            or 0
        )
        run_count = int(
            await session.scalar(select(func.count()).select_from(DetectionRunRecord))
            or 0
        )
    method_attempts = sum(
        item.attempts for item in aggregate_records if len(item.cohort) == 1
    )
    assert len(incidents) == 2
    assert {item.status for item in incidents} == {"resolved"}
    assert all(item.action_eligible is False for item in incidents)
    assert incidents[0].affected_cohort[1]["value"] == "issuer_synthetic_alpha"
    assert method_attempts == 1_440
    assert observation_count == 54
    assert run_count == 2
    return incidents[0].incident_id, incidents[1].incident_id


async def _exercise_incremental_refresh(settings: Settings) -> tuple[str, str]:
    database = Database(settings.database_dsn())
    metrics = PipelineMetrics()
    events = _partition_events(DatasetSplit.TUNING)
    boundary = min(item.occurred_at for item in events) + timedelta(hours=5)
    first_batch = tuple(item for item in events if item.occurred_at < boundary)
    second_batch = tuple(item for item in events if item.occurred_at >= boundary)
    try:
        await _persist_completed_events(database, first_batch)
        partial = await DetectionService(database, metrics).refresh(settings.merchant_id)
        assert partial.incidents == partial.active_incidents == 1
        assert partial.at_risk_gmv_subunits > 0
        async with database.sessions() as session:
            partial_incident = await session.scalar(select(IncidentRecord))
            assert partial_incident is not None
            assert partial_incident.action_eligible is False

        await _persist_completed_events(database, second_batch)
        service = DetectionService(database, metrics)
        complete = await service.refresh(settings.merchant_id)
        repeated = await service.refresh(settings.merchant_id)
        assert complete.reused is False
        assert complete.attempts == 1_440
        assert complete.incidents == 2
        assert complete.active_incidents == 0
        assert repeated.reused is True
        assert repeated.run_id == complete.run_id
        incident_ids = await _assert_persisted_detection(database)

        async with database.sessions() as session:
            source_observation = await session.scalar(
                select(IncidentObservationRecord).limit(1)
            )
        assert source_observation is not None
        async with database.sessions() as session:
            with pytest.raises(SQLAlchemyError):
                async with session.begin():
                    session.add(
                        IncidentObservationRecord(
                            observation_id="obs_cross_merchant_rejected_001",
                            incident_id=source_observation.incident_id,
                            merchant_id="merchant_other_001",
                            detector_version=source_observation.detector_version,
                            detector_config_sha256=(
                                source_observation.detector_config_sha256
                            ),
                            evaluated_at=(
                                source_observation.evaluated_at
                                + timedelta(seconds=1)
                            ),
                            statistics=source_observation.statistics,
                            evidence_event_ids=source_observation.evidence_event_ids,
                            created_at=source_observation.created_at,
                        )
                    )

        async with database.sessions() as session:
            with pytest.raises(SQLAlchemyError, match="immutable"):
                await session.execute(
                    text(
                        "UPDATE incident_observations "
                        "SET merchant_id='merchant_other_001'"
                    )
                )
            await session.rollback()
        return incident_ids
    finally:
        await database.dispose()


def test_detector_refresh_is_incremental_repeat_safe_and_api_visible(
    settings: Settings,
) -> None:
    first_incident_id, _ = asyncio.run(_exercise_incremental_refresh(settings))

    with TestClient(create_app(settings)) as client:
        overview = client.get("/api/v1/overview")
        incidents = client.get("/api/v1/incidents")
        resolved = client.get("/api/v1/incidents", params={"status": "resolved"})
        open_items = client.get("/api/v1/incidents", params={"status": "open"})
        detail = client.get(f"/api/v1/incidents/{first_incident_id}")
        missing = client.get("/api/v1/incidents/inc_other_merchant_001")

    assert overview.status_code == 200
    assert overview.json()["active_incidents"] == 0
    assert overview.json()["action_eligible_incidents"] == 0
    assert overview.json()["detector_release_status"] == "blocked"
    assert set(overview.json()["detector_release_failed_targets"]) == {
        "precision",
        "recall",
        "top_1_attribution",
        "median_detection_delay",
    }
    assert overview.json()["total_incidents"] == 2
    assert overview.json()["synthetic"] is True
    assert incidents.status_code == 200
    assert incidents.json()["count"] == resolved.json()["count"] == 2
    assert open_items.json()["count"] == 0
    assert detail.status_code == 200
    assert detail.json()["summary"]["incident"]["synthetic"] is True
    assert detail.json()["summary"]["action_eligible"] is False
    assert detail.json()["evidence_labels"] == [
        "verified_observation",
        "inferred_hypothesis",
        "unknown",
    ]
    assert detail.json()["observations"]
    assert missing.status_code == 404
    assert missing.json()["detail"]["reason_code"] == "INCIDENT_NOT_FOUND"


def test_empty_pending_and_invalid_persisted_inputs_fail_safely(
    settings: Settings,
) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        service = DetectionService(database, metrics)
        now = build_dataset().manifest.partitions[0].starts_at
        authorized = NormalizedPaymentEvent(
            merchant_id=settings.merchant_id,
            razorpay_event_id="evt_pending_detector_001",
            event_type=PaymentEventType.AUTHORIZED,
            occurred_at=now,
            received_at=now + timedelta(seconds=1),
            synthetic=True,
            payment=PaymentSnapshot(
                payment_id="pay_pending_detector_001",
                status=PaymentStatus.AUTHORIZED,
                amount_subunits=10_000,
                currency="INR",
                method=PaymentMethod.CARD,
                issuer="issuer_synthetic_alpha",
            ),
        )
        try:
            empty = await service.refresh(settings.merchant_id)
            assert empty.source_events == empty.attempts == 0

            await _persist_completed_events(database, (authorized,))
            pending = await service.refresh(settings.merchant_id)
            assert pending.source_events == 1
            assert pending.attempts == 0

            captured_at = now + timedelta(minutes=6)
            captured = NormalizedPaymentEvent(
                merchant_id=settings.merchant_id,
                razorpay_event_id="evt_terminal_detector_001",
                event_type=PaymentEventType.CAPTURED,
                occurred_at=captured_at,
                received_at=captured_at + timedelta(seconds=1),
                synthetic=True,
                payment=PaymentSnapshot(
                    payment_id="pay_pending_detector_001",
                    status=PaymentStatus.CAPTURED,
                    amount_subunits=10_000,
                    currency="INR",
                    method=PaymentMethod.CARD,
                    issuer="issuer_synthetic_alpha",
                ),
            )
            await _persist_completed_events(database, (captured,))
            terminal = await service.refresh(settings.merchant_id)
            assert terminal.source_events == 2
            assert terminal.attempts == 1

            invalid_id = "00000000-0000-0000-0000-000000000099"
            async with database.sessions() as session, session.begin():
                session.add(
                    PaymentEventRecord(
                        internal_id=invalid_id,
                        merchant_id=settings.merchant_id,
                        razorpay_event_id="evt_invalid_detector_001",
                        schema_version="1.0.0",
                        signature_status="verified",
                        event_type="payment.failed",
                        payment_id="pay_invalid_detector_001",
                        occurred_at=now,
                        received_at=now,
                        payload_sha256="1" * 64,
                        sanitized_payload={"synthetic": True},
                        normalized_event={"unexpected": "shape"},
                        synthetic=True,
                        created_at=now,
                    )
                )
                await session.flush()
                session.add(
                    OutboxMessageRecord(
                        outbox_id="00000000-0000-0000-0000-000000000199",
                        merchant_id=settings.merchant_id,
                        event_internal_id=invalid_id,
                        topic="payment.project.v1",
                        payload={"schema_version": "1.0.0"},
                        idempotency_key="project:invalid-detector-001",
                        status="completed",
                        attempts=1,
                        max_attempts=5,
                        available_at=now,
                        completed_at=now,
                        created_at=now,
                    )
                )
            with pytest.raises(DetectionPersistenceError):
                await service.refresh(settings.merchant_id)
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_detector_service_rejects_uncommitted_runtime_thresholds(settings: Settings) -> None:
    database = Database(settings.database_dsn())
    altered = load_detector_config().model_copy(
        update={"minimum_current_attempts": 13}
    )
    try:
        with pytest.raises(DetectorArtifactMismatchError):
            DetectionService(database, PipelineMetrics(), altered)
    finally:
        asyncio.run(database.dispose())
