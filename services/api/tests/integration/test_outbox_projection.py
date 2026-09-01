"""Crash recovery, bounded retry and monotonic projection integration tests."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from retryrail.config import Settings
from retryrail.db.session import Database
from retryrail.db.tables import (
    OutboxMessageRecord,
    PaymentEventRecord,
    PaymentProjectionRecord,
)
from retryrail.events.ingestion import EventIngestionService
from retryrail.events.models import (
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.events.outbox import OutboxWorker, ProcessedMessage, RetryableOutboxError
from retryrail.observability.metrics import PipelineMetrics
from retryrail.webhooks.serialization import serialize_razorpay_webhook
from retryrail.webhooks.signatures import compute_webhook_signature


@dataclass
class MutableClock:
    """Explicit time source for deterministic lease and retry tests."""

    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class AlwaysTransientProcessor:
    """Controlled dependency outage used to exercise the bounded retry state."""

    async def process(
        self,
        session: AsyncSession,
        message: OutboxMessageRecord,
        *,
        processed_at: datetime,
    ) -> ProcessedMessage:
        del session, message, processed_at
        raise RetryableOutboxError


def _event(
    *,
    event_id: str,
    payment_id: str,
    status: PaymentStatus,
    occurred_at: datetime,
    received_at: datetime,
    amount_subunits: int = 25_000,
) -> NormalizedPaymentEvent:
    event_type = {
        PaymentStatus.AUTHORIZED: PaymentEventType.AUTHORIZED,
        PaymentStatus.CAPTURED: PaymentEventType.CAPTURED,
        PaymentStatus.FAILED: PaymentEventType.FAILED,
    }[status]
    return NormalizedPaymentEvent(
        merchant_id="merchant_synthetic_001",
        razorpay_event_id=event_id,
        event_type=event_type,
        occurred_at=occurred_at,
        received_at=received_at,
        synthetic=True,
        payment=PaymentSnapshot(
            payment_id=payment_id,
            status=status,
            amount_subunits=amount_subunits,
            currency="INR",
            method=PaymentMethod.CARD,
            issuer="issuer_synthetic_alpha",
        ),
    )


async def _ingest(
    service: EventIngestionService,
    secret: SecretStr,
    event: NormalizedPaymentEvent,
) -> None:
    raw_body = serialize_razorpay_webhook(event)
    await service.ingest(
        merchant_id=event.merchant_id,
        razorpay_event_id=event.razorpay_event_id,
        raw_body=raw_body,
        signature=compute_webhook_signature(raw_body, secret),
        received_at=event.received_at,
    )


async def _records(
    database: Database,
) -> tuple[
    list[OutboxMessageRecord],
    list[PaymentProjectionRecord],
]:
    async with database.sessions() as session:
        outbox = list(
            (
                await session.scalars(
                    select(OutboxMessageRecord).order_by(OutboxMessageRecord.created_at)
                )
            ).all()
        )
        projections = list((await session.scalars(select(PaymentProjectionRecord))).all())
    return outbox, projections


def test_captured_before_authorized_never_regresses_projection(settings: Settings) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        start = datetime.now(tz=UTC) - timedelta(minutes=2)
        clock = MutableClock(start + timedelta(seconds=2))
        service = EventIngestionService(
            database,
            settings.webhook_secret,
            metrics,
            clock=clock,
        )
        captured = _event(
            event_id="event_captured_first_001",
            payment_id="pay_out_of_order_001",
            status=PaymentStatus.CAPTURED,
            occurred_at=start + timedelta(seconds=10),
            received_at=start + timedelta(seconds=2),
        )
        authorized = _event(
            event_id="event_authorized_late_001",
            payment_id="pay_out_of_order_001",
            status=PaymentStatus.AUTHORIZED,
            occurred_at=start,
            received_at=start + timedelta(seconds=90),
        )
        try:
            await _ingest(service, settings.webhook_secret, captured)
            clock.advance(88)
            await _ingest(service, settings.webhook_secret, authorized)
            clock.advance(10)
            worker = OutboxWorker(
                database,
                metrics,
                worker_id="worker-out-of-order",
                batch_size=10,
                lease_seconds=5,
                retry_base_seconds=1,
                clock=clock,
            )

            cycle = await worker.run_once()
            outbox, projections = await _records(database)

            assert cycle.completed == 2
            assert {message.status for message in outbox} == {"completed"}
            assert len(projections) == 1
            assert projections[0].status == "captured"
            assert projections[0].state_rank == 3
            assert projections[0].version == 1
            assert int(projections[0].state_changed_at.timestamp()) == int(
                captured.occurred_at.timestamp()
            )
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_expired_worker_claim_is_recovered_without_event_loss(settings: Settings) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        clock = MutableClock(datetime.now(tz=UTC) - timedelta(minutes=1))
        service = EventIngestionService(database, settings.webhook_secret, metrics, clock=clock)
        event = _event(
            event_id="event_worker_crash_001",
            payment_id="pay_worker_crash_001",
            status=PaymentStatus.CAPTURED,
            occurred_at=clock.value,
            received_at=clock.value,
        )
        first_worker = OutboxWorker(
            database,
            metrics,
            worker_id="worker-before-crash",
            batch_size=10,
            lease_seconds=5,
            retry_base_seconds=1,
            clock=clock,
        )
        second_worker = OutboxWorker(
            database,
            metrics,
            worker_id="worker-after-crash",
            batch_size=10,
            lease_seconds=5,
            retry_base_seconds=1,
            clock=clock,
        )
        try:
            await _ingest(service, settings.webhook_secret, event)
            claimed = await first_worker.claim_batch()
            assert len(claimed) == 1
            assert len(await second_worker.claim_batch()) == 0
            clock.advance(6)

            recovered = await second_worker.run_once()
            outbox, projections = await _records(database)

            assert recovered.completed == 1
            assert outbox[0].status == "completed"
            assert outbox[0].attempts == 2
            assert len(projections) == 1
            assert projections[0].status == "captured"
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_crashed_final_attempt_dead_letters_without_exceeding_bound(
    settings: Settings,
) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        clock = MutableClock(datetime.now(tz=UTC) - timedelta(minutes=1))
        service = EventIngestionService(
            database,
            settings.webhook_secret,
            metrics,
            clock=clock,
            outbox_max_attempts=1,
        )
        event = _event(
            event_id="event_final_claim_crash_001",
            payment_id="pay_final_claim_crash_001",
            status=PaymentStatus.CAPTURED,
            occurred_at=clock.value,
            received_at=clock.value,
        )
        first_worker = OutboxWorker(
            database,
            metrics,
            worker_id="worker-final-attempt",
            batch_size=10,
            lease_seconds=5,
            retry_base_seconds=1,
            clock=clock,
        )
        recovery_worker = OutboxWorker(
            database,
            metrics,
            worker_id="worker-after-final-attempt",
            batch_size=10,
            lease_seconds=5,
            retry_base_seconds=1,
            clock=clock,
        )
        try:
            await _ingest(service, settings.webhook_secret, event)
            assert len(await first_worker.claim_batch()) == 1
            clock.advance(6)

            result = await recovery_worker.run_once()
            outbox, projections = await _records(database)

            assert result.claimed == 0
            assert result.dead_lettered == 1
            assert outbox[0].attempts == outbox[0].max_attempts == 1
            assert outbox[0].status == "dead_letter"
            assert outbox[0].last_error_code == "OUTBOX_ATTEMPTS_EXHAUSTED"
            assert projections == []
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_poison_message_dead_letters_without_blocking_following_work(
    settings: Settings,
) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        clock = MutableClock(datetime.now(tz=UTC) - timedelta(minutes=1))
        service = EventIngestionService(database, settings.webhook_secret, metrics, clock=clock)
        poison = _event(
            event_id="event_poison_001",
            payment_id="pay_poison_001",
            status=PaymentStatus.CAPTURED,
            occurred_at=clock.value,
            received_at=clock.value,
        )
        healthy = _event(
            event_id="event_healthy_after_poison_001",
            payment_id="pay_healthy_after_poison_001",
            status=PaymentStatus.CAPTURED,
            occurred_at=clock.value,
            received_at=clock.value,
        )
        try:
            await _ingest(service, settings.webhook_secret, poison)
            clock.advance(1)
            await _ingest(service, settings.webhook_secret, healthy)
            async with database.sessions() as session, session.begin():
                poison_message = await session.scalar(
                    select(OutboxMessageRecord)
                    .join(
                        PaymentEventRecord,
                        PaymentEventRecord.internal_id == OutboxMessageRecord.event_internal_id,
                    )
                    .where(PaymentEventRecord.razorpay_event_id == poison.razorpay_event_id)
                )
                assert poison_message is not None
                poison_message.topic = "unknown.poison.topic"

            worker = OutboxWorker(
                database,
                metrics,
                worker_id="worker-poison",
                batch_size=10,
                lease_seconds=5,
                retry_base_seconds=1,
                clock=clock,
            )
            cycle = await worker.run_once()
            outbox, projections = await _records(database)

            assert cycle.completed == 1
            assert cycle.dead_lettered == 1
            assert {message.status for message in outbox} == {"completed", "dead_letter"}
            dead_letter = next(message for message in outbox if message.status == "dead_letter")
            assert dead_letter.last_error_code == "OUTBOX_MESSAGE_INVALID"
            assert [projection.payment_id for projection in projections] == [
                "pay_healthy_after_poison_001"
            ]
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_transient_failures_stop_at_configured_attempt_limit(settings: Settings) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        clock = MutableClock(datetime.now(tz=UTC) - timedelta(minutes=1))
        service = EventIngestionService(
            database,
            settings.webhook_secret,
            metrics,
            clock=clock,
            outbox_max_attempts=3,
        )
        event = _event(
            event_id="event_retry_limit_001",
            payment_id="pay_retry_limit_001",
            status=PaymentStatus.CAPTURED,
            occurred_at=clock.value,
            received_at=clock.value,
        )
        worker = OutboxWorker(
            database,
            metrics,
            worker_id="worker-retry-limit",
            batch_size=1,
            lease_seconds=5,
            retry_base_seconds=1,
            processor=AlwaysTransientProcessor(),
            clock=clock,
        )
        try:
            await _ingest(service, settings.webhook_secret, event)
            outcomes = []
            for _attempt in range(3):
                outcomes.append(await worker.run_once())
                clock.advance(10)
            outbox, projections = await _records(database)

            assert [cycle.retried for cycle in outcomes] == [1, 1, 0]
            assert outcomes[-1].dead_lettered == 1
            assert outbox[0].status == "dead_letter"
            assert outbox[0].attempts == 3
            assert outbox[0].last_error_code == "OUTBOX_TRANSIENT_FAILURE"
            assert projections == []
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_payment_money_identity_change_is_terminal(settings: Settings) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        clock = MutableClock(datetime.now(tz=UTC) - timedelta(minutes=1))
        service = EventIngestionService(database, settings.webhook_secret, metrics, clock=clock)
        authorized = _event(
            event_id="event_identity_authorized_001",
            payment_id="pay_identity_conflict_001",
            status=PaymentStatus.AUTHORIZED,
            occurred_at=clock.value,
            received_at=clock.value,
            amount_subunits=25_000,
        )
        captured_with_changed_amount = _event(
            event_id="event_identity_captured_001",
            payment_id="pay_identity_conflict_001",
            status=PaymentStatus.CAPTURED,
            occurred_at=clock.value + timedelta(seconds=1),
            received_at=clock.value + timedelta(seconds=1),
            amount_subunits=26_000,
        )
        worker = OutboxWorker(
            database,
            metrics,
            worker_id="worker-identity-conflict",
            batch_size=10,
            lease_seconds=5,
            retry_base_seconds=1,
            clock=clock,
        )
        try:
            await _ingest(service, settings.webhook_secret, authorized)
            first = await worker.run_once()
            clock.advance(1)
            await _ingest(
                service,
                settings.webhook_secret,
                captured_with_changed_amount,
            )
            second = await worker.run_once()
            outbox, projections = await _records(database)

            assert first.completed == 1
            assert second.dead_lettered == 1
            assert len(projections) == 1
            assert projections[0].status == "authorized"
            assert projections[0].amount_subunits == 25_000
            dead_letter = next(message for message in outbox if message.status == "dead_letter")
            assert dead_letter.last_error_code == "PROJECTION_PAYMENT_IDENTITY_CONFLICT"
        finally:
            await database.dispose()

    asyncio.run(exercise())
