"""Lease-based transactional-outbox worker for payment projection."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

import structlog
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from retryrail.db.session import Database
from retryrail.db.tables import OutboxMessageRecord, PaymentEventRecord
from retryrail.events.ingestion import PROJECT_PAYMENT_TOPIC
from retryrail.events.projector import PaymentProjector, ProjectionError, ProjectionResult
from retryrail.observability.metrics import PipelineMetrics

LOGGER = structlog.get_logger(__name__)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class RetryableOutboxError(RuntimeError):
    """A bounded transient failure that may safely be attempted again."""

    reason_code = "OUTBOX_TRANSIENT_FAILURE"


class OutboxMessageInvalidError(ValueError):
    """A terminal malformed message that must not block later messages."""

    reason_code = "OUTBOX_MESSAGE_INVALID"


class OutboxProcessor(Protocol):
    """Typed side-effect boundary used by the durable worker."""

    async def process(
        self,
        session: AsyncSession,
        message: OutboxMessageRecord,
        *,
        processed_at: datetime,
    ) -> "ProcessedMessage":
        """Apply one message atomically and return its source event."""


class ProjectionOutboxProcessor:
    """Validate a projection message and invoke the deterministic projector."""

    def __init__(self, projector: PaymentProjector) -> None:
        self._projector = projector

    async def process(
        self,
        session: AsyncSession,
        message: OutboxMessageRecord,
        *,
        processed_at: datetime,
    ) -> "ProcessedMessage":
        if message.topic != PROJECT_PAYMENT_TOPIC:
            raise OutboxMessageInvalidError
        payload = message.payload
        if not isinstance(payload, dict):
            raise OutboxMessageInvalidError
        if (
            payload.get("schema_version") != "1.0.0"
            or payload.get("event_internal_id") != message.event_internal_id
            or payload.get("merchant_id") != message.merchant_id
        ):
            raise OutboxMessageInvalidError

        event = await session.get(PaymentEventRecord, message.event_internal_id)
        if event is None or event.merchant_id != message.merchant_id:
            raise OutboxMessageInvalidError
        projection_result = await self._projector.apply(
            session,
            event,
            processed_at=processed_at,
        )
        return ProcessedMessage(event=event, projection_result=projection_result)


@dataclass(frozen=True, slots=True)
class ProcessedMessage:
    """Successful in-transaction result emitted only after commit."""

    event: PaymentEventRecord
    projection_result: ProjectionResult


@dataclass(frozen=True, slots=True)
class ClaimBatch:
    """Durable claims plus leases terminalized before processing."""

    message_ids: tuple[str, ...]
    dead_lettered: int

    def __len__(self) -> int:
        return len(self.message_ids)


class FailureDisposition(StrEnum):
    """Result of attempting to persist a claimed-message failure."""

    CLAIM_LOST = "claim_lost"
    RETRY = "retry"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True, slots=True)
class WorkerCycle:
    """One bounded worker iteration, useful for operations and tests."""

    claimed: int
    completed: int
    retried: int
    dead_lettered: int


class OutboxWorker:
    """Claim with a lease, process atomically and record bounded failure state."""

    def __init__(
        self,
        database: Database,
        metrics: PipelineMetrics,
        *,
        worker_id: str,
        batch_size: int,
        lease_seconds: int,
        retry_base_seconds: int,
        processor: OutboxProcessor | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._database = database
        self._metrics = metrics
        self._worker_id = worker_id
        self._batch_size = batch_size
        self._lease = timedelta(seconds=lease_seconds)
        self._retry_base_seconds = retry_base_seconds
        self._processor = processor or ProjectionOutboxProcessor(PaymentProjector())
        self._clock = clock

    async def claim_batch(self) -> ClaimBatch:
        """Durably lease available or abandoned messages before processing."""

        now = self._clock()
        async with self._database.sessions() as session, session.begin():
            available = or_(
                and_(
                    OutboxMessageRecord.status.in_(("pending", "retry")),
                    OutboxMessageRecord.available_at <= now,
                ),
                and_(
                    OutboxMessageRecord.status == "processing",
                    OutboxMessageRecord.lease_expires_at.is_not(None),
                    OutboxMessageRecord.lease_expires_at <= now,
                ),
            )
            exhausted_statement = (
                select(OutboxMessageRecord)
                .where(
                    available,
                    OutboxMessageRecord.attempts >= OutboxMessageRecord.max_attempts,
                )
                .order_by(OutboxMessageRecord.available_at, OutboxMessageRecord.outbox_id)
                .limit(self._batch_size)
                .with_for_update(skip_locked=True)
            )
            exhausted = tuple((await session.scalars(exhausted_statement)).all())
            for message in exhausted:
                message.status = "dead_letter"
                message.last_error_code = "OUTBOX_ATTEMPTS_EXHAUSTED"
                message.lease_expires_at = None

            statement = (
                select(OutboxMessageRecord)
                .where(
                    available,
                    OutboxMessageRecord.attempts < OutboxMessageRecord.max_attempts,
                )
                .order_by(OutboxMessageRecord.available_at, OutboxMessageRecord.outbox_id)
                .limit(self._batch_size)
                .with_for_update(skip_locked=True)
            )
            messages = tuple((await session.scalars(statement)).all())
            for message in messages:
                message.status = "processing"
                message.attempts += 1
                message.claimed_at = now
                message.claimed_by = self._worker_id
                message.lease_expires_at = now + self._lease
            claimed = tuple(message.outbox_id for message in messages)

        if exhausted:
            self._metrics.dead_letters.labels(reason="OUTBOX_ATTEMPTS_EXHAUSTED").inc(
                len(exhausted)
            )
            self._metrics.outbox_results.labels(result="dead_letter").inc(len(exhausted))
            for message in exhausted:
                LOGGER.warning(
                    "outbox_message_dead_lettered",
                    merchant_id=message.merchant_id,
                    outbox_id=message.outbox_id,
                    reason_code="OUTBOX_ATTEMPTS_EXHAUSTED",
                )
        if claimed:
            self._metrics.outbox_results.labels(result="claimed").inc(len(claimed))
        return ClaimBatch(message_ids=claimed, dead_lettered=len(exhausted))

    async def run_once(self) -> WorkerCycle:
        """Process one finite claim batch; poison messages never stop the batch."""

        claim_batch = await self.claim_batch()
        completed = 0
        retried = 0
        dead_lettered = claim_batch.dead_lettered
        for outbox_id in claim_batch.message_ids:
            try:
                processed = await self._process_claimed(outbox_id)
            except (OutboxMessageInvalidError, ProjectionError) as error:
                disposition = await self._record_failure(
                    outbox_id,
                    reason_code=error.reason_code,
                    terminal=True,
                )
                if disposition is FailureDisposition.DEAD_LETTER:
                    dead_lettered += 1
            except (IntegrityError, RetryableOutboxError) as error:
                reason_code = (
                    "OUTBOX_DATABASE_CONFLICT"
                    if isinstance(error, IntegrityError)
                    else error.reason_code
                )
                disposition = await self._record_failure(
                    outbox_id,
                    reason_code=reason_code,
                    terminal=False,
                )
                if disposition is FailureDisposition.DEAD_LETTER:
                    dead_lettered += 1
                elif disposition is FailureDisposition.RETRY:
                    retried += 1
            else:
                if processed is not None:
                    completed += 1

        return WorkerCycle(
            claimed=len(claim_batch),
            completed=completed,
            retried=retried,
            dead_lettered=dead_lettered,
        )

    async def _process_claimed(self, outbox_id: str) -> ProcessedMessage | None:
        processed_at = self._clock()
        async with self._database.sessions() as session, session.begin():
            message = await session.scalar(
                select(OutboxMessageRecord)
                .where(OutboxMessageRecord.outbox_id == outbox_id)
                .with_for_update()
            )
            if (
                message is None
                or message.status != "processing"
                or message.claimed_by != self._worker_id
            ):
                return None
            processed = await self._processor.process(
                session,
                message,
                processed_at=processed_at,
            )
            message.status = "completed"
            message.completed_at = processed_at
            message.lease_expires_at = None

        lag_seconds = max((processed_at - processed.event.received_at).total_seconds(), 0.0)
        self._metrics.event_processing_lag.observe(lag_seconds)
        self._metrics.projection_results.labels(
            result=processed.projection_result.value
        ).inc()
        self._metrics.outbox_results.labels(result="completed").inc()
        LOGGER.info(
            "outbox_message_completed",
            event_internal_id=processed.event.internal_id,
            merchant_id=processed.event.merchant_id,
            outbox_id=outbox_id,
            projection_result=processed.projection_result.value,
        )
        return processed

    async def _record_failure(
        self,
        outbox_id: str,
        *,
        reason_code: str,
        terminal: bool,
    ) -> FailureDisposition:
        """Persist retry or terminal state without miscounting a lost claim."""

        now = self._clock()
        disposition = FailureDisposition.CLAIM_LOST
        async with self._database.sessions() as session, session.begin():
            message = await session.scalar(
                select(OutboxMessageRecord)
                .where(OutboxMessageRecord.outbox_id == outbox_id)
                .with_for_update()
            )
            if (
                message is None
                or message.status != "processing"
                or message.claimed_by != self._worker_id
            ):
                return FailureDisposition.CLAIM_LOST
            dead_lettered = terminal or message.attempts >= message.max_attempts
            disposition = (
                FailureDisposition.DEAD_LETTER
                if dead_lettered
                else FailureDisposition.RETRY
            )
            message.status = "dead_letter" if dead_lettered else "retry"
            message.last_error_code = reason_code
            message.lease_expires_at = None
            if not dead_lettered:
                message.claimed_by = None
                message.claimed_at = None
                delay = self._retry_base_seconds * (2 ** (message.attempts - 1))
                message.available_at = now + timedelta(seconds=min(delay, 300))

        if disposition is FailureDisposition.DEAD_LETTER:
            self._metrics.dead_letters.labels(reason=reason_code).inc()
            self._metrics.outbox_results.labels(result="dead_letter").inc()
        elif disposition is FailureDisposition.RETRY:
            self._metrics.outbox_retries.inc()
            self._metrics.outbox_results.labels(result="retry").inc()
        if disposition is not FailureDisposition.CLAIM_LOST:
            LOGGER.warning(
                "outbox_message_failed",
                disposition=disposition.value,
                merchant_id=message.merchant_id,
                outbox_id=outbox_id,
                reason_code=reason_code,
            )
        return disposition
