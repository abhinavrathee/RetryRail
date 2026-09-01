"""Authenticate, normalize and atomically persist one webhook event."""

import hashlib
import json
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import structlog
from pydantic import SecretStr, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from retryrail.db.session import Database
from retryrail.db.tables import OutboxMessageRecord, PaymentEventRecord
from retryrail.events.models import Identifier
from retryrail.observability.metrics import PipelineMetrics
from retryrail.webhooks.payloads import normalize_razorpay_payload, sanitize_razorpay_payload
from retryrail.webhooks.signatures import WebhookSignatureError, verify_webhook_signature

_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)
_IDENTITY_NAMESPACE = uuid.UUID("ae25a4b9-b4b5-51dd-b4bd-ef712bc97c94")
PROJECT_PAYMENT_TOPIC = "payment.project.v1"
LOGGER = structlog.get_logger(__name__)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class IngestionDisposition(StrEnum):
    """Bounded durable-ingestion outcomes returned to HTTP and replay callers."""

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class IngestionResult:
    """Safe receipt proving whether a logical event was newly persisted."""

    disposition: IngestionDisposition
    event_internal_id: str
    razorpay_event_id: str


class WebhookPayloadError(ValueError):
    """Invalid JSON or schema content that is safe to report by reason code."""

    reason_code = "WEBHOOK_PAYLOAD_INVALID"


class EventIdentityConflictError(ValueError):
    """Same merchant/event identity was reused for different sanitized content."""

    reason_code = "WEBHOOK_EVENT_IDENTITY_CONFLICT"


class EventPersistenceError(RuntimeError):
    """Database failure converted to a bounded response without driver details."""

    reason_code = "WEBHOOK_PERSISTENCE_UNAVAILABLE"


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WebhookPayloadError
        result[key] = value
    return result


def _decode_json_object(raw_body: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(raw_body, object_pairs_hook=_reject_duplicate_object_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, WebhookPayloadError) as error:
        raise WebhookPayloadError from error
    if not isinstance(value, dict):
        raise WebhookPayloadError
    return value


def _canonical_payload_hash(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _event_internal_id(merchant_id: str, razorpay_event_id: str) -> str:
    return str(uuid.uuid5(_IDENTITY_NAMESPACE, f"event\x1f{merchant_id}\x1f{razorpay_event_id}"))


def _outbox_id(merchant_id: str, razorpay_event_id: str) -> str:
    return str(uuid.uuid5(_IDENTITY_NAMESPACE, f"outbox\x1f{merchant_id}\x1f{razorpay_event_id}"))


class EventIngestionService:
    """Raw-body verification and event/outbox transaction boundary."""

    def __init__(
        self,
        database: Database,
        webhook_secret: SecretStr,
        metrics: PipelineMetrics,
        *,
        clock: Callable[[], datetime] = _utc_now,
        outbox_max_attempts: int = 5,
    ) -> None:
        self._database = database
        self._webhook_secret = webhook_secret
        self._metrics = metrics
        self._clock = clock
        self._outbox_max_attempts = outbox_max_attempts

    async def ingest(
        self,
        *,
        merchant_id: str,
        razorpay_event_id: str,
        raw_body: bytes,
        signature: str | None,
        received_at: datetime | None = None,
    ) -> IngestionResult:
        """Verify before parsing, then commit the event and outbox atomically."""

        started = time.perf_counter()
        try:
            verify_webhook_signature(raw_body, signature, self._webhook_secret)
        except WebhookSignatureError as error:
            self._metrics.webhook_signature_failures.labels(reason=error.reason_code).inc()
            self._metrics.webhook_requests.labels(result="rejected_signature").inc()
            LOGGER.warning("webhook_rejected", reason_code=error.reason_code)
            raise

        try:
            validated_merchant_id = _IDENTIFIER_ADAPTER.validate_python(merchant_id)
            validated_event_id = _IDENTIFIER_ADAPTER.validate_python(razorpay_event_id)
            payload = _decode_json_object(raw_body)
            sanitized = sanitize_razorpay_payload(payload)
            normalized = normalize_razorpay_payload(
                payload,
                merchant_id=validated_merchant_id,
                razorpay_event_id=validated_event_id,
                received_at=received_at or self._clock(),
            )
        except (ValidationError, WebhookPayloadError, KeyError, TypeError, ValueError) as error:
            self._metrics.webhook_requests.labels(result="rejected_payload").inc()
            if isinstance(error, WebhookPayloadError):
                raise
            raise WebhookPayloadError from error

        payload_sha256 = _canonical_payload_hash(sanitized)
        internal_id = _event_internal_id(validated_merchant_id, validated_event_id)
        now = self._clock()
        try:
            result = await self._persist(
                event=PaymentEventRecord(
                    internal_id=internal_id,
                    merchant_id=validated_merchant_id,
                    razorpay_event_id=validated_event_id,
                    schema_version=normalized.schema_version,
                    signature_status="verified",
                    event_type=normalized.event_type.value,
                    payment_id=normalized.payment.payment_id,
                    occurred_at=normalized.occurred_at,
                    received_at=normalized.received_at,
                    payload_sha256=payload_sha256,
                    sanitized_payload=sanitized,
                    normalized_event=normalized.canonical_dict(),
                    synthetic=normalized.synthetic,
                    created_at=now,
                ),
                outbox=OutboxMessageRecord(
                    outbox_id=_outbox_id(validated_merchant_id, validated_event_id),
                    merchant_id=validated_merchant_id,
                    event_internal_id=internal_id,
                    topic=PROJECT_PAYMENT_TOPIC,
                    payload={
                        "schema_version": "1.0.0",
                        "event_internal_id": internal_id,
                        "merchant_id": validated_merchant_id,
                    },
                    idempotency_key=(
                        f"project-payment-v1:{validated_merchant_id}:{validated_event_id}"
                    ),
                    status="pending",
                    attempts=0,
                    max_attempts=self._outbox_max_attempts,
                    available_at=now,
                    created_at=now,
                ),
                payload_sha256=payload_sha256,
            )
        except EventIdentityConflictError:
            self._metrics.webhook_requests.labels(result="identity_conflict").inc()
            LOGGER.warning(
                "webhook_event_identity_conflict",
                merchant_id=validated_merchant_id,
                razorpay_event_id=validated_event_id,
            )
            raise
        except SQLAlchemyError as error:
            self._metrics.webhook_requests.labels(result="persistence_failure").inc()
            LOGGER.warning(
                "webhook_persistence_failed",
                merchant_id=validated_merchant_id,
                razorpay_event_id=validated_event_id,
                reason_code=EventPersistenceError.reason_code,
            )
            raise EventPersistenceError from error
        finally:
            self._metrics.ingestion_duration.observe(max(time.perf_counter() - started, 0.0))

        self._metrics.webhook_requests.labels(result=result.disposition.value).inc()
        if result.disposition is IngestionDisposition.DUPLICATE:
            self._metrics.duplicate_events.inc()
        LOGGER.info(
            "webhook_ingested",
            disposition=result.disposition.value,
            event_internal_id=result.event_internal_id,
            merchant_id=validated_merchant_id,
            razorpay_event_id=validated_event_id,
        )
        return result

    async def _persist(
        self,
        *,
        event: PaymentEventRecord,
        outbox: OutboxMessageRecord,
        payload_sha256: str,
    ) -> IngestionResult:
        async with self._database.sessions() as session, session.begin():
            existing = await session.scalar(
                select(PaymentEventRecord).where(
                    PaymentEventRecord.merchant_id == event.merchant_id,
                    PaymentEventRecord.razorpay_event_id == event.razorpay_event_id,
                )
            )
            if existing is not None:
                return self._existing_result(existing, payload_sha256)

            try:
                async with session.begin_nested():
                    session.add(event)
                    await session.flush()
                    session.add(outbox)
                    await session.flush()
            except IntegrityError:
                existing = await session.scalar(
                    select(PaymentEventRecord).where(
                        PaymentEventRecord.merchant_id == event.merchant_id,
                        PaymentEventRecord.razorpay_event_id == event.razorpay_event_id,
                    )
                )
                if existing is None:
                    raise
                return self._existing_result(existing, payload_sha256)

        return IngestionResult(
            disposition=IngestionDisposition.ACCEPTED,
            event_internal_id=event.internal_id,
            razorpay_event_id=event.razorpay_event_id,
        )

    @staticmethod
    def _existing_result(
        existing: PaymentEventRecord,
        payload_sha256: str,
    ) -> IngestionResult:
        if existing.payload_sha256 != payload_sha256:
            raise EventIdentityConflictError
        return IngestionResult(
            disposition=IngestionDisposition.DUPLICATE,
            event_internal_id=existing.internal_id,
            razorpay_event_id=existing.razorpay_event_id,
        )
