"""SQLAlchemy tables for the durable M2 event pipeline."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utc_now() -> datetime:
    """Return an aware UTC timestamp for application-generated writes."""

    return datetime.now(tz=UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Store UTC timestamps and restore SQLite's otherwise-naive results."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Reject naive timestamps and normalize aware values to UTC."""

        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            msg = "database timestamps must be timezone-aware"
            raise ValueError(msg)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Return an aware UTC value for every supported dialect."""

        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    """Declarative metadata root used by Alembic and repositories."""


class PaymentEventRecord(Base):
    """Immutable authenticated event with sanitized and normalized forms."""

    __tablename__ = "payment_events"
    __table_args__ = (
        UniqueConstraint(
            "merchant_id",
            "razorpay_event_id",
            name="uq_payment_events_merchant_event",
        ),
        CheckConstraint("length(payload_sha256) = 64", name="ck_payment_events_payload_sha256"),
        CheckConstraint("schema_version = '1.0.0'", name="ck_payment_events_schema_version"),
        CheckConstraint(
            "signature_status = 'verified'",
            name="ck_payment_events_signature_verified",
        ),
        CheckConstraint(
            "event_type IN ('payment.failed', 'payment.authorized', 'payment.captured')",
            name="ck_payment_events_event_type",
        ),
        Index("ix_payment_events_merchant_received", "merchant_id", "received_at"),
    )

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    razorpay_event_id: Mapped[str] = mapped_column(String(80), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    signature_status: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    payment_id: Mapped[str] = mapped_column(String(80), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sanitized_payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    normalized_event: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class OutboxMessageRecord(Base):
    """Durable process request committed atomically with its source event."""

    __tablename__ = "outbox_messages"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_outbox_messages_idempotency_key"),
        UniqueConstraint(
            "event_internal_id",
            "topic",
            name="uq_outbox_messages_event_topic",
        ),
        CheckConstraint("attempts >= 0", name="ck_outbox_messages_attempts_nonnegative"),
        CheckConstraint("max_attempts > 0", name="ck_outbox_messages_max_attempts_positive"),
        CheckConstraint(
            "attempts <= max_attempts",
            name="ck_outbox_messages_attempts_bounded",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'retry', 'completed', 'dead_letter')",
            name="ck_outbox_messages_status",
        ),
        Index("ix_outbox_messages_claim", "status", "available_at", "created_at"),
    )

    outbox_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    event_internal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("payment_events.internal_id", ondelete="RESTRICT"),
        nullable=False,
    )
    topic: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    available_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class PaymentProjectionRecord(Base):
    """Latest monotonic payment state derived only from immutable events."""

    __tablename__ = "payment_projections"
    __table_args__ = (
        CheckConstraint("amount_subunits > 0", name="ck_payment_projections_amount_positive"),
        CheckConstraint(
            "(status = 'failed' AND state_rank = 1) OR "
            "(status = 'authorized' AND state_rank = 2) OR "
            "(status = 'captured' AND state_rank = 3)",
            name="ck_payment_projections_status_rank",
        ),
        Index("ix_payment_projections_merchant_status", "merchant_id", "status"),
    )

    merchant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    payment_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    state_rank: Mapped[int] = mapped_column(Integer, nullable=False)
    amount_subunits: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    method: Mapped[str] = mapped_column(String(24), nullable=False)
    issuer: Mapped[str | None] = mapped_column(String(80), nullable=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    last_event_internal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("payment_events.internal_id", ondelete="RESTRICT"),
        nullable=False,
    )
    state_changed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_processed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
