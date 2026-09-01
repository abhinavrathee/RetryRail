"""Strict normalized payment-event models shared by ingestion and replay."""

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator

Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=80,
        pattern=r"^[A-Za-z0-9_-]+$",
    ),
]
Currency = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=3, max_length=3, pattern=r"^[A-Z]{3}$"),
]
Dimension = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    ),
]


class PaymentEventType(StrEnum):
    """Razorpay payment events accepted by the P0 normalized contract."""

    FAILED = "payment.failed"
    AUTHORIZED = "payment.authorized"
    CAPTURED = "payment.captured"


class PaymentStatus(StrEnum):
    """Monotonic payment states represented by P0 fixtures."""

    FAILED = "failed"
    AUTHORIZED = "authorized"
    CAPTURED = "captured"


class PaymentMethod(StrEnum):
    """Bounded method dimensions used by the deterministic truth set."""

    CARD = "card"
    NETBANKING = "netbanking"
    UPI = "upi"
    WALLET = "wallet"


class ErrorEvidence(BaseModel):
    """Allowlisted failure evidence; descriptions and customer data are excluded."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: Dimension | None = None
    source: Dimension | None = None
    step: Dimension | None = None
    reason: Dimension | None = None

    def has_signal(self) -> bool:
        """Return whether the failed event contains actionable structured evidence."""

        return any((self.code, self.source, self.step, self.reason))


class PaymentSnapshot(BaseModel):
    """PII-free payment fields required by detection, policy and measurement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    payment_id: Identifier
    status: PaymentStatus
    amount_subunits: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    method: PaymentMethod
    issuer: Dimension | None = None
    error: ErrorEvidence | None = None


class NormalizedPaymentEvent(BaseModel):
    """Immutable versioned event envelope persisted after webhook verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    merchant_id: Identifier
    razorpay_event_id: Identifier
    event_type: PaymentEventType
    occurred_at: AwareDatetime
    received_at: AwareDatetime
    synthetic: bool
    payment: PaymentSnapshot

    @model_validator(mode="after")
    def validate_event_semantics(self) -> Self:
        """Reject inconsistent state mappings, ungrounded failures and future events."""

        expected_status = {
            PaymentEventType.FAILED: PaymentStatus.FAILED,
            PaymentEventType.AUTHORIZED: PaymentStatus.AUTHORIZED,
            PaymentEventType.CAPTURED: PaymentStatus.CAPTURED,
        }[self.event_type]
        if self.payment.status is not expected_status:
            msg = f"{self.event_type} requires payment status {expected_status}"
            raise ValueError(msg)

        if self.event_type is PaymentEventType.FAILED:
            if self.payment.error is None or not self.payment.error.has_signal():
                msg = "payment.failed requires structured error evidence"
                raise ValueError(msg)
        elif self.payment.error is not None:
            msg = "non-failed payment events cannot carry failure evidence"
            raise ValueError(msg)

        occurred_at = self.occurred_at.astimezone(UTC)
        received_at = self.received_at.astimezone(UTC)
        if occurred_at > received_at + timedelta(minutes=5):
            msg = "occurred_at cannot be more than five minutes after received_at"
            raise ValueError(msg)
        return self

    def canonical_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible representation with UTC timestamps."""

        data = self.model_dump(mode="json", exclude_none=True)
        data["occurred_at"] = _canonical_timestamp(self.occurred_at)
        data["received_at"] = _canonical_timestamp(self.received_at)
        return data


def _canonical_timestamp(value: datetime) -> str:
    """Render an aware timestamp as fixed microsecond UTC text."""

    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
