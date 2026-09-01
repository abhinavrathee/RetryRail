"""Allowlisted Razorpay-shaped payload parsing and normalization."""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from retryrail.events.models import (
    Currency,
    Dimension,
    ErrorEvidence,
    Identifier,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)


class RazorpayPaymentEntity(BaseModel):
    """Only the Razorpay fields RetryRail is permitted to retain."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: Identifier
    entity: Literal["payment"] = "payment"
    amount: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    status: PaymentStatus
    method: PaymentMethod
    bank: Dimension | None = None
    wallet: Dimension | None = None
    error_code: Dimension | None = None
    error_source: Dimension | None = None
    error_step: Dimension | None = None
    error_reason: Dimension | None = None
    created_at: int = Field(ge=0, le=4_102_444_800)


class RazorpayPaymentPayload(BaseModel):
    """Payment entity wrapper used by Razorpay webhook envelopes."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    entity: RazorpayPaymentEntity


class RazorpayPayloadEntities(BaseModel):
    """Required entity collection for the P0 payment event boundary."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    payment: RazorpayPaymentPayload


class RazorpayWebhookPayload(BaseModel):
    """Strict outer shape with unknown and sensitive fields discarded."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    entity: Literal["event"] = "event"
    event: PaymentEventType
    contains: tuple[Literal["payment"]] = ("payment",)
    payload: RazorpayPayloadEntities
    created_at: int = Field(ge=0, le=4_102_444_800)
    retryrail_synthetic: bool = False


class SanitizedRazorpayPaymentEntity(RazorpayPaymentEntity):
    """Persistable payment entity that rejects any field outside the allowlist."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class SanitizedRazorpayPaymentPayload(RazorpayPaymentPayload):
    """Strict persisted payment wrapper."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity: SanitizedRazorpayPaymentEntity


class SanitizedRazorpayPayloadEntities(RazorpayPayloadEntities):
    """Strict persisted entity collection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    payment: SanitizedRazorpayPaymentPayload


class SanitizedRazorpayWebhookPayload(RazorpayWebhookPayload):
    """Exact PII-free representation permitted in fixtures and durable storage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: SanitizedRazorpayPayloadEntities


def parse_allowlisted_payload(payload: Mapping[str, Any]) -> RazorpayWebhookPayload:
    """Validate an untrusted decoded payload while dropping non-allowlisted data."""

    return RazorpayWebhookPayload.model_validate(payload)


def sanitize_razorpay_payload(payload: Mapping[str, Any]) -> dict[str, object]:
    """Return the validated allowlisted representation for immutable storage."""

    parsed = parse_allowlisted_payload(payload)
    sanitized = SanitizedRazorpayWebhookPayload.model_validate(
        parsed.model_dump(mode="json", exclude_none=True)
    )
    return sanitized.model_dump(mode="json", exclude_none=True)


def normalize_razorpay_payload(
    payload: Mapping[str, Any],
    *,
    merchant_id: str,
    razorpay_event_id: str,
    received_at: datetime,
) -> NormalizedPaymentEvent:
    """Create the versioned PII-free event used by downstream domain logic."""

    parsed = parse_allowlisted_payload(payload)
    payment = parsed.payload.payment.entity
    occurred_at = datetime.fromtimestamp(payment.created_at, tz=UTC)
    error = None
    if parsed.event is PaymentEventType.FAILED:
        error = ErrorEvidence(
            code=payment.error_code,
            source=payment.error_source,
            step=payment.error_step,
            reason=payment.error_reason,
        )

    return NormalizedPaymentEvent(
        merchant_id=merchant_id,
        razorpay_event_id=razorpay_event_id,
        event_type=parsed.event,
        occurred_at=occurred_at,
        received_at=received_at,
        synthetic=parsed.retryrail_synthetic,
        payment=PaymentSnapshot(
            payment_id=payment.id,
            status=payment.status,
            amount_subunits=payment.amount,
            currency=payment.currency,
            method=payment.method,
            issuer=payment.bank or payment.wallet,
            error=error,
        ),
    )
