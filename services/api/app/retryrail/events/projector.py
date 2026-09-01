"""Deterministic, monotonic payment-state projection."""

from datetime import datetime
from enum import StrEnum

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from retryrail.db.tables import PaymentEventRecord, PaymentProjectionRecord
from retryrail.events.models import NormalizedPaymentEvent, PaymentStatus


class ProjectionResult(StrEnum):
    """Bounded outcomes emitted for each successfully handled event."""

    CREATED = "created"
    ADVANCED = "advanced"
    STALE = "stale"


class ProjectionError(ValueError):
    """Terminal event error safe to store as a low-cardinality reason code."""

    reason_code = "PROJECTION_EVENT_INVALID"


class ProjectionIdentityConflictError(ProjectionError):
    """A payment identity attempted to change immutable money dimensions."""

    reason_code = "PROJECTION_PAYMENT_IDENTITY_CONFLICT"


_STATE_RANK = {
    PaymentStatus.FAILED: 1,
    PaymentStatus.AUTHORIZED: 2,
    PaymentStatus.CAPTURED: 3,
}


class PaymentProjector:
    """Apply authenticated events without allowing out-of-order state regression."""

    async def apply(
        self,
        session: AsyncSession,
        event: PaymentEventRecord,
        *,
        processed_at: datetime,
    ) -> ProjectionResult:
        """Apply one event inside the caller's outbox-completion transaction."""

        try:
            normalized = NormalizedPaymentEvent.model_validate(event.normalized_event)
        except ValidationError as error:
            raise ProjectionError from error
        if (
            normalized.merchant_id != event.merchant_id
            or normalized.razorpay_event_id != event.razorpay_event_id
            or normalized.schema_version != event.schema_version
            or event.signature_status != "verified"
            or normalized.payment.payment_id != event.payment_id
            or normalized.event_type.value != event.event_type
            or normalized.occurred_at != event.occurred_at
            or normalized.received_at != event.received_at
            or normalized.synthetic is not event.synthetic
        ):
            raise ProjectionError

        payment = normalized.payment
        rank = _STATE_RANK[payment.status]
        projection = await session.scalar(
            select(PaymentProjectionRecord)
            .where(
                PaymentProjectionRecord.merchant_id == event.merchant_id,
                PaymentProjectionRecord.payment_id == event.payment_id,
            )
            .with_for_update()
        )
        if projection is None:
            session.add(
                PaymentProjectionRecord(
                    merchant_id=event.merchant_id,
                    payment_id=event.payment_id,
                    status=payment.status.value,
                    state_rank=rank,
                    amount_subunits=payment.amount_subunits,
                    currency=payment.currency,
                    method=payment.method.value,
                    issuer=payment.issuer,
                    synthetic=normalized.synthetic,
                    last_event_internal_id=event.internal_id,
                    state_changed_at=normalized.occurred_at,
                    last_processed_at=processed_at,
                    version=1,
                )
            )
            result = ProjectionResult.CREATED
        else:
            self._validate_identity(projection, event, normalized)
            if projection.issuer is None and payment.issuer is not None:
                projection.issuer = payment.issuer
            projection.last_processed_at = processed_at
            if rank > projection.state_rank:
                projection.status = payment.status.value
                projection.state_rank = rank
                projection.last_event_internal_id = event.internal_id
                projection.state_changed_at = normalized.occurred_at
                projection.version += 1
                result = ProjectionResult.ADVANCED
            else:
                result = ProjectionResult.STALE

        return result

    @staticmethod
    def _validate_identity(
        projection: PaymentProjectionRecord,
        event: PaymentEventRecord,
        normalized: NormalizedPaymentEvent,
    ) -> None:
        payment = normalized.payment
        if (
            projection.merchant_id != event.merchant_id
            or projection.payment_id != event.payment_id
            or projection.amount_subunits != payment.amount_subunits
            or projection.currency != payment.currency
            or projection.method != payment.method.value
            or projection.synthetic is not normalized.synthetic
            or (
                projection.issuer is not None
                and payment.issuer is not None
                and projection.issuer != payment.issuer
            )
        ):
            raise ProjectionIdentityConflictError
