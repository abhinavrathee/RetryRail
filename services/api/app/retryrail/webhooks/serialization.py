"""Canonical Razorpay-shaped serialization for deterministic synthetic replay."""

import json

from retryrail.events.models import NormalizedPaymentEvent, PaymentEventType, PaymentMethod


def serialize_razorpay_webhook(event: NormalizedPaymentEvent) -> bytes:
    """Build a PII-free raw webhook body from one normalized synthetic event."""

    payment = event.payment
    entity: dict[str, object] = {
        "amount": payment.amount_subunits,
        "created_at": int(event.occurred_at.timestamp()),
        "currency": payment.currency,
        "entity": "payment",
        "id": payment.payment_id,
        "method": payment.method.value,
        "status": payment.status.value,
    }
    if payment.issuer is not None:
        issuer_field = "wallet" if payment.method is PaymentMethod.WALLET else "bank"
        entity[issuer_field] = payment.issuer
    if event.event_type is PaymentEventType.FAILED and payment.error is not None:
        error_fields = {
            "error_code": payment.error.code,
            "error_source": payment.error.source,
            "error_step": payment.error.step,
            "error_reason": payment.error.reason,
        }
        entity.update({key: value for key, value in error_fields.items() if value is not None})

    payload = {
        "contains": ["payment"],
        "created_at": int(event.occurred_at.timestamp()),
        "entity": "event",
        "event": event.event_type.value,
        "payload": {"payment": {"entity": entity}},
        "retryrail_synthetic": True,
    }
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
