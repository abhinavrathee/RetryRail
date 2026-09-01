"""Normalized event semantic and privacy boundary tests."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from retryrail.events.models import (
    ErrorEvidence,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.webhooks.payloads import (
    normalize_razorpay_payload,
    parse_allowlisted_payload,
    sanitize_razorpay_payload,
)


def _raw_failed_payload() -> dict[str, Any]:
    return {
        "entity": "event",
        "account_id": "account_synthetic_ignored",
        "event": "payment.failed",
        "contains": ["payment"],
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_synthetic_001",
                    "entity": "payment",
                    "amount": 125_000,
                    "currency": "INR",
                    "status": "failed",
                    "method": "upi",
                    "bank": "HDFC",
                    "email": "synthetic-user@example.invalid",
                    "contact": "+910000000000",
                    "vpa": "synthetic@invalid",
                    "card": {"last4": "0000"},
                    "notes": {"do_not_store": "value"},
                    "error_code": "BAD_REQUEST_ERROR",
                    "error_source": "bank",
                    "error_step": "payment_authentication",
                    "error_reason": "payment_timed_out",
                    "created_at": 1_788_192_000,
                }
            }
        },
        "created_at": 1_788_192_001,
        "retryrail_synthetic": True,
    }


def test_allowlist_removes_customer_and_card_fields() -> None:
    sanitized = sanitize_razorpay_payload(_raw_failed_payload())
    serialized = str(sanitized).lower()

    for prohibited in ("account_id", "card", "contact", "email", "notes", "vpa"):
        assert prohibited not in serialized
    assert "payment_timed_out" in serialized


def test_payload_contract_requires_exactly_one_payment_entity() -> None:
    missing_payment = deepcopy(_raw_failed_payload())
    missing_payment["payload"] = {}
    with pytest.raises(ValidationError, match="payment"):
        parse_allowlisted_payload(missing_payment)

    empty_contains = deepcopy(_raw_failed_payload())
    empty_contains["contains"] = []
    with pytest.raises(ValidationError, match="contains"):
        parse_allowlisted_payload(empty_contains)


def test_normalization_emits_utc_money_and_structured_failure_evidence() -> None:
    received_at = datetime(2026, 9, 1, 0, 1, tzinfo=UTC)
    event = normalize_razorpay_payload(
        _raw_failed_payload(),
        merchant_id="merchant_demo_001",
        razorpay_event_id="event_synthetic_001",
        received_at=received_at,
    )

    assert event.synthetic is True
    assert event.payment.amount_subunits == 125_000
    assert event.payment.currency == "INR"
    assert event.payment.error is not None
    assert event.payment.error.reason == "payment_timed_out"
    assert event.occurred_at.tzinfo is UTC
    assert event.canonical_dict()["received_at"] == "2026-09-01T00:01:00.000000Z"


def test_failed_event_requires_structured_error_evidence() -> None:
    now = datetime.now(tz=UTC)
    with pytest.raises(ValidationError, match="structured error evidence"):
        NormalizedPaymentEvent(
            merchant_id="merchant_demo_001",
            razorpay_event_id="event_synthetic_001",
            event_type=PaymentEventType.FAILED,
            occurred_at=now,
            received_at=now,
            synthetic=True,
            payment=PaymentSnapshot(
                payment_id="pay_synthetic_001",
                status=PaymentStatus.FAILED,
                amount_subunits=100,
                currency="INR",
                method=PaymentMethod.UPI,
            ),
        )


def test_non_failed_event_rejects_error_evidence() -> None:
    now = datetime.now(tz=UTC)
    with pytest.raises(ValidationError, match="cannot carry failure evidence"):
        NormalizedPaymentEvent(
            merchant_id="merchant_demo_001",
            razorpay_event_id="event_synthetic_002",
            event_type=PaymentEventType.CAPTURED,
            occurred_at=now,
            received_at=now,
            synthetic=True,
            payment=PaymentSnapshot(
                payment_id="pay_synthetic_001",
                status=PaymentStatus.CAPTURED,
                amount_subunits=100,
                currency="INR",
                method=PaymentMethod.CARD,
                error=ErrorEvidence(reason="payment_timed_out"),
            ),
        )


def test_event_status_must_match_event_type() -> None:
    now = datetime.now(tz=UTC)
    with pytest.raises(ValidationError, match="requires payment status"):
        NormalizedPaymentEvent(
            merchant_id="merchant_demo_001",
            razorpay_event_id="event_synthetic_003",
            event_type=PaymentEventType.AUTHORIZED,
            occurred_at=now,
            received_at=now,
            synthetic=True,
            payment=PaymentSnapshot(
                payment_id="pay_synthetic_001",
                status=PaymentStatus.CAPTURED,
                amount_subunits=100,
                currency="INR",
                method=PaymentMethod.CARD,
            ),
        )


def test_future_event_beyond_clock_skew_is_rejected() -> None:
    received_at = datetime.now(tz=UTC)
    with pytest.raises(ValidationError, match="five minutes"):
        NormalizedPaymentEvent(
            merchant_id="merchant_demo_001",
            razorpay_event_id="event_synthetic_004",
            event_type=PaymentEventType.FAILED,
            occurred_at=received_at + timedelta(minutes=6),
            received_at=received_at,
            synthetic=True,
            payment=PaymentSnapshot(
                payment_id="pay_synthetic_001",
                status=PaymentStatus.FAILED,
                amount_subunits=100,
                currency="INR",
                method=PaymentMethod.UPI,
                error=ErrorEvidence(reason="payment_timed_out"),
            ),
        )
