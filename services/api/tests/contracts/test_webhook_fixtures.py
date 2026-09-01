"""Sanitized Razorpay-shaped fixture privacy and normalization checks."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from retryrail.events.models import PaymentEventType
from retryrail.webhooks.payloads import (
    normalize_razorpay_payload,
    parse_allowlisted_payload,
    sanitize_razorpay_payload,
)

_ROOT = Path(__file__).resolve().parents[4]
_FIXTURE_DIRECTORY = _ROOT / "fixtures/webhooks"
_PROHIBITED_KEYS = {
    "account_id",
    "card",
    "contact",
    "customer_id",
    "email",
    "key_secret",
    "notes",
    "token",
    "vpa",
}


def _all_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = {str(key).lower() for key in value}
        for nested in value.values():
            keys.update(_all_keys(nested))
        return keys
    if isinstance(value, list):
        list_keys: set[str] = set()
        for nested in value:
            list_keys.update(_all_keys(nested))
        return list_keys
    return set()


@pytest.mark.parametrize(
    ("filename", "event_type"),
    [
        ("payment.failed.v1.json", PaymentEventType.FAILED),
        ("payment.authorized.v1.json", PaymentEventType.AUTHORIZED),
        ("payment.captured.v1.json", PaymentEventType.CAPTURED),
    ],
)
def test_committed_webhook_fixture_is_sanitized_and_normalizable(
    filename: str,
    event_type: PaymentEventType,
) -> None:
    payload = json.loads((_FIXTURE_DIRECTORY / filename).read_text(encoding="utf-8"))
    parsed = parse_allowlisted_payload(payload)
    sanitized = sanitize_razorpay_payload(payload)
    received_at = datetime.fromtimestamp(parsed.created_at, tz=UTC)
    event = normalize_razorpay_payload(
        payload,
        merchant_id="merchant_synthetic_fixture",
        razorpay_event_id=f"event_{event_type.value.replace('.', '_')}_fixture",
        received_at=received_at,
    )

    assert parsed.retryrail_synthetic is True
    assert sanitized == payload
    assert _all_keys(payload).isdisjoint(_PROHIBITED_KEYS)
    assert event.event_type is event_type
    assert event.synthetic is True
    assert event.payment.currency == "INR"
    assert event.payment.amount_subunits > 0


def test_all_webhook_fixtures_validate_against_committed_json_schema() -> None:
    schema_path = _ROOT / "contracts/events/razorpay_webhook.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    fixture_paths = sorted(_FIXTURE_DIRECTORY.glob("*.json"))
    assert {path.name for path in fixture_paths} == {
        "payment.authorized.v1.json",
        "payment.captured.v1.json",
        "payment.failed.v1.json",
    }
    for fixture_path in fixture_paths:
        validator.validate(json.loads(fixture_path.read_text(encoding="utf-8")))

    prohibited = deepcopy(
        json.loads((_FIXTURE_DIRECTORY / "payment.failed.v1.json").read_text(encoding="utf-8"))
    )
    prohibited["payload"]["payment"]["entity"]["email"] = "blocked@example.invalid"
    assert list(validator.iter_errors(prohibited))
