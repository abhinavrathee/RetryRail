"""Authenticated webhook durability, idempotency and privacy tests."""

import asyncio
import json
import math
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from retryrail.config import Settings
from retryrail.db.session import Database
from retryrail.db.tables import OutboxMessageRecord, PaymentEventRecord
from retryrail.events.ingestion import EventIngestionService, IngestionDisposition
from retryrail.events.models import (
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.observability.metrics import PipelineMetrics
from retryrail.webhooks.serialization import serialize_razorpay_webhook
from retryrail.webhooks.signatures import compute_webhook_signature


def _captured_event(*, event_id: str = "event_webhook_001", amount: int = 12_500) -> Any:
    now = datetime.now(tz=UTC) - timedelta(minutes=1)
    event = NormalizedPaymentEvent(
        merchant_id="merchant_synthetic_001",
        razorpay_event_id=event_id,
        event_type=PaymentEventType.CAPTURED,
        occurred_at=now,
        received_at=now + timedelta(seconds=1),
        synthetic=True,
        payment=PaymentSnapshot(
            payment_id="pay_webhook_001",
            status=PaymentStatus.CAPTURED,
            amount_subunits=amount,
            currency="INR",
            method=PaymentMethod.UPI,
            issuer="issuer_synthetic_alpha",
        ),
    )
    return json.loads(serialize_razorpay_webhook(event))


def _raw(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _headers(settings: Settings, raw_body: bytes, *, event_id: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Razorpay-Event-Id": event_id,
        "X-Razorpay-Signature": compute_webhook_signature(raw_body, settings.webhook_secret),
    }


def _post(
    client: TestClient,
    settings: Settings,
    raw_body: bytes,
    *,
    event_id: str,
    headers: dict[str, str] | None = None,
) -> Any:
    return client.post(
        f"/v1/merchants/{settings.merchant_id}/webhooks/razorpay",
        content=raw_body,
        headers=headers or _headers(settings, raw_body, event_id=event_id),
    )


async def _stored_records(settings: Settings) -> tuple[list[PaymentEventRecord], int]:
    database = Database(settings.database_dsn())
    try:
        async with database.sessions() as session:
            events = list((await session.scalars(select(PaymentEventRecord))).all())
            outbox_count = await session.scalar(
                select(func.count()).select_from(OutboxMessageRecord)
            )
        return events, int(outbox_count or 0)
    finally:
        await database.dispose()


async def _first_outbox_id(settings: Settings) -> str:
    database = Database(settings.database_dsn())
    try:
        async with database.sessions() as session:
            outbox_id = await session.scalar(select(OutboxMessageRecord.outbox_id))
        assert outbox_id is not None
        return outbox_id
    finally:
        await database.dispose()


def test_triple_delivery_creates_one_event_and_one_outbox_chain(
    client: TestClient,
    settings: Settings,
) -> None:
    event_id = "event_triple_001"
    payload = _captured_event(event_id=event_id)
    payment = payload["payload"]["payment"]["entity"]
    payment.update(
        {
            "card": {"last4": "0000"},
            "contact": "+910000000000",
            "email": "synthetic@example.invalid",
            "notes": {"do_not_store": "sensitive"},
            "vpa": "synthetic@invalid",
        }
    )
    raw_body = _raw(payload)

    responses = [
        _post(client, settings, raw_body, event_id=event_id)
        for _delivery_attempt in range(3)
    ]

    assert [response.status_code for response in responses] == [202, 202, 202]
    assert [response.json()["status"] for response in responses] == [
        "accepted",
        "duplicate",
        "duplicate",
    ]
    records, outbox_count = asyncio.run(_stored_records(settings))
    assert len(records) == 1
    assert outbox_count == 1
    assert records[0].schema_version == "1.0.0"
    assert records[0].signature_status == "verified"
    persisted = json.dumps(records[0].sanitized_payload, sort_keys=True).lower()
    for prohibited in ("card", "contact", "email", "notes", "vpa"):
        assert prohibited not in persisted


def test_invalid_or_modified_signature_is_rejected_before_persistence(
    client: TestClient,
    settings: Settings,
) -> None:
    first_id = "event_invalid_signature_001"
    first_body = _raw(_captured_event(event_id=first_id))
    invalid_headers = _headers(settings, first_body, event_id=first_id)
    invalid_headers["X-Razorpay-Signature"] = "0" * 64

    invalid = _post(
        client,
        settings,
        first_body,
        event_id=first_id,
        headers=invalid_headers,
    )

    second_id = "event_modified_body_001"
    signed_body = _raw(_captured_event(event_id=second_id))
    modified_headers = _headers(settings, signed_body, event_id=second_id)
    modified = _post(
        client,
        settings,
        signed_body + b"\n",
        event_id=second_id,
        headers=modified_headers,
    )

    assert invalid.status_code == 401
    assert modified.status_code == 401
    records, outbox_count = asyncio.run(_stored_records(settings))
    assert records == []
    assert outbox_count == 0

    recovered = _post(client, settings, first_body, event_id=first_id)
    assert recovered.status_code == 202
    assert recovered.json()["status"] == "accepted"
    records, outbox_count = asyncio.run(_stored_records(settings))
    assert [record.razorpay_event_id for record in records] == [first_id]
    assert outbox_count == 1


def test_event_identity_reuse_with_changed_money_is_a_conflict(
    client: TestClient,
    settings: Settings,
) -> None:
    event_id = "event_conflict_001"
    original = _raw(_captured_event(event_id=event_id, amount=12_500))
    changed = _raw(_captured_event(event_id=event_id, amount=99_999))

    accepted = _post(client, settings, original, event_id=event_id)
    conflict = _post(client, settings, changed, event_id=event_id)

    assert accepted.status_code == 202
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["reason_code"] == "WEBHOOK_EVENT_IDENTITY_CONFLICT"
    records, outbox_count = asyncio.run(_stored_records(settings))
    assert len(records) == 1
    assert records[0].sanitized_payload["payload"]["payment"]["entity"]["amount"] == 12_500
    assert outbox_count == 1


def test_outbox_insert_failure_rolls_back_the_event(
    client: TestClient,
    settings: Settings,
) -> None:
    first_id = "event_atomic_first_001"
    first_body = _raw(_captured_event(event_id=first_id))
    assert _post(client, settings, first_body, event_id=first_id).status_code == 202
    conflicting_outbox_id = asyncio.run(_first_outbox_id(settings))

    second_id = "event_atomic_rolled_back_001"
    second_body = _raw(_captured_event(event_id=second_id))
    with patch(
        "retryrail.events.ingestion._outbox_id",
        return_value=conflicting_outbox_id,
    ):
        failed = _post(client, settings, second_body, event_id=second_id)

    assert failed.status_code == 503
    assert failed.json()["detail"]["reason_code"] == "WEBHOOK_PERSISTENCE_UNAVAILABLE"
    records, outbox_count = asyncio.run(_stored_records(settings))
    assert [record.razorpay_event_id for record in records] == [first_id]
    assert outbox_count == 1


def test_same_external_event_id_is_scoped_by_merchant(settings: Settings) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        service = EventIngestionService(
            database,
            settings.webhook_secret,
            PipelineMetrics(),
        )
        event_id = "event_shared_external_001"
        raw_body = _raw(_captured_event(event_id=event_id))
        signature = compute_webhook_signature(raw_body, settings.webhook_secret)
        try:
            first = await service.ingest(
                merchant_id="merchant_scope_alpha",
                razorpay_event_id=event_id,
                raw_body=raw_body,
                signature=signature,
            )
            second = await service.ingest(
                merchant_id="merchant_scope_beta",
                razorpay_event_id=event_id,
                raw_body=raw_body,
                signature=signature,
            )
            async with database.sessions() as session:
                records = list((await session.scalars(select(PaymentEventRecord))).all())

            assert first.disposition is IngestionDisposition.ACCEPTED
            assert second.disposition is IngestionDisposition.ACCEPTED
            assert first.event_internal_id != second.event_internal_id
            assert {record.merchant_id for record in records} == {
                "merchant_scope_alpha",
                "merchant_scope_beta",
            }
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_duplicate_json_keys_and_oversized_bodies_fail_closed(
    client: TestClient,
    settings: Settings,
) -> None:
    duplicate_keys = b'{"entity":"event","entity":"event"}'
    invalid = _post(
        client,
        settings,
        duplicate_keys,
        event_id="event_duplicate_keys_001",
    )
    oversized = b"{" + b" " * settings.max_webhook_body_bytes + b"}"
    too_large = _post(
        client,
        settings,
        oversized,
        event_id="event_oversized_001",
    )

    assert invalid.status_code == 422
    assert invalid.json()["detail"]["reason_code"] == "WEBHOOK_PAYLOAD_INVALID"
    assert too_large.status_code == 413
    assert too_large.json()["detail"]["reason_code"] == "WEBHOOK_BODY_TOO_LARGE"


def test_http_boundary_rejects_unknown_merchant_and_wrong_content_type(
    client: TestClient,
    settings: Settings,
) -> None:
    event_id = "event_http_boundary_001"
    raw_body = _raw(_captured_event(event_id=event_id))
    headers = _headers(settings, raw_body, event_id=event_id)

    unknown = client.post(
        "/v1/merchants/merchant_unknown/webhooks/razorpay",
        content=raw_body,
        headers=headers,
    )
    headers["Content-Type"] = "text/plain"
    unsupported = _post(
        client,
        settings,
        raw_body,
        event_id=event_id,
        headers=headers,
    )

    assert unknown.status_code == 404
    assert unsupported.status_code == 415


def test_local_ingestion_p95_is_below_release_budget(
    client: TestClient,
    settings: Settings,
) -> None:
    durations: list[float] = []
    for sequence in range(30):
        event_id = f"event_latency_{sequence:03d}"
        raw_body = _raw(_captured_event(event_id=event_id))
        started = time.perf_counter()
        response = _post(client, settings, raw_body, event_id=event_id)
        durations.append(time.perf_counter() - started)
        assert response.status_code == 202

    p95_index = math.ceil(0.95 * len(durations)) - 1
    assert sorted(durations)[p95_index] < 0.5
