"""Committed schema and OpenAPI drift checks."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from retryrail.contracts.export import (
    check_event_schema,
    render_event_schema,
    stale_schema_paths,
    write_all_schemas,
    write_event_schema,
)
from retryrail.contracts.export import main as export_main
from retryrail.events.models import (
    ErrorEvidence,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)


def test_schema_export_is_deterministic_and_current() -> None:
    first = render_event_schema()
    second = render_event_schema()

    assert first == second
    assert check_event_schema()


def test_contract_check_cli_reports_current_schema(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.argv", ["retryrail-contracts", "--check"])

    export_main()

    assert "10 contract schemas are current" in capsys.readouterr().out


def test_contract_check_detects_a_missing_file(tmp_path: Path) -> None:
    assert check_event_schema(tmp_path / "missing.schema.json") is False


def test_all_schema_export_detects_missing_and_stale_files(tmp_path: Path) -> None:
    assert len(stale_schema_paths(tmp_path)) == 10

    write_all_schemas(tmp_path)
    assert stale_schema_paths(tmp_path) == ()
    schema_paths = sorted(tmp_path.glob("contracts/**/*.schema.json"))
    assert len(schema_paths) == 10
    for schema_path in schema_paths:
        Draft202012Validator.check_schema(
            json.loads(schema_path.read_text(encoding="utf-8"))
        )

    stale_path = tmp_path / "contracts/events/payment_event.v1.schema.json"
    stale_path.write_text("{}\n", encoding="utf-8")
    assert stale_schema_paths(tmp_path) == ("contracts/events/payment_event.v1.schema.json",)


def test_exported_schema_validates_a_canonical_event(tmp_path: Path) -> None:
    contract_path = tmp_path / "event.schema.json"
    write_event_schema(contract_path)
    schema = json.loads(contract_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    now = datetime(2026, 9, 1, tzinfo=UTC)
    event = NormalizedPaymentEvent(
        merchant_id="merchant_demo_001",
        razorpay_event_id="event_synthetic_001",
        event_type=PaymentEventType.FAILED,
        occurred_at=now,
        received_at=now,
        synthetic=True,
        payment=PaymentSnapshot(
            payment_id="pay_synthetic_001",
            status=PaymentStatus.FAILED,
            amount_subunits=125_000,
            currency="INR",
            method=PaymentMethod.UPI,
            issuer="HDFC",
            error=ErrorEvidence(reason="payment_timed_out"),
        ),
    )

    Draft202012Validator(schema).validate(event.canonical_dict())


def test_health_routes_have_response_schemas(client: TestClient) -> None:
    openapi = client.get("/openapi.json").json()

    for path in ("/health/live", "/health/ready"):
        response_schema = openapi["paths"][path]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]
        assert response_schema["$ref"].endswith("/HealthResponse")
