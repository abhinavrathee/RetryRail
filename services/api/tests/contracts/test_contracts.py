"""Committed schema and OpenAPI drift checks."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

import retryrail.contracts.export as contract_export
from retryrail.contracts.export import (
    FrozenSchemaChangeError,
    check_event_schema,
    frozen_schema_source_changes,
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

    assert "18 contract schemas are current" in capsys.readouterr().out


def test_contract_check_detects_a_missing_file(tmp_path: Path) -> None:
    assert check_event_schema(tmp_path / "missing.schema.json") is False


def test_all_schema_export_detects_missing_and_stale_files(tmp_path: Path) -> None:
    assert len(stale_schema_paths(tmp_path)) == 18

    write_all_schemas(tmp_path)
    assert stale_schema_paths(tmp_path) == ()
    schema_paths = sorted(tmp_path.glob("contracts/**/*.schema.json"))
    assert len(schema_paths) == 18
    for schema_path in schema_paths:
        Draft202012Validator.check_schema(json.loads(schema_path.read_text(encoding="utf-8")))

    stale_path = tmp_path / "contracts/events/payment_event.v1.schema.json"
    stale_path.write_text("{}\n", encoding="utf-8")
    assert stale_schema_paths(tmp_path) == ("contracts/events/payment_event.v1.schema.json",)


def test_frozen_m1_recovery_schemas_reject_in_place_source_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assert frozen_schema_source_changes() == ()
    original_render = contract_export._render_schema  # noqa: SLF001

    def render_with_recovery_plan_drift(
        definition: contract_export.SchemaDefinition,
    ) -> str:
        rendered = original_render(definition)
        if definition.relative_path == "contracts/domain/recovery_plan.v1.schema.json":
            return rendered.replace(
                "RetryRail Recovery Plan v1",
                "RetryRail Recovery Plan silently changed",
            )
        return rendered

    monkeypatch.setattr(contract_export, "_render_schema", render_with_recovery_plan_drift)

    assert frozen_schema_source_changes() == ("contracts/domain/recovery_plan.v1.schema.json",)
    with pytest.raises(FrozenSchemaChangeError, match="create a new schema version"):
        write_all_schemas(tmp_path)
    assert not tuple(tmp_path.glob("contracts/**/*.schema.json"))


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
