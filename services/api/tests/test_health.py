"""M0 API process and response-hardening tests."""

from fastapi.testclient import TestClient
from pydantic import AnyHttpUrl, SecretStr

from retryrail.config import Environment, Settings
from retryrail.main import create_app


def test_liveness_is_typed_and_does_not_leak_configuration(client: TestClient) -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {
        "service": "retryrail-api",
        "status": "ok",
        "version": "0.1.0",
    }
    serialized = response.text.lower()
    assert "password" not in serialized
    assert "secret" not in serialized


def test_readiness_and_security_headers_are_present(client: TestClient) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_empty_overview_reports_the_activated_detector_identity(client: TestClient) -> None:
    response = client.get("/api/v1/overview")

    assert response.status_code == 200
    assert response.json()["detector_version"] == "detector_v4_0_0"
    assert response.json()["detector_release_status"] == "qualified"
    assert response.json()["detector_release_failed_targets"] == []
    assert response.json()["action_eligible_incidents"] == 0


def test_production_disables_interactive_api_documentation() -> None:
    settings = Settings(
        environment=Environment.PRODUCTION,
        database_url="postgresql+psycopg://service:runtime-value@db.internal/retryrail",
        webhook_secret=SecretStr("runtime-injected-production-value"),
        merchant_approval_secret=SecretStr(
            "runtime-injected-merchant-approval-value"
        ),
        approval_token_hmac_key=SecretStr(
            "runtime-injected-token-hmac-key-value"
        ),
        cors_origins=[AnyHttpUrl("https://merchant.example")],
    )

    with TestClient(create_app(settings)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
