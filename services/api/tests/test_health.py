"""M0 API process and response-hardening tests."""

import re

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
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-trace-id"])
    assert response.headers["traceparent"].startswith(
        f"00-{response.headers['x-trace-id']}-"
    )


def test_valid_traceparent_is_continued_without_reusing_the_caller_span(
    client: TestClient,
) -> None:
    trace_id = "0123456789abcdef0123456789abcdef"
    caller_span = "0123456789abcdef"
    response = client.get(
        "/health/live",
        headers={"Traceparent": f"00-{trace_id}-{caller_span}-01"},
    )

    assert response.status_code == 200
    assert response.headers["x-trace-id"] == trace_id
    returned = response.headers["traceparent"].split("-")
    assert returned[0:2] == ["00", trace_id]
    assert returned[2] != caller_span
    assert re.fullmatch(r"[0-9a-f]{16}", returned[2])


def test_trace_context_is_allowed_and_exposed_to_the_configured_web_origin(
    client: TestClient,
) -> None:
    origin = "http://localhost:5173"
    preflight = client.options(
        "/health/live",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "traceparent",
        },
    )
    response = client.get("/health/live", headers={"Origin": origin})

    assert preflight.status_code == 200
    assert "traceparent" in preflight.headers["access-control-allow-headers"].lower()
    exposed = response.headers["access-control-expose-headers"].lower()
    assert "traceparent" in exposed
    assert "x-retryrail-domain-trace-id" in exposed


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
