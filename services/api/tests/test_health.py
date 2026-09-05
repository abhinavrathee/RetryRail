"""M0 API process and response-hardening tests."""

import re
from pathlib import Path

import pytest
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
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "payment=()" in response.headers["permissions-policy"]
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


def test_compiled_web_serves_spa_routes_and_hashed_assets(
    settings: Settings,
    tmp_path: Path,
) -> None:
    index = tmp_path / "index.html"
    assets = tmp_path / "assets"
    assets.mkdir()
    index.write_text("<!doctype html><title>RetryRail reviewer sandbox</title>", encoding="utf-8")
    (assets / "index-a1b2c3.js").write_text("export const ready = true;", encoding="utf-8")
    hosted_settings = settings.model_copy(
        update={"serve_web": True, "web_dist_path": tmp_path}
    )

    with TestClient(create_app(hosted_settings)) as hosted:
        root = hosted.get("/")
        nested_route = hosted.get("/incidents/inc_synthetic_001/recover")
        asset = hosted.get("/assets/index-a1b2c3.js")
        missing_asset = hosted.get("/assets/missing.js")
        hidden_file = hosted.get("/.env")
        api = hosted.get("/health/live")

    assert root.status_code == nested_route.status_code == 200
    assert "RetryRail reviewer sandbox" in root.text
    assert nested_route.text == root.text
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert missing_asset.status_code == hidden_file.status_code == 404
    assert api.status_code == 200
    assert api.json()["service"] == "retryrail-api"


def test_compiled_web_requires_a_real_build_directory(settings: Settings, tmp_path: Path) -> None:
    hosted_settings = settings.model_copy(
        update={"serve_web": True, "web_dist_path": tmp_path / "missing"}
    )

    with pytest.raises(RuntimeError, match="compiled web directory"):
        create_app(hosted_settings)


def test_review_deployment_does_not_expose_interactive_api_docs(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<!doctype html><title>Review</title>", encoding="utf-8")
    settings = Settings(
        environment=Environment.REVIEW,
        database_url="postgresql://service:runtime-value@db.internal/retryrail",
        webhook_secret=SecretStr("review-runtime-webhook-value"),
        merchant_approval_secret=SecretStr("review-runtime-merchant-approval-value"),
        approval_token_hmac_key=SecretStr("review-runtime-token-hmac-key-value"),
        replay_enabled=True,
        replay_token=SecretStr("review-runtime-replay-value"),
        recovery_kill_switch=True,
        cors_origins=[],
        serve_web=True,
        web_dist_path=tmp_path,
    )

    with TestClient(create_app(settings)) as hosted:
        assert hosted.get("/docs").status_code == 404
        assert hosted.get("/openapi.json").status_code == 404
        assert hosted.get("/").status_code == 200
