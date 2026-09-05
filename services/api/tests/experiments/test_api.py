"""Read-only API and activation tests for the frozen M5 experiment report."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from retryrail.config import Settings
from retryrail.experiments.models import RecoveryExperimentReport
from retryrail.experiments.service import (
    ExperimentReportEvidenceError,
    ExperimentReportService,
)

_AUTHORIZATION = {
    "X-RetryRail-Merchant-Authorization": "unit-test-merchant-approval-secret-value"
}


def test_experiment_api_is_authenticated_typed_and_causally_labelled(
    client: TestClient,
    settings: Settings,
) -> None:
    path = "/api/v1/experiments/recovery_experiment_v1"

    unauthenticated = client.get(path)
    missing = client.get(
        "/api/v1/experiments/recovery_experiment_unknown",
        headers=_AUTHORIZATION,
    )
    response = client.get(path, headers=_AUTHORIZATION)

    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["detail"]["reason_code"] == (
        "MERCHANT_AUTHENTICATION_FAILED"
    )
    assert missing.status_code == 404
    assert missing.json()["detail"]["reason_code"] == "EXPERIMENT_NOT_FOUND"
    assert response.status_code == 200
    report = RecoveryExperimentReport.model_validate(response.json())
    assert report.synthetic is True
    assert report.metric_scope == "synthetic_batch_not_live_merchant_performance"
    assert report.treatment.eligible_count == 224
    assert report.control.eligible_count == 56
    assert report.value.gross_treatment_recovered_gmv_subunits != (
        report.value.incremental_recovered_gmv_subunits
    )

    metrics = client.get("/metrics").text
    assert "retryrail_experiment_eligible_payments 280.0" in metrics
    assert "retryrail_experiment_incremental_recovered_gmv_subunits" in metrics
    assert settings.merchant_id not in metrics


def test_experiment_service_rejects_changed_report_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    changed = tmp_path / "changed-report.json"
    changed.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        "retryrail.experiments.service._SOURCE_REPORT_PATH",
        changed,
    )

    with pytest.raises(ExperimentReportEvidenceError, match="digest"):
        ExperimentReportService()
