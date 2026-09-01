"""Local secret and fixture scan behavior."""

import json
from pathlib import Path

from retryrail.security.repository_scan import scan_repository


def test_current_repository_has_no_scanner_findings() -> None:
    root = Path(__file__).resolve().parents[4]

    assert scan_repository(root) == []


def test_scanner_reports_credentials_without_echoing_values(tmp_path: Path) -> None:
    secret_file = tmp_path / "unsafe.env"
    secret_file.write_text("PAYMENT_KEY=rzp_" + "live_1234567890ABCDEF\n", encoding="utf-8")

    findings = scan_repository(tmp_path)

    assert [finding.code for finding in findings] == ["RAZORPAY_KEY"]
    rendered = findings[0].render(tmp_path)
    assert "1234567890ABCDEF" not in rendered


def test_scanner_reports_generic_high_entropy_sensitive_assignment(
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps(
            {
                "authorization_id": "truth_access_" + "a1b2c3d4e5f60718293a",
                "synthetic": True,
            }
        ),
        encoding="utf-8",
    )

    findings = scan_repository(tmp_path)

    assert [finding.code for finding in findings] == ["GENERIC_HIGH_ENTROPY_SENSITIVE_ASSIGNMENT"]
    assert "a1b2c3d4e5f60718293a" not in findings[0].render(tmp_path)


def test_scanner_blocks_prohibited_fixture_keys(tmp_path: Path) -> None:
    fixture_directory = tmp_path / "fixtures" / "webhooks"
    fixture_directory.mkdir(parents=True)
    fixture_path = fixture_directory / "unsafe.json"
    fixture_path.write_text(json.dumps({"payload": {"email": "synthetic@example.invalid"}}))

    findings = scan_repository(tmp_path)

    assert [finding.code for finding in findings] == ["PROHIBITED_FIXTURE_KEY:email"]


def test_scanner_rejects_malformed_json_fixtures(tmp_path: Path) -> None:
    fixture_directory = tmp_path / "fixtures" / "webhooks"
    fixture_directory.mkdir(parents=True)
    (fixture_directory / "malformed.json").write_text("{not-json", encoding="utf-8")

    findings = scan_repository(tmp_path)

    assert [finding.code for finding in findings] == ["FIXTURE_NOT_VALID_JSON"]
