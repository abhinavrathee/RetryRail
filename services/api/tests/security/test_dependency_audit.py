"""Fail-closed web dependency audit behavior."""

import json
import os
import subprocess

import pytest

from retryrail.security import dependency_audit
from retryrail.security.dependency_audit import AuditAttempt


def _report(*, high: int, critical: int = 0) -> str:
    return json.dumps(
        {
            "actions": [],
            "advisories": {},
            "metadata": {
                "vulnerabilities": {
                    "info": 0,
                    "low": 0,
                    "moderate": 0,
                    "high": high,
                    "critical": critical,
                }
            },
        }
    )


def _install_attempts(
    monkeypatch: pytest.MonkeyPatch,
    attempts: tuple[AuditAttempt, ...],
) -> list[dict[str, object]]:
    remaining = iter(attempts)
    captured: list[dict[str, object]] = []

    def fake_run(
        executable: str,
        *,
        timeout_seconds: int,
        environment: dict[str, str],
    ) -> AuditAttempt:
        captured.append(
            {
                "executable": executable,
                "timeout_seconds": timeout_seconds,
                "environment": environment,
            }
        )
        return next(remaining)

    monkeypatch.setattr(dependency_audit, "_run_audit_once", fake_run)
    return captured


def test_audit_passes_only_with_a_structured_registry_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _install_attempts(monkeypatch, (AuditAttempt(0, _report(high=0)),))

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        timeout_seconds=17,
        sleep=lambda _delay: None,
    )

    assert result == 0
    assert len(captured) == 1
    assert captured[0]["executable"] == "pnpm-test"
    assert captured[0]["timeout_seconds"] == 17


def test_modern_npm_audit_report_is_recognized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = json.dumps(
        {
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {"vulnerabilities": {"high": 0, "critical": 0}},
        }
    )
    _install_attempts(monkeypatch, (AuditAttempt(0, report),))

    assert (
        dependency_audit.run_pnpm_audit(
            executable="pnpm-test",
            sleep=lambda _delay: None,
        )
        == 0
    )


@pytest.mark.parametrize(("high", "critical"), [(1, 0), (0, 1)])
def test_audit_fails_immediately_on_structured_security_findings(
    monkeypatch: pytest.MonkeyPatch,
    high: int,
    critical: int,
) -> None:
    captured = _install_attempts(
        monkeypatch,
        (AuditAttempt(1, _report(high=high, critical=critical)),),
    )
    sleeps: list[float] = []

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        sleep=sleeps.append,
    )

    assert result == 1
    assert len(captured) == 1
    assert sleeps == []


def test_audit_rejects_high_findings_even_when_pnpm_returns_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_attempts(monkeypatch, (AuditAttempt(0, _report(high=1)),))

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        sleep=lambda _delay: None,
    )

    assert result == 1


def test_audit_retries_missing_report_then_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _install_attempts(
        monkeypatch,
        (
            AuditAttempt(1),
            AuditAttempt(124, timed_out=True),
            AuditAttempt(0, _report(high=0)),
        ),
    )
    sleeps: list[float] = []

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        max_attempts=3,
        backoff_seconds=7,
        sleep=sleeps.append,
    )

    assert result == 0
    assert len(captured) == 3
    assert sleeps == [7, 14]


def test_audit_does_not_echo_unstructured_registry_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_attempts(
        monkeypatch,
        (
            AuditAttempt(1, "sensitive transport detail"),
            AuditAttempt(0, _report(high=0)),
        ),
    )

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        max_attempts=2,
        backoff_seconds=0,
        sleep=lambda _delay: None,
    )

    assert result == 0
    output = capsys.readouterr()
    assert "sensitive transport detail" not in output.out
    assert "sensitive transport detail" not in output.err


def test_audit_retries_clean_report_from_abnormal_process_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _install_attempts(
        monkeypatch,
        (
            AuditAttempt(124, _report(high=0), timed_out=True),
            AuditAttempt(0, _report(high=0)),
        ),
    )
    sleeps: list[float] = []

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        max_attempts=2,
        backoff_seconds=3,
        sleep=sleeps.append,
    )

    assert result == 0
    assert len(captured) == 2
    assert sleeps == [3]


def test_audit_fails_closed_when_registry_never_returns_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_attempts(
        monkeypatch,
        (
            AuditAttempt(0),
            AuditAttempt(1),
            AuditAttempt(124, timed_out=True),
        ),
    )

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        max_attempts=3,
        backoff_seconds=0,
        sleep=lambda _delay: None,
    )

    assert result == 124


def test_audit_rejects_zero_exit_without_registry_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_attempts(monkeypatch, (AuditAttempt(0),))

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        max_attempts=1,
        sleep=lambda _delay: None,
    )

    assert result == 1


def test_audit_pins_registry_and_removes_auth_and_fail_open_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NPM_TOKEN", "must-not-propagate")
    monkeypatch.setenv(
        "NPM_CONFIG_//REGISTRY.NPMJS.ORG/:_AUTHTOKEN",
        "must-not-propagate-either",
    )
    monkeypatch.setenv("npm_config_registry", "https://example.invalid/")
    monkeypatch.setenv("NPM_CONFIG_IGNORE_REGISTRY_ERRORS", "true")
    monkeypatch.setenv("PNPM_CONFIG_ONLY", "production")
    captured = _install_attempts(monkeypatch, (AuditAttempt(0, _report(high=0)),))

    result = dependency_audit.run_pnpm_audit(
        executable="pnpm-test",
        sleep=lambda _delay: None,
    )

    assert result == 0
    environment = captured[0]["environment"]
    assert isinstance(environment, dict)
    assert environment["NPM_CONFIG_REGISTRY"] == "https://registry.npmjs.org/"
    assert environment["NPM_CONFIG_GLOBALCONFIG"] == os.devnull
    assert environment["NPM_CONFIG_USERCONFIG"] == os.devnull
    assert all(key.casefold() != "npm_token" for key in environment)
    assert all(key.casefold() != "npm_config_ignore_registry_errors" for key in environment)
    assert all(key.casefold() != "pnpm_config_only" for key in environment)
    assert all("auth" not in key.casefold() for key in environment if key.startswith("NPM_CONFIG_"))


def test_audit_subprocess_timeout_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []

    def raise_timeout(command: tuple[str, ...], **_kwargs: object) -> None:
        commands.append(command)
        raise subprocess.TimeoutExpired(
            cmd=("pnpm-test", "audit"),
            timeout=5,
            output=b'not-json-with-sensitive-registry-details',
        )

    monkeypatch.setattr("retryrail.security.dependency_audit.subprocess.run", raise_timeout)

    result = dependency_audit._run_audit_once(  # noqa: SLF001
        "pnpm-test",
        timeout_seconds=5,
        environment={},
    )

    assert result == AuditAttempt(
        returncode=124,
        stdout="not-json-with-sensitive-registry-details",
        timed_out=True,
    )
    assert commands == [
        (
            "pnpm-test",
            "audit",
            "--audit-level",
            "high",
            "--json",
            "--no-ignore-registry-errors",
            "--no-ignore-unfixable",
        )
    ]


def test_audit_fails_closed_without_pnpm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("retryrail.security.dependency_audit.shutil.which", lambda _name: None)

    assert dependency_audit.run_pnpm_audit(sleep=lambda _delay: None) == 1


@pytest.mark.parametrize(
    ("max_attempts", "timeout_seconds", "backoff_seconds"),
    [(0, 1, 0), (1, 0, 0), (1, 1, -1)],
)
def test_audit_rejects_invalid_retry_settings(
    max_attempts: int,
    timeout_seconds: int,
    backoff_seconds: int,
) -> None:
    with pytest.raises(ValueError, match="outside their valid range"):
        dependency_audit.run_pnpm_audit(
            executable="pnpm-test",
            max_attempts=max_attempts,
            timeout_seconds=timeout_seconds,
            backoff_seconds=backoff_seconds,
            sleep=lambda _delay: None,
        )
