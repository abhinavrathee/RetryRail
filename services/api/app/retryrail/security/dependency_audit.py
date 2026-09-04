"""Fail-closed pnpm dependency audit with bounded registry retries."""

import argparse
import json
import os
import shutil
import subprocess  # nosec B404
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

_DEFAULT_MAX_ATTEMPTS = 3
_DEFAULT_TIMEOUT_SECONDS = 240
_DEFAULT_BACKOFF_SECONDS = 10
_AUDIT_REGISTRY = "https://registry.npmjs.org/"
_INVALID_RETRY_SETTINGS = "audit retry settings are outside their valid range"
_UNREACHABLE_RETRY_STATE = "unreachable audit retry state"
_TOKEN_ENVIRONMENT_KEYS = frozenset(
    {
        "node_auth_token",
        "npm_token",
        "yarn_npm_auth_token",
    }
)


@dataclass(frozen=True, slots=True)
class AuditAttempt:
    """Sanitized outcome from one invocation of the package-manager audit."""

    returncode: int
    stdout: str = ""
    timed_out: bool = False


@dataclass(frozen=True, slots=True)
class AuditReport:
    """Security-relevant counts from one structurally valid audit report."""

    high: int
    critical: int


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(encoding="utf-8", errors="replace")
    return value


def _is_untrusted_environment_key(key: str) -> bool:
    normalized = key.casefold()
    if normalized in _TOKEN_ENVIRONMENT_KEYS:
        return True
    return normalized.startswith(("npm_config_", "pnpm_config_"))


def _audit_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not _is_untrusted_environment_key(key)
    }
    # RetryRail has no private JavaScript packages. Pinning the public registry
    # prevents a caller-controlled npm configuration from redirecting the audit.
    environment.update(
        {
            "NPM_CONFIG_GLOBALCONFIG": os.devnull,
            "NPM_CONFIG_REGISTRY": _AUDIT_REGISTRY,
            "NPM_CONFIG_USERCONFIG": os.devnull,
        }
    )
    return environment


def _run_audit_once(
    executable: str,
    *,
    timeout_seconds: int,
    environment: dict[str, str],
) -> AuditAttempt:
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            (
                executable,
                "audit",
                "--audit-level",
                "high",
                "--json",
                "--no-ignore-registry-errors",
                "--no-ignore-unfixable",
            ),
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        return AuditAttempt(
            returncode=124,
            stdout=_as_text(error.stdout),
            timed_out=True,
        )
    return AuditAttempt(
        returncode=completed.returncode,
        stdout=completed.stdout,
    )


def _parse_audit_report(output: str) -> AuditReport | None:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    metadata = payload.get("metadata")
    is_legacy_report = isinstance(payload.get("advisories"), dict)
    is_modern_report = isinstance(payload.get("auditReportVersion"), int) and isinstance(
        payload.get("vulnerabilities"), dict
    )
    if not (is_legacy_report or is_modern_report):
        return None

    counts = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
    if not isinstance(counts, dict):
        return None
    high = counts.get("high")
    critical = counts.get("critical")
    if (
        not isinstance(high, int)
        or isinstance(high, bool)
        or high < 0
        or not isinstance(critical, int)
        or isinstance(critical, bool)
        or critical < 0
    ):
        return None
    return AuditReport(high=high, critical=critical)


def _retry_reason(attempt: AuditAttempt, report: AuditReport | None) -> str:
    if report is not None:
        return "returned a clean report but exited abnormally"
    if attempt.timed_out:
        return "timed out without a complete report"
    return "returned no structured report"


def run_pnpm_audit(
    *,
    executable: str | None = None,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    backoff_seconds: int = _DEFAULT_BACKOFF_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Run a high-severity audit, retrying incomplete or abnormal results."""

    if max_attempts < 1 or timeout_seconds < 1 or backoff_seconds < 0:
        raise ValueError(_INVALID_RETRY_SETTINGS)

    resolved_executable = executable or shutil.which("pnpm")
    if resolved_executable is None:
        sys.stderr.write("pnpm is required for the web dependency audit\n")
        return 1

    environment = _audit_environment()
    for attempt_number in range(1, max_attempts + 1):
        attempt = _run_audit_once(
            resolved_executable,
            timeout_seconds=timeout_seconds,
            environment=environment,
        )
        report = _parse_audit_report(attempt.stdout)
        if report is not None:
            if report.high > 0 or report.critical > 0:
                sys.stderr.write(attempt.stdout.rstrip() + "\n")
                sys.stderr.write("pnpm reported dependency findings at or above high severity\n")
                return attempt.returncode or 1
            if attempt.returncode == 0:
                sys.stdout.write("pnpm high-severity dependency audit passed\n")
                return 0
        reason = _retry_reason(attempt, report)
        if attempt_number == max_attempts:
            sys.stderr.write(
                "pnpm dependency audit failed closed after "
                f"{max_attempts} attempts; final attempt {reason}\n"
            )
            return attempt.returncode or 1

        delay = backoff_seconds * attempt_number
        sys.stderr.write(
            f"pnpm audit attempt {attempt_number}/{max_attempts} {reason}; "
            f"retrying in {delay} seconds\n"
        )
        sleep(delay)

    raise AssertionError(_UNREACHABLE_RETRY_STATE)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the fail-closed RetryRail pnpm dependency audit.",
    )
    parser.add_argument("--max-attempts", type=int, default=_DEFAULT_MAX_ATTEMPTS)
    parser.add_argument("--timeout-seconds", type=int, default=_DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--backoff-seconds", type=int, default=_DEFAULT_BACKOFF_SECONDS)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Execute the bounded web dependency audit."""

    arguments = _parser().parse_args(argv)
    try:
        result = run_pnpm_audit(
            max_attempts=arguments.max_attempts,
            timeout_seconds=arguments.timeout_seconds,
            backoff_seconds=arguments.backoff_seconds,
        )
    except ValueError as error:
        raise SystemExit(str(error)) from error
    raise SystemExit(result)


if __name__ == "__main__":  # pragma: no cover
    main()
