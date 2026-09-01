"""Fail-closed local and GitGuardian checks for every protected push."""

import os
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Sequence
from pathlib import Path

from retryrail.security.repository_scan import scan_repository

_GITGUARDIAN_INSTANCE = "https://dashboard.gitguardian.com"
_UNTRUSTED_GITGUARDIAN_ENVIRONMENT_KEYS = (
    "GITGUARDIAN_API_KEY",
    "GITGUARDIAN_API_URL",
    "GITGUARDIAN_DOTENV_PATH",
    "GITGUARDIAN_EXIT_ZERO",
    "GITGUARDIAN_MAX_COMMITS_FOR_HOOK",
    "SKIP",
)


def _run_ggshield(
    command: Sequence[str],
    *,
    refs: bytes,
    root: Path,
    environment: dict[str, str],
) -> int:
    # The executable is resolved locally and every argument remains a distinct argv item.
    completed = subprocess.run(  # noqa: S603  # nosec B603
        command,
        input=refs,
        cwd=root,
        env=environment,
        check=False,
    )
    return completed.returncode


def execute_pre_push(
    root: Path,
    hook_args: Sequence[str],
    refs: bytes,
    *,
    ggshield_path: str | None = None,
) -> int:
    """Run offline, full-history and outgoing-commit scans in fail-closed order."""

    resolved_root = root.resolve()
    findings = scan_repository(resolved_root)
    if findings:
        sys.stderr.write("\n".join(finding.render(resolved_root) for finding in findings) + "\n")
        return 1

    config_path = resolved_root / ".gitguardian.yaml"
    if not config_path.is_file():
        sys.stderr.write(".gitguardian.yaml is required for protected pushes\n")
        return 1

    executable = ggshield_path or shutil.which("ggshield")
    if executable is None:
        sys.stderr.write("ggshield is required; run `uv sync --all-groups --frozen` first\n")
        return 1

    environment = os.environ.copy()
    for key in _UNTRUSTED_GITGUARDIAN_ENVIRONMENT_KEYS:
        environment.pop(key, None)
    environment["GITGUARDIAN_DONT_LOAD_ENV"] = "1"
    environment["GITGUARDIAN_FAIL_ON_SERVER_ERROR"] = "true"
    environment["GITGUARDIAN_INSTANCE"] = _GITGUARDIAN_INSTANCE
    base_command = (
        executable,
        "--config-path",
        str(config_path),
    )
    repository_scan_result = _run_ggshield(
        (*base_command, "secret", "scan", "repo", str(resolved_root)),
        refs=b"",
        root=resolved_root,
        environment=environment,
    )
    if repository_scan_result != 0:
        return repository_scan_result

    return _run_ggshield(
        (
            *base_command,
            "secret",
            "scan",
            "pre-push",
            *hook_args,
        ),
        refs=refs,
        root=resolved_root,
        environment=environment,
    )


def main() -> None:
    """Execute the protected pre-push workflow from a Git hook."""

    exit_code = execute_pre_push(
        Path.cwd(),
        tuple(sys.argv[1:]),
        sys.stdin.buffer.read(),
    )
    raise SystemExit(exit_code)


if __name__ == "__main__":  # pragma: no cover
    main()
