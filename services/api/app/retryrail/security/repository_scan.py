"""Fail-fast local scan for credential patterns and prohibited fixture keys."""

import hashlib
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "coverage",
        "dist",
        "node_modules",
        "playwright-report",
        "test-results",
    }
)
_TEXT_SUFFIXES = frozenset(
    {
        ".css",
        ".env",
        ".example",
        ".html",
        ".js",
        ".json",
        ".jsonl",
        ".md",
        ".py",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
    }
)
_STRUCTURED_ASSIGNMENT_SUFFIXES = frozenset(
    {".env", ".example", ".json", ".jsonl", ".toml", ".yaml", ".yml"}
)
_SECRET_PATTERNS = (
    ("RAZORPAY_KEY", re.compile("rzp_" + r"(?:live|test)_[A-Za-z0-9]{8,}")),
    ("AWS_ACCESS_KEY", re.compile("AK" + r"IA[0-9A-Z]{16}")),
    (
        "PRIVATE_KEY",
        re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("GITHUB_TOKEN", re.compile("gh" + r"[oprs]_[A-Za-z0-9_]{30,}")),
)
_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?P<key>
        ["']?[A-Za-z0-9_-]*
        (?:authorization|api[_-]?key|secret|token|password|private[_-]?key)
        [A-Za-z0-9_-]*["']?
    )
    \s*(?:=|:)\s*
    (?P<quote>["'])
    (?P<value>[A-Za-z0-9_./+=-]{20,})
    (?P=quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_MINIMUM_GENERIC_ENTROPY_BITS = 3.5
_KNOWN_NON_SECRET_ASSIGNMENT_DIGESTS = {
    (
        "evals/blind/detector_v2/runs/"
        "detector_v2_official_blind_ef49a16703b1612ef774/"
        "truth_access.receipt.json"
    ): frozenset(
        {
            # Immutable synthetic receipt identifier from official blind run ef49a167.
            "a2723b705638e53c95abaa54c8d21d9ce876377a720975a80b0cebca18876d07",
        }
    ),
}
_PROHIBITED_FIXTURE_KEYS = frozenset(
    {
        "account_id",
        "address",
        "billing_address",
        "card",
        "contact",
        "customer",
        "customer_id",
        "email",
        "key_secret",
        "name",
        "notes",
        "shipping_address",
        "token",
        "vpa",
    }
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One safe scanner finding without echoing sensitive content."""

    path: Path
    code: str
    line: int | None = None

    def render(self, root: Path) -> str:
        location = self.path.relative_to(root).as_posix()
        if self.line is not None:
            location = f"{location}:{self.line}"
        return f"{location}: {self.code}"


def _iter_text_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for directory, directory_names, file_names in root.walk():
        directory_names[:] = [name for name in directory_names if name not in _EXCLUDED_DIRECTORIES]
        paths.extend(
            path
            for name in file_names
            if (path := directory / name).suffix.lower() in _TEXT_SUFFIXES
            or path.name in {"Makefile", "Dockerfile"}
        )
    return sorted(paths)


def _entropy_bits_per_character(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_known_non_secret_assignment(path: Path, root: Path, value: str) -> bool:
    relative_path = path.relative_to(root).as_posix()
    allowed_digests = _KNOWN_NON_SECRET_ASSIGNMENT_DIGESTS.get(
        relative_path,
        frozenset(),
    )
    value_digest = hashlib.sha256(value.encode()).hexdigest()
    return value_digest in allowed_digests


def _scan_text(path: Path, root: Path) -> list[Finding]:
    if path.name == "repository_scan.py":
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    findings: list[Finding] = []
    for code, pattern in _SECRET_PATTERNS:
        findings.extend(
            Finding(
                path=path,
                code=code,
                line=text.count("\n", 0, match.start()) + 1,
            )
            for match in pattern.finditer(text)
        )
    if path.suffix.lower() in _STRUCTURED_ASSIGNMENT_SUFFIXES:
        for match in _SENSITIVE_ASSIGNMENT_PATTERN.finditer(text):
            value = match.group("value")
            if _entropy_bits_per_character(
                value
            ) >= _MINIMUM_GENERIC_ENTROPY_BITS and not _is_known_non_secret_assignment(
                path, root, value
            ):
                findings.append(
                    Finding(
                        path=path,
                        code="GENERIC_HIGH_ENTROPY_SENSITIVE_ASSIGNMENT",
                        line=text.count("\n", 0, match.start()) + 1,
                    )
                )
    return findings


def _collect_prohibited_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        mapping_keys = {str(key).lower() for key in value}
        for nested in value.values():
            mapping_keys.update(_collect_prohibited_keys(nested))
        return mapping_keys
    if isinstance(value, list):
        list_keys: set[str] = set()
        for nested in value:
            list_keys.update(_collect_prohibited_keys(nested))
        return list_keys
    return set()


def _scan_fixture(path: Path) -> list[Finding]:
    if "fixtures" not in path.parts or path.suffix.lower() not in {".json", ".jsonl"}:
        return []
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            documents = [json.loads(text)]
        else:
            documents = [json.loads(line) for line in text.splitlines() if line]
    except (json.JSONDecodeError, UnicodeDecodeError):
        return [Finding(path=path, code="FIXTURE_NOT_VALID_JSON")]

    keys: set[str] = set()
    for document in documents:
        keys.update(_collect_prohibited_keys(document))
    return [
        Finding(path=path, code=f"PROHIBITED_FIXTURE_KEY:{key}")
        for key in sorted(keys & _PROHIBITED_FIXTURE_KEYS)
    ]


def scan_repository(root: Path) -> list[Finding]:
    """Scan first-party text and fixture structure without printing secret values."""

    findings: list[Finding] = []
    resolved_root = root.resolve()
    for path in _iter_text_files(resolved_root):
        findings.extend(_scan_text(path, resolved_root))
        findings.extend(_scan_fixture(path))
    return findings


def main() -> None:
    """Run the repository scan from the current working directory."""

    root = Path.cwd().resolve()
    findings = scan_repository(root)
    if findings:
        sys.stderr.write("\n".join(finding.render(root) for finding in findings) + "\n")
        raise SystemExit(1)
    sys.stdout.write("repository secret and fixture scan passed\n")


if __name__ == "__main__":  # pragma: no cover
    main()
