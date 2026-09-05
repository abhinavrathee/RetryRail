"""Process-wide structured logging with recursive fail-closed redaction."""

import logging
import re
from collections.abc import Mapping, MutableMapping, Sequence
from typing import Any

import structlog

REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = frozenset(
    {
        "address",
        "authorization",
        "card",
        "contact",
        "cookie",
        "customer",
        "email",
        "key_secret",
        "name",
        "notes",
        "password",
        "phone",
        "private_key",
        "raw_body",
        "set_cookie",
        "signature",
        "token",
        "vpa",
    }
)
_SENSITIVE_SUFFIXES = (
    "_api_key",
    "_authorization",
    "_credential",
    "_key_secret",
    "_password",
    "_private_key",
    "_secret",
    "_signature",
    "_token",
    "_token_hash",
)
_VALUE_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}"),
    re.compile("s" + r"k-(?:proj-)?[A-Za-z0-9_-]{16,}"),
    re.compile("rzp" + r"_(?:live|test)_[A-Za-z0-9]{8,}"),
)
_DATABASE_CREDENTIAL = re.compile(
    r"(?P<prefix>[A-Za-z][A-Za-z0-9+.-]*://[^:/\s]+:)[^@\s]+@"
)


def redact_event_dict(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Remove credential and PII shapes from nested structured-log values."""

    return {key: _redact_value(value, key=key) for key, value in event_dict.items()}


def _redact_value(value: Any, *, key: str | None = None) -> Any:
    if key is not None and _is_sensitive_key(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {
            str(nested_key): _redact_value(nested_value, key=str(nested_key))
            for nested_key, nested_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact_value(item) for item in value]
    if isinstance(value, BaseException):
        return _redact_string(str(value))
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or normalized.endswith(_SENSITIVE_SUFFIXES)


def _redact_string(value: str) -> str:
    redacted = _DATABASE_CREDENTIAL.sub(r"\g<prefix>" + REDACTED + "@", value)
    for pattern in _VALUE_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def configure_logging(log_level: str) -> None:
    """Configure JSON application logs at one validated severity."""

    level = getattr(logging, log_level, logging.INFO)
    logging.basicConfig(level=level, format="%(message)s")
    structlog.configure(
        processors=(
            structlog.contextvars.merge_contextvars,
            redact_event_dict,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(sort_keys=True),
        ),
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
