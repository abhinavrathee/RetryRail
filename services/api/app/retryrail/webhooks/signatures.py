"""Razorpay raw-body HMAC verification."""

import hashlib
import hmac
import re

from pydantic import SecretStr

_HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class WebhookSignatureError(ValueError):
    """Safe base error that never includes request bodies or secret material."""

    reason_code = "WEBHOOK_SIGNATURE_INVALID"


class MissingWebhookSignatureError(WebhookSignatureError):
    """Raised when the required signature header is absent."""

    reason_code = "WEBHOOK_SIGNATURE_MISSING"


class InvalidWebhookSignatureError(WebhookSignatureError):
    """Raised when the signature has the wrong shape or does not match."""


def compute_webhook_signature(raw_body: bytes, secret: SecretStr | str) -> str:
    """Return the HMAC-SHA256 hex digest over the exact unmodified body bytes."""

    secret_value = secret.get_secret_value() if isinstance(secret, SecretStr) else secret
    if not secret_value:
        msg = "webhook secret is not configured"
        raise ValueError(msg)
    return hmac.new(secret_value.encode(), raw_body, hashlib.sha256).hexdigest()


def verify_webhook_signature(
    raw_body: bytes,
    provided_signature: str | None,
    secret: SecretStr | str,
) -> None:
    """Verify a Razorpay signature using constant-time digest comparison."""

    expected = compute_webhook_signature(raw_body, secret)
    if provided_signature is None or not provided_signature.strip():
        raise MissingWebhookSignatureError

    candidate = provided_signature.strip()
    valid_shape = _HEX_SHA256.fullmatch(candidate) is not None
    comparable_candidate = candidate.lower() if valid_shape else "0" * 64
    matches = hmac.compare_digest(expected, comparable_candidate)
    if not valid_shape or not matches:
        raise InvalidWebhookSignatureError

