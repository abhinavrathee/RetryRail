"""Raw-body webhook HMAC and mutation-resistance tests."""

import hashlib
import hmac

import pytest
from hypothesis import given
from hypothesis import strategies as st

from retryrail.webhooks.signatures import (
    InvalidWebhookSignatureError,
    MissingWebhookSignatureError,
    compute_webhook_signature,
    verify_webhook_signature,
)

_SECRET = "unit-test-secret-not-a-real-credential"


def test_signature_matches_standard_hmac_sha256() -> None:
    raw_body = b'{"event":"payment.failed","amount":125000}'
    expected = hmac.new(_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()

    assert compute_webhook_signature(raw_body, _SECRET) == expected
    verify_webhook_signature(raw_body, expected.upper(), _SECRET)


@pytest.mark.parametrize("signature", [None, "", "   "])
def test_missing_signature_is_rejected(signature: str | None) -> None:
    with pytest.raises(MissingWebhookSignatureError):
        verify_webhook_signature(b"{}", signature, _SECRET)


@pytest.mark.parametrize("signature", ["not-hex", "a" * 63, "g" * 64, "0" * 65])
def test_malformed_or_wrong_signature_is_rejected(signature: str) -> None:
    with pytest.raises(InvalidWebhookSignatureError):
        verify_webhook_signature(b"{}", signature, _SECRET)


def test_even_semantically_equivalent_body_mutation_is_rejected() -> None:
    signed = b'{"event":"payment.failed","amount":125000}'
    reformatted = b'{"amount":125000,"event":"payment.failed"}'
    signature = compute_webhook_signature(signed, _SECRET)

    with pytest.raises(InvalidWebhookSignatureError):
        verify_webhook_signature(reformatted, signature, _SECRET)


@given(
    raw_body=st.binary(max_size=4096),
    secret=st.text(
        alphabet=st.characters(min_codepoint=1, max_codepoint=0xD7FF),
        min_size=1,
        max_size=128,
    ),
)
def test_any_exact_raw_body_round_trips(raw_body: bytes, secret: str) -> None:
    signature = compute_webhook_signature(raw_body, secret)

    verify_webhook_signature(raw_body, signature, secret)


def test_empty_configured_secret_is_rejected_without_processing() -> None:
    with pytest.raises(ValueError, match="not configured"):
        compute_webhook_signature(b"{}", "")
