"""Failure-focused tests for the real Razorpay Test Mode provider boundary."""

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from retryrail.contracts.recovery import RecoveryActionErrorCategory
from retryrail.recovery.adapter import (
    PaymentLinkCreateRequest,
    PaymentLinkResult,
    PaymentLinkStatus,
    ProviderError,
    ProviderOutcomeAmbiguousError,
    RazorpayTestModeAdapter,
)

_CREATED_AT = datetime(2026, 9, 5, 12, tzinfo=UTC)
_VERIFIED_AT = _CREATED_AT + timedelta(seconds=2)
_REFERENCE_ID = "rr_0123456789abcdef0123456789abcdef"
_KEY_ID = "rzp" + "_test_retryrail_key"
_KEY_SECRET = "test_secret_never_log"
_TRANSPORT_TIMEOUT_DETAIL = "do not expose transport detail"


def _request() -> PaymentLinkCreateRequest:
    return PaymentLinkCreateRequest(
        amount_subunits=149_900,
        currency="INR",
        reference_id=_REFERENCE_ID,
        expires_at=_CREATED_AT + timedelta(minutes=30),
        synthetic=True,
    )


def _link_payload(*, reference_id: str = _REFERENCE_ID) -> dict[str, object]:
    return {
        "id": "plink_RetryRailTest001",
        "entity": "payment_link",
        "reference_id": reference_id,
        "status": "created",
        "amount": 149_900,
        "amount_paid": 0,
        "currency": "INR",
        "short_url": "https://rzp.io/i/retryrail-test",
        "created_at": int(_CREATED_AT.timestamp()),
        "customer": {"contact": "must-not-be-persisted"},
    }


def _adapter(
    handler: httpx.AsyncBaseTransport,
) -> RazorpayTestModeAdapter:
    return RazorpayTestModeAdapter(
        key_id=SecretStr(_KEY_ID),
        key_secret=SecretStr(_KEY_SECRET),
        transport=handler,
        clock=lambda: _VERIFIED_AT,
    )


def test_create_uses_one_pii_free_non_notifying_test_mode_request() -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json=_link_payload())

    adapter = _adapter(httpx.MockTransport(handler))
    try:
        result = asyncio.run(adapter.create_standard_payment_link(_request()))
    finally:
        asyncio.run(adapter.aclose())

    assert result.provider_action_id == "plink_RetryRailTest001"
    assert result.reference_id == _REFERENCE_ID
    assert result.status is PaymentLinkStatus.CREATED
    assert result.amount_subunits == 149_900
    assert str(result.short_url) == "https://rzp.io/i/retryrail-test"
    assert len(observed) == 1
    sent = observed[0]
    assert sent.method == "POST"
    assert sent.url == "https://api.razorpay.com/v1/payment_links"
    expected_auth = base64.b64encode(f"{_KEY_ID}:{_KEY_SECRET}".encode()).decode()
    assert sent.headers["Authorization"] == f"Basic {expected_auth}"
    body = json.loads(sent.content)
    assert body == {
        "amount": 149_900,
        "currency": "INR",
        "accept_partial": False,
        "reference_id": _REFERENCE_ID,
        "description": "RetryRail Test Mode recovery",
        "expire_by": int((_CREATED_AT + timedelta(minutes=30)).timestamp()),
        "notify": {"sms": False, "email": False},
        "reminder_enable": False,
    }
    assert "customer" not in body
    assert _KEY_SECRET not in result.model_dump_json()


@pytest.mark.parametrize(
    ("status_code", "category", "reason_code"),
    [
        (400, RecoveryActionErrorCategory.INVALID_INPUT, "RAZORPAY_CREATE_INVALID_INPUT"),
        (401, RecoveryActionErrorCategory.UNAUTHORIZED, "RAZORPAY_TEST_MODE_UNAUTHORIZED"),
        (429, RecoveryActionErrorCategory.RATE_LIMITED, "RAZORPAY_RATE_LIMITED"),
    ],
)
def test_create_maps_known_http_failures_without_raw_provider_content(
    status_code: int,
    category: RecoveryActionErrorCategory,
    reason_code: str,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            json={"error": {"description": f"sensitive {_KEY_SECRET}"}},
        )

    adapter = _adapter(httpx.MockTransport(handler))
    try:
        with pytest.raises(ProviderError) as captured:
            asyncio.run(adapter.create_standard_payment_link(_request()))
    finally:
        asyncio.run(adapter.aclose())

    assert captured.value.error.category is category
    assert captured.value.error.reason_code == reason_code
    assert _KEY_SECRET not in str(captured.value)
    assert _KEY_SECRET not in captured.value.error.model_dump_json()


@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
def test_create_treats_server_responses_as_ambiguous_and_never_retries(
    status_code: int,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status_code, json={"error": "unknown outcome"})

    adapter = _adapter(httpx.MockTransport(handler))
    try:
        with pytest.raises(ProviderOutcomeAmbiguousError) as captured:
            asyncio.run(adapter.create_standard_payment_link(_request()))
    finally:
        asyncio.run(adapter.aclose())

    assert calls == 1
    assert captured.value.error.reconciliation_required is True
    assert captured.value.error.retry_permitted is False


def test_create_transport_timeout_is_ambiguous_and_called_once() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout(_TRANSPORT_TIMEOUT_DETAIL, request=request)

    adapter = _adapter(httpx.MockTransport(handler))
    try:
        with pytest.raises(ProviderOutcomeAmbiguousError):
            asyncio.run(adapter.create_standard_payment_link(_request()))
    finally:
        asyncio.run(adapter.aclose())
    assert calls == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"not": "a payment link"},
        _link_payload(reference_id="rr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ],
)
def test_create_rejects_malformed_or_rebound_success_as_ambiguous(
    payload: dict[str, object],
) -> None:
    adapter = _adapter(
        httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    try:
        with pytest.raises(ProviderOutcomeAmbiguousError):
            asyncio.run(adapter.create_standard_payment_link(_request()))
    finally:
        asyncio.run(adapter.aclose())


def test_reconcile_is_lookup_only_and_requires_one_exact_reference() -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        assert request.url.params["reference_id"] == _REFERENCE_ID
        return httpx.Response(200, json={"payment_links": [_link_payload()]})

    adapter = _adapter(httpx.MockTransport(handler))
    try:
        result = asyncio.run(adapter.reconcile(_REFERENCE_ID))
    finally:
        asyncio.run(adapter.aclose())

    assert result is not None
    assert result.reference_id == _REFERENCE_ID
    assert methods == ["GET"]


def test_reconcile_returns_none_for_confirmed_absence() -> None:
    adapter = _adapter(
        httpx.MockTransport(
            lambda _request: httpx.Response(200, json={"payment_links": []})
        )
    )
    try:
        assert asyncio.run(adapter.reconcile(_REFERENCE_ID)) is None
    finally:
        asyncio.run(adapter.aclose())


def test_reconcile_rejects_duplicate_reference_evidence() -> None:
    adapter = _adapter(
        httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={"payment_links": [_link_payload(), _link_payload()]},
            )
        )
    )
    try:
        with pytest.raises(ProviderError) as captured:
            asyncio.run(adapter.reconcile(_REFERENCE_ID))
    finally:
        asyncio.run(adapter.aclose())
    assert captured.value.error.reason_code == "RAZORPAY_REFERENCE_NOT_UNIQUE"


def test_adapter_and_result_reject_live_credentials_or_insecure_urls() -> None:
    with pytest.raises(ValueError, match="Test Mode"):
        RazorpayTestModeAdapter(
            key_id=SecretStr("rzp" + "_live_forbidden"),
            key_secret=SecretStr(_KEY_SECRET),
        )
    with pytest.raises(ValidationError, match="HTTPS"):
        PaymentLinkResult(
            provider_action_id="plink_RetryRailTest001",
            reference_id=_REFERENCE_ID,
            status=PaymentLinkStatus.CREATED,
            amount_subunits=149_900,
            currency="INR",
            short_url="http://example.invalid/link",
            provider_created_at=_CREATED_AT,
            verified_at=_VERIFIED_AT,
            synthetic=True,
        )
