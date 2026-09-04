"""Bounded provider adapters for fake and Razorpay Test Mode Payment Links."""

import asyncio
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol, Self

import httpx
from pydantic import (
    AnyHttpUrl,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    ValidationError,
    model_validator,
)

from retryrail.contracts.domain import StrictContract
from retryrail.contracts.recovery import (
    RecoveryActionError,
    RecoveryActionErrorCategory,
)
from retryrail.events.models import Currency, Identifier

RAZORPAY_API_BASE_URL = "https://api.razorpay.com"
_MAX_PROVIDER_RESPONSE_BYTES = 262_144
_HTTP_OK = 200
_HTTP_TOO_MANY_REQUESTS = 429

RazorpayReferenceId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=40,
        pattern=r"^[A-Za-z0-9_-]+$",
    ),
]


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class PaymentLinkStatus(StrEnum):
    """Razorpay Standard Payment Link states admitted into stored evidence."""

    CREATED = "created"
    PARTIALLY_PAID = "partially_paid"
    PAID = "paid"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class PaymentLinkCreateRequest(StrictContract):
    """PII-free create request; customer notifications are structurally disabled."""

    amount_subunits: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    reference_id: RazorpayReferenceId
    expires_at: AwareDatetime
    external_notifications_enabled: Literal[False] = False
    synthetic: Literal[True] = True


class PaymentLinkResult(StrictContract):
    """Sanitized provider result with only fields needed for verification and demo."""

    provider_action_id: Identifier
    reference_id: RazorpayReferenceId
    status: PaymentLinkStatus
    amount_subunits: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    short_url: AnyHttpUrl | None = None
    provider_created_at: AwareDatetime
    verified_at: AwareDatetime
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_times_and_url(self) -> Self:
        """Reject time reversal and non-HTTPS provider links."""

        if self.verified_at < self.provider_created_at:
            msg = "provider verification cannot precede creation"
            raise ValueError(msg)
        if self.short_url is not None and self.short_url.scheme != "https":
            msg = "provider short URL must use HTTPS"
            raise ValueError(msg)
        return self


class RecoveryProvider(Protocol):
    """Create-once and lookup-only boundary shared by fake and Test Mode."""

    async def create_standard_payment_link(
        self,
        request: PaymentLinkCreateRequest,
    ) -> PaymentLinkResult:
        """Create once by stable reference or raise a typed bounded failure."""

    async def reconcile(self, reference_id: str) -> PaymentLinkResult | None:
        """Look up a prior create by stable reference without creating anything."""


class ProviderError(RuntimeError):
    """Known provider failure carrying only a redacted typed error."""

    def __init__(self, error: RecoveryActionError) -> None:
        super().__init__(error.reason_code)
        self.error = error


class ProviderOutcomeAmbiguousError(ProviderError):
    """The caller must reconcile because creation may have succeeded."""


class FakeProviderScenario(StrEnum):
    """Deterministic outcomes injectable only at the internal adapter boundary."""

    SUCCESS = "success"
    INVALID_INPUT = "invalid_input"
    UNAUTHORIZED = "unauthorized"
    RATE_LIMITED = "rate_limited"
    UPSTREAM_FAILURE = "upstream_failure"
    TIMEOUT_BEFORE_CREATE = "timeout_before_create"
    TIMEOUT_AFTER_CREATE = "timeout_after_create"


class DeterministicFakeRazorpayAdapter:
    """Process-local fake with reference-level idempotency and scripted ambiguity."""

    def __init__(
        self,
        *,
        scenario: FakeProviderScenario = FakeProviderScenario.SUCCESS,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._scenario = scenario
        self._clock = clock
        self._lock = asyncio.Lock()
        self._by_reference: dict[str, PaymentLinkResult] = {}
        self.create_calls = 0
        self.reconcile_calls = 0

    async def create_standard_payment_link(
        self,
        request: PaymentLinkCreateRequest,
    ) -> PaymentLinkResult:
        """Produce one logical fake link, including timeout-after-create behavior."""

        async with self._lock:
            self.create_calls += 1
            existing = self._by_reference.get(request.reference_id)
            if existing is not None:
                return existing

            failure = _scenario_error(self._scenario)
            if failure is not None:
                if self._scenario is FakeProviderScenario.TIMEOUT_BEFORE_CREATE:
                    raise ProviderOutcomeAmbiguousError(failure)
                raise ProviderError(failure)

            now = self._clock_utc()
            result = PaymentLinkResult(
                provider_action_id=_fake_provider_id(request.reference_id),
                reference_id=request.reference_id,
                status=PaymentLinkStatus.CREATED,
                amount_subunits=request.amount_subunits,
                currency=request.currency,
                provider_created_at=now,
                verified_at=now,
                synthetic=True,
            )
            self._by_reference[request.reference_id] = result
            if self._scenario is FakeProviderScenario.TIMEOUT_AFTER_CREATE:
                raise ProviderOutcomeAmbiguousError(_ambiguous_error("FAKE_PROVIDER"))
            return result

    async def reconcile(self, reference_id: str) -> PaymentLinkResult | None:
        """Return the already-created fake link, never creating during lookup."""

        async with self._lock:
            self.reconcile_calls += 1
            return self._by_reference.get(reference_id)

    def _clock_utc(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            msg = "fake provider clock must be timezone-aware"
            raise ValueError(msg)
        return now.astimezone(UTC)


class _RazorpayPaymentLink(BaseModel):
    """Tolerant parser for the allowlisted subset of an external API response."""

    model_config = ConfigDict(extra="ignore")

    id: Identifier
    reference_id: RazorpayReferenceId
    status: PaymentLinkStatus
    amount: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    short_url: AnyHttpUrl
    created_at: int = Field(gt=0)


class _RazorpayPaymentLinkCollection(BaseModel):
    """Current collection envelope used for reference-id reconciliation."""

    model_config = ConfigDict(extra="ignore")

    payment_links: tuple[_RazorpayPaymentLink, ...] = ()


class RazorpayTestModeAdapter:
    """No-retry Razorpay client that accepts Test Mode keys and sanitized data only."""

    def __init__(
        self,
        *,
        key_id: SecretStr,
        key_secret: SecretStr,
        connect_timeout_seconds: float = 3.0,
        read_timeout_seconds: float = 8.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        raw_key_id = key_id.get_secret_value()
        raw_key_secret = key_secret.get_secret_value()
        if not raw_key_id.startswith("rzp_test_") or not raw_key_secret:
            msg = "Razorpay adapter requires a complete Test Mode credential pair"
            raise ValueError(msg)
        timeout = httpx.Timeout(
            connect=connect_timeout_seconds,
            read=read_timeout_seconds,
            write=read_timeout_seconds,
            pool=connect_timeout_seconds,
        )
        self._client = httpx.AsyncClient(
            base_url=RAZORPAY_API_BASE_URL,
            auth=httpx.BasicAuth(raw_key_id, raw_key_secret),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "RetryRail/0.1 TestMode",
            },
            follow_redirects=False,
            timeout=timeout,
            transport=transport,
        )
        self._clock = clock

    async def create_standard_payment_link(
        self,
        request: PaymentLinkCreateRequest,
    ) -> PaymentLinkResult:
        """Perform exactly one POST; any uncertain result requires lookup."""

        payload: dict[str, object] = {
            "amount": request.amount_subunits,
            "currency": request.currency,
            "accept_partial": False,
            "reference_id": request.reference_id,
            "description": "RetryRail Test Mode recovery",
            "expire_by": int(request.expires_at.timestamp()),
            "notify": {"sms": False, "email": False},
            "reminder_enable": False,
        }
        try:
            response = await self._client.post("/v1/payment_links", json=payload)
        except httpx.HTTPError as error:
            raise ProviderOutcomeAmbiguousError(
                _ambiguous_error("RAZORPAY_TEST_MODE")
            ) from error
        if response.status_code in {200, 201}:
            return self._parse_single_response(
                response,
                expected_reference_id=request.reference_id,
            )
        self._raise_create_failure(response.status_code)
        raise AssertionError("unreachable")

    async def reconcile(self, reference_id: str) -> PaymentLinkResult | None:
        """Fetch by unique reference id; this method never calls the create endpoint."""

        try:
            response = await self._client.get(
                "/v1/payment_links",
                params={"reference_id": reference_id},
            )
        except httpx.HTTPError as error:
            raise ProviderOutcomeAmbiguousError(
                _ambiguous_error("RAZORPAY_TEST_MODE_LOOKUP")
            ) from error
        if response.status_code != _HTTP_OK:
            self._raise_lookup_failure(response.status_code)
        payload = self._safe_json(response, ambiguous=False)
        try:
            collection = _RazorpayPaymentLinkCollection.model_validate(payload)
        except ValidationError as error:
            raise ProviderError(_upstream_error("RAZORPAY_LOOKUP_RESPONSE_INVALID")) from error
        exact = tuple(
            item for item in collection.payment_links if item.reference_id == reference_id
        )
        if not exact:
            return None
        if len(exact) != 1:
            raise ProviderError(_upstream_error("RAZORPAY_REFERENCE_NOT_UNIQUE"))
        return self._to_result(exact[0])

    async def aclose(self) -> None:
        """Release the bounded HTTP connection pool owned by this adapter."""

        await self._client.aclose()

    def _parse_single_response(
        self,
        response: httpx.Response,
        *,
        expected_reference_id: str,
    ) -> PaymentLinkResult:
        payload = self._safe_json(response, ambiguous=True)
        try:
            link = _RazorpayPaymentLink.model_validate(payload)
        except ValidationError as error:
            raise ProviderOutcomeAmbiguousError(
                _ambiguous_error("RAZORPAY_CREATE_RESPONSE_INVALID")
            ) from error
        if link.reference_id != expected_reference_id:
            raise ProviderOutcomeAmbiguousError(
                _ambiguous_error("RAZORPAY_CREATE_REFERENCE_MISMATCH")
            )
        return self._to_result(link)

    def _to_result(self, link: _RazorpayPaymentLink) -> PaymentLinkResult:
        try:
            created_at = datetime.fromtimestamp(link.created_at, tz=UTC)
        except (OverflowError, OSError, ValueError) as error:
            raise ProviderError(_upstream_error("RAZORPAY_CREATED_AT_INVALID")) from error
        return PaymentLinkResult(
            provider_action_id=link.id,
            reference_id=link.reference_id,
            status=link.status,
            amount_subunits=link.amount,
            currency=link.currency,
            short_url=link.short_url,
            provider_created_at=created_at,
            verified_at=self._clock_utc(),
            synthetic=True,
        )

    @staticmethod
    def _safe_json(response: httpx.Response, *, ambiguous: bool) -> Any:
        if len(response.content) > _MAX_PROVIDER_RESPONSE_BYTES:
            if ambiguous:
                raise ProviderOutcomeAmbiguousError(
                    _ambiguous_error("RAZORPAY_RESPONSE_TOO_LARGE")
                )
            raise ProviderError(_upstream_error("RAZORPAY_RESPONSE_TOO_LARGE"))
        try:
            return response.json()
        except ValueError as error:
            if ambiguous:
                raise ProviderOutcomeAmbiguousError(
                    _ambiguous_error("RAZORPAY_RESPONSE_NOT_JSON")
                ) from error
            raise ProviderError(_upstream_error("RAZORPAY_RESPONSE_NOT_JSON")) from error

    @staticmethod
    def _raise_create_failure(status_code: int) -> None:
        if status_code in {400, 404, 409, 422}:
            raise ProviderError(
                _known_error(
                    RecoveryActionErrorCategory.INVALID_INPUT,
                    "RAZORPAY_CREATE_INVALID_INPUT",
                    retry_permitted=False,
                )
            )
        if status_code in {401, 403}:
            raise ProviderError(
                _known_error(
                    RecoveryActionErrorCategory.UNAUTHORIZED,
                    "RAZORPAY_TEST_MODE_UNAUTHORIZED",
                    retry_permitted=False,
                )
            )
        if status_code == _HTTP_TOO_MANY_REQUESTS:
            raise ProviderError(
                _known_error(
                    RecoveryActionErrorCategory.RATE_LIMITED,
                    "RAZORPAY_RATE_LIMITED",
                    retry_permitted=True,
                )
            )
        raise ProviderOutcomeAmbiguousError(_ambiguous_error("RAZORPAY_CREATE_AMBIGUOUS"))

    @staticmethod
    def _raise_lookup_failure(status_code: int) -> None:
        if status_code in {401, 403}:
            raise ProviderError(
                _known_error(
                    RecoveryActionErrorCategory.UNAUTHORIZED,
                    "RAZORPAY_TEST_MODE_UNAUTHORIZED",
                    retry_permitted=False,
                )
            )
        if status_code == _HTTP_TOO_MANY_REQUESTS:
            raise ProviderError(
                _known_error(
                    RecoveryActionErrorCategory.RATE_LIMITED,
                    "RAZORPAY_LOOKUP_RATE_LIMITED",
                    retry_permitted=True,
                )
            )
        raise ProviderOutcomeAmbiguousError(
            _ambiguous_error("RAZORPAY_LOOKUP_UNAVAILABLE")
        )

    def _clock_utc(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            msg = "Razorpay adapter clock must be timezone-aware"
            raise ValueError(msg)
        return now.astimezone(UTC)


def _scenario_error(scenario: FakeProviderScenario) -> RecoveryActionError | None:
    values = {
        FakeProviderScenario.INVALID_INPUT: (
            RecoveryActionErrorCategory.INVALID_INPUT,
            "FAKE_PROVIDER_INVALID_INPUT",
            False,
            False,
        ),
        FakeProviderScenario.UNAUTHORIZED: (
            RecoveryActionErrorCategory.UNAUTHORIZED,
            "FAKE_PROVIDER_UNAUTHORIZED",
            False,
            False,
        ),
        FakeProviderScenario.RATE_LIMITED: (
            RecoveryActionErrorCategory.RATE_LIMITED,
            "FAKE_PROVIDER_RATE_LIMITED",
            True,
            False,
        ),
        FakeProviderScenario.UPSTREAM_FAILURE: (
            RecoveryActionErrorCategory.UPSTREAM_FAILURE,
            "FAKE_PROVIDER_UPSTREAM_FAILURE",
            True,
            False,
        ),
        FakeProviderScenario.TIMEOUT_BEFORE_CREATE: (
            RecoveryActionErrorCategory.RECONCILIATION_REQUIRED,
            "FAKE_PROVIDER_OUTCOME_AMBIGUOUS",
            False,
            True,
        ),
    }.get(scenario)
    if values is None:
        return None
    category, reason_code, retry_permitted, reconciliation_required = values
    return RecoveryActionError(
        category=category,
        reason_code=reason_code,
        retry_permitted=retry_permitted,
        reconciliation_required=reconciliation_required,
    )


def _known_error(
    category: RecoveryActionErrorCategory,
    reason_code: str,
    *,
    retry_permitted: bool,
) -> RecoveryActionError:
    return RecoveryActionError(
        category=category,
        reason_code=reason_code,
        retry_permitted=retry_permitted,
        reconciliation_required=False,
    )


def _upstream_error(reason_code: str) -> RecoveryActionError:
    return _known_error(
        RecoveryActionErrorCategory.UPSTREAM_FAILURE,
        reason_code,
        retry_permitted=True,
    )


def _ambiguous_error(reason_prefix: str) -> RecoveryActionError:
    return RecoveryActionError(
        category=RecoveryActionErrorCategory.RECONCILIATION_REQUIRED,
        reason_code=f"{reason_prefix}_OUTCOME_AMBIGUOUS",
        retry_permitted=False,
        reconciliation_required=True,
    )


def _fake_provider_id(reference_id: str) -> str:
    return f"plink_fake_{hashlib.sha256(reference_id.encode()).hexdigest()}"
