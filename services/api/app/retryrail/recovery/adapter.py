"""Deterministic provider boundary used by M4 recovery integration tests."""

import asyncio
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from pydantic import AwareDatetime, Field

from retryrail.contracts.domain import StrictContract
from retryrail.contracts.recovery import (
    RecoveryActionError,
    RecoveryActionErrorCategory,
)
from retryrail.events.models import Currency, Identifier


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class PaymentLinkCreateRequest(StrictContract):
    """Allowlisted provider request with no contact details or notification path."""

    amount_subunits: int = Field(gt=0, le=100_000_000_000)
    currency: Currency
    reference_id: Identifier
    external_notifications_enabled: bool = False
    synthetic: bool


class PaymentLinkResult(StrictContract):
    """Redacted, provider-independent creation or reconciliation result."""

    provider_action_id: Identifier
    reference_id: Identifier
    verified_at: AwareDatetime
    synthetic: bool


class RecoveryProvider(Protocol):
    """Small interface implemented by the fake now and Razorpay Test Mode in M5."""

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

            result = PaymentLinkResult(
                provider_action_id=_fake_provider_id(request.reference_id),
                reference_id=request.reference_id,
                verified_at=self._clock_utc(),
                synthetic=True,
            )
            self._by_reference[request.reference_id] = result
            if self._scenario is FakeProviderScenario.TIMEOUT_AFTER_CREATE:
                raise ProviderOutcomeAmbiguousError(_ambiguous_error())
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


def _ambiguous_error() -> RecoveryActionError:
    return RecoveryActionError(
        category=RecoveryActionErrorCategory.RECONCILIATION_REQUIRED,
        reason_code="FAKE_PROVIDER_OUTCOME_AMBIGUOUS",
        retry_permitted=False,
        reconciliation_required=True,
    )


def _fake_provider_id(reference_id: str) -> str:
    return f"plink_fake_{hashlib.sha256(reference_id.encode()).hexdigest()}"
