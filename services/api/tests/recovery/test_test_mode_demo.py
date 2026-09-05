"""Human approval and credential-boundary tests for the one-link M5 demo."""

import asyncio
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy import func, select

from retryrail.db.migrate import upgrade_database
from retryrail.db.session import Database
from retryrail.db.tables import (
    ApprovalDecisionRecord,
    RecoveryActionRecord,
    RecoveryProviderDispatchRecord,
    RecoveryProviderReceiptRecord,
)
from retryrail.recovery import test_mode_demo
from retryrail.recovery.adapter import (
    DeterministicFakeRazorpayAdapter,
    FakeProviderScenario,
    PaymentLinkCreateRequest,
    PaymentLinkResult,
)
from retryrail.recovery.models import ProviderVerificationSource
from retryrail.recovery.test_mode_demo import (
    TestModeDemoError,
    _database_url,
    _read_razorpay_csv,
    _write_evidence,
    approval_challenge,
    prepare_demo,
    require_interactive_approval,
)


def test_credential_csv_is_parsed_without_exposing_values(tmp_path: Path) -> None:
    key_id = "rzp" + "_test_demo_id"
    key_secret = "unit-test-demo-secret"
    path = tmp_path / "razorpay.csv"
    path.write_text(
        f"Key Type,Value\nTest Key ID,{key_id}\nTest Key Secret,{key_secret}\n",
        encoding="utf-8",
    )

    parsed_id, parsed_secret = _read_razorpay_csv(path)

    assert isinstance(parsed_id, SecretStr)
    assert isinstance(parsed_secret, SecretStr)
    assert parsed_id.get_secret_value() == key_id
    assert parsed_secret.get_secret_value() == key_secret
    assert key_id not in repr(parsed_id)
    assert key_secret not in repr(parsed_secret)


@pytest.mark.parametrize(
    "content",
    [
        "Key Type,Value\nTest Key ID,not-test-mode\n",
        "unexpected,columns\none,two\n",
        "Key Type,Value\nTest Key ID,rzp_test_short\nTest Key Secret,\n",
        "Key Type,Value\nUnknown Key,rzp_test_short\nTest Key Secret,secret\n",
    ],
)
def test_credential_csv_rejects_unknown_or_incomplete_shapes(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "invalid.csv"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(TestModeDemoError):
        _read_razorpay_csv(path)


def test_human_approval_requires_an_interactive_exact_match() -> None:
    class _Plan:
        plan_id = "plan_0123456789abcdef"

    class _Preview:
        plan = _Plan()
        amount_subunits = 149_900
        currency = "INR"

    preview = _Preview()
    challenge = approval_challenge(preview)  # type: ignore[arg-type]

    require_interactive_approval(
        preview,  # type: ignore[arg-type]
        input_function=lambda _prompt: challenge,
        interactive=True,
    )
    with pytest.raises(TestModeDemoError, match="interactive"):
        require_interactive_approval(
            preview,  # type: ignore[arg-type]
            input_function=lambda _prompt: challenge,
            interactive=False,
        )
    with pytest.raises(TestModeDemoError, match="did not match"):
        require_interactive_approval(
            preview,  # type: ignore[arg-type]
            input_function=lambda _prompt: challenge.lower(),
            interactive=True,
        )


def test_prepare_creates_no_approval_action_dispatch_or_provider_call(tmp_path: Path) -> None:
    database_path = tmp_path / "m5-demo.sqlite3"
    upgrade_database(_database_url(database_path))

    prepared = asyncio.run(prepare_demo(database_path))

    assert prepared.execution_target == "razorpay_test_mode"
    assert prepared.external_notifications_enabled is False
    assert prepared.provider_reference_id.startswith("rr_")
    assert prepared.synthetic is True

    async def verify_no_authority_or_action() -> None:
        database = Database(_database_url(database_path))
        try:
            async with database.sessions() as session:
                for model in (
                    ApprovalDecisionRecord,
                    RecoveryActionRecord,
                    RecoveryProviderDispatchRecord,
                ):
                    assert await session.scalar(select(func.count()).select_from(model)) == 0
        finally:
            await database.dispose()

    asyncio.run(verify_no_authority_or_action())


class _ClosableFakeTestModeAdapter:
    """Exercise the CLI coordinator without crossing the real network boundary."""

    def __init__(self, scenario: FakeProviderScenario) -> None:
        self._provider = DeterministicFakeRazorpayAdapter(scenario=scenario)

    async def create_standard_payment_link(
        self,
        request: PaymentLinkCreateRequest,
    ) -> PaymentLinkResult:
        result = await self._provider.create_standard_payment_link(request)
        return self._with_test_mode_url(result)

    async def reconcile(self, reference_id: str) -> PaymentLinkResult | None:
        result = await self._provider.reconcile(reference_id)
        return self._with_test_mode_url(result) if result is not None else None

    async def aclose(self) -> None:
        return None

    @staticmethod
    def _with_test_mode_url(result: PaymentLinkResult) -> PaymentLinkResult:
        document = result.model_dump(mode="python")
        document["short_url"] = "https://rzp.io/i/retryrail-unit-test"
        return PaymentLinkResult.model_validate(document)


@pytest.mark.parametrize(
    ("scenario", "verification_source"),
    [
        (FakeProviderScenario.SUCCESS, ProviderVerificationSource.CREATE_RESPONSE),
        (
            FakeProviderScenario.TIMEOUT_AFTER_CREATE,
            ProviderVerificationSource.REFERENCE_LOOKUP,
        ),
    ],
)
def test_execute_demo_requires_the_full_authority_chain_and_exports_safe_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: FakeProviderScenario,
    verification_source: ProviderVerificationSource,
) -> None:
    database_path = tmp_path / f"m5-{scenario.value}.sqlite3"
    credential_path = tmp_path / "razorpay.csv"
    key_id = "rzp" + "_test_demo_id"
    credential_path.write_text(
        "Key Type,Value\n"
        f"Test Key ID,{key_id}\n"
        "Test Key Secret,unit-test-demo-secret\n",
        encoding="utf-8",
    )
    upgrade_database(_database_url(database_path))
    asyncio.run(prepare_demo(database_path))
    monkeypatch.setattr(
        test_mode_demo,
        "RazorpayTestModeAdapter",
        lambda **_kwargs: _ClosableFakeTestModeAdapter(scenario),
    )
    monkeypatch.setattr(
        test_mode_demo,
        "require_interactive_approval",
        lambda _preview: None,
    )

    evidence = asyncio.run(
        test_mode_demo.execute_demo(database_path, credential_path)
    )

    assert evidence.scope == "razorpay_test_mode_no_real_money"
    assert evidence.credentials_persisted is False
    assert evidence.raw_provider_response_persisted is False
    assert evidence.external_notifications_enabled is False
    assert evidence.audit.complete is True
    assert evidence.provider_receipt.verification_source is verification_source
    monkeypatch.setattr(test_mode_demo, "_REPOSITORY_ROOT", tmp_path)
    evidence_path = _write_evidence(evidence)
    assert evidence_path == tmp_path / "evals/reports/razorpay_test_mode_receipt.v1.json"
    assert _write_evidence(evidence) == evidence_path

    async def verify_durable_chain() -> None:
        database = Database(_database_url(database_path))
        try:
            async with database.sessions() as session:
                for model in (
                    ApprovalDecisionRecord,
                    RecoveryActionRecord,
                    RecoveryProviderDispatchRecord,
                    RecoveryProviderReceiptRecord,
                ):
                    assert await session.scalar(select(func.count()).select_from(model)) == 1
        finally:
            await database.dispose()

    asyncio.run(verify_durable_chain())
