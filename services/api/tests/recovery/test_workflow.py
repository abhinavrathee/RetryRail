"""M4.3 authoritative preview, approval and bearer-misuse integration tests."""

import asyncio
import hashlib
import hmac
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from pydantic import SecretStr, ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from retryrail.config import Settings
from retryrail.contracts.domain import CohortDimension
from retryrail.contracts.recovery import ApprovalDecision, ApprovalStatus
from retryrail.db.session import Database
from retryrail.db.tables import (
    ApprovalDecisionRecord,
    ApprovalTokenConsumptionRecord,
    IncidentRecord,
    PaymentEventRecord,
    PaymentProjectionRecord,
    PaymentRecoveryControlRecord,
    PolicyResultRecord,
    RecoveryActionRecord,
    RecoveryActionTransitionRecord,
    RecoveryPlanRecord,
    RulesBasedIncidentBriefRecord,
)
from retryrail.detection.models import (
    AttributionItem,
    DetectorGateReason,
    DetectorStatistics,
    DiagnosisHypothesis,
    DiagnosisSnapshot,
)
from retryrail.detection.v4_config import detector_v4_config_sha256
from retryrail.events.models import (
    ErrorEvidence,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.main import create_app
from retryrail.observability.metrics import PipelineMetrics
from retryrail.recovery.adapter import (
    DeterministicFakeRazorpayAdapter,
    FakeProviderScenario,
)
from retryrail.recovery.audit import RecoveryAuditVerifier
from retryrail.recovery.execution import RecoveryExecutionService
from retryrail.recovery.models import (
    ApprovalDecisionResponse,
    ApprovalTokenBinding,
    RecoveryExecutionResponse,
    RecoveryPlanPreview,
)
from retryrail.recovery.workflow import (
    ApprovalActorError,
    ApprovalTokenAlreadyUsedError,
    ApprovalTokenExpiredError,
    ApprovalTokenInvalidError,
    MerchantScopeError,
    PlanExpiredError,
    RecoveryEvidenceInvalidError,
    RecoveryIdempotencyConflictError,
    RecoveryWorkflowService,
)

if TYPE_CHECKING:
    from fastapi import FastAPI

_AUTHORIZATION = {"X-RetryRail-Merchant-Authorization": "unit-test-merchant-approval-secret-value"}
_BASE_TIME = datetime(2026, 9, 4, 8, 0, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _SeededCase:
    incident_id: str
    payment_id: str


@dataclass(frozen=True, slots=True)
class _DeniedPreviewCase:
    recovery_mode: Literal["analyze_only", "review_first"] = "review_first"
    kill_switch: bool = False
    action_eligible: bool = True
    customer_opted_out: bool = False
    already_recovered: bool = False
    prior_action_attempts: int = 0
    incident_status: str = "open"
    denied_rule: str = "incident_action_eligibility"


async def _seed_case(
    settings: Settings,
    *,
    suffix: str = "001",
    action_eligible: bool = True,
    incident_status: str = "open",
    payment_status: PaymentStatus = PaymentStatus.FAILED,
    customer_opted_out: bool = False,
    already_recovered: bool = False,
    prior_action_attempts: int = 0,
    last_action_at: datetime | None = None,
    include_controls: bool = True,
    synthetic: bool = True,
    cohort_source: str = "bank",
    source_amount_subunits: int = 12_345,
    invalid_cohort: bool = False,
    detector_config_digest: str | None = None,
) -> _SeededCase:
    database = Database(settings.database_dsn())
    incident_id = f"incident_recovery_{suffix}"
    payment_id = f"pay_recovery_{suffix}"
    event_id = f"event_recovery_{suffix}"
    internal_id = f"00000000-0000-0000-0000-{int(suffix):012d}"
    event_type = (
        PaymentEventType.FAILED
        if payment_status is PaymentStatus.FAILED
        else PaymentEventType.CAPTURED
    )
    error = (
        ErrorEvidence(
            code="BAD_GATEWAY",
            source="bank",
            step="authorization",
            reason="temporarily_unavailable",
        )
        if payment_status is PaymentStatus.FAILED
        else None
    )
    normalized = NormalizedPaymentEvent(
        merchant_id=settings.merchant_id,
        razorpay_event_id=event_id,
        event_type=event_type,
        occurred_at=_BASE_TIME,
        received_at=_BASE_TIME + timedelta(seconds=1),
        synthetic=synthetic,
        payment=PaymentSnapshot(
            payment_id=payment_id,
            status=payment_status,
            amount_subunits=source_amount_subunits,
            currency="INR",
            method=PaymentMethod.CARD,
            issuer="issuer_synthetic_alpha",
            error=error,
        ),
    )
    try:
        async with database.sessions() as session, session.begin():
            session.add(
                PaymentEventRecord(
                    internal_id=internal_id,
                    merchant_id=settings.merchant_id,
                    razorpay_event_id=event_id,
                    schema_version="1.0.0",
                    signature_status="verified",
                    event_type=event_type.value,
                    payment_id=payment_id,
                    occurred_at=normalized.occurred_at,
                    received_at=normalized.received_at,
                    payload_sha256=hashlib.sha256(event_id.encode()).hexdigest(),
                    sanitized_payload={"synthetic": synthetic},
                    normalized_event=normalized.model_dump(mode="json"),
                    synthetic=synthetic,
                    created_at=_BASE_TIME + timedelta(seconds=1),
                )
            )
            await session.flush()
            rank = 1 if payment_status is PaymentStatus.FAILED else 3
            session.add(
                PaymentProjectionRecord(
                    merchant_id=settings.merchant_id,
                    payment_id=payment_id,
                    status=payment_status.value,
                    state_rank=rank,
                    amount_subunits=12_345,
                    currency="INR",
                    method=PaymentMethod.CARD.value,
                    issuer="issuer_synthetic_alpha",
                    synthetic=synthetic,
                    last_event_internal_id=internal_id,
                    state_changed_at=_BASE_TIME,
                    last_processed_at=_BASE_TIME + timedelta(seconds=2),
                    version=1,
                )
            )
            await session.flush()
            if include_controls:
                session.add(
                    PaymentRecoveryControlRecord(
                        merchant_id=settings.merchant_id,
                        payment_id=payment_id,
                        contact_consent_verified=False,
                        customer_opted_out=customer_opted_out,
                        already_recovered=already_recovered,
                        prior_action_attempts=prior_action_attempts,
                        last_action_at=last_action_at,
                        source="synthetic_fixture_default",
                        version=1,
                        updated_at=_BASE_TIME + timedelta(seconds=2),
                    )
                )
            resolved_at = (
                _BASE_TIME + timedelta(minutes=15) if incident_status == "resolved" else None
            )
            session.add(
                IncidentRecord(
                    incident_id=incident_id,
                    merchant_id=settings.merchant_id,
                    detector_version="detector_v4_0_0",
                    detector_config_sha256=(
                        detector_config_digest or detector_v4_config_sha256()
                    ),
                    detector_cohort_key=f"cohort_recovery_{suffix}",
                    detector_cohort=[{"dimension": "method", "value": "card"}],
                    affected_cohort=(
                        [{"dimension": "unsupported", "value": "card"}]
                        if invalid_cohort
                        else [
                            {"dimension": "method", "value": "card"},
                            {"dimension": "error_source", "value": cohort_source},
                        ]
                    ),
                    status=incident_status,
                    opened_at=_BASE_TIME,
                    last_observed_at=_BASE_TIME + timedelta(minutes=10),
                    resolved_at=resolved_at,
                    peak_statistics={"synthetic": True},
                    diagnosis={"synthetic": True},
                    evidence_event_ids=[internal_id],
                    gmv_at_risk_subunits=12_345,
                    currency="INR",
                    action_eligible=action_eligible,
                    synthetic=synthetic,
                    created_at=_BASE_TIME,
                    updated_at=_BASE_TIME,
                )
            )
    finally:
        await database.dispose()
    return _SeededCase(incident_id=incident_id, payment_id=payment_id)


async def _seed_valid_analysis_evidence(
    settings: Settings,
    seeded: _SeededCase,
) -> None:
    database = Database(settings.database_dsn())
    try:
        async with database.sessions() as session, session.begin():
            incident = await session.get(IncidentRecord, seeded.incident_id)
            assert incident is not None
            event_ids = tuple(incident.evidence_event_ids)
            statistics = DetectorStatistics(
                evaluated_at=_BASE_TIME + timedelta(minutes=10),
                current_window_minutes=10,
                current_started_at=_BASE_TIME,
                baseline_started_at=_BASE_TIME - timedelta(hours=2),
                baseline_ended_at=_BASE_TIME - timedelta(minutes=10),
                baseline_attempts=100,
                baseline_successes=95,
                baseline_failures=5,
                current_attempts=20,
                current_successes=10,
                current_failures=10,
                baseline_failure_rate_bps=500,
                current_failure_rate_bps=5_000,
                success_rate_drop_bps=4_500,
                confidence_ppm=990_000,
                ewma_failure_rate_bps=4_000,
                ewma_drop_bps=3_500,
                cusum_milli=90_000,
                excess_failures=9,
                at_risk_gmv_subunits=12_345,
                currency="INR",
                gate_reason=DetectorGateReason.PASSED,
                minimum_current_attempts=20,
                baseline_minimum_attempts=50,
                minimum_current_failures=5,
                minimum_success_rate_drop_bps=1_000,
                confidence_threshold_ppm=950_000,
                ewma_drop_threshold_bps=1_000,
                cusum_threshold_milli=10_000,
                minimum_excess_failures=3,
                minimum_at_risk_gmv_subunits=5_000,
            )
            diagnosis = DiagnosisSnapshot(
                verified_attributions=(
                    AttributionItem(
                        dimension=CohortDimension.ERROR_SOURCE,
                        value="bank",
                        rank=1,
                        current_attempts=20,
                        current_failures=10,
                        baseline_attempts=100,
                        baseline_failures=5,
                        expected_failures_milli=1_000,
                        excess_failures_milli=9_000,
                        contribution_ppm=900_000,
                        confidence_ppm=990_000,
                        evidence_event_ids=event_ids,
                    ),
                ),
                hypotheses=(
                    DiagnosisHypothesis(
                        statement=(
                            "Merchant-local evidence is consistent with elevated bank "
                            "authorization failures."
                        ),
                        confidence_ppm=900_000,
                        evidence_event_ids=event_ids,
                    ),
                ),
                unknowns=("External issuer health is not independently verified.",),
                likely_causes=("bank",),
            )
            incident.peak_statistics = statistics.model_dump(mode="json")
            incident.diagnosis = diagnosis.model_dump(mode="json")
    finally:
        await database.dispose()


def _create_preview(
    client: TestClient,
    seeded: _SeededCase,
    *,
    idempotency_key: str = "preview_request_001",
) -> Response:
    return client.post(
        f"/api/v1/incidents/{seeded.incident_id}/plans",
        headers=_AUTHORIZATION,
        json={
            "payment_id": seeded.payment_id,
            "idempotency_key": idempotency_key,
        },
    )


def _preview_and_approve(
    client: TestClient,
    seeded: _SeededCase,
    *,
    prefix: str,
) -> tuple[RecoveryPlanPreview, str]:
    preview_response = _create_preview(
        client,
        seeded,
        idempotency_key=f"{prefix}_preview",
    )
    assert preview_response.status_code == 200
    preview = RecoveryPlanPreview.model_validate(preview_response.json()["preview"])
    approval = client.post(
        f"/api/v1/plans/{preview.plan.plan_id}/approve",
        headers=_AUTHORIZATION,
        json={"idempotency_key": f"{prefix}_approval"},
    )
    assert approval.status_code == 200
    token = approval.json()["approval_token"]
    assert isinstance(token, str)
    return preview, token


def _assert_terminal_reconciliation_rejected(client: TestClient, action_id: str) -> None:
    path = f"/api/v1/actions/{action_id}/reconcile"
    unauthenticated = client.post(
        path,
        json={"idempotency_key": "terminal_action_reconcile_unauthenticated"},
    )
    terminal = client.post(
        path,
        headers=_AUTHORIZATION,
        json={"idempotency_key": "terminal_action_reconcile"},
    )
    assert unauthenticated.status_code == 401
    assert terminal.status_code == 409
    assert terminal.json()["detail"]["reason_code"] == "RECOVERY_ACTION_NOT_RECONCILIABLE"


async def _assert_preview_storage(settings: Settings) -> None:
    database = Database(settings.database_dsn())
    try:
        async with database.sessions() as session:
            assert await session.scalar(select(func.count()).select_from(RecoveryPlanRecord)) == 1
            assert await session.scalar(select(func.count()).select_from(PolicyResultRecord)) == 1
        async with database.sessions() as session:
            with pytest.raises(SQLAlchemyError, match="immutable"):
                await session.execute(
                    text("UPDATE recovery_plans SET plan_sha256 = :digest"),
                    {"digest": "0" * 64},
                )
            await session.rollback()
        async with database.sessions() as session:
            with pytest.raises(SQLAlchemyError, match="immutable"):
                await session.execute(text("DELETE FROM policy_results"))
    finally:
        await database.dispose()


def test_preview_is_authoritative_complete_immutable_and_idempotent(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings))
    request = {
        "payment_id": seeded.payment_id,
        "idempotency_key": "preview_request_001",
    }

    missing_auth = client.post(
        f"/api/v1/incidents/{seeded.incident_id}/plans",
        json=request,
    )
    wrong_auth = client.post(
        f"/api/v1/incidents/{seeded.incident_id}/plans",
        headers={"X-RetryRail-Merchant-Authorization": "wrong"},
        json=request,
    )
    caller_fact_injection = client.post(
        f"/api/v1/incidents/{seeded.incident_id}/plans",
        headers=_AUTHORIZATION,
        json={**request, "amount_subunits": 1, "merchant_kill_switch": False},
    )
    first = _create_preview(client, seeded)
    replayed = _create_preview(client, seeded)

    assert missing_auth.status_code == wrong_auth.status_code == 401
    assert missing_auth.json()["detail"]["reason_code"] == "MERCHANT_AUTHENTICATION_FAILED"
    assert caller_fact_injection.status_code == 422
    assert first.status_code == replayed.status_code == 200
    assert first.json()["disposition"] == "created"
    assert replayed.json()["disposition"] == "replayed"
    assert first.json()["preview"] == replayed.json()["preview"]

    preview = first.json()["preview"]
    plan_id = preview["plan"]["plan_id"]
    assert preview["amount_subunits"] == 12_345
    assert preview["currency"] == "INR"
    assert preview["effect"] == "create_standard_payment_link"
    assert preview["external_notifications_enabled"] is False
    assert preview["execution_target"] == "deterministic_fake"
    assert preview["preview_policy_allowed"] is True
    assert len(preview["source_evidence_sha256"]) == 64
    assert preview["source_evidence"]["merchant_id"] == settings.merchant_id
    assert preview["source_evidence"]["incident_id"] == seeded.incident_id
    assert preview["source_evidence"]["payment_id"] == seeded.payment_id
    assert preview["source_evidence"]["source_event_internal_id"].endswith("000001")
    assert preview["source_evidence"]["payment_projection_version"] == 1
    assert preview["source_evidence"]["recovery_control_version"] == 1
    assert preview["source_evidence"]["detector_version"] == "detector_v4_0_0"
    assert preview["policy_result"]["decision"] == "allow"
    assert len(preview["policy_result"]["rule_results"]) == 13
    context = preview["policy_result"]["context"]
    assert context["source_amount_subunits"] == context["proposed_amount_subunits"]
    assert context["source_currency"] == context["proposed_currency"] == "INR"
    assert context["contact_required"] is False
    assert context["contact_consent_verified"] is False
    assert context["customer_opted_out"] is False

    retrieved = client.post(
        f"/api/v1/plans/{plan_id}/preview",
        headers=_AUTHORIZATION,
    )
    assert retrieved.status_code == 200
    assert retrieved.json()["disposition"] == "retrieved"
    assert retrieved.json()["preview"] == preview

    asyncio.run(_assert_preview_storage(settings))


def test_preview_rejects_idempotency_rebinding_and_ineligible_sources(
    settings: Settings,
    client: TestClient,
) -> None:
    eligible = asyncio.run(_seed_case(settings, suffix="011"))
    other = asyncio.run(_seed_case(settings, suffix="012"))
    mismatch = asyncio.run(_seed_case(settings, suffix="013", cohort_source="gateway"))
    captured = asyncio.run(
        _seed_case(settings, suffix="014", payment_status=PaymentStatus.CAPTURED)
    )
    missing_controls = asyncio.run(
        _seed_case(
            settings,
            suffix="015",
            include_controls=False,
            synthetic=False,
        )
    )

    assert (
        _create_preview(
            client,
            eligible,
            idempotency_key="shared_preview_key",
        ).status_code
        == 200
    )
    rebound = _create_preview(
        client,
        other,
        idempotency_key="shared_preview_key",
    )
    outside_cohort = _create_preview(client, mismatch, idempotency_key="mismatch_key")
    nonfailed = _create_preview(client, captured, idempotency_key="captured_key")
    no_controls = _create_preview(
        client,
        missing_controls,
        idempotency_key="missing_controls_key",
    )

    assert rebound.status_code == 409
    assert rebound.json()["detail"]["reason_code"] == "RECOVERY_IDEMPOTENCY_CONFLICT"
    assert outside_cohort.status_code == 409
    assert outside_cohort.json()["detail"]["reason_code"] == ("PAYMENT_NOT_ELIGIBLE_FOR_INCIDENT")
    assert nonfailed.status_code == 409
    assert no_controls.status_code == 409
    assert no_controls.json()["detail"]["reason_code"] == "RECOVERY_CONTROLS_MISSING"


@pytest.mark.parametrize(
    "case",
    [
        _DeniedPreviewCase(action_eligible=False),
        _DeniedPreviewCase(
            recovery_mode="analyze_only",
            denied_rule="operating_mode",
        ),
        _DeniedPreviewCase(kill_switch=True, denied_rule="kill_switch"),
        _DeniedPreviewCase(
            customer_opted_out=True,
            denied_rule="customer_opt_out",
        ),
        _DeniedPreviewCase(
            already_recovered=True,
            denied_rule="already_recovered",
        ),
        _DeniedPreviewCase(
            prior_action_attempts=1,
            denied_rule="attempt_cap",
        ),
        _DeniedPreviewCase(incident_status="resolved"),
    ],
)
def test_denied_authoritative_preview_cannot_be_approved(
    settings: Settings,
    case: _DeniedPreviewCase,
) -> None:
    configured = settings.model_copy(
        update={
            "recovery_mode": case.recovery_mode,
            "recovery_kill_switch": case.kill_switch,
        }
    )
    seeded = asyncio.run(
        _seed_case(
            configured,
            suffix="021",
            action_eligible=case.action_eligible,
            customer_opted_out=case.customer_opted_out,
            already_recovered=case.already_recovered,
            prior_action_attempts=case.prior_action_attempts,
            incident_status=case.incident_status,
        )
    )
    with TestClient(create_app(configured)) as client:
        preview_response = _create_preview(client, seeded, idempotency_key="denied_preview")
        preview = preview_response.json()["preview"]
        approve = client.post(
            f"/api/v1/plans/{preview['plan']['plan_id']}/approve",
            headers=_AUTHORIZATION,
            json={"idempotency_key": "denied_approval"},
        )

    assert preview_response.status_code == 200
    assert preview["policy_result"]["decision"] == "deny"
    outcomes = {item["rule"]: item["outcome"] for item in preview["policy_result"]["rule_results"]}
    assert outcomes[case.denied_rule] == "deny"
    assert approve.status_code == 409
    assert approve.json()["detail"]["reason_code"] == "RECOVERY_PLAN_POLICY_DENIED"


def test_approval_delivers_bearer_once_and_persists_only_keyed_hash(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="031"))
    preview = _create_preview(client, seeded, idempotency_key="approval_preview").json()["preview"]
    plan_id = preview["plan"]["plan_id"]

    first = client.post(
        f"/api/v1/plans/{plan_id}/approve",
        headers=_AUTHORIZATION,
        json={"idempotency_key": "approval_decision_001"},
    )
    replayed = client.post(
        f"/api/v1/plans/{plan_id}/approve",
        headers=_AUTHORIZATION,
        json={"idempotency_key": "approval_decision_001"},
    )
    second_decision = client.post(
        f"/api/v1/plans/{plan_id}/reject",
        headers=_AUTHORIZATION,
        json={"idempotency_key": "approval_decision_002"},
    )
    rebound_decision = client.post(
        f"/api/v1/plans/{plan_id}/reject",
        headers=_AUTHORIZATION,
        json={"idempotency_key": "approval_decision_001"},
    )

    assert first.status_code == replayed.status_code == 200
    first_body = first.json()
    raw_token = first_body["approval_token"]
    assert first_body["disposition"] == "created"
    assert first_body["token_delivery"] == "issued_once"
    assert raw_token.startswith("rr_apv_")
    assert len(raw_token) == 50
    assert "token_hash" not in first_body["approval"]
    assert replayed.json()["disposition"] == "replayed"
    assert replayed.json()["approval_token"] is None
    assert replayed.json()["token_delivery"] == "not_repeated"
    assert second_decision.status_code == 409
    assert second_decision.json()["detail"]["reason_code"] == ("RECOVERY_PLAN_ALREADY_DECIDED")
    assert rebound_decision.status_code == 409
    assert rebound_decision.json()["detail"]["reason_code"] == ("RECOVERY_IDEMPOTENCY_CONFLICT")

    async def assert_hash_only() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                record = await session.scalar(select(ApprovalDecisionRecord))
                assert record is not None
                expected = hmac.new(
                    settings.approval_token_hmac_key.get_secret_value().encode(),
                    raw_token.encode(),
                    hashlib.sha256,
                ).hexdigest()
                assert record.token_hash == expected
                assert raw_token != record.token_hash
                durable_text = json.dumps(
                    {
                        "approval": {
                            column.name: getattr(record, column.name)
                            for column in ApprovalDecisionRecord.__table__.columns
                            if column.name
                            not in {
                                "decided_at",
                                "issued_at",
                                "expires_at",
                                "created_at",
                            }
                        },
                        "plan": preview,
                    },
                    default=str,
                )
                assert raw_token not in durable_text
            async with database.sessions() as session:
                with pytest.raises(SQLAlchemyError, match="immutable"):
                    await session.execute(
                        text("UPDATE approval_decisions SET actor_id = 'merchant_other'")
                    )
        finally:
            await database.dispose()

    asyncio.run(assert_hash_only())


def test_rejection_is_token_free_terminal_and_idempotent(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="041"))
    preview = _create_preview(client, seeded, idempotency_key="reject_preview").json()["preview"]
    plan_id = preview["plan"]["plan_id"]
    body = {"idempotency_key": "reject_decision_001"}

    first = client.post(
        f"/api/v1/plans/{plan_id}/reject",
        headers=_AUTHORIZATION,
        json=body,
    )
    replayed = client.post(
        f"/api/v1/plans/{plan_id}/reject",
        headers=_AUTHORIZATION,
        json=body,
    )

    assert first.status_code == replayed.status_code == 200
    assert first.json()["approval"]["decision"] == "reject"
    assert first.json()["approval"]["status"] == "rejected"
    assert first.json()["approval_token"] is None
    assert replayed.json()["approval_token"] is None

    async def assert_no_token() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                record = await session.scalar(select(ApprovalDecisionRecord))
                assert record is not None
                assert record.token_hash is None
                assert record.issued_at is None
                assert record.expires_at is None
        finally:
            await database.dispose()

    asyncio.run(assert_no_token())


def test_token_binding_and_atomic_single_use(settings: Settings) -> None:
    async def exercise() -> None:
        seeded = await _seed_case(settings, suffix="051")
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        current = [_BASE_TIME + timedelta(hours=1)]
        raw_token = f"rr_apv_{'A' * 43}"
        service = RecoveryWorkflowService(
            database,
            settings,
            metrics,
            clock=lambda: current[0],
            token_factory=lambda: raw_token,
        )
        try:
            preview_response = await service.create_preview(
                merchant_id=settings.merchant_id,
                incident_id=seeded.incident_id,
                payment_id=seeded.payment_id,
                idempotency_key="consume_preview_001",
            )
            preview = preview_response.preview
            await service.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key="consume_approval_001",
            )
            binding = ApprovalTokenBinding(
                merchant_id=settings.merchant_id,
                incident_id=seeded.incident_id,
                plan_id=preview.plan.plan_id,
                policy_result_id=preview.policy_result.policy_result_id,
                plan_sha256=preview.plan_sha256,
                policy_result_sha256=preview.policy_result_sha256,
                consumption_idempotency_key="consume_action_001",
            )
            with pytest.raises(ApprovalTokenInvalidError):
                await service.consume_approval_token(raw_token=None, binding=binding)
            with pytest.raises(ApprovalTokenInvalidError):
                await service.consume_approval_token(
                    raw_token=f"rr_apv_{'B' * 43}",
                    binding=binding,
                )
            with pytest.raises(ApprovalTokenInvalidError):
                await service.consume_approval_token(
                    raw_token=raw_token,
                    binding=binding.model_copy(update={"plan_sha256": "0" * 64}),
                )

            results = await asyncio.gather(
                service.consume_approval_token(raw_token=raw_token, binding=binding),
                service.consume_approval_token(raw_token=raw_token, binding=binding),
                return_exceptions=True,
            )
            successes = [item for item in results if not isinstance(item, BaseException)]
            failures = [item for item in results if isinstance(item, BaseException)]
            assert len(successes) == 1
            assert successes[0].status is ApprovalStatus.CONSUMED
            assert len(failures) == 1
            assert isinstance(failures[0], ApprovalTokenAlreadyUsedError)
            with pytest.raises(ApprovalTokenAlreadyUsedError):
                await service.consume_approval_token(raw_token=raw_token, binding=binding)

            async with database.sessions() as session:
                assert (
                    await session.scalar(
                        select(func.count()).select_from(ApprovalTokenConsumptionRecord)
                    )
                    == 1
                )
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_token_exact_expiry_is_rejected_and_visible_on_replay(settings: Settings) -> None:
    async def exercise() -> None:
        seeded = await _seed_case(settings, suffix="052")
        database = Database(settings.database_dsn())
        raw_token = f"rr_apv_{'C' * 43}"
        current = [_BASE_TIME + timedelta(hours=2)]
        service = RecoveryWorkflowService(
            database,
            settings,
            PipelineMetrics(),
            clock=lambda: current[0],
            token_factory=lambda: raw_token,
        )
        try:
            preview = (
                await service.create_preview(
                    merchant_id=settings.merchant_id,
                    incident_id=seeded.incident_id,
                    payment_id=seeded.payment_id,
                    idempotency_key="expired_preview_001",
                )
            ).preview
            approval = await service.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key="expired_approval_001",
            )
            expiry = approval.approval.expires_at
            assert expiry is not None
            current[0] = expiry
            replayed = await service.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key="expired_approval_001",
            )
            assert replayed.approval.status is ApprovalStatus.EXPIRED
            binding = ApprovalTokenBinding(
                merchant_id=settings.merchant_id,
                incident_id=seeded.incident_id,
                plan_id=preview.plan.plan_id,
                policy_result_id=preview.policy_result.policy_result_id,
                plan_sha256=preview.plan_sha256,
                policy_result_sha256=preview.policy_result_sha256,
                consumption_idempotency_key="expired_action_001",
            )
            with pytest.raises(ApprovalTokenExpiredError):
                await service.consume_approval_token(
                    raw_token=raw_token,
                    binding=binding,
                )
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_missing_resources_authentication_and_service_readiness_fail_closed(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="071"))
    missing_incident = client.post(
        "/api/v1/incidents/incident_missing_071/plans",
        headers=_AUTHORIZATION,
        json={"payment_id": seeded.payment_id, "idempotency_key": "missing_incident"},
    )
    missing_payment = client.post(
        f"/api/v1/incidents/{seeded.incident_id}/plans",
        headers=_AUTHORIZATION,
        json={"payment_id": "pay_missing_071", "idempotency_key": "missing_payment"},
    )
    missing_preview = client.post(
        "/api/v1/plans/plan_missing_071/preview",
        headers=_AUTHORIZATION,
    )
    missing_approval_plan = client.post(
        "/api/v1/plans/plan_missing_071/approve",
        headers=_AUTHORIZATION,
        json={"idempotency_key": "missing_approval_plan"},
    )
    preview = _create_preview(client, seeded, idempotency_key="auth_preview").json()["preview"]
    unauthenticated_approval = client.post(
        f"/api/v1/plans/{preview['plan']['plan_id']}/approve",
        json={"idempotency_key": "unauthenticated_approval"},
    )

    assert missing_incident.status_code == missing_payment.status_code == 404
    assert missing_incident.json()["detail"]["reason_code"] == "INCIDENT_NOT_FOUND"
    assert missing_payment.json()["detail"]["reason_code"] == "PAYMENT_NOT_FOUND"
    assert missing_preview.status_code == missing_approval_plan.status_code == 404
    assert unauthenticated_approval.status_code == 401

    application = cast("FastAPI", client.app)
    original = application.state.recovery_workflow_service
    application.state.recovery_workflow_service = None
    try:
        unavailable = client.post(
            f"/api/v1/plans/{preview['plan']['plan_id']}/preview",
            headers=_AUTHORIZATION,
        )
    finally:
        application.state.recovery_workflow_service = original
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"]["reason_code"] == "SERVICE_NOT_READY"


def test_plan_expiry_actor_scope_naive_clock_and_invalid_token_factory_fail_closed(
    settings: Settings,
) -> None:
    async def exercise() -> None:
        seeded = await _seed_case(settings, suffix="081")
        database = Database(settings.database_dsn())
        current = [_BASE_TIME + timedelta(hours=3)]
        service = RecoveryWorkflowService(
            database,
            settings,
            PipelineMetrics(),
            clock=lambda: current[0],
            token_factory=lambda: "invalid-token",
        )
        try:
            with pytest.raises(MerchantScopeError):
                await service.create_preview(
                    merchant_id="merchant_other_081",
                    incident_id=seeded.incident_id,
                    payment_id=seeded.payment_id,
                    idempotency_key="scope_preview",
                )
            preview = (
                await service.create_preview(
                    merchant_id=settings.merchant_id,
                    incident_id=seeded.incident_id,
                    payment_id=seeded.payment_id,
                    idempotency_key="expiry_preview",
                )
            ).preview
            with pytest.raises(ApprovalActorError):
                await service.decide(
                    merchant_id=settings.merchant_id,
                    plan_id=preview.plan.plan_id,
                    actor_id="merchant_other_actor",
                    decision=ApprovalDecision.APPROVE,
                    idempotency_key="wrong_actor",
                )
            with pytest.raises(RecoveryEvidenceInvalidError):
                await service.decide(
                    merchant_id=settings.merchant_id,
                    plan_id=preview.plan.plan_id,
                    actor_id=settings.merchant_approver_id,
                    decision=ApprovalDecision.APPROVE,
                    idempotency_key="invalid_token_factory",
                )
            current[0] = preview.plan.stopping_rules.expires_at
            with pytest.raises(PlanExpiredError):
                await service.decide(
                    merchant_id=settings.merchant_id,
                    plan_id=preview.plan.plan_id,
                    actor_id=settings.merchant_approver_id,
                    decision=ApprovalDecision.APPROVE,
                    idempotency_key="expired_plan",
                )
        finally:
            await database.dispose()

        naive_database = Database(settings.database_dsn())
        naive_service = RecoveryWorkflowService(
            naive_database,
            settings,
            PipelineMetrics(),
            clock=lambda: _BASE_TIME.replace(tzinfo=None),
        )
        try:
            with pytest.raises(RecoveryEvidenceInvalidError):
                await naive_service.create_preview(
                    merchant_id=settings.merchant_id,
                    incident_id=seeded.incident_id,
                    payment_id=seeded.payment_id,
                    idempotency_key="naive_clock_preview",
                )
        finally:
            await naive_database.dispose()

    asyncio.run(exercise())


def test_response_contracts_reject_cross_bound_preview_and_bearer_states(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="091"))
    preview = _create_preview(client, seeded, idempotency_key="model_preview").json()["preview"]
    invalid_previews: list[dict[str, object]] = []

    wrong_context = deepcopy(preview)
    wrong_context["policy_result"]["context"]["plan_id"] = "plan_other_091"
    invalid_previews.append(wrong_context)
    wrong_source = deepcopy(preview)
    wrong_source["source_evidence"]["payment_id"] = "pay_other_091"
    invalid_previews.append(wrong_source)
    wrong_money = deepcopy(preview)
    wrong_money["amount_subunits"] = 99
    invalid_previews.append(wrong_money)
    wrong_template = deepcopy(preview)
    wrong_template["execution_target"] = "razorpay_test_mode"
    invalid_previews.append(wrong_template)
    wrong_decision = deepcopy(preview)
    wrong_decision["preview_policy_allowed"] = False
    invalid_previews.append(wrong_decision)
    wrong_label = deepcopy(preview)
    wrong_label["synthetic"] = False
    invalid_previews.append(wrong_label)

    for invalid in invalid_previews:
        with pytest.raises(ValidationError):
            RecoveryPlanPreview.model_validate(invalid)

    plan_id = preview["plan"]["plan_id"]
    approved = client.post(
        f"/api/v1/plans/{plan_id}/approve",
        headers=_AUTHORIZATION,
        json={"idempotency_key": "model_approval"},
    ).json()
    invalid_delivery = deepcopy(approved)
    invalid_delivery["disposition"] = "replayed"
    with pytest.raises(ValidationError, match="first issued"):
        ApprovalDecisionResponse.model_validate(invalid_delivery)
    missing_delivery = deepcopy(approved)
    missing_delivery["approval_token"] = None
    with pytest.raises(ValidationError, match="delivery status"):
        ApprovalDecisionResponse.model_validate(missing_delivery)


def test_unmigrated_recovery_store_returns_bounded_unavailable_error(
    settings: Settings,
    tmp_path: Path,
) -> None:
    database_path = (tmp_path / "unmigrated-recovery.sqlite3").resolve().as_posix()
    configured = settings.model_copy(
        update={"database_url": SecretStr(f"sqlite+aiosqlite:///{database_path}")}
    )
    with TestClient(create_app(configured)) as client:
        response = client.post(
            "/api/v1/incidents/incident_unmigrated/plans",
            headers=_AUTHORIZATION,
            json={
                "payment_id": "pay_unmigrated",
                "idempotency_key": "unmigrated_preview",
            },
        )

    assert response.status_code == 503
    assert response.json()["detail"]["reason_code"] == ("RECOVERY_PERSISTENCE_UNAVAILABLE")


def test_inconsistent_authoritative_evidence_returns_bounded_integrity_error(
    settings: Settings,
    client: TestClient,
) -> None:
    mismatched_money = asyncio.run(_seed_case(settings, suffix="101", source_amount_subunits=99))
    invalid_cohort = asyncio.run(_seed_case(settings, suffix="102", invalid_cohort=True))
    future_control = asyncio.run(
        _seed_case(
            settings,
            suffix="103",
            last_action_at=_BASE_TIME + timedelta(days=2),
        )
    )

    responses = (
        _create_preview(client, mismatched_money, idempotency_key="bad_money"),
        _create_preview(client, invalid_cohort, idempotency_key="bad_cohort"),
        _create_preview(client, future_control, idempotency_key="bad_control_time"),
    )
    for response in responses:
        assert response.status_code == 500
        assert response.json()["detail"]["reason_code"] == "RECOVERY_EVIDENCE_INVALID"


def test_concurrent_preview_and_approval_replay_one_durable_result(
    settings: Settings,
) -> None:
    async def exercise() -> None:
        seeded = await _seed_case(settings, suffix="111")
        database = Database(settings.database_dsn())
        service = RecoveryWorkflowService(
            database,
            settings,
            PipelineMetrics(),
            clock=lambda: _BASE_TIME + timedelta(hours=4),
            token_factory=lambda: f"rr_apv_{'E' * 43}",
        )
        try:
            previews = await asyncio.gather(
                *(
                    service.create_preview(
                        merchant_id=settings.merchant_id,
                        incident_id=seeded.incident_id,
                        payment_id=seeded.payment_id,
                        idempotency_key="concurrent_preview",
                    )
                    for _ in range(2)
                )
            )
            assert {item.disposition.value for item in previews} == {
                "created",
                "replayed",
            }
            plan_id = previews[0].preview.plan.plan_id
            approvals = await asyncio.gather(
                *(
                    service.decide(
                        merchant_id=settings.merchant_id,
                        plan_id=plan_id,
                        actor_id=settings.merchant_approver_id,
                        decision=ApprovalDecision.APPROVE,
                        idempotency_key="concurrent_approval",
                    )
                    for _ in range(2)
                )
            )
            assert {item.disposition for item in approvals} == {"created", "replayed"}
            assert sum(item.approval_token is not None for item in approvals) == 1
            async with database.sessions() as session:
                assert (
                    await session.scalar(select(func.count()).select_from(RecoveryPlanRecord)) == 1
                )
                assert (
                    await session.scalar(select(func.count()).select_from(ApprovalDecisionRecord))
                    == 1
                )
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_stale_decision_lookup_replays_identical_request_after_plan_lock(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        seeded = await _seed_case(settings, suffix="112")
        database = Database(settings.database_dsn())
        service = RecoveryWorkflowService(
            database,
            settings,
            PipelineMetrics(),
            clock=lambda: _BASE_TIME + timedelta(hours=4),
            token_factory=lambda: f"rr_apv_{'F' * 43}",
        )
        try:
            preview = (
                await service.create_preview(
                    merchant_id=settings.merchant_id,
                    incident_id=seeded.incident_id,
                    payment_id=seeded.payment_id,
                    idempotency_key="stale_lookup_preview",
                )
            ).preview
            created = await service.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key="stale_lookup_approval",
            )

            async def stale_initial_lookup(
                _session: object,
                *,
                merchant_id: str,
                idempotency_key: str,
            ) -> None:
                assert merchant_id == settings.merchant_id
                assert idempotency_key == "stale_lookup_approval"

            monkeypatch.setattr(
                service,
                "_decision_by_idempotency",
                stale_initial_lookup,
            )
            replayed = await service.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key="stale_lookup_approval",
            )

            assert created.disposition == "created"
            assert created.approval_token is not None
            assert replayed.disposition == "replayed"
            assert replayed.approval_token is None
            assert replayed.approval.approval_id == created.approval.approval_id
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_consumption_idempotency_key_cannot_cross_approvals_after_stale_read(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        first = await _seed_case(settings, suffix="121")
        second = await _seed_case(settings, suffix="122")
        database = Database(settings.database_dsn())
        current = _BASE_TIME + timedelta(hours=5)

        async def issue(
            seeded: _SeededCase,
            *,
            suffix: str,
            token: str,
        ) -> tuple[RecoveryWorkflowService, ApprovalTokenBinding]:
            service = RecoveryWorkflowService(
                database,
                settings,
                PipelineMetrics(),
                clock=lambda: current,
                token_factory=lambda: token,
            )
            preview = (
                await service.create_preview(
                    merchant_id=settings.merchant_id,
                    incident_id=seeded.incident_id,
                    payment_id=seeded.payment_id,
                    idempotency_key=f"cross_preview_{suffix}",
                )
            ).preview
            await service.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key=f"cross_approval_{suffix}",
            )
            return service, ApprovalTokenBinding(
                merchant_id=settings.merchant_id,
                incident_id=seeded.incident_id,
                plan_id=preview.plan.plan_id,
                policy_result_id=preview.policy_result.policy_result_id,
                plan_sha256=preview.plan_sha256,
                policy_result_sha256=preview.policy_result_sha256,
                consumption_idempotency_key="shared_consumption_key",
            )

        try:
            first_token = f"rr_apv_{'F' * 43}"
            second_token = f"rr_apv_{'G' * 43}"
            first_service, first_binding = await issue(
                first,
                suffix="first",
                token=first_token,
            )
            await first_service.consume_approval_token(
                raw_token=first_token,
                binding=first_binding,
            )
            second_service, second_binding = await issue(
                second,
                suffix="second",
                token=second_token,
            )
            with pytest.raises(RecoveryIdempotencyConflictError):
                await second_service.consume_approval_token(
                    raw_token=second_token,
                    binding=second_binding,
                )

            original_lookup = second_service._consumption_by_idempotency  # noqa: SLF001
            lookup_calls = 0

            async def stale_first_lookup(
                session: AsyncSession,
                *,
                merchant_id: str,
                idempotency_key: str,
            ) -> ApprovalTokenConsumptionRecord | None:
                nonlocal lookup_calls
                lookup_calls += 1
                if lookup_calls == 1:
                    return None
                return await original_lookup(
                    session,
                    merchant_id=merchant_id,
                    idempotency_key=idempotency_key,
                )

            monkeypatch.setattr(
                second_service,
                "_consumption_by_idempotency",
                stale_first_lookup,
            )
            with pytest.raises(RecoveryIdempotencyConflictError):
                await second_service.consume_approval_token(
                    raw_token=second_token,
                    binding=second_binding,
                )
            assert lookup_calls == 2
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_openapi_has_execution_route_and_metrics_are_identifier_free(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="061"))
    _create_preview(client, seeded, idempotency_key="metrics_preview")

    schema = client.get("/openapi.json").json()
    metrics = client.get("/metrics")
    assert "/api/v1/plans/{plan_id}/execute" in schema["paths"]
    assert "/api/v1/actions/{action_id}/reconcile" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}/analyze" in schema["paths"]
    assert "retryrail_recovery_plan_previews_total" in metrics.text
    assert settings.merchant_id not in metrics.text
    assert seeded.incident_id not in metrics.text
    assert seeded.payment_id not in metrics.text


def test_model_unavailable_rules_fallback_completes_plan_to_audited_receipt(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="131"))
    asyncio.run(_seed_valid_analysis_evidence(settings, seeded))
    path = f"/api/v1/incidents/{seeded.incident_id}/analyze"

    unauthenticated = client.post(path)
    first = client.post(path, headers=_AUTHORIZATION)
    replayed = client.post(path, headers=_AUTHORIZATION)

    assert unauthenticated.status_code == 401
    assert first.status_code == replayed.status_code == 200
    body = first.json()
    assert body["disposition"] == "created"
    assert replayed.json()["disposition"] == "replayed"
    assert replayed.json()["brief"] == body["brief"]
    assert body["model_status"] == "unavailable"
    assert body["fallback_used"] is True
    assert body["brief"]["analyst_mode"] == "deterministic_rules"
    assert len(body["brief"]["verified_evidence"]) == 3
    assert all(item["evidence_event_ids"] for item in body["brief"]["verified_evidence"])
    assert body["brief"]["expected_benefit"] == {
        "opportunity_gmv_subunits": 12_345,
        "currency": "INR",
        "interpretation": "at_risk_opportunity_not_forecast",
    }
    assert body["brief"]["customer_risk"]["external_notifications_enabled"] is False
    assert body["plan_fallback"]["can_create_plan"] is True
    assert body["plan_fallback"]["requires_external_approval"] is True
    application = cast("FastAPI", client.app)
    assert application.state.incident_analyst_provider is None

    preview, token = _preview_and_approve(client, seeded, prefix="fallback_full_path")
    execution = client.post(
        f"/api/v1/plans/{preview.plan.plan_id}/execute",
        headers={**_AUTHORIZATION, "X-RetryRail-Approval-Token": token},
        json={"idempotency_key": "fallback_full_path_execute"},
    )
    assert execution.status_code == 200
    receipt = execution.json()["receipt"]
    assert receipt["state"] == "succeeded"
    assert receipt["synthetic"] is True

    async def verify_audit() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        workflow = RecoveryWorkflowService(database, settings, metrics)
        execution_service = RecoveryExecutionService(
            database,
            settings,
            metrics,
            workflow,
            DeterministicFakeRazorpayAdapter(),
        )
        verifier = RecoveryAuditVerifier(database, settings, execution_service)
        try:
            report = await verifier.verify_action(
                merchant_id=settings.merchant_id,
                action_id=receipt["action_id"],
            )
            assert report.complete is True
            assert report.missing_facts == ()
            assert report.transition_count == 5
            assert report.terminal_state.value == "succeeded"
            async with database.sessions() as session:
                assert (
                    await session.scalar(
                        select(func.count()).select_from(RulesBasedIncidentBriefRecord)
                    )
                    == 1
                )
            async with database.sessions() as session:
                with pytest.raises(SQLAlchemyError, match="immutable"):
                    await session.execute(text("DELETE FROM rules_based_incident_briefs"))
        finally:
            await database.dispose()

    asyncio.run(verify_audit())


def test_rules_fallback_fails_closed_on_invalid_incident_evidence(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="139"))
    response = client.post(
        f"/api/v1/incidents/{seeded.incident_id}/analyze",
        headers=_AUTHORIZATION,
    )

    assert response.status_code == 500
    assert response.json()["detail"]["reason_code"] == "RECOVERY_EVIDENCE_INVALID"

    async def assert_no_brief() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                assert (
                    await session.scalar(
                        select(func.count()).select_from(RulesBasedIncidentBriefRecord)
                    )
                    == 0
                )
        finally:
            await database.dispose()

    asyncio.run(assert_no_brief())


def test_preview_denies_forged_detector_artifact_identity(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(
        _seed_case(
            settings,
            suffix="140",
            detector_config_digest="a" * 64,
        )
    )

    response = _create_preview(
        client,
        seeded,
        idempotency_key="forged_detector_identity_preview",
    )

    assert response.status_code == 200
    policy = response.json()["preview"]["policy_result"]
    assert policy["decision"] == "deny"
    incident_rule = next(
        item for item in policy["rule_results"] if item["rule"] == "incident_action_eligibility"
    )
    assert incident_rule["reason_code"] == "POLICY_INCIDENT_ACTION_INELIGIBLE"


@pytest.mark.parametrize(
    ("suffix", "mutation", "denied_rule"),
    [
        ("151", "customer_opted_out", "customer_opt_out"),
        ("152", "already_recovered", "already_recovered"),
        ("153", "attempt_cap", "attempt_cap"),
        ("154", "incident_resolved", "incident_action_eligibility"),
    ],
)
def test_execution_revalidates_mutable_stop_conditions_without_provider_call(
    settings: Settings,
    client: TestClient,
    suffix: str,
    mutation: str,
    denied_rule: str,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix=suffix))
    preview, token = _preview_and_approve(client, seeded, prefix=f"drift_{suffix}")

    async def mutate_authoritative_fact() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session, session.begin():
                if mutation == "incident_resolved":
                    incident = await session.get(IncidentRecord, seeded.incident_id)
                    assert incident is not None
                    incident.status = "resolved"
                    incident.resolved_at = incident.last_observed_at
                    incident.updated_at = _BASE_TIME + timedelta(minutes=15)
                else:
                    controls = await session.get(
                        PaymentRecoveryControlRecord,
                        (settings.merchant_id, seeded.payment_id),
                    )
                    assert controls is not None
                    if mutation == "customer_opted_out":
                        controls.customer_opted_out = True
                    elif mutation == "already_recovered":
                        controls.already_recovered = True
                    else:
                        controls.prior_action_attempts = (
                            settings.recovery_maximum_attempts_per_payment
                        )
                    controls.version += 1
                    controls.updated_at = _BASE_TIME + timedelta(minutes=15)
        finally:
            await database.dispose()

    asyncio.run(mutate_authoritative_fact())
    response = client.post(
        f"/api/v1/plans/{preview.plan.plan_id}/execute",
        headers={**_AUTHORIZATION, "X-RetryRail-Approval-Token": token},
        json={"idempotency_key": f"drift_execution_{suffix}"},
    )

    assert response.status_code == 200
    assert response.json()["disposition"] == "blocked"
    assert response.json()["receipt"] is None
    outcomes = {
        item["rule"]: item for item in response.json()["execution_policy_result"]["rule_results"]
    }
    assert outcomes[denied_rule]["outcome"] == "deny"
    application = cast("FastAPI", client.app)
    provider = cast(
        "DeterministicFakeRazorpayAdapter",
        application.state.recovery_provider,
    )
    assert provider.create_calls == 0


def test_approved_execution_creates_one_append_only_fake_receipt(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="131"))
    preview = _create_preview(
        client,
        seeded,
        idempotency_key="execution_preview_001",
    ).json()["preview"]
    plan_id = preview["plan"]["plan_id"]
    approval = client.post(
        f"/api/v1/plans/{plan_id}/approve",
        headers=_AUTHORIZATION,
        json={"idempotency_key": "execution_approval_001"},
    )
    token = approval.json()["approval_token"]
    headers = {**_AUTHORIZATION, "X-RetryRail-Approval-Token": token}

    first = client.post(
        f"/api/v1/plans/{plan_id}/execute",
        headers=headers,
        json={"idempotency_key": "execution_request_001"},
    )
    rebound = client.post(
        f"/api/v1/plans/{plan_id}/execute",
        headers=headers,
        json={"idempotency_key": "execution_request_002"},
    )
    replayed = client.post(
        f"/api/v1/plans/{plan_id}/execute",
        headers=headers,
        json={"idempotency_key": "execution_request_001"},
    )

    assert approval.status_code == 200
    assert first.status_code == replayed.status_code == 200
    assert rebound.status_code == 409
    assert rebound.json()["detail"]["reason_code"] == "RECOVERY_IDEMPOTENCY_CONFLICT"
    assert first.json()["disposition"] == "created"
    assert replayed.json()["disposition"] == "replayed"
    assert first.json()["receipt"] == replayed.json()["receipt"]
    receipt = first.json()["receipt"]
    _assert_terminal_reconciliation_rejected(client, receipt["action_id"])
    assert receipt["state"] == "succeeded"
    assert [item["new_state"] for item in receipt["transitions"]] == [
        "previewed",
        "awaiting_approval",
        "approved",
        "executing",
        "succeeded",
    ]
    assert receipt["execution_target"] == "deterministic_fake"
    assert receipt["execution_side_effect"] == "simulated_external_mutation"
    assert receipt["external_notifications_enabled"] is False
    assert first.json()["execution_policy_result"]["context"]["stage"] == "execution"

    async def assert_storage() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                assert (
                    await session.scalar(select(func.count()).select_from(RecoveryActionRecord))
                    == 1
                )
                assert (
                    await session.scalar(
                        select(func.count()).select_from(RecoveryActionTransitionRecord)
                    )
                    == 5
                )
                controls = await session.get(
                    PaymentRecoveryControlRecord,
                    (settings.merchant_id, seeded.payment_id),
                )
                assert controls is not None
                assert controls.prior_action_attempts == 1
                assert controls.version == 2
                durable_action = await session.scalar(select(RecoveryActionRecord))
                assert durable_action is not None
                assert token not in json.dumps(durable_action.request_document)
            async with database.sessions() as session:
                with pytest.raises(SQLAlchemyError, match="immutable"):
                    await session.execute(text("DELETE FROM recovery_actions"))
                await session.rollback()
                with pytest.raises(SQLAlchemyError, match="immutable"):
                    await session.execute(
                        text("UPDATE recovery_action_transitions SET reason_code='tampered'")
                    )
        finally:
            await database.dispose()

    asyncio.run(assert_storage())


def test_audit_verifier_reports_missing_rules_brief(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="155"))
    preview, token = _preview_and_approve(client, seeded, prefix="incomplete_audit")
    response = client.post(
        f"/api/v1/plans/{preview.plan.plan_id}/execute",
        headers={**_AUTHORIZATION, "X-RetryRail-Approval-Token": token},
        json={"idempotency_key": "incomplete_audit_execution"},
    )
    assert response.status_code == 200
    receipt = response.json()["receipt"]

    async def verify() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        workflow = RecoveryWorkflowService(database, settings, metrics)
        executor = RecoveryExecutionService(
            database,
            settings,
            metrics,
            workflow,
            DeterministicFakeRazorpayAdapter(),
        )
        try:
            report = await RecoveryAuditVerifier(database, settings, executor).verify_action(
                merchant_id=settings.merchant_id,
                action_id=receipt["action_id"],
            )
            assert report.complete is False
            assert report.missing_facts == ("rules_based_brief",)
        finally:
            await database.dispose()

    asyncio.run(verify())


def test_execute_rejects_missing_or_unbound_approval_before_provider_call(
    settings: Settings,
    client: TestClient,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="132"))
    preview = RecoveryPlanPreview.model_validate(
        _create_preview(
            client,
            seeded,
            idempotency_key="unapproved_execution_preview",
        ).json()["preview"]
    )
    path = f"/api/v1/plans/{preview.plan.plan_id}/execute"
    request = {"idempotency_key": "unapproved_execution_request"}
    missing_merchant_auth = client.post(
        path,
        headers={"X-RetryRail-Approval-Token": f"rr_apv_{'U' * 43}"},
        json=request,
    )
    missing_token = client.post(path, headers=_AUTHORIZATION, json=request)
    unknown_token = client.post(
        path,
        headers={
            **_AUTHORIZATION,
            "X-RetryRail-Approval-Token": f"rr_apv_{'U' * 43}",
        },
        json=request,
    )
    other = asyncio.run(_seed_case(settings, suffix="138"))
    _, other_token = _preview_and_approve(client, other, prefix="cross_plan_token")
    mismatched_token = client.post(
        path,
        headers={
            **_AUTHORIZATION,
            "X-RetryRail-Approval-Token": other_token,
        },
        json=request,
    )

    assert missing_merchant_auth.status_code == 401
    assert missing_token.status_code == unknown_token.status_code == 401
    assert mismatched_token.status_code == 401
    assert missing_token.json()["detail"]["reason_code"] == "APPROVAL_TOKEN_INVALID"
    application = cast("FastAPI", client.app)
    provider = cast(
        "DeterministicFakeRazorpayAdapter",
        application.state.recovery_provider,
    )
    assert provider.create_calls == 0

    async def assert_no_mutation() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                assert (
                    await session.scalar(select(func.count()).select_from(RecoveryActionRecord))
                    == 0
                )
                assert (
                    await session.scalar(
                        select(func.count()).select_from(ApprovalTokenConsumptionRecord)
                    )
                    == 0
                )
        finally:
            await database.dispose()

    asyncio.run(assert_no_mutation())


def test_execution_revalidates_kill_switch_and_records_complete_denial(
    settings: Settings,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix="133"))
    with TestClient(create_app(settings)) as approval_client:
        preview, token = _preview_and_approve(
            approval_client,
            seeded,
            prefix="kill_switch",
        )

    provider = DeterministicFakeRazorpayAdapter()
    blocked_settings = settings.model_copy(update={"recovery_kill_switch": True})
    with TestClient(create_app(blocked_settings, recovery_provider=provider)) as execution_client:
        response = execution_client.post(
            f"/api/v1/plans/{preview.plan.plan_id}/execute",
            headers={**_AUTHORIZATION, "X-RetryRail-Approval-Token": token},
            json={"idempotency_key": "kill_switch_execution"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["disposition"] == "blocked"
    assert body["receipt"] is None
    assert body["execution_policy_result"]["decision"] == "deny"
    outcomes = {item["rule"]: item for item in body["execution_policy_result"]["rule_results"]}
    assert outcomes["kill_switch"] == {
        "rule": "kill_switch",
        "outcome": "deny",
        "reason_code": "POLICY_KILL_SWITCH_ON",
    }
    assert len(outcomes) == 13
    assert provider.create_calls == 0

    async def assert_denial_storage() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                assert (
                    await session.scalar(select(func.count()).select_from(RecoveryActionRecord))
                    == 0
                )
                assert (
                    await session.scalar(
                        select(func.count()).select_from(ApprovalTokenConsumptionRecord)
                    )
                    == 0
                )
                execution_policy = await session.scalar(
                    select(PolicyResultRecord).where(PolicyResultRecord.stage == "execution")
                )
                assert execution_policy is not None
                assert execution_policy.result_document["decision"] == "deny"
        finally:
            await database.dispose()

    asyncio.run(assert_denial_storage())


@pytest.mark.parametrize(
    ("scenario", "terminal_state", "reason_code"),
    [
        (
            FakeProviderScenario.TIMEOUT_AFTER_CREATE,
            "succeeded",
            None,
        ),
        (
            FakeProviderScenario.TIMEOUT_BEFORE_CREATE,
            "failed",
            "FAKE_PROVIDER_CONFIRMED_NOT_CREATED",
        ),
    ],
)
def test_ambiguous_fake_execution_reconciles_without_second_create(
    settings: Settings,
    scenario: FakeProviderScenario,
    terminal_state: str,
    reason_code: str | None,
) -> None:
    suffix = "134" if scenario is FakeProviderScenario.TIMEOUT_AFTER_CREATE else "135"
    seeded = asyncio.run(_seed_case(settings, suffix=suffix))
    provider = DeterministicFakeRazorpayAdapter(scenario=scenario)
    with TestClient(create_app(settings, recovery_provider=provider)) as client:
        preview, token = _preview_and_approve(client, seeded, prefix=f"ambiguous_{suffix}")
        headers = {**_AUTHORIZATION, "X-RetryRail-Approval-Token": token}
        execute_path = f"/api/v1/plans/{preview.plan.plan_id}/execute"
        request = {"idempotency_key": f"ambiguous_execute_{suffix}"}
        first = client.post(execute_path, headers=headers, json=request)
        duplicate = client.post(execute_path, headers=headers, json=request)
        action_id = first.json()["receipt"]["action_id"]
        reconcile_path = f"/api/v1/actions/{action_id}/reconcile"
        reconcile = client.post(
            reconcile_path,
            headers=_AUTHORIZATION,
            json={"idempotency_key": f"ambiguous_reconcile_{suffix}"},
        )
        replayed_reconciliation = client.post(
            reconcile_path,
            headers=_AUTHORIZATION,
            json={"idempotency_key": f"ambiguous_reconcile_{suffix}"},
        )
        conflicting_reconciliation = client.post(
            reconcile_path,
            headers=_AUTHORIZATION,
            json={"idempotency_key": f"ambiguous_reconcile_conflict_{suffix}"},
        )

    assert first.status_code == duplicate.status_code == 200
    assert first.json()["receipt"]["state"] == "reconciliation_required"
    assert duplicate.json()["disposition"] == "replayed"
    assert duplicate.json()["receipt"] == first.json()["receipt"]
    assert reconcile.status_code == replayed_reconciliation.status_code == 200
    assert reconcile.json()["disposition"] == "created"
    assert replayed_reconciliation.json()["disposition"] == "replayed"
    terminal = reconcile.json()["receipt"]
    assert terminal["state"] == terminal_state
    assert len(terminal["transitions"]) == 6
    if reason_code is None:
        assert terminal["provider_action_id"].startswith("plink_fake_")
        assert terminal["error"] is None
    else:
        assert terminal["provider_action_id"] is None
        assert terminal["error"]["reason_code"] == reason_code
    assert conflicting_reconciliation.status_code == 409
    assert conflicting_reconciliation.json()["detail"]["reason_code"] == (
        "RECOVERY_IDEMPOTENCY_CONFLICT"
    )
    assert provider.create_calls == 1
    assert provider.reconcile_calls == 1


@pytest.mark.parametrize(
    ("suffix", "scenario", "category", "retry_permitted"),
    [
        ("141", FakeProviderScenario.INVALID_INPUT, "invalid_input", False),
        ("142", FakeProviderScenario.UNAUTHORIZED, "unauthorized", False),
        ("143", FakeProviderScenario.RATE_LIMITED, "rate_limited", True),
        ("144", FakeProviderScenario.UPSTREAM_FAILURE, "upstream_failure", True),
    ],
)
def test_fake_provider_known_failures_return_typed_terminal_receipts(
    settings: Settings,
    suffix: str,
    scenario: FakeProviderScenario,
    category: str,
    retry_permitted: object,
) -> None:
    seeded = asyncio.run(_seed_case(settings, suffix=suffix))
    provider = DeterministicFakeRazorpayAdapter(scenario=scenario)
    with TestClient(create_app(settings, recovery_provider=provider)) as client:
        preview, token = _preview_and_approve(client, seeded, prefix=f"failure_{suffix}")
        response = client.post(
            f"/api/v1/plans/{preview.plan.plan_id}/execute",
            headers={**_AUTHORIZATION, "X-RetryRail-Approval-Token": token},
            json={"idempotency_key": f"failure_execute_{suffix}"},
        )

    assert response.status_code == 200
    receipt = response.json()["receipt"]
    assert receipt["state"] == "failed"
    assert receipt["provider_action_id"] is None
    assert receipt["verified_at"] is None
    assert receipt["error"]["category"] == category
    assert receipt["error"]["retry_permitted"] is retry_permitted
    assert receipt["error"]["reconciliation_required"] is False
    assert provider.create_calls == 1
    assert provider.reconcile_calls == 0


def test_expired_approval_creates_replayable_receipt_without_provider_call(
    settings: Settings,
) -> None:
    async def exercise() -> None:
        seeded = await _seed_case(settings, suffix="136")
        database = Database(settings.database_dsn())
        current = [_BASE_TIME + timedelta(hours=6)]
        metrics = PipelineMetrics()
        workflow = RecoveryWorkflowService(
            database,
            settings,
            metrics,
            clock=lambda: current[0],
            token_factory=lambda: f"rr_apv_{'X' * 43}",
        )
        provider = DeterministicFakeRazorpayAdapter(clock=lambda: current[0])
        execution = RecoveryExecutionService(
            database,
            settings,
            metrics,
            workflow,
            provider,
            clock=lambda: current[0],
        )
        try:
            preview = (
                await workflow.create_preview(
                    merchant_id=settings.merchant_id,
                    incident_id=seeded.incident_id,
                    payment_id=seeded.payment_id,
                    idempotency_key="expired_preview",
                )
            ).preview
            approval = await workflow.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key="expired_approval",
            )
            assert approval.approval_token is not None
            current[0] += timedelta(seconds=settings.approval_token_lifetime_seconds)
            first = await execution.execute(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                raw_approval_token=approval.approval_token,
                idempotency_key="expired_execution",
            )
            replayed = await execution.execute(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                raw_approval_token=approval.approval_token,
                idempotency_key="expired_execution",
            )

            assert first.disposition.value == "created"
            assert replayed.disposition.value == "replayed"
            assert first.receipt == replayed.receipt
            assert first.receipt is not None
            assert first.receipt.state.value == "expired"
            assert first.receipt.transitions[-1].reason_code == (
                "approval_expired_before_execution"
            )
            assert first.execution_policy_result is None
            assert provider.create_calls == 0
            async with database.sessions() as session:
                assert (
                    await session.scalar(
                        select(func.count()).select_from(ApprovalTokenConsumptionRecord)
                    )
                    == 0
                )
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_concurrent_duplicate_execute_has_one_consumption_and_provider_call(
    settings: Settings,
) -> None:
    async def exercise() -> None:
        seeded = await _seed_case(settings, suffix="137")
        database = Database(settings.database_dsn())
        now = _BASE_TIME + timedelta(hours=7)
        metrics = PipelineMetrics()
        workflow = RecoveryWorkflowService(
            database,
            settings,
            metrics,
            clock=lambda: now,
            token_factory=lambda: f"rr_apv_{'Y' * 43}",
        )
        provider = DeterministicFakeRazorpayAdapter(clock=lambda: now)
        execution = RecoveryExecutionService(
            database,
            settings,
            metrics,
            workflow,
            provider,
            clock=lambda: now,
        )
        try:
            preview = (
                await workflow.create_preview(
                    merchant_id=settings.merchant_id,
                    incident_id=seeded.incident_id,
                    payment_id=seeded.payment_id,
                    idempotency_key="concurrent_execution_preview",
                )
            ).preview
            approval = await workflow.decide(
                merchant_id=settings.merchant_id,
                plan_id=preview.plan.plan_id,
                actor_id=settings.merchant_approver_id,
                decision=ApprovalDecision.APPROVE,
                idempotency_key="concurrent_execution_approval",
            )
            assert approval.approval_token is not None

            async def execute() -> RecoveryExecutionResponse:
                return await execution.execute(
                    merchant_id=settings.merchant_id,
                    plan_id=preview.plan.plan_id,
                    raw_approval_token=approval.approval_token,
                    idempotency_key="concurrent_execution_request",
                )

            results = await asyncio.gather(execute(), execute())
            dispositions = {result.disposition.value for result in results}
            assert dispositions == {"created", "replayed"}
            assert provider.create_calls == 1
            async with database.sessions() as session:
                assert (
                    await session.scalar(select(func.count()).select_from(RecoveryActionRecord))
                    == 1
                )
                assert (
                    await session.scalar(
                        select(func.count()).select_from(ApprovalTokenConsumptionRecord)
                    )
                    == 1
                )
        finally:
            await database.dispose()

    asyncio.run(exercise())
