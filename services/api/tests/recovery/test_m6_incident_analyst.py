"""M6 redaction, structured-output, fallback and persistence tests."""

import asyncio
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError

from retryrail.config import Settings
from retryrail.contracts.domain import CohortDimension
from retryrail.db.session import Database
from retryrail.db.tables import (
    IncidentRecord,
    ModelIncidentAnalysisRecord,
    PaymentEventRecord,
    RulesBasedIncidentBriefRecord,
)
from retryrail.detection.models import (
    AttributionItem,
    DetectorGateReason,
    DetectorStatistics,
    DiagnosisHypothesis,
    DiagnosisSnapshot,
)
from retryrail.events.models import (
    ErrorEvidence,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.main import create_app
from retryrail.recovery import analyst_evaluation as analyst_eval
from retryrail.recovery.analyst_evaluation import (
    AnalystBakeoffReport,
    AnalystThresholds,
    build_snapshot,
    check_report,
    load_corpus,
    run_bakeoff,
    write_report_create_only,
)
from retryrail.recovery.analyst_models import (
    AnalystEvidenceClaim,
    AnalystHypothesis,
    AnalystProvenance,
    ModelIncidentAnalysisDraft,
    ModelIncidentBrief,
    ModelRecoveryProposal,
)
from retryrail.recovery.integrity import canonical_sha256
from retryrail.recovery.openai_analyst import (
    IncidentAnalystInvalidResponseError,
    IncidentAnalystRefusalError,
    IncidentAnalystTimeoutError,
    IncidentAnalystUnavailableError,
    OpenAIIncidentAnalystProvider,
    ProviderAnalysisResult,
    estimate_cost_microusd,
)

_NOW = datetime(2026, 8, 31, 10, 0, tzinfo=UTC)
_AUTHORIZATION = {"X-RetryRail-Merchant-Authorization": "unit-test-merchant-approval-secret-value"}
_STOP_CONDITIONS = (
    "POLICY_INCIDENT_NOT_ACTION_ELIGIBLE",
    "POLICY_OPERATING_MODE_ANALYZE_ONLY",
    "POLICY_CUSTOMER_OPTED_OUT",
    "POLICY_ATTEMPT_CAP_REACHED",
    "POLICY_COOLDOWN_ACTIVE",
    "POLICY_PLAN_EXPIRED",
    "POLICY_KILL_SWITCH_ON",
    "POLICY_PAYMENT_ALREADY_RECOVERED",
)


def _snapshot() -> Any:
    return build_snapshot(load_corpus().cases[0])


def test_packaged_corpus_and_report_are_runtime_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    packaged_corpus = analyst_eval._CORPUS_PATH  # noqa: SLF001
    packaged_report = analyst_eval._REPORT_PATH  # noqa: SLF001
    monkeypatch.setattr(analyst_eval, "_CORPUS_PATH", tmp_path / "missing-corpus.json")
    monkeypatch.setattr(analyst_eval, "_REPORT_PATH", tmp_path / "missing-report.json")
    monkeypatch.setattr(analyst_eval, "_PACKAGED_CORPUS_PATH", packaged_corpus)
    monkeypatch.setattr(analyst_eval, "_PACKAGED_REPORT_PATH", packaged_report)

    corpus = load_corpus()
    report = check_report()

    assert corpus.corpus_id == report.corpus_id
    assert report.status == "passed"
    assert report.selected_model == "gpt-5.4-nano-2026-03-17"


def _draft(snapshot: Any, *, confidence_ppm: int = 900_000) -> ModelIncidentAnalysisDraft:
    evidence_id = snapshot.verified_attributions[0].evidence_event_ids[0]
    return ModelIncidentAnalysisDraft(
        brief=ModelIncidentBrief(
            executive_summary="This merchant has a verified payment degradation.",
            executive_summary_evidence_ids=(evidence_id,),
            verified_evidence=(
                AnalystEvidenceClaim(
                    statement="The current success rate is below its baseline.",
                    evidence_ids=(evidence_id,),
                ),
                AnalystEvidenceClaim(
                    statement="At-risk value is observed exposure, not recovered GMV.",
                    evidence_ids=(evidence_id,),
                ),
            ),
            hypotheses=(
                AnalystHypothesis(
                    statement="The merchant-local issuer concentration may explain the drop.",
                    evidence_ids=(evidence_id,),
                    confidence_ppm=confidence_ppm,
                ),
            ),
            unknowns=("Provider-wide conditions are not independently verified.",),
            confidence_ppm=confidence_ppm,
        ),
        proposal=ModelRecoveryProposal(
            rationale="Offer the bounded standard link only after merchant approval.",
            evidence_ids=(evidence_id,),
            opportunity_gmv_subunits=snapshot.gmv_at_risk_subunits,
            currency=snapshot.currency,
            stop_conditions=_STOP_CONDITIONS,
        ),
    )


def _provider_response(draft: ModelIncidentAnalysisDraft) -> dict[str, Any]:
    return {
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": draft.model_dump_json()}],
            }
        ],
        "usage": {"input_tokens": 800, "output_tokens": 300},
    }


def _provider(client: httpx.AsyncClient) -> OpenAIIncidentAnalystProvider:
    return OpenAIIncidentAnalystProvider(
        api_key=SecretStr("sk-unit-test-not-a-real-platform-api-key"),
        model="gpt-5.4-mini-2026-03-17",
        prompt_version="incident_analyst_prompt_v1",
        evaluator_version="incident_analyst_eval_v1",
        timeout_seconds=3,
        max_output_tokens=1_600,
        max_schema_repairs=1,
        client=client,
    )


def test_openai_adapter_sends_only_redacted_snapshot_and_strict_schema() -> None:
    snapshot = _snapshot()
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload: dict[str, Any] = json.loads(request.content)
        requests.append(payload)
        return httpx.Response(200, json=_provider_response(_draft(snapshot)))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        result = asyncio.run(_provider(client).analyze(snapshot))
    finally:
        asyncio.run(client.aclose())

    assert result.draft.proposal.executable is False
    assert result.provenance.total_tokens == 1_100
    assert result.provenance.estimated_cost_microusd == 1_950
    assert result.provenance.response_stored_by_provider is False
    payload = requests[0]
    assert payload["store"] is False
    assert payload["text"]["format"]["type"] == "json_schema"
    assert payload["text"]["format"]["strict"] is True
    serialized = json.dumps(payload)
    assert "customer_email" not in serialized
    assert "payment_note" not in serialized
    assert "merchant_synthetic_eval" not in serialized
    assert "razorpay_key" not in serialized


def test_openai_adapter_repairs_once_without_replaying_invalid_output() -> None:
    snapshot = _snapshot()
    calls = 0
    payloads: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payloads.append(request.content.decode())
        if calls == 1:
            return httpx.Response(
                200,
                json={
                    "output": [
                        {
                            "type": "message",
                            "content": [{"type": "output_text", "text": "INVALID_RAW_OUTPUT"}],
                        }
                    ],
                    "usage": {"input_tokens": 100, "output_tokens": 50},
                },
            )
        return httpx.Response(200, json=_provider_response(_draft(snapshot)))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        result = asyncio.run(_provider(client).analyze(snapshot))
    finally:
        asyncio.run(client.aclose())

    assert calls == 2
    assert result.provenance.schema_repair_attempts == 1
    assert result.provenance.total_tokens == 1_250
    assert result.provenance.estimated_cost_microusd == 2_250
    assert "Regenerate from this same snapshot" in payloads[1]
    assert "INVALID_RAW_OUTPUT" not in payloads[1]


def test_openai_adapter_fails_closed_after_repair_limit() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "{"}],
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(IncidentAnalystInvalidResponseError):
            asyncio.run(_provider(client).analyze(_snapshot()))
    finally:
        asyncio.run(client.aclose())


@pytest.mark.parametrize("mode", ["refusal", "timeout"])
def test_openai_adapter_maps_refusal_and_timeout_without_body(mode: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "timeout":
            message = "synthetic timeout"
            raise httpx.ReadTimeout(message, request=request)
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "refusal", "refusal": "not retained"}],
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    expected = IncidentAnalystTimeoutError if mode == "timeout" else IncidentAnalystRefusalError
    try:
        with pytest.raises(expected):
            asyncio.run(_provider(client).analyze(_snapshot()))
    finally:
        asyncio.run(client.aclose())


def test_structured_output_rejects_unknown_template_and_extra_authority() -> None:
    document = _draft(_snapshot()).model_dump(mode="json")
    document["proposal"]["recommended_template"] = "send_sms"
    document["proposal"]["execute_now"] = True
    with pytest.raises(ValidationError):
        ModelIncidentAnalysisDraft.model_validate(document)

    stop_document = _draft(_snapshot()).model_dump(mode="json")
    stop_document["proposal"]["stop_conditions"][-1] = "POLICY_UNKNOWN_ACTION"
    with pytest.raises(ValidationError):
        ModelIncidentAnalysisDraft.model_validate(stop_document)


class _FakeAnalystProvider:
    def __init__(
        self,
        *,
        unsafe_mode: str | None = None,
        evaluator_version: str = "incident_analyst_eval_v1",
    ) -> None:
        self.calls = 0
        self.unsafe_mode = unsafe_mode
        self.evaluator_version = evaluator_version

    @property
    def model(self) -> str:
        return "gpt-5.4-mini-2026-03-17"

    async def analyze(self, snapshot: Any) -> ProviderAnalysisResult:
        self.calls += 1
        draft = _draft(snapshot)
        if self.unsafe_mode == "global_claim_in_unknowns":
            draft = draft.model_copy(
                update={
                    "brief": draft.brief.model_copy(
                        update={"unknowns": ("A global outage is confirmed.",)}
                    )
                }
            )
        return ProviderAnalysisResult(
            draft=draft,
            provenance=AnalystProvenance(
                model=(
                    "gpt-5.4-nano-2026-03-17"
                    if self.unsafe_mode == "mismatched_provenance"
                    else self.model
                ),
                prompt_version="incident_analyst_prompt_v1",
                evaluator_version=self.evaluator_version,
                latency_ms=25,
                input_tokens=500,
                output_tokens=200,
                total_tokens=700,
                estimated_cost_microusd=1_275,
                pricing_version="openai_public_pricing_2026_09_05",
                schema_repair_attempts=0,
            ),
        )


def test_model_analysis_is_content_addressed_and_keeps_rules_audit_baseline(
    settings: Settings,
) -> None:
    asyncio.run(_seed_incident(settings))
    provider = _FakeAnalystProvider()
    with TestClient(create_app(settings, incident_analyst_provider=provider)) as client:
        first = client.post(
            "/api/v1/incidents/inc_m6_test/analyze",
            headers=_AUTHORIZATION,
        )
        second = client.post(
            "/api/v1/incidents/inc_m6_test/analyze",
            headers=_AUTHORIZATION,
        )
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["disposition"] == "created"
    assert second.json()["disposition"] == "replayed"
    assert first.json()["analysis"]["fallback_used"] is False
    assert first.json()["analysis"]["proposal"]["executable"] is False
    assert provider.calls == 1

    async def counts() -> tuple[int, int]:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                analyses = int(
                    await session.scalar(
                        select(func.count()).select_from(ModelIncidentAnalysisRecord)
                    )
                    or 0
                )
                baselines = int(
                    await session.scalar(
                        select(func.count()).select_from(RulesBasedIncidentBriefRecord)
                    )
                    or 0
                )
                with pytest.raises(SQLAlchemyError, match="immutable"):
                    await session.execute(text("DELETE FROM model_incident_analyses"))
                return analyses, baselines
        finally:
            await database.dispose()

    assert asyncio.run(counts()) == (1, 1)


def test_changed_evaluator_version_creates_distinct_analysis_evidence(
    settings: Settings,
) -> None:
    asyncio.run(_seed_incident(settings))
    first_provider = _FakeAnalystProvider()
    with TestClient(create_app(settings, incident_analyst_provider=first_provider)) as client:
        assert client.post(
            "/api/v1/incidents/inc_m6_test/analyze",
            headers=_AUTHORIZATION,
        ).status_code == 200

    v2_settings = settings.model_copy(
        update={"incident_analyst_evaluator_version": "incident_analyst_eval_v2"}
    )
    second_provider = _FakeAnalystProvider(evaluator_version="incident_analyst_eval_v2")
    with TestClient(
        create_app(v2_settings, incident_analyst_provider=second_provider)
    ) as client:
        second = client.post(
            "/api/v1/incidents/inc_m6_test/analyze",
            headers=_AUTHORIZATION,
        )

    assert second.status_code == 200
    assert second.json()["disposition"] == "created"
    assert second_provider.calls == 1

    async def count_analyses() -> int:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                return int(
                    await session.scalar(
                        select(func.count()).select_from(ModelIncidentAnalysisRecord)
                    )
                    or 0
                )
        finally:
            await database.dispose()

    assert asyncio.run(count_analyses()) == 2


@pytest.mark.parametrize(
    "unsafe_mode",
    ["global_claim_in_unknowns", "mismatched_provenance"],
)
def test_orchestrator_rejects_ungrounded_or_unbound_provider_results(
    settings: Settings,
    unsafe_mode: str,
) -> None:
    asyncio.run(_seed_incident(settings))
    provider = _FakeAnalystProvider(unsafe_mode=unsafe_mode)
    with TestClient(create_app(settings, incident_analyst_provider=provider)) as client:
        response = client.post(
            "/api/v1/incidents/inc_m6_test/analyze",
            headers=_AUTHORIZATION,
        )

    assert response.status_code == 200
    assert response.json()["fallback_used"] is True
    assert response.json()["model_status"] == "invalid_response"
    assert response.json()["fallback_reason_code"] == "ANALYST_RESPONSE_INVALID"

    async def counts() -> tuple[int, int]:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                analyses = int(
                    await session.scalar(
                        select(func.count()).select_from(ModelIncidentAnalysisRecord)
                    )
                    or 0
                )
                baselines = int(
                    await session.scalar(
                        select(func.count()).select_from(RulesBasedIncidentBriefRecord)
                    )
                    or 0
                )
                return analyses, baselines
        finally:
            await database.dispose()

    assert asyncio.run(counts()) == (0, 1)


async def _seed_incident(settings: Settings) -> None:
    event_id = "evt_m6_test_001"
    internal_id = "00000000-0000-0000-0000-000000000601"
    normalized = NormalizedPaymentEvent(
        merchant_id=settings.merchant_id,
        razorpay_event_id=event_id,
        event_type=PaymentEventType.FAILED,
        occurred_at=_NOW,
        received_at=_NOW + timedelta(seconds=1),
        synthetic=True,
        payment=PaymentSnapshot(
            payment_id="pay_m6_test",
            status=PaymentStatus.FAILED,
            amount_subunits=149_900,
            currency="INR",
            method=PaymentMethod.UPI,
            issuer="HDFC",
            error=ErrorEvidence(
                code="BAD_GATEWAY",
                source="issuer",
                step="authorization",
                reason="temporarily_unavailable",
            ),
        ),
    )
    statistics = DetectorStatistics(
        evaluated_at=_NOW + timedelta(minutes=15),
        current_window_minutes=15,
        current_started_at=_NOW,
        baseline_started_at=_NOW - timedelta(hours=2),
        baseline_ended_at=_NOW - timedelta(minutes=15),
        baseline_attempts=500,
        baseline_successes=470,
        baseline_failures=30,
        current_attempts=120,
        current_successes=70,
        current_failures=50,
        baseline_failure_rate_bps=600,
        current_failure_rate_bps=4_167,
        success_rate_drop_bps=3_567,
        confidence_ppm=990_000,
        ewma_failure_rate_bps=3_500,
        ewma_drop_bps=2_900,
        cusum_milli=90_000,
        excess_failures=43,
        at_risk_gmv_subunits=149_900,
        currency="INR",
        gate_reason=DetectorGateReason.PASSED,
        minimum_current_attempts=60,
        baseline_minimum_attempts=100,
        minimum_current_failures=10,
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
                value="issuer",
                rank=1,
                current_attempts=120,
                current_failures=50,
                baseline_attempts=500,
                baseline_failures=30,
                expected_failures_milli=7_200,
                excess_failures_milli=42_800,
                contribution_ppm=1_000_000,
                confidence_ppm=990_000,
                evidence_event_ids=(internal_id,),
            ),
        ),
        hypotheses=(
            DiagnosisHypothesis(
                statement="Merchant-local failures are concentrated at the issuer.",
                confidence_ppm=900_000,
                evidence_event_ids=(internal_id,),
            ),
        ),
        unknowns=("Provider-wide conditions are not independently verified.",),
        likely_causes=("issuer",),
    )
    database = Database(settings.database_dsn())
    try:
        async with database.sessions() as session, session.begin():
            session.add(
                PaymentEventRecord(
                    internal_id=internal_id,
                    merchant_id=settings.merchant_id,
                    razorpay_event_id=event_id,
                    schema_version="1.0.0",
                    signature_status="verified",
                    event_type="payment.failed",
                    payment_id="pay_m6_test",
                    occurred_at=_NOW,
                    received_at=_NOW + timedelta(seconds=1),
                    payload_sha256=hashlib.sha256(event_id.encode()).hexdigest(),
                    sanitized_payload={"synthetic": True},
                    normalized_event=normalized.model_dump(mode="json"),
                    synthetic=True,
                    created_at=_NOW + timedelta(seconds=1),
                )
            )
            session.add(
                IncidentRecord(
                    incident_id="inc_m6_test",
                    merchant_id=settings.merchant_id,
                    detector_version="detector_v4_0_0",
                    detector_config_sha256="a" * 64,
                    detector_cohort_key="m6_upi_hdfc",
                    detector_cohort=[{"dimension": "method", "value": "upi"}],
                    affected_cohort=[
                        {"dimension": "method", "value": "upi"},
                        {"dimension": "issuer", "value": "HDFC"},
                    ],
                    status="open",
                    opened_at=_NOW,
                    last_observed_at=_NOW + timedelta(minutes=15),
                    resolved_at=None,
                    peak_statistics=statistics.model_dump(mode="json"),
                    diagnosis=diagnosis.model_dump(mode="json"),
                    evidence_event_ids=[internal_id],
                    gmv_at_risk_subunits=149_900,
                    currency="INR",
                    action_eligible=True,
                    synthetic=True,
                    created_at=_NOW,
                    updated_at=_NOW,
                )
            )
    finally:
        await database.dispose()


def test_evaluation_corpus_has_adversarial_coverage_and_excludes_source_text() -> None:
    corpus = load_corpus()
    categories = {item.category for item in corpus.cases}
    assert len(corpus.cases) >= 20
    assert {"prompt_injection", "privacy", "abstention", "scope"}.issubset(categories)
    for case in corpus.cases:
        snapshot = build_snapshot(case)
        serialized = snapshot.model_dump_json()
        assert case.case_id not in serialized
        assert "expected_abstention" not in serialized
        assert "excluded_untrusted_text" not in serialized
        if case.excluded_untrusted_text is not None:
            assert case.excluded_untrusted_text not in serialized


def test_bakeoff_rejects_unpinned_duplicate_models_and_unsafe_concurrency() -> None:
    corpus = load_corpus()
    api_key = SecretStr(f"sk-{'x' * 64}")

    with pytest.raises(ValueError, match="distinct pinned models"):
        asyncio.run(
            run_bakeoff(
                corpus=corpus,
                api_key=api_key,
                models=("gpt-5.4-2026-03-05", "gpt-5.4-2026-03-05"),
                concurrency=1,
            )
        )
    with pytest.raises(ValueError, match="dated model snapshots"):
        asyncio.run(
            run_bakeoff(
                corpus=corpus,
                api_key=api_key,
                models=("gpt-5.4", "gpt-5.4-mini-2026-03-17"),
                concurrency=1,
            )
        )
    with pytest.raises(ValueError, match="between one and six"):
        asyncio.run(
            run_bakeoff(
                corpus=corpus,
                api_key=api_key,
                models=("gpt-5.4-2026-03-05", "gpt-5.4-mini-2026-03-17"),
                concurrency=0,
            )
        )


def test_live_bakeoff_report_is_create_only(tmp_path: Path) -> None:
    report = AnalystBakeoffReport.model_construct(
        schema_version="1.0.0",
        report_id="analyst_eval_test",
        corpus_id="incident_analyst_v1",
        corpus_sha256="a" * 64,
        prompt_version="incident_analyst_prompt_v1",
        evaluator_version="incident_analyst_eval_v1",
        generated_at=_NOW,
        candidates=(),
        thresholds=AnalystThresholds(),
        selected_model=None,
        selection_rule="pass_safety_gates_then_quality_then_lower_cost_then_latency",
        status="threshold_gap",
        model_output_retained=False,
        synthetic=True,
    )
    path = tmp_path / "incident_analyst_bakeoff.v1.json"

    write_report_create_only(report, path)

    assert path.read_text(encoding="utf-8").endswith("\n")
    with pytest.raises(RuntimeError, match="will not be overwritten"):
        write_report_create_only(report, path)


def test_fixed_bakeoff_scores_every_case_selects_cost_winner_and_rechecks_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeStructuredProvider:
        def __init__(self, **arguments: Any) -> None:
            self.model = str(arguments["model"])

        async def analyze(self, snapshot: Any) -> ProviderAnalysisResult:
            confidence = (
                550_000
                if snapshot.evidence.confidence_ppm <= 600_000 or len(snapshot.unknowns) > 1
                else 900_000
            )
            input_tokens = 100
            output_tokens = 50
            cost, pricing_version = estimate_cost_microusd(
                self.model,
                input_tokens,
                output_tokens,
            )
            return ProviderAnalysisResult(
                draft=_draft(snapshot, confidence_ppm=confidence),
                provenance=AnalystProvenance(
                    model=self.model,
                    prompt_version="incident_analyst_prompt_v1",
                    evaluator_version="incident_analyst_eval_v1",
                    latency_ms=(12 if "nano" in self.model else 24),
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    total_tokens=input_tokens + output_tokens,
                    estimated_cost_microusd=cost,
                    pricing_version=pricing_version,
                    schema_repair_attempts=0,
                ),
            )

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(
        analyst_eval,
        "OpenAIIncidentAnalystProvider",
        FakeStructuredProvider,
    )
    report = asyncio.run(
        run_bakeoff(
            corpus=load_corpus(),
            api_key=SecretStr(f"sk-{'x' * 64}"),
            models=("gpt-5.4-mini-2026-03-17", "gpt-5.4-nano-2026-03-17"),
            concurrency=3,
        )
    )

    assert report.status == "passed"
    assert report.selected_model == "gpt-5.4-nano-2026-03-17"
    assert all(candidate.case_count == 24 for candidate in report.candidates)
    assert all(candidate.threshold_passed for candidate in report.candidates)
    assert all(
        case.completed and case.schema_valid and not case.unsafe_action
        for candidate in report.candidates
        for case in candidate.cases
    )

    report_path = tmp_path / "passing-report.json"
    write_report_create_only(report, report_path)
    assert check_report(report_path) == report


def test_failed_provider_run_discloses_threshold_gap_and_preserves_fixed_cases(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class UnavailableProvider:
        def __init__(self, **arguments: Any) -> None:
            self.model = str(arguments["model"])

        async def analyze(self, _snapshot: Any) -> ProviderAnalysisResult:
            raise IncidentAnalystUnavailableError

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(
        analyst_eval,
        "OpenAIIncidentAnalystProvider",
        UnavailableProvider,
    )
    report = asyncio.run(
        run_bakeoff(
            corpus=load_corpus(),
            api_key=SecretStr(f"sk-{'x' * 64}"),
            models=("gpt-5.4-mini-2026-03-17", "gpt-5.4-nano-2026-03-17"),
            concurrency=6,
        )
    )

    assert report.status == "threshold_gap"
    assert report.selected_model is None
    assert all(not candidate.threshold_passed for candidate in report.candidates)
    assert all(
        case.reason_code == "ANALYST_PROVIDER_UNAVAILABLE"
        and not case.completed
        and case.estimated_cost_microusd is None
        for candidate in report.candidates
        for case in candidate.cases
    )

    report_path = tmp_path / "gap-report.json"
    write_report_create_only(report, report_path)
    assert check_report(report_path) == report


def test_report_check_rejects_cost_and_aggregate_tampering(tmp_path: Path) -> None:
    corpus = load_corpus()
    unavailable_case = analyst_eval.AnalystCaseResult(
        case_id=corpus.cases[0].case_id,
        category=corpus.cases[0].category,
        completed=False,
        schema_valid=False,
        grounding_passed=False,
        abstention_passed=False,
        trajectory_passed=False,
        unsafe_action=False,
        redaction_passed=True,
        reason_code="ANALYST_PROVIDER_UNAVAILABLE",
        latency_ms=0,
        input_tokens=0,
        output_tokens=0,
    )
    cases = tuple(
        unavailable_case.model_copy(
            update={"case_id": case.case_id, "category": case.category}
        )
        for case in corpus.cases
    )
    candidates = tuple(
        analyst_eval._candidate_score(model, cases)  # noqa: SLF001
        for model in ("gpt-5.4-mini-2026-03-17", "gpt-5.4-nano-2026-03-17")
    )
    report = AnalystBakeoffReport(
        report_id="analyst_eval_tamper_test",
        corpus_id=corpus.corpus_id,
        corpus_sha256=canonical_sha256(corpus),
        prompt_version=corpus.prompt_version,
        evaluator_version=corpus.evaluator_version,
        generated_at=_NOW,
        candidates=candidates,
        thresholds=AnalystThresholds(),
        selected_model=None,
        status="threshold_gap",
    )
    document = report.model_dump(mode="json")
    document["candidates"][0]["cases"][0]["input_tokens"] = 1
    path = tmp_path / "tampered-cost.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(RuntimeError, match="case cost"):
        check_report(path)

    document = report.model_dump(mode="json")
    document["candidates"][0]["grounding_ppm"] = 1
    path = tmp_path / "tampered-aggregate.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(RuntimeError, match="aggregate score"):
        check_report(path)


def test_evaluation_cli_exposes_checks_and_fails_closed_without_a_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invalid_corpus = tmp_path / "invalid-corpus.json"
    invalid_corpus.write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid analyst evaluation corpus"):
        load_corpus(invalid_corpus)

    monkeypatch.setattr(sys, "argv", ["analyst-eval", "corpus", "--check"])
    analyst_eval.main()
    assert "24 analyst cases are valid" in capsys.readouterr().out

    monkeypatch.setattr(
        analyst_eval,
        "check_report",
        lambda: SimpleNamespace(status="threshold_gap", selected_model=None),
    )
    monkeypatch.setattr(sys, "argv", ["analyst-eval", "report", "--check"])
    analyst_eval.main()
    assert "status=threshold_gap; selected=None" in capsys.readouterr().out

    report_path = tmp_path / "official-report.json"
    monkeypatch.setattr(analyst_eval, "_REPORT_PATH", report_path)
    monkeypatch.delenv("RETRYRAIL_OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["analyst-eval", "bakeoff"])
    with pytest.raises(SystemExit, match="2"):
        analyst_eval.main()
    assert "RETRYRAIL_OPENAI_API_KEY is required" in capsys.readouterr().err

    report_path.write_text("reserved", encoding="utf-8")
    with pytest.raises(SystemExit, match="2"):
        analyst_eval.main()
    assert "refusing another live run" in capsys.readouterr().err
