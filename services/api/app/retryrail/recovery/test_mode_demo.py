"""Human-approved one-link Razorpay Test Mode evidence workflow for M5."""

# Specific bounded CLI errors are more useful here than one generic exception message.
# No message includes credential values or raw provider response content.
# ruff: noqa: TRY003

import argparse
import asyncio
import csv
import hashlib
import json
import sys
import tempfile
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, SecretStr
from sqlalchemy import select

from retryrail.config import Environment, Settings
from retryrail.contracts.domain import ActionState, StrictContract
from retryrail.contracts.recovery import ApprovalDecision, PolicyDecision
from retryrail.db.migrate import upgrade_database
from retryrail.db.session import Database
from retryrail.db.tables import (
    IncidentRecord,
    OutboxMessageRecord,
    PaymentEventRecord,
    PolicyResultRecord,
    RecoveryActionRecord,
    RecoveryPlanRecord,
)
from retryrail.detection.runtime_activation import load_detector_v4_activation
from retryrail.detection.service import DetectionService
from retryrail.events.ingestion import PROJECT_PAYMENT_TOPIC
from retryrail.events.models import Currency, Identifier, NormalizedPaymentEvent, PaymentEventType
from retryrail.events.projector import PaymentProjector
from retryrail.observability.logging import configure_logging
from retryrail.observability.metrics import PipelineMetrics
from retryrail.recovery.adapter import RazorpayTestModeAdapter
from retryrail.recovery.analysis import RulesBasedIncidentAnalyst
from retryrail.recovery.audit import RecoveryAuditVerifier
from retryrail.recovery.execution import RecoveryExecutionService
from retryrail.recovery.integrity import stable_identifier
from retryrail.recovery.models import (
    RazorpayTestModeEvidenceReceipt,
    RecoveryPlanPreview,
    RecoveryProviderReceipt,
)
from retryrail.recovery.workflow import (
    RecoveryWorkflowError,
    RecoveryWorkflowService,
    materialize_preview,
)
from retryrail.synthetic.v2_generator import build_development_dataset

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_DEFAULT_DATABASE_PATH = Path(tempfile.gettempdir()) / "retryrail-m5-demo-v1.sqlite3"
_EVIDENCE_PATH = Path("evals/reports/razorpay_test_mode_receipt.v1.json")
_MAX_CREDENTIAL_FILE_BYTES = 16_384
_CREDENTIAL_ROW_COUNT = 2
_DEMO_WINDOW_HOURS = 24


class TestModeDemoError(RuntimeError):
    """Safe operator-facing refusal without provider or credential content."""

    __test__ = False


class PreparedTestModePlan(StrictContract):
    """Exact, non-secret effects a human must review before approval."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    plan_id: Identifier
    incident_id: Identifier
    payment_id: Identifier
    provider_reference_id: Identifier
    amount_subunits: int
    currency: Currency
    expires_at: AwareDatetime
    execution_target: Literal["razorpay_test_mode"] = "razorpay_test_mode"
    external_notifications_enabled: Literal[False] = False
    approval_status: Literal["awaiting_human_confirmation"] = (
        "awaiting_human_confirmation"
    )
    synthetic: Literal[True] = True


def _utc_now() -> datetime:
    return datetime.now(tz=UTC).replace(microsecond=0)


def _database_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path.resolve().as_posix()}"


def _validated_database_path(raw_path: Path, *, must_exist: bool) -> Path:
    path = raw_path.expanduser().resolve()
    if path.is_relative_to(_REPOSITORY_ROOT):
        raise TestModeDemoError("demo database must remain outside the Git repository")
    if must_exist and not path.is_file():
        raise TestModeDemoError("prepared M5 demo database was not found")
    if not must_exist and path.exists():
        raise TestModeDemoError(
            "demo database already exists; use the shown file or choose a new absolute path"
        )
    return path


def _demo_settings(
    database_path: Path,
    *,
    key_id: SecretStr | None = None,
    key_secret: SecretStr | None = None,
) -> Settings:
    placeholder_id = SecretStr("rzp" + "_test_local_id")
    placeholder_secret = SecretStr("local-only-not-a-provider-secret")
    return Settings(
        environment=Environment.TEST,
        database_url=_database_url(database_path),
        webhook_secret=SecretStr("m5-local-webhook-secret-not-a-provider-key"),
        merchant_approval_secret=SecretStr(
            "m5-local-human-approval-boundary-secret-value"
        ),
        approval_token_hmac_key=SecretStr(
            "m5-local-approval-token-hmac-boundary-key"
        ),
        merchant_approver_id="merchant_operator_m5_demo",
        recovery_plan_lifetime_seconds=_DEMO_WINDOW_HOURS * 60 * 60,
        approval_token_lifetime_seconds=900,
        recovery_execution_target="razorpay_test_mode",
        razorpay_key_id=key_id or placeholder_id,
        razorpay_key_secret=key_secret or placeholder_secret,
        replay_enabled=True,
    )


def _shifted_open_incident_events(now: datetime) -> tuple[NormalizedPaymentEvent, ...]:
    dataset = build_development_dataset()
    cutoff = dataset.manifest.starts_at + timedelta(hours=5)
    source_events = tuple(
        event
        for line in dataset.event_artifact.content.splitlines()
        if (event := NormalizedPaymentEvent.model_validate_json(line)).occurred_at < cutoff
    )
    latest_received = max(event.received_at for event in source_events)
    shift = now - timedelta(minutes=5) - latest_received
    shifted: list[NormalizedPaymentEvent] = []
    for event in source_events:
        document = event.model_dump(mode="python")
        document["occurred_at"] = event.occurred_at + shift
        document["received_at"] = event.received_at + shift
        shifted.append(NormalizedPaymentEvent.model_validate(document))
    return tuple(shifted)


async def _persist_completed_events(
    database: Database,
    events: Sequence[NormalizedPaymentEvent],
) -> None:
    async with database.sessions() as session, session.begin():
        identities: list[tuple[NormalizedPaymentEvent, str]] = []
        for event in events:
            internal_id = str(uuid.uuid5(uuid.NAMESPACE_URL, event.razorpay_event_id))
            identities.append((event, internal_id))
            session.add(
                PaymentEventRecord(
                    internal_id=internal_id,
                    merchant_id=event.merchant_id,
                    razorpay_event_id=event.razorpay_event_id,
                    schema_version=event.schema_version,
                    signature_status="verified",
                    event_type=event.event_type.value,
                    payment_id=event.payment.payment_id,
                    occurred_at=event.occurred_at,
                    received_at=event.received_at,
                    payload_sha256=hashlib.sha256(event.model_dump_json().encode()).hexdigest(),
                    sanitized_payload={"synthetic": True},
                    normalized_event=event.model_dump(mode="json"),
                    synthetic=True,
                    created_at=event.received_at,
                )
            )
        await session.flush()
        for event, internal_id in identities:
            session.add(
                OutboxMessageRecord(
                    outbox_id=str(uuid.uuid5(uuid.NAMESPACE_OID, event.razorpay_event_id)),
                    merchant_id=event.merchant_id,
                    event_internal_id=internal_id,
                    topic=PROJECT_PAYMENT_TOPIC,
                    payload={
                        "schema_version": "1.0.0",
                        "event_internal_id": internal_id,
                        "merchant_id": event.merchant_id,
                    },
                    idempotency_key=f"project:{internal_id}",
                    status="completed",
                    attempts=1,
                    max_attempts=5,
                    available_at=event.received_at,
                    completed_at=event.received_at,
                    created_at=event.received_at,
                )
            )


async def _project_evidence_payment(
    database: Database,
    incident: IncidentRecord,
) -> PaymentEventRecord:
    async with database.sessions() as session, session.begin():
        source = await session.scalar(
            select(PaymentEventRecord)
            .where(
                PaymentEventRecord.merchant_id == incident.merchant_id,
                PaymentEventRecord.razorpay_event_id.in_(incident.evidence_event_ids),
                PaymentEventRecord.event_type == PaymentEventType.FAILED.value,
            )
            .order_by(PaymentEventRecord.occurred_at, PaymentEventRecord.internal_id)
            .limit(1)
        )
        if source is None:
            raise TestModeDemoError("detected incident had no failed evidence payment")
        await PaymentProjector().apply(
            session,
            source,
            processed_at=incident.last_observed_at + timedelta(seconds=1),
        )
        return source


async def prepare_demo(database_path: Path) -> PreparedTestModePlan:
    """Create an outcome-free, unapproved Test Mode plan in a fresh local database."""

    settings = _demo_settings(database_path)
    database = Database(settings.database_dsn())
    metrics = PipelineMetrics()
    now = _utc_now()
    try:
        await _persist_completed_events(database, _shifted_open_incident_events(now))
        detection = await DetectionService(
            database,
            metrics,
            runtime_version="v4",
        ).refresh(settings.merchant_id)
        if detection.active_incidents != 1:
            raise TestModeDemoError("M5 demo expected exactly one qualified active incident")
        async with database.sessions() as session:
            incident = await session.scalar(
                select(IncidentRecord).where(
                    IncidentRecord.merchant_id == settings.merchant_id,
                    IncidentRecord.status == "open",
                )
            )
        activation = load_detector_v4_activation()
        if incident is None or not activation.allows_incident(incident):
            raise TestModeDemoError("M5 demo incident did not pass the qualified activation")
        source = await _project_evidence_payment(database, incident)
        analyst = RulesBasedIncidentAnalyst(database, settings, metrics, clock=lambda: now)
        analysis = await analyst.analyze(
            merchant_id=settings.merchant_id,
            incident_id=incident.incident_id,
        )
        if not analysis.fallback_used or not analysis.plan_fallback.can_create_plan:
            raise TestModeDemoError("rules-only analysis did not authorize plan creation")
        workflow = RecoveryWorkflowService(database, settings, metrics, clock=lambda: now)
        result = await workflow.create_preview(
            merchant_id=settings.merchant_id,
            incident_id=incident.incident_id,
            payment_id=source.payment_id,
            idempotency_key="m5_real_test_mode_preview_v1",
        )
        preview = result.preview
        if (
            preview.policy_result.decision is not PolicyDecision.ALLOW
            or preview.execution_target.value != "razorpay_test_mode"
        ):
            raise TestModeDemoError("prepared plan did not pass the Test Mode policy gate")
        return _prepared_plan(preview)
    finally:
        await database.dispose()


def _prepared_plan(preview: RecoveryPlanPreview) -> PreparedTestModePlan:
    return PreparedTestModePlan(
        plan_id=preview.plan.plan_id,
        incident_id=preview.plan.incident_id,
        payment_id=preview.payment_id,
        provider_reference_id=preview.provider_reference_id,
        amount_subunits=preview.amount_subunits,
        currency=preview.currency,
        expires_at=preview.plan.stopping_rules.expires_at,
        external_notifications_enabled=False,
        synthetic=True,
    )


def _read_razorpay_csv(path: Path) -> tuple[SecretStr, SecretStr]:
    try:
        usable_file = path.is_file() and path.stat().st_size <= _MAX_CREDENTIAL_FILE_BYTES
    except OSError as error:
        raise TestModeDemoError("credential CSV could not be inspected safely") from error
    if not usable_file:
        raise TestModeDemoError("credential CSV is missing or exceeds the safe size limit")
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames != ["Key Type", "Value"]:
                raise TestModeDemoError("credential CSV does not match Razorpay's export format")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise TestModeDemoError("credential CSV could not be read safely") from error
    if len(rows) != _CREDENTIAL_ROW_COUNT:
        raise TestModeDemoError("credential CSV must contain exactly two data rows")
    by_type = {row.get("Key Type"): row.get("Value") for row in rows}
    if set(by_type) != {"Test Key ID", "Test Key Secret"}:
        raise TestModeDemoError(
            "credential CSV must contain the Test Key ID and Test Key Secret rows"
        )
    key_id = by_type["Test Key ID"]
    key_secret = by_type["Test Key Secret"]
    values = (key_id, key_secret)
    if any(value is None or not value or value != value.strip() for value in values):
        raise TestModeDemoError("credential CSV contains an empty or malformed value")
    if key_id is None or not key_id.startswith("rzp_test_") or key_secret is None:
        raise TestModeDemoError("credential CSV must contain a Razorpay Test Mode key pair")
    return SecretStr(key_id), SecretStr(key_secret)


async def _load_prepared_preview(
    database: Database,
    settings: Settings,
    metrics: PipelineMetrics,
) -> tuple[RecoveryWorkflowService, RecoveryPlanPreview]:
    workflow = RecoveryWorkflowService(database, settings, metrics)
    async with database.sessions() as session:
        plans = tuple((await session.scalars(select(RecoveryPlanRecord))).all())
        actions = tuple((await session.scalars(select(RecoveryActionRecord))).all())
    if len(plans) != 1:
        raise TestModeDemoError("demo database must contain exactly one prepared plan")
    if actions:
        raise TestModeDemoError(
            "demo already has an action; use reconcile if it is not terminal"
        )
    preview = materialize_preview(
        plans[0],
        await _preview_policy_record(database, plans[0]),
    )
    return workflow, preview


async def _preview_policy_record(
    database: Database,
    plan: RecoveryPlanRecord,
) -> PolicyResultRecord:
    async with database.sessions() as session:
        policy = await session.scalar(
            select(PolicyResultRecord).where(
                PolicyResultRecord.plan_id == plan.plan_id,
                PolicyResultRecord.merchant_id == plan.merchant_id,
                PolicyResultRecord.stage == "preview",
            )
        )
    if policy is None:
        raise TestModeDemoError("prepared plan is missing its preview policy evidence")
    return policy


def approval_challenge(preview: RecoveryPlanPreview) -> str:
    """Return the exact phrase a human must enter in an interactive terminal."""

    return (
        f"APPROVE TEST MODE {preview.plan.plan_id[-12:]} "
        f"{preview.amount_subunits} {preview.currency}"
    )


def require_interactive_approval(
    preview: RecoveryPlanPreview,
    *,
    input_function: Callable[[str], str] = input,
    interactive: bool | None = None,
) -> None:
    """Collect approval outside model/tool execution and reject pipes or near matches."""

    is_interactive = sys.stdin.isatty() if interactive is None else interactive
    if not is_interactive:
        raise TestModeDemoError("human approval requires an interactive terminal")
    challenge = approval_challenge(preview)
    try:
        supplied = input_function(
            f'Type exactly "{challenge}" to approve one Test Mode link: '
        )
    except EOFError as error:
        raise TestModeDemoError(
            "human approval input was not provided; no action was authorized"
        ) from error
    if supplied != challenge:
        raise TestModeDemoError("approval phrase did not match; no action was authorized")


async def execute_demo(
    database_path: Path,
    credential_path: Path,
) -> RazorpayTestModeEvidenceReceipt:
    """After interactive approval, create once and export a sanitized audited receipt."""

    key_id, key_secret = _read_razorpay_csv(credential_path)
    settings = _demo_settings(database_path, key_id=key_id, key_secret=key_secret)
    database = Database(settings.database_dsn())
    metrics = PipelineMetrics()
    provider = RazorpayTestModeAdapter(
        key_id=key_id,
        key_secret=key_secret,
        connect_timeout_seconds=settings.razorpay_connect_timeout_seconds,
        read_timeout_seconds=settings.razorpay_read_timeout_seconds,
    )
    try:
        workflow, preview = await _load_prepared_preview(database, settings, metrics)
        require_interactive_approval(preview)
        approval = await workflow.decide(
            merchant_id=settings.merchant_id,
            plan_id=preview.plan.plan_id,
            actor_id=settings.merchant_approver_id,
            decision=ApprovalDecision.APPROVE,
            idempotency_key="m5_real_test_mode_approval_v1",
        )
        if approval.approval_token is None:
            raise TestModeDemoError("approval token was not issued exactly once")
        executor = RecoveryExecutionService(database, settings, metrics, workflow, provider)
        execution = await executor.execute(
            merchant_id=settings.merchant_id,
            plan_id=preview.plan.plan_id,
            raw_approval_token=approval.approval_token,
            idempotency_key="m5_real_test_mode_execution_v1",
        )
        if execution.receipt is None:
            raise TestModeDemoError("execution stopped before a durable action was created")
        if execution.receipt.state is ActionState.RECONCILIATION_REQUIRED:
            reconciliation = await executor.reconcile(
                merchant_id=settings.merchant_id,
                action_id=execution.receipt.action_id,
                idempotency_key="m5_real_test_mode_reconciliation_v1",
            )
            provider_receipt = reconciliation.provider_receipt
            action_id = reconciliation.receipt.action_id
            terminal_state = reconciliation.receipt.state
        else:
            provider_receipt = execution.provider_receipt
            action_id = execution.receipt.action_id
            terminal_state = execution.receipt.state
        if terminal_state is not ActionState.SUCCEEDED or provider_receipt is None:
            raise TestModeDemoError("Test Mode action did not reach verified success")
        return await _evidence_receipt(
            database,
            settings,
            executor,
            provider_receipt,
            action_id,
        )
    finally:
        await provider.aclose()
        await database.dispose()


async def reconcile_demo(
    database_path: Path,
    credential_path: Path,
) -> RazorpayTestModeEvidenceReceipt:
    """Resume only by provider lookup after a local crash or ambiguous create."""

    key_id, key_secret = _read_razorpay_csv(credential_path)
    settings = _demo_settings(database_path, key_id=key_id, key_secret=key_secret)
    database = Database(settings.database_dsn())
    metrics = PipelineMetrics()
    workflow = RecoveryWorkflowService(database, settings, metrics)
    provider = RazorpayTestModeAdapter(key_id=key_id, key_secret=key_secret)
    executor = RecoveryExecutionService(database, settings, metrics, workflow, provider)
    try:
        async with database.sessions() as session:
            actions = tuple((await session.scalars(select(RecoveryActionRecord))).all())
        if len(actions) != 1:
            raise TestModeDemoError("demo database must contain exactly one dispatched action")
        result = await executor.reconcile(
            merchant_id=settings.merchant_id,
            action_id=actions[0].action_id,
            idempotency_key="m5_real_test_mode_reconciliation_v1",
        )
        if result.receipt.state is not ActionState.SUCCEEDED or result.provider_receipt is None:
            raise TestModeDemoError("lookup did not verify a successful Test Mode link")
        return await _evidence_receipt(
            database,
            settings,
            executor,
            result.provider_receipt,
            result.receipt.action_id,
        )
    finally:
        await provider.aclose()
        await database.dispose()


async def _evidence_receipt(
    database: Database,
    settings: Settings,
    executor: RecoveryExecutionService,
    provider_receipt: RecoveryProviderReceipt,
    action_id: str,
) -> RazorpayTestModeEvidenceReceipt:
    audit = await RecoveryAuditVerifier(database, settings, executor).verify_action(
        merchant_id=settings.merchant_id,
        action_id=action_id,
    )
    if not audit.complete:
        raise TestModeDemoError("Test Mode action exists but its audit is incomplete")
    return RazorpayTestModeEvidenceReceipt(
        evidence_id=stable_identifier("evidence", settings.merchant_id, action_id),
        recorded_at=_utc_now(),
        provider_receipt=provider_receipt,
        audit=audit,
        synthetic=True,
    )


def _write_evidence(evidence: RazorpayTestModeEvidenceReceipt) -> Path:
    path = _REPOSITORY_ROOT / _EVIDENCE_PATH
    content = f"{json.dumps(evidence.model_dump(mode='json'), indent=2, sort_keys=True)}\n"
    if path.exists():
        if path.read_text(encoding="utf-8") == content:
            return path
        raise TestModeDemoError("a different Test Mode evidence artifact already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as destination:
            destination.write(content)
    except FileExistsError as error:
        raise TestModeDemoError("Test Mode evidence artifact was created concurrently") from error
    return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--database-path", type=Path, default=_DEFAULT_DATABASE_PATH)
    for name in ("execute", "reconcile"):
        command = subparsers.add_parser(name)
        command.add_argument("--database-path", type=Path, default=_DEFAULT_DATABASE_PATH)
        command.add_argument("--credential-csv", type=Path, required=True)
    return parser


def _print_plan(plan: PreparedTestModePlan, database_path: Path) -> None:
    amount = plan.amount_subunits / 100
    sys.stdout.write(
        "M5 Test Mode plan prepared; no approval or provider call occurred.\n"
        f"Database: {database_path}\n"
        f"Plan: {plan.plan_id}\n"
        f"Amount: {plan.currency} {amount:.2f} ({plan.amount_subunits} subunits)\n"
        f"Reference: {plan.provider_reference_id}\n"
        f"Expires: {plan.expires_at.isoformat()}\n"
        "Customer notification: OFF (no SMS, email or reminder)\n"
        "Target: Razorpay Test Mode; no real money\n"
    )


def main() -> None:
    """Prepare, human-approve/execute, or lookup-reconcile the one M5 action."""

    arguments = _parser().parse_args()
    configure_logging("INFO")
    try:
        if arguments.command == "prepare":
            database_path = _validated_database_path(arguments.database_path, must_exist=False)
            database_path.parent.mkdir(parents=True, exist_ok=True)
            upgrade_database(_database_url(database_path))
            plan = asyncio.run(prepare_demo(database_path))
            _print_plan(plan, database_path)
            return
        database_path = _validated_database_path(arguments.database_path, must_exist=True)
        credential_path = arguments.credential_csv.expanduser().resolve()
        evidence = asyncio.run(
            execute_demo(database_path, credential_path)
            if arguments.command == "execute"
            else reconcile_demo(database_path, credential_path)
        )
        evidence_path = _write_evidence(evidence)
        provider = evidence.provider_receipt
        sys.stdout.write(
            "Verified one Razorpay Test Mode link and complete audit.\n"
            f"Action: {provider.action_id}\n"
            f"Provider link: {provider.provider_action_id}\n"
            f"Reference: {provider.reference_id}\n"
            f"Status: {provider.status.value}\n"
            f"Short URL: {provider.short_url}\n"
            f"Sanitized evidence: {evidence_path}\n"
        )
    except TestModeDemoError as error:
        sys.stderr.write(f"M5 demo stopped safely: {error}\n")
        raise SystemExit(1) from None
    except RecoveryWorkflowError as error:
        sys.stderr.write(
            "M5 demo stopped safely at the recovery boundary: "
            f"{error.reason_code}\n"
        )
        raise SystemExit(1) from None


if __name__ == "__main__":  # pragma: no cover
    main()
