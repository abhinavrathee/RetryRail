"""Export and verify committed JSON Schemas from their Pydantic source."""

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from retryrail.contracts.domain import (
    ActionReceiptContract,
    DetectorEvaluationContract,
    IncidentContract,
    RecoveryPlanContract,
)
from retryrail.contracts.recovery import (
    ApprovalRecordContract,
    PolicyResultContract,
    RecoveryActionContract,
    RecoveryTemplateContract,
)
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.experiments.models import (
    ExperimentAssignmentFreeze,
    RecoveryExperimentProtocol,
    RecoveryExperimentReport,
    RecoveryOutcomeBatch,
)
from retryrail.synthetic.models import (
    AttemptGroundTruth,
    ExperimentDesign,
    SyntheticDatasetManifest,
    WebhookDeliveryInstruction,
)
from retryrail.webhooks.payloads import SanitizedRazorpayWebhookPayload

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_EVENT_SCHEMA_PATH = _REPOSITORY_ROOT / "contracts/events/payment_event.v1.schema.json"


@dataclass(frozen=True, slots=True)
class SchemaDefinition:
    """One generated schema and its stable public identity."""

    model: type[BaseModel]
    relative_path: str
    schema_id: str
    title: str


_SCHEMAS = (
    SchemaDefinition(
        model=NormalizedPaymentEvent,
        relative_path="contracts/events/payment_event.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/events/payment-event/v1",
        title="RetryRail Normalized Payment Event v1",
    ),
    SchemaDefinition(
        model=SanitizedRazorpayWebhookPayload,
        relative_path="contracts/events/razorpay_webhook.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/events/razorpay-webhook/v1",
        title="RetryRail Sanitized Razorpay Webhook v1",
    ),
    SchemaDefinition(
        model=WebhookDeliveryInstruction,
        relative_path="contracts/events/webhook_delivery.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/events/webhook-delivery/v1",
        title="RetryRail Webhook Delivery Instruction v1",
    ),
    SchemaDefinition(
        model=IncidentContract,
        relative_path="contracts/domain/incident.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/incident/v1",
        title="RetryRail Incident v1",
    ),
    SchemaDefinition(
        model=RecoveryPlanContract,
        relative_path="contracts/domain/recovery_plan.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/recovery-plan/v1",
        title="RetryRail Recovery Plan v1",
    ),
    SchemaDefinition(
        model=ActionReceiptContract,
        relative_path="contracts/domain/action_receipt.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/action-receipt/v1",
        title="RetryRail Action Receipt v1",
    ),
    SchemaDefinition(
        model=RecoveryTemplateContract,
        relative_path="contracts/domain/recovery_template.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/recovery-template/v1",
        title="RetryRail Recovery Template v1",
    ),
    SchemaDefinition(
        model=PolicyResultContract,
        relative_path="contracts/domain/policy_result.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/policy-result/v1",
        title="RetryRail Policy Result v1",
    ),
    SchemaDefinition(
        model=ApprovalRecordContract,
        relative_path="contracts/domain/approval_record.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/approval-record/v1",
        title="RetryRail Approval Record v1",
    ),
    SchemaDefinition(
        model=RecoveryActionContract,
        relative_path="contracts/domain/recovery_action.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/recovery-action/v1",
        title="RetryRail Recovery Action v1",
    ),
    SchemaDefinition(
        model=DetectorEvaluationContract,
        relative_path="contracts/domain/detector_evaluation.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/detector-evaluation/v1",
        title="RetryRail Detector Evaluation v1",
    ),
    SchemaDefinition(
        model=AttemptGroundTruth,
        relative_path="contracts/domain/attempt_ground_truth.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/attempt-ground-truth/v1",
        title="RetryRail Attempt Ground Truth v1",
    ),
    SchemaDefinition(
        model=SyntheticDatasetManifest,
        relative_path="contracts/domain/synthetic_dataset_manifest.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/synthetic-dataset-manifest/v1",
        title="RetryRail Synthetic Dataset Manifest v1",
    ),
    SchemaDefinition(
        model=ExperimentDesign,
        relative_path="contracts/domain/experiment_design.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/experiment-design/v1",
        title="RetryRail Experiment Design v1",
    ),
    SchemaDefinition(
        model=RecoveryExperimentProtocol,
        relative_path="contracts/domain/recovery_experiment_protocol.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/recovery-experiment-protocol/v1",
        title="RetryRail Recovery Experiment Protocol v1",
    ),
    SchemaDefinition(
        model=ExperimentAssignmentFreeze,
        relative_path="contracts/domain/experiment_assignment_freeze.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/experiment-assignment-freeze/v1",
        title="RetryRail Experiment Assignment Freeze v1",
    ),
    SchemaDefinition(
        model=RecoveryOutcomeBatch,
        relative_path="contracts/domain/recovery_outcome_batch.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/recovery-outcome-batch/v1",
        title="RetryRail Recovery Outcome Batch v1",
    ),
    SchemaDefinition(
        model=RecoveryExperimentReport,
        relative_path="contracts/domain/recovery_experiment_report.v1.schema.json",
        schema_id="https://retryrail.dev/contracts/domain/recovery-experiment-report/v1",
        title="RetryRail Recovery Experiment Report v1",
    ),
)

_FROZEN_M1_SCHEMA_SHA256 = {
    "contracts/domain/recovery_plan.v1.schema.json": (
        "c53a01c5f8cd527559fa0ee7ecbf781ed5785b432cd7bffce5fad9d5d28b0889"
    ),
    "contracts/domain/action_receipt.v1.schema.json": (
        "e1100a957f1c6bb14117e3e6f059ead5ba465af9013be7cb714934545f552ff2"
    ),
}


class FrozenSchemaChangeError(RuntimeError):
    """Raised before an exporter can rewrite a frozen published schema."""


def _render_schema(definition: SchemaDefinition) -> str:
    schema = definition.model.model_json_schema(
        ref_template="#/$defs/{model}",
        mode="validation",
    )
    schema["$id"] = definition.schema_id
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = definition.title
    return f"{json.dumps(schema, indent=2, sort_keys=True)}\n"


def frozen_schema_source_changes() -> tuple[str, ...]:
    """Return frozen M1 schemas whose current model no longer renders canonically."""

    frozen_definitions = {
        definition.relative_path: definition
        for definition in _SCHEMAS
        if definition.relative_path in _FROZEN_M1_SCHEMA_SHA256
    }
    return tuple(
        relative_path
        for relative_path, expected_sha256 in _FROZEN_M1_SCHEMA_SHA256.items()
        if hashlib.sha256(
            _render_schema(frozen_definitions[relative_path]).encode("utf-8")
        ).hexdigest()
        != expected_sha256
    )


def _assert_frozen_schema_sources() -> None:
    """Fail closed when code would silently alter a published M1 schema."""

    changed_paths = frozen_schema_source_changes()
    if changed_paths:
        details = "\n".join(f"- {path}" for path in changed_paths)
        msg = (
            "generated source would alter frozen M1 schemas:\n"
            f"{details}\ncreate a new schema version instead of changing v1"
        )
        raise FrozenSchemaChangeError(msg)


def render_event_schema() -> str:
    """Render the canonical payment-event schema deterministically."""

    return _render_schema(_SCHEMAS[0])


def check_event_schema(path: Path = _EVENT_SCHEMA_PATH) -> bool:
    """Return whether the committed contract is byte-for-byte current."""

    return path.is_file() and path.read_text(encoding="utf-8") == render_event_schema()


def write_event_schema(path: Path = _EVENT_SCHEMA_PATH) -> None:
    """Write the generated schema to its versioned contract path."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_event_schema(), encoding="utf-8", newline="\n")


def stale_schema_paths(root: Path = _REPOSITORY_ROOT) -> tuple[str, ...]:
    """Return every missing or byte-stale committed schema path."""

    return tuple(
        definition.relative_path
        for definition in _SCHEMAS
        if not (root / definition.relative_path).is_file()
        or (root / definition.relative_path).read_text(encoding="utf-8")
        != _render_schema(definition)
    )


def write_all_schemas(root: Path = _REPOSITORY_ROOT) -> None:
    """Write every versioned schema from its Pydantic source model."""

    _assert_frozen_schema_sources()
    for definition in _SCHEMAS:
        path = root / definition.relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_render_schema(definition), encoding="utf-8", newline="\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the committed schema differs from the Pydantic model",
    )
    return parser


def main() -> None:
    """Export the contract or verify the committed representation."""

    arguments = _parser().parse_args()
    try:
        _assert_frozen_schema_sources()
    except FrozenSchemaChangeError as exc:
        sys.stderr.write(f"{exc}\n")
        raise SystemExit(1) from None
    if arguments.check:
        stale_paths = stale_schema_paths()
        if stale_paths:
            sys.stderr.write(
                "missing or stale schemas:\n"
                + "\n".join(f"- {path}" for path in stale_paths)
                + "\nrun `uv run retryrail-contracts`\n"
            )
            raise SystemExit(1)
        sys.stdout.write(f"{len(_SCHEMAS)} contract schemas are current\n")
        return

    write_all_schemas()
    sys.stdout.write(f"wrote {len(_SCHEMAS)} contract schemas\n")


if __name__ == "__main__":  # pragma: no cover
    main()
