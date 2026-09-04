"""Post-freeze M4 activation gate for the qualified detector-v4 artifacts."""

import hashlib
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from retryrail.db.tables import IncidentRecord
from retryrail.detection.v4_blind_models import (
    V4BlindReleaseDecision,
    V4BlindReleaseStatus,
)
from retryrail.detection.v4_models import DetectorV4Config

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_V4_RUN_ID = "detector_v4_official_blind_5497598109b06d21c625"
_V4_RUN_ROOT = _REPOSITORY_ROOT / "evals/blind/detector_v4/runs" / _V4_RUN_ID
_V4_RELEASE_PATH = _V4_RUN_ROOT / "blind.release.v1.json"
_V4_REPORT_PATH = _V4_RUN_ROOT / "blind.report.v1.json"
_PACKAGED_ASSET_ROOT = Path(__file__).resolve().parent / "assets"
_PACKAGED_CONFIG_PATH = _PACKAGED_ASSET_ROOT / "detector_v4.candidate.json"
_PACKAGED_RELEASE_PATH = _PACKAGED_ASSET_ROOT / "detector_v4.blind.release.v1.json"
_PACKAGED_REPORT_PATH = _PACKAGED_ASSET_ROOT / "detector_v4.blind.report.v1.json"
M4_DETECTOR_ACTIVATION_VERSION = "m4_detector_v4_activation_v1_0_0"
ACTIVATED_DETECTOR_V4_CONFIG_SHA256 = (
    "c94c10e257599ec59e323bfbc9ba9a1084bf0607c18d0ebdcdfba5a602f9527b"
)
ACTIVATED_DETECTOR_V4_RELEASE_SHA256 = (
    "da633356f34e358327be73bf733165b9993fdbb4d159bf7ace9fa512813a0faa"
)
ACTIVATED_DETECTOR_V4_REPORT_SHA256 = (
    "b39d1e389920b2c2c03ba7dc0ec1feb4694788a03c38bac2e025f125c1552e4d"
)


class DetectorV4ActivationError(RuntimeError):
    """Qualified artifacts are absent, inconsistent or not approved for M4."""


@dataclass(frozen=True, slots=True)
class DetectorV4Activation:
    """Verified release identity that M4 may turn into runtime eligibility."""

    detector_version: str
    detector_config_sha256: str
    release_decision_sha256: str
    source_report_sha256: str
    status: V4BlindReleaseStatus
    action_eligible: bool
    activation_version: str = M4_DETECTOR_ACTIVATION_VERSION

    def allows_incident(self, incident: IncidentRecord) -> bool:
        """Require both detector-set eligibility and exact activated artifact identity."""

        return (
            self.action_eligible
            and incident.action_eligible
            and incident.status == "open"
            and incident.detector_version == self.detector_version
            and incident.detector_config_sha256 == self.detector_config_sha256
            and incident.synthetic
        )


@cache
def load_activated_detector_v4_config() -> DetectorV4Config:
    """Load the frozen v4 bytes through an additive checkout-or-wheel boundary."""

    path = (
        _REPOSITORY_ROOT / "evals/golden/detector_v4.candidate.json"
        if (_REPOSITORY_ROOT / "evals/golden/detector_v4.candidate.json").is_file()
        else _PACKAGED_CONFIG_PATH
    )
    try:
        config_bytes = path.read_bytes()
        if (
            hashlib.sha256(config_bytes).hexdigest()
            != ACTIVATED_DETECTOR_V4_CONFIG_SHA256
        ):
            raise DetectorV4ActivationError
        return DetectorV4Config.model_validate_json(config_bytes)
    except (OSError, ValueError) as error:
        raise DetectorV4ActivationError from error


@cache
def load_detector_v4_activation() -> DetectorV4Activation:
    """Validate the append-only release and activate it only behind completed M4 gates."""

    try:
        release_path = (
            _V4_RELEASE_PATH if _V4_RELEASE_PATH.is_file() else _PACKAGED_RELEASE_PATH
        )
        report_path = _V4_REPORT_PATH if _V4_REPORT_PATH.is_file() else _PACKAGED_REPORT_PATH
        release_bytes = release_path.read_bytes()
        report_bytes = report_path.read_bytes()
        release = V4BlindReleaseDecision.model_validate_json(release_bytes)
        config = load_activated_detector_v4_config()
    except (OSError, ValueError) as error:
        raise DetectorV4ActivationError from error
    config_sha256 = ACTIVATED_DETECTOR_V4_CONFIG_SHA256
    release_sha256 = hashlib.sha256(release_bytes).hexdigest()
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    qualified = (
        release_sha256 == ACTIVATED_DETECTOR_V4_RELEASE_SHA256
        and report_sha256 == ACTIVATED_DETECTOR_V4_REPORT_SHA256
        and release.run_id == _V4_RUN_ID
        and release.status is V4BlindReleaseStatus.QUALIFIED
        and release.release_qualified
        and release.approved_for_m4_integration
        and release.activation_requires_m4
        and not release.failed_targets
        and not release.runtime_action_eligible
        and release.detector_version == config.detector_version
        and release.detector_config_sha256 == config_sha256
        and release.source_report_sha256 == report_sha256
    )
    if not qualified:
        raise DetectorV4ActivationError
    return DetectorV4Activation(
        detector_version=release.detector_version,
        detector_config_sha256=config_sha256,
        release_decision_sha256=release_sha256,
        source_report_sha256=report_sha256,
        status=release.status,
        action_eligible=True,
    )
