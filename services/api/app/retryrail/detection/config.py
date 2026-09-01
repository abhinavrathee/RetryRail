"""Load and identify committed detector and release-decision artifacts."""

import hashlib
from functools import cache
from pathlib import Path

from retryrail.detection.models import DetectorConfig, DetectorReleaseDecision

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_REPOSITORY_CONFIG_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v1.freeze.json"
_REPOSITORY_RELEASE_PATH = _REPOSITORY_ROOT / "evals/reports/detector_v1.release.json"
_PACKAGED_ASSET_ROOT = Path(__file__).resolve().parent / "assets"
_PACKAGED_CONFIG_PATH = _PACKAGED_ASSET_ROOT / "detector_v1.freeze.json"
_PACKAGED_RELEASE_PATH = _PACKAGED_ASSET_ROOT / "detector_v1.release.json"


class DetectorArtifactMismatchError(RuntimeError):
    """Detector artifacts disagree and consequential use must fail closed."""


def _artifact_path(repository_path: Path, packaged_path: Path) -> Path:
    if repository_path.is_file():
        return repository_path
    return packaged_path


@cache
def load_detector_config(path: Path | None = None) -> DetectorConfig:
    """Validate the frozen configuration without accepting runtime overrides."""

    selected = path or detector_config_path()
    return DetectorConfig.model_validate_json(selected.read_bytes())


def detector_config_sha256(path: Path | None = None) -> str:
    """Return the exact committed threshold artifact identity."""

    selected = path or detector_config_path()
    return hashlib.sha256(selected.read_bytes()).hexdigest()


def detector_config_path() -> Path:
    """Use the checkout artifact when present, otherwise the wheel asset."""

    return _artifact_path(_REPOSITORY_CONFIG_PATH, _PACKAGED_CONFIG_PATH)


def detector_release_path() -> Path:
    """Use the checkout release decision when present, otherwise the wheel asset."""

    return _artifact_path(_REPOSITORY_RELEASE_PATH, _PACKAGED_RELEASE_PATH)


@cache
def load_detector_release_decision(
    path: Path | None = None,
) -> DetectorReleaseDecision:
    """Validate the release decision and its binding to the frozen detector."""

    selected = path or detector_release_path()
    decision = DetectorReleaseDecision.model_validate_json(selected.read_bytes())
    config = load_detector_config()
    if (
        decision.detector_version != config.detector_version
        or decision.detector_config_sha256 != detector_config_sha256()
    ):
        raise DetectorArtifactMismatchError
    return decision
