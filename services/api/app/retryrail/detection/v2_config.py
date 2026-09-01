"""Load the detector-v2 candidate artifact without runtime threshold overrides."""

import hashlib
from functools import cache
from pathlib import Path

from retryrail.detection.v2_models import DetectorV2Config

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_CANDIDATE_CONFIG_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v2.candidate.json"


@cache
def load_detector_v2_config(path: Path | None = None) -> DetectorV2Config:
    """Validate the frozen candidate configuration from exact artifact bytes."""

    return DetectorV2Config.model_validate_json(
        (path or _CANDIDATE_CONFIG_PATH).read_bytes()
    )


def detector_v2_config_path() -> Path:
    """Return the repository candidate path used during R2/R3."""

    return _CANDIDATE_CONFIG_PATH


def detector_v2_config_sha256(path: Path | None = None) -> str:
    """Return the exact candidate configuration identity."""

    return hashlib.sha256((path or _CANDIDATE_CONFIG_PATH).read_bytes()).hexdigest()
