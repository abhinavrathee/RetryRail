"""Load the detector-v3 candidate without runtime threshold overrides."""

import hashlib
from functools import cache
from pathlib import Path

from retryrail.detection.v3_models import DetectorV3Config

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_CANDIDATE_CONFIG_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v3.candidate.json"


@cache
def load_detector_v3_config(path: Path | None = None) -> DetectorV3Config:
    """Validate the candidate configuration from exact artifact bytes."""

    return DetectorV3Config.model_validate_json((path or _CANDIDATE_CONFIG_PATH).read_bytes())


def detector_v3_config_path() -> Path:
    """Return the repository candidate path used during M3R.4."""

    return _CANDIDATE_CONFIG_PATH


def detector_v3_config_sha256(path: Path | None = None) -> str:
    """Return the exact candidate configuration identity."""

    return hashlib.sha256((path or _CANDIDATE_CONFIG_PATH).read_bytes()).hexdigest()
