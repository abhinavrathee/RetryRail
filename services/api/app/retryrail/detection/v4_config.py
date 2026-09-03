"""Load the detector-v4 development candidate without runtime overrides."""

import hashlib
from functools import cache
from pathlib import Path

from retryrail.detection.v4_models import DetectorV4Config

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_CANDIDATE_CONFIG_PATH = _REPOSITORY_ROOT / "evals/golden/detector_v4.candidate.json"


@cache
def load_detector_v4_config(path: Path | None = None) -> DetectorV4Config:
    """Validate the separately versioned candidate from exact artifact bytes."""

    return DetectorV4Config.model_validate_json(
        (path or _CANDIDATE_CONFIG_PATH).read_bytes()
    )


def detector_v4_config_path() -> Path:
    """Return the candidate path used only by detector-v4 development."""

    return _CANDIDATE_CONFIG_PATH


def detector_v4_config_sha256(path: Path | None = None) -> str:
    """Return the exact candidate configuration identity."""

    return hashlib.sha256((path or _CANDIDATE_CONFIG_PATH).read_bytes()).hexdigest()
