"""Independent digest pins for the post-freeze detector-v4 activation gate."""

from collections.abc import Iterator
from pathlib import Path

import pytest

import retryrail.detection.runtime_activation as activation_module
from retryrail.detection.runtime_activation import DetectorV4ActivationError


@pytest.fixture(autouse=True)
def clear_activation_caches() -> Iterator[None]:
    """Keep monkeypatched artifact paths isolated across activation tests."""

    activation_module.load_activated_detector_v4_config.cache_clear()
    activation_module.load_detector_v4_activation.cache_clear()
    yield
    activation_module.load_activated_detector_v4_config.cache_clear()
    activation_module.load_detector_v4_activation.cache_clear()


def test_exact_qualified_artifacts_activate() -> None:
    activation = activation_module.load_detector_v4_activation()

    assert activation.action_eligible is True
    assert (
        activation.detector_config_sha256
        == activation_module.ACTIVATED_DETECTOR_V4_CONFIG_SHA256
    )
    assert (
        activation.release_decision_sha256
        == activation_module.ACTIVATED_DETECTOR_V4_RELEASE_SHA256
    )
    assert (
        activation.source_report_sha256
        == activation_module.ACTIVATED_DETECTOR_V4_REPORT_SHA256
    )


@pytest.mark.parametrize("tampered_artifact", ["config", "release", "report"])
def test_any_independently_tampered_artifact_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tampered_artifact: str,
) -> None:
    source_root = Path(__file__).resolve().parents[4]
    run_root = (
        source_root
        / "evals/blind/detector_v4/runs"
        / "detector_v4_official_blind_5497598109b06d21c625"
    )
    payloads = {
        "config": (source_root / "evals/golden/detector_v4.candidate.json").read_bytes(),
        "release": (run_root / "blind.release.v1.json").read_bytes(),
        "report": (run_root / "blind.report.v1.json").read_bytes(),
    }
    payloads[tampered_artifact] += b"\n"

    packaged = tmp_path / "assets"
    packaged.mkdir()
    config_path = packaged / "detector_v4.candidate.json"
    release_path = packaged / "detector_v4.blind.release.v1.json"
    report_path = packaged / "detector_v4.blind.report.v1.json"
    config_path.write_bytes(payloads["config"])
    release_path.write_bytes(payloads["release"])
    report_path.write_bytes(payloads["report"])

    absent_checkout = tmp_path / "no-source-checkout"
    monkeypatch.setattr(activation_module, "_REPOSITORY_ROOT", absent_checkout)
    monkeypatch.setattr(activation_module, "_V4_RELEASE_PATH", absent_checkout / "release")
    monkeypatch.setattr(activation_module, "_V4_REPORT_PATH", absent_checkout / "report")
    monkeypatch.setattr(activation_module, "_PACKAGED_CONFIG_PATH", config_path)
    monkeypatch.setattr(activation_module, "_PACKAGED_RELEASE_PATH", release_path)
    monkeypatch.setattr(activation_module, "_PACKAGED_REPORT_PATH", report_path)

    with pytest.raises(DetectorV4ActivationError):
        activation_module.load_detector_v4_activation()
