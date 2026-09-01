"""Typed configuration for the separately versioned detector-v3 candidate."""

from typing import Literal, Self

from pydantic import Field, model_validator

from retryrail.detection.v2_models import DetectorV2Config


class DetectorV3Config(DetectorV2Config):
    """V2-compatible evidence schema with a pre-signal baseline guard."""

    schema_version: Literal["3.0.0"] = "3.0.0"  # type: ignore[assignment]
    detector_version: Literal["detector_v3_0_0"] = "detector_v3_0_0"
    protocol_id: Literal["detector_v3_protocol_v1"] = "detector_v3_protocol_v1"
    protocol_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    development_evidence_ids: tuple[str, str]
    revealed_development_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_guard_minutes: int = Field(gt=0, le=1_440)
    method_confirmation_maximum_minutes: int = Field(gt=0, le=240)
    method_confirmation_tolerates_statistical_misses: Literal[True] = True

    @model_validator(mode="after")
    def validate_v3_boundary(self) -> Self:
        """Require exact evidence identities and a guard covering every window."""

        if self.development_evidence_ids != (
            "detector_v2_development_v1",
            "detector_v2_official_blind_ef49a16703b1612ef774",
        ):
            msg = "detector-v3 development evidence must match the precommitted pair"
            raise ValueError(msg)
        if self.baseline_guard_minutes < max(self.current_window_minutes):
            msg = "baseline guard must cover the maximum current window"
            raise ValueError(msg)
        if self.baseline_guard_minutes % self.step_minutes:
            msg = "baseline guard must align to the detector step"
            raise ValueError(msg)
        minimum_confirmation_minutes = (self.method_confirmation_signals - 1) * self.step_minutes
        if self.method_confirmation_maximum_minutes < minimum_confirmation_minutes:
            msg = "method confirmation maximum cannot precede its signal horizon"
            raise ValueError(msg)
        if self.method_confirmation_maximum_minutes % self.step_minutes:
            msg = "method confirmation maximum must align to the detector step"
            raise ValueError(msg)
        return self
