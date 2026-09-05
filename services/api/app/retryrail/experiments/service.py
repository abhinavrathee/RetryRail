"""Hash-bound read service for the committed M5 synthetic impact report."""

import hashlib
from importlib.resources import files
from pathlib import Path

from pydantic import ValidationError

from retryrail.experiments.models import RecoveryExperimentReport

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_SOURCE_REPORT_PATH = _REPOSITORY_ROOT / "evals/reports/recovery_experiment_v1.report.json"
_PACKAGED_REPORT_PATH = "assets/recovery_experiment_v1.report.json"
_REPORT_SHA256 = "165dbed8d4116aae353a4df85d6dbd1906f5e8bf9e14c25880b08c5996762ec6"


class ExperimentReportNotFoundError(LookupError):
    """Requested experiment does not match the sole frozen M5 report."""


class ExperimentReportEvidenceError(RuntimeError):
    """Committed or packaged experiment evidence failed its exact identity."""


class ExperimentReportService:
    """Validate once, then serve the immutable report without recomputing outcomes."""

    def __init__(self) -> None:
        content = self._read_report_bytes()
        if hashlib.sha256(content).hexdigest() != _REPORT_SHA256:
            msg = "recovery experiment report digest does not match the activated M5 evidence"
            raise ExperimentReportEvidenceError(msg)
        try:
            self._report = RecoveryExperimentReport.model_validate_json(content)
        except ValidationError as error:
            msg = "recovery experiment report failed its strict contract"
            raise ExperimentReportEvidenceError(msg) from error

    @property
    def report(self) -> RecoveryExperimentReport:
        """Return the already validated immutable report."""

        return self._report

    def get(self, experiment_id: str) -> RecoveryExperimentReport:
        """Return the exact report or a tenant-safe not-found result."""

        if experiment_id != self._report.experiment_id:
            raise ExperimentReportNotFoundError
        return self._report

    @staticmethod
    def _read_report_bytes() -> bytes:
        if _SOURCE_REPORT_PATH.is_file():
            return _SOURCE_REPORT_PATH.read_bytes()
        try:
            return files("retryrail.experiments").joinpath(_PACKAGED_REPORT_PATH).read_bytes()
        except (FileNotFoundError, ModuleNotFoundError) as error:
            msg = "recovery experiment report is unavailable"
            raise ExperimentReportEvidenceError(msg) from error
