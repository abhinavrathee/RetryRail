"""Failure-safe command-line boundaries for local operational tooling."""

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from alembic import command as alembic_command
from alembic.util.exc import CommandError
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError

from retryrail import detect, replay
from retryrail.db import migrate
from retryrail.db.session import DatabaseReadiness
from retryrail.detection.engine import DetectorInputError
from retryrail.detection.service import DetectionPersistenceError, DetectionRefreshResult
from retryrail.events.ingestion import EventIdentityConflictError, EventPersistenceError


class _SettingsStub:
    merchant_id = "merchant_synthetic_001"
    log_level = "INFO"
    webhook_secret = SecretStr("local-synthetic-test-value")
    outbox_max_attempts = 3
    replay_enabled = True
    environment = SimpleNamespace(value="test")

    @staticmethod
    def database_dsn() -> str:
        return "sqlite+aiosqlite:///synthetic-test.db"


def test_detect_run_formats_bounded_result_and_disposes_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disposed: list[bool] = []

    class FakeDatabase:
        def __init__(self, database_url: str) -> None:
            assert database_url.endswith("synthetic-test.db")

        async def dispose(self) -> None:
            disposed.append(True)

    class FakeService:
        def __init__(
            self,
            database: object,
            metrics: object,
            *,
            runtime_version: str,
        ) -> None:
            assert isinstance(database, FakeDatabase)
            assert metrics is not None
            assert runtime_version == "v4"

        async def refresh(self, merchant_id: str) -> DetectionRefreshResult:
            assert merchant_id == _SettingsStub.merchant_id
            return DetectionRefreshResult(
                run_id="run_synthetic",
                reused=False,
                source_events=12,
                attempts=6,
                aggregates=3,
                incidents=1,
                active_incidents=1,
                at_risk_gmv_subunits=100,
            )

    monkeypatch.setattr(detect, "get_settings", _SettingsStub)
    monkeypatch.setattr(detect, "Database", FakeDatabase)
    monkeypatch.setattr(detect, "DetectionService", FakeService)
    monkeypatch.setattr(detect, "PipelineMetrics", object)

    output = asyncio.run(detect._run())  # noqa: SLF001

    assert output == (
        "detector refresh complete: events=12 attempts=6 aggregates=3 "
        "incidents=1 active=1 reused=false"
    )
    assert disposed == [True]


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (DetectionPersistenceError(), "DETECTOR_PERSISTED_EVENT_INVALID"),
        (DetectorInputError(), "DETECTOR_INPUT_INVALID"),
    ],
)
def test_detect_cli_redacts_domain_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    expected: str,
) -> None:
    async def fail() -> str:
        raise error

    monkeypatch.setattr(detect, "get_settings", _SettingsStub)
    monkeypatch.setattr(detect, "configure_logging", lambda _level: None)
    monkeypatch.setattr(detect, "_run", fail)

    with pytest.raises(SystemExit) as raised:
        detect.main()

    assert raised.value.code == 1
    assert capsys.readouterr().err == f"detector refresh failed: {expected}\n"


def test_detect_cli_handles_database_failure_and_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def database_failure() -> str:
        raise SQLAlchemyError

    monkeypatch.setattr(detect, "get_settings", _SettingsStub)
    monkeypatch.setattr(detect, "configure_logging", lambda _level: None)
    monkeypatch.setattr(detect, "_run", database_failure)
    with pytest.raises(SystemExit) as raised:
        detect.main()
    assert raised.value.code == 1
    assert capsys.readouterr().err == (
        "detector refresh failed: DETECTOR_DATABASE_UNAVAILABLE\n"
    )

    async def succeed() -> str:
        return "bounded detector result"

    monkeypatch.setattr(detect, "_run", succeed)
    detect.main()
    assert capsys.readouterr().out == "bounded detector result\n"


def test_migration_wrappers_use_redacted_alembic_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        alembic_command,
        "upgrade",
        lambda _config, revision: calls.append(("upgrade", revision)),
    )
    monkeypatch.setattr(
        alembic_command,
        "downgrade",
        lambda _config, revision: calls.append(("downgrade", revision)),
    )
    monkeypatch.setattr(
        alembic_command,
        "check",
        lambda _config: calls.append(("check", "head")),
    )

    migrate.upgrade_database("postgresql://user:p%ss@invalid/db", "next")
    migrate.downgrade_database("postgresql://user:p%ss@invalid/db", "base")
    migrate.check_database_schema("postgresql://user:p%ss@invalid/db")

    assert calls == [("upgrade", "next"), ("downgrade", "base"), ("check", "head")]


@pytest.mark.parametrize(
    "case",
    [
        ("upgrade", "upgrade_database", "next", "database migration upgrade complete\n"),
        (
            "downgrade",
            "downgrade_database",
            "previous",
            "database migration downgrade complete\n",
        ),
        (
            "schema-check",
            "check_database_schema",
            None,
            "database schema matches committed migrations\n",
        ),
    ],
)
def test_migration_cli_success_paths(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[str, str, str | None, str],
) -> None:
    command_name, function_name, revision, expected = case
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(migrate, "get_settings", _SettingsStub)
    monkeypatch.setattr(migrate, function_name, lambda *args: calls.append(args))
    arguments = ["retryrail-db", command_name]
    if revision is not None:
        arguments.extend(("--revision", revision))
    monkeypatch.setattr("sys.argv", arguments)

    migrate.main()

    assert calls
    assert capsys.readouterr().out == expected


@pytest.mark.parametrize(
    ("command_name", "expected"),
    [
        ("upgrade", "database migration upgrade failed\n"),
        ("downgrade", "database migration downgrade failed\n"),
        ("schema-check", "database schema differs from committed migrations\n"),
    ],
)
def test_migration_cli_redacts_command_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command_name: str,
    expected: str,
) -> None:
    function_name = {
        "upgrade": "upgrade_database",
        "downgrade": "downgrade_database",
        "schema-check": "check_database_schema",
    }[command_name]

    def fail(*_args: object) -> None:
        raise CommandError

    monkeypatch.setattr(migrate, "get_settings", _SettingsStub)
    monkeypatch.setattr(migrate, function_name, fail)
    monkeypatch.setattr("sys.argv", ["retryrail-db", command_name])

    with pytest.raises(SystemExit) as raised:
        migrate.main()

    assert raised.value.code == 1
    assert capsys.readouterr().err == expected


@pytest.mark.parametrize(
    ("readiness", "expected_error", "expected_output"),
    [
        (
            DatabaseReadiness(ready=False, reason_code="DATABASE_MIGRATION_STALE"),
            "database not ready: DATABASE_MIGRATION_STALE\n",
            "",
        ),
        (
            DatabaseReadiness(ready=True, reason_code="READY"),
            "",
            "database is ready and migrations are current\n",
        ),
    ],
)
def test_database_readiness_cli_always_disposes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    readiness: DatabaseReadiness,
    expected_error: str,
    expected_output: str,
) -> None:
    disposed: list[bool] = []

    class FakeDatabase:
        def __init__(self, _database_url: str) -> None:
            pass

        async def readiness(self) -> DatabaseReadiness:
            return readiness

        async def dispose(self) -> None:
            disposed.append(True)

    monkeypatch.setattr(migrate, "get_settings", _SettingsStub)
    monkeypatch.setattr(migrate, "Database", FakeDatabase)
    monkeypatch.setattr("sys.argv", ["retryrail-db", "check"])

    if readiness.ready:
        migrate.main()
    else:
        with pytest.raises(SystemExit) as raised:
            migrate.main()
        assert raised.value.code == 1

    captured = capsys.readouterr()
    assert captured.err == expected_error
    assert captured.out == expected_output
    assert disposed == [True]


def _replay_settings(*, enabled: bool = True, environment: str = "test") -> Any:
    return SimpleNamespace(
        database_dsn=lambda: "sqlite+aiosqlite:///synthetic-test.db",
        webhook_secret=SecretStr("local-synthetic-test-value"),
        outbox_max_attempts=3,
        replay_enabled=enabled,
        environment=SimpleNamespace(value=environment),
        log_level="INFO",
    )


def test_replay_run_cli_disposes_database(monkeypatch: pytest.MonkeyPatch) -> None:
    disposed: list[bool] = []
    expected = replay.ReplayReport("a" * 64, 1, 1, 0, 0, 0)

    class FakeDatabase:
        def __init__(self, _database_url: str) -> None:
            pass

        async def dispose(self) -> None:
            disposed.append(True)

    class FakeRunner:
        def __init__(self, service: object, settings: object) -> None:
            assert service is not None
            assert settings is not None

        async def run(
            self,
            mode: replay.ReplayMode,
            *,
            limit: int | None,
        ) -> replay.ReplayReport:
            assert mode is replay.ReplayMode.REQUIRED_CASES
            assert limit == 1
            return expected

    monkeypatch.setattr(replay, "Database", FakeDatabase)
    monkeypatch.setattr(replay, "PipelineMetrics", object)
    monkeypatch.setattr(replay, "EventIngestionService", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(replay, "ReplayRunner", FakeRunner)

    actual = asyncio.run(
        replay._run_cli(  # noqa: SLF001
            _replay_settings(), replay.ReplayMode.REQUIRED_CASES, 1
        )
    )

    assert actual == expected
    assert disposed == [True]


@pytest.mark.parametrize("limit", [0, 10_001])
def test_replay_cli_rejects_unbounded_limits(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    limit: int,
) -> None:
    monkeypatch.setattr("sys.argv", ["retryrail-replay", "--limit", str(limit)])

    with pytest.raises(SystemExit) as raised:
        replay.main()

    assert raised.value.code == 2
    assert capsys.readouterr().err == "--limit must be between 1 and 10000\n"


@pytest.mark.parametrize(
    "case",
    [(False, "test"), (True, "production")],
)
def test_replay_cli_refuses_disabled_or_production_execution(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[bool, str],
) -> None:
    enabled, environment = case
    monkeypatch.setattr(
        replay,
        "get_settings",
        lambda: _replay_settings(enabled=enabled, environment=environment),
    )
    monkeypatch.setattr(replay, "configure_logging", lambda _level: None)
    monkeypatch.setattr("sys.argv", ["retryrail-replay"])

    with pytest.raises(SystemExit) as raised:
        replay.main()

    assert raised.value.code == 1
    assert capsys.readouterr().err == "synthetic replay is disabled by configuration\n"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (EventIdentityConflictError(), "replay failed: WEBHOOK_EVENT_IDENTITY_CONFLICT\n"),
        (EventPersistenceError(), "replay failed: WEBHOOK_PERSISTENCE_UNAVAILABLE\n"),
    ],
)
def test_replay_cli_redacts_ingestion_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    expected: str,
) -> None:
    async def fail(*_args: object, **_kwargs: object) -> replay.ReplayReport:
        raise error

    monkeypatch.setattr(replay, "get_settings", _replay_settings)
    monkeypatch.setattr(replay, "configure_logging", lambda _level: None)
    monkeypatch.setattr(replay, "_run_cli", fail)
    monkeypatch.setattr("sys.argv", ["retryrail-replay"])

    with pytest.raises(SystemExit) as raised:
        replay.main()

    assert raised.value.code == 1
    assert capsys.readouterr().err == expected


def test_replay_cli_reports_only_aggregate_counts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = replay.ReplayReport("a" * 64, 7, 3, 2, 2, 0)

    async def succeed(*_args: object, **_kwargs: object) -> replay.ReplayReport:
        return report

    monkeypatch.setattr(replay, "get_settings", _replay_settings)
    monkeypatch.setattr(replay, "configure_logging", lambda _level: None)
    monkeypatch.setattr(replay, "_run_cli", succeed)
    monkeypatch.setattr("sys.argv", ["retryrail-replay", "--limit", "7"])

    replay.main()

    assert capsys.readouterr().out == (
        "replay complete: selected=7 accepted=3 duplicates=2 rejected=2 mismatches=0\n"
    )
