"""Shared test fixtures with synthetic identifiers only."""

import asyncio
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from retryrail.config import Environment, Settings
from retryrail.db.migrate import upgrade_database
from retryrail.main import create_app


def _reset_local_postgres_test_schema(database_url: str) -> None:
    """Reset only the explicitly named local CI database between tests."""

    url = make_url(database_url)
    if (
        url.get_backend_name() != "postgresql"
        or url.database != "retryrail_test"
        or url.host not in {"127.0.0.1", "localhost"}
    ):
        msg = "PostgreSQL tests require the local retryrail_test database"
        raise pytest.UsageError(msg)
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public AUTHORIZATION CURRENT_USER"))
    finally:
        engine.dispose()


@pytest.fixture
def settings(tmp_path: Path) -> Iterator[Settings]:
    postgres_url = os.environ.get("RETRYRAIL_TEST_DATABASE_URL")
    if postgres_url is None:
        database_path = (tmp_path / "retryrail-test.sqlite3").resolve().as_posix()
        database_url = f"sqlite+aiosqlite:///{database_path}"
    else:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        database_url = postgres_url
        _reset_local_postgres_test_schema(database_url)
    upgrade_database(database_url)
    configured = Settings(
        environment=Environment.TEST,
        database_url=database_url,
        webhook_secret=SecretStr("unit-test-secret-not-a-real-credential"),
        merchant_approval_secret=SecretStr(
            "unit-test-merchant-approval-secret-value"
        ),
        approval_token_hmac_key=SecretStr(
            "unit-test-approval-token-hmac-key-value"
        ),
        replay_enabled=True,
        replay_token=SecretStr("unit-test-replay-token"),
        worker_poll_interval_seconds=0.01,
    )
    yield configured
    if postgres_url is not None:
        _reset_local_postgres_test_schema(database_url)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client
