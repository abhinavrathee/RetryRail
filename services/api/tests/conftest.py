"""Shared test fixtures with synthetic identifiers only."""

import asyncio
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from retryrail.config import Environment, Settings
from retryrail.db.migrate import downgrade_database, upgrade_database
from retryrail.main import create_app


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
        downgrade_database(database_url)
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
        downgrade_database(database_url)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client
