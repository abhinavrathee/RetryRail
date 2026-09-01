"""Async database lifecycle and bounded readiness checks."""

from dataclasses import dataclass

from sqlalchemy import event, text
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

MIGRATION_HEAD = "0001_m2_event_pipeline"


@dataclass(frozen=True, slots=True)
class DatabaseReadiness:
    """Safe readiness result without connection details."""

    ready: bool
    reason_code: str


class Database:
    """Own one async engine and session factory per process."""

    def __init__(self, database_url: str) -> None:
        self.engine: AsyncEngine = create_async_engine(
            database_url,
            pool_pre_ping=True,
        )
        self.sessions = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        if self.engine.dialect.name == "sqlite":
            event.listen(self.engine.sync_engine, "connect", _enable_sqlite_foreign_keys)

    async def readiness(self) -> DatabaseReadiness:
        """Check connectivity and the exact expected migration revision."""

        try:
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return DatabaseReadiness(ready=False, reason_code="DATABASE_UNAVAILABLE")
        try:
            async with self.engine.connect() as connection:
                revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
        except SQLAlchemyError:
            return DatabaseReadiness(ready=False, reason_code="DATABASE_MIGRATION_MISSING")
        if revision != MIGRATION_HEAD:
            return DatabaseReadiness(ready=False, reason_code="DATABASE_MIGRATION_STALE")
        return DatabaseReadiness(ready=True, reason_code="READY")

    async def dispose(self) -> None:
        """Close pooled connections during graceful process shutdown."""

        await self.engine.dispose()


def _enable_sqlite_foreign_keys(connection: DBAPIConnection, _record: object) -> None:
    """Keep local integration behavior aligned with PostgreSQL foreign keys."""

    cursor = connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()
