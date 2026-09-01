"""Safe Alembic command wrapper that never prints the database URL."""

import argparse
import asyncio
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.util.exc import CommandError
from sqlalchemy.exc import SQLAlchemyError

from retryrail.config import get_settings
from retryrail.db.session import Database


def _find_alembic_config() -> Path:
    """Locate repository migration assets in source and installed-container layouts."""

    packaged = Path(__file__).with_name("alembic.ini")
    if packaged.is_file():
        return packaged
    candidates = (Path.cwd(), *Path(__file__).resolve().parents)
    for root in candidates:
        candidate = root / "services/api/alembic.ini"
        if candidate.is_file():
            return candidate
    msg = "services/api/alembic.ini was not found from the current installation"
    raise RuntimeError(msg)


def alembic_config(database_url: str) -> Config:
    """Create an Alembic configuration without logging credential-bearing URLs."""

    configuration = Config(str(_find_alembic_config()))
    configuration.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return configuration


def upgrade_database(database_url: str, revision: str = "head") -> None:
    """Upgrade a database to the requested migration revision."""

    command.upgrade(alembic_config(database_url), revision)


def downgrade_database(database_url: str, revision: str = "base") -> None:
    """Downgrade a database explicitly for migration verification."""

    command.downgrade(alembic_config(database_url), revision)


def check_database_schema(database_url: str) -> None:
    """Fail when ORM metadata would require an uncommitted migration."""

    command.check(alembic_config(database_url))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("upgrade", "downgrade", "check", "schema-check"),
    )
    parser.add_argument("--revision", default=None)
    return parser


def main() -> None:
    """Run a bounded database migration or readiness command."""

    arguments = _parser().parse_args()
    settings = get_settings()
    if arguments.command == "upgrade":
        try:
            upgrade_database(settings.database_dsn(), arguments.revision or "head")
        except (CommandError, SQLAlchemyError):
            sys.stderr.write("database migration upgrade failed\n")
            raise SystemExit(1) from None
        sys.stdout.write("database migration upgrade complete\n")
        return
    if arguments.command == "downgrade":
        try:
            downgrade_database(settings.database_dsn(), arguments.revision or "base")
        except (CommandError, SQLAlchemyError):
            sys.stderr.write("database migration downgrade failed\n")
            raise SystemExit(1) from None
        sys.stdout.write("database migration downgrade complete\n")
        return
    if arguments.command == "schema-check":
        try:
            check_database_schema(settings.database_dsn())
        except (CommandError, SQLAlchemyError):
            sys.stderr.write("database schema differs from committed migrations\n")
            raise SystemExit(1) from None
        sys.stdout.write("database schema matches committed migrations\n")
        return

    async def check() -> bool:
        database = Database(settings.database_dsn())
        try:
            readiness = await database.readiness()
        finally:
            await database.dispose()
        if not readiness.ready:
            sys.stderr.write(f"database not ready: {readiness.reason_code}\n")
        return readiness.ready

    if not asyncio.run(check()):
        raise SystemExit(1)
    sys.stdout.write("database is ready and migrations are current\n")


if __name__ == "__main__":  # pragma: no cover
    main()
