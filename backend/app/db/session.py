"""Database engine and session management with dual-engine resilience.

Supports async PostgreSQL (production) with automatic fallback to durable
local SQLite (via aiosqlite in var/proofops.db) when external database
is unreachable.
"""
from __future__ import annotations

import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app import paths
from app.config import get_settings
from app.logging_setup import get_logger  # noqa: E402 (M00.5)

logger = get_logger(__name__)


def _async_psycopg_supported() -> bool:
    """Whether async psycopg can run on this platform at all.

    psycopg's async layer needs a selector event loop. Windows' default
    ProactorEventLoop is not one, so on a Windows host the async Postgres engine
    cannot work no matter how reachable the server is.

    This is why the runtime source of truth is the ``python:3.12-slim`` image
    (AGENTS.md 13.2). The Windows host is a unit-test platform: it must fall back
    to sqlite deliberately, not fail at the first query.
    """
    return not (sys.platform == "win32")


_ENGINE: AsyncEngine | None = None
_SESSIONMAKER: async_sessionmaker[AsyncSession] | None = None
_ACTIVE_DIALECT: str = "sqlite"
#: Why we are not on postgres, as an exception *type* only. Never the URL: it
#: carries a password. None means postgres is in use or was never configured.
_FALLBACK_REASON: str | None = None


def get_sqlite_path() -> Path:
    """Return local durable SQLite database path in state dir."""
    state_dir = paths.state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / "proofops.db"


def get_engine() -> AsyncEngine:
    """Lazy-load process-wide async engine with dual-engine fallback."""
    global _ENGINE, _SESSIONMAKER, _ACTIVE_DIALECT
    if _ENGINE is not None:
        return _ENGINE

    settings = get_settings()
    db_url = settings.DATABASE_URL.strip() if settings.DATABASE_URL else ""

    # Attempt PostgreSQL whenever we are configured for it *and* this platform can
    # actually run it, and fall back to the local durable file otherwise.
    #
    # This used to reject any URL containing "@db:5432" on the assumption that
    # hostname was unresolvable. Inside the compose network it is the opposite:
    # `db` IS the Postgres service and resolves fine, so the guard discarded the
    # exact host we are configured to use, silently degraded to the local file,
    # and then 500'd because aiosqlite was never declared.
    #
    # A hostname is not evidence of reachability, and a platform is not evidence
    # of support. Both are now decided by the thing itself: the platform by
    # psycopg's actual requirement, the connection by attempting it.
    use_postgres = bool(db_url and db_url.startswith("postgresql"))
    if use_postgres and not _async_psycopg_supported():
        use_postgres = False
        _FALLBACK_REASON = "async-psycopg-unsupported-on-this-platform"
    if use_postgres:
        try:
            # psycopg async connection string: postgresql+psycopg://...
            if db_url.startswith("postgresql://"):
                db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
            engine = create_async_engine(
                db_url,
                echo=False,
                pool_pre_ping=True,
                future=True,
            )
            _ACTIVE_DIALECT = "postgresql"
            _ENGINE = engine
            _SESSIONMAKER = async_sessionmaker(
                _ENGINE, class_=AsyncSession, expire_on_commit=False
            )
            return _ENGINE
        except Exception as exc:
            # Degrade loudly. An operator must be able to tell whether the audit
            # trail is in Postgres or in a local file, so the reason is kept --
            # as an exception *type* only, never the URL, which carries a
            # password.
            _FALLBACK_REASON = type(exc).__name__
            logger.warning(
                "postgres unavailable (%s); falling back to durable local sqlite",
                _FALLBACK_REASON,
            )

    # Durable local SQLite fallback via aiosqlite
    sqlite_file = get_sqlite_path()
    sqlite_url = f"sqlite+aiosqlite:///{sqlite_file.as_posix()}"
    try:
        _ENGINE = create_async_engine(
            sqlite_url,
            echo=False,
            future=True,
        )
    except Exception as exc:
        # Both engines failed. Refuse loudly rather than pretending to have a
        # datastore: a caller that believes it is persisting, when it is not, is
        # the worst possible state for an audit trail.
        raise RuntimeError(
            "no usable datastore: postgres failed and the sqlite fallback could "
            f"not be initialised ({type(exc).__name__}). Refusing to run without "
            "a datastore rather than silently dropping writes."
        ) from exc
    _ACTIVE_DIALECT = "sqlite"
    _SESSIONMAKER = async_sessionmaker(
        _ENGINE, class_=AsyncSession, expire_on_commit=False
    )
    return _ENGINE


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return sessionmaker, initializing engine if needed."""
    get_engine()
    assert _SESSIONMAKER is not None
    return _SESSIONMAKER


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager for transactional database sessions."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async session."""
    async with get_db_session() as session:
        yield session


async def init_db() -> None:
    """Initialize database schema asynchronously."""
    from app.db.models import Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def db_health() -> dict[str, Any]:
    """Health status check of persistence engine."""
    from sqlalchemy import text

    engine = get_engine()
    healthy = False
    error = ""
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            healthy = result.scalar() == 1
    except Exception as exc:
        error = str(exc)

    return {
        "healthy": healthy,
        "dialect": _ACTIVE_DIALECT,
        "database": "proofops",
        "error": error if error else None,
        # Degraded is reported, never hidden: a local sqlite file is a working
        # fallback, but an operator reading "healthy" must be able to tell that
        # the audit trail is not in Postgres right now.
        "degraded": _ACTIVE_DIALECT != "postgresql",
        "fallback_reason": _FALLBACK_REASON,
    }
