"""Database engine and session management with dual-engine resilience.

Supports async PostgreSQL (production) with automatic fallback to durable
local SQLite (via aiosqlite in var/proofops.db) when external database
is unreachable.
"""
from __future__ import annotations

import asyncio
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

_ENGINE: AsyncEngine | None = None
_SESSIONMAKER: async_sessionmaker[AsyncSession] | None = None
_ACTIVE_DIALECT: str = "sqlite"


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

    # Prefer PostgreSQL if explicit host provided and not unresolvable 'db:5432'
    use_postgres = bool(
        db_url
        and db_url.startswith("postgresql")
        and "@db:5432" not in db_url
    )

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
        except Exception:
            pass

    # Durable local SQLite fallback via aiosqlite
    sqlite_file = get_sqlite_path()
    sqlite_url = f"sqlite+aiosqlite:///{sqlite_file.as_posix()}"
    _ENGINE = create_async_engine(
        sqlite_url,
        echo=False,
        future=True,
    )
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
    }
