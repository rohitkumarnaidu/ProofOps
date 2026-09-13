"""M00.4 health checks & readiness (dependency depth).

Two distinct signals (do not conflate):
- LIVENESS  (/healthz, M00.1 contract, byte-identical): the process is alive.
  Answers 200 even with dependencies down. Drives the image HEALTHCHECK and
  the restart policy: only a dead process should restart a container.
- READINESS (/readyz, M00.4): the app can serve traffic. Checks every
  configured dependency with a bounded timeout. 200 when ready, 503 when not.
  A flapping dependency must NEVER restart the container — hence HEALTHCHECK
  stays on /healthz (decision documented in docs/HEALTH.md).

This module owns probe logic only. No product behavior, no migrations.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import psycopg

SERVICE_NAME = "proofops-api"
SPEC_ID = "PS03_FINAL_SPEC_V2"

# Bounded so /readyz degrades fast instead of hanging callers/orchestrators.
DEFAULT_PROBE_TIMEOUT_S = 2.0


@dataclass(frozen=True)
class DatabaseCheck:
    ok: bool
    latency_ms: float | None
    error: str | None  # static text only; DSN/credentials never echoed


def _to_psycopg_dsn(dsn: str) -> str:
    # App contract (M00.2) stores the SQLAlchemy dialect; psycopg wants the
    # plain scheme. Convert at this boundary, nowhere else.
    return dsn.replace("+psycopg", "", 1)


def check_database(dsn: str, timeout_s: float = DEFAULT_PROBE_TIMEOUT_S) -> DatabaseCheck:
    """Probe the configured database. Never raises; never echoes the DSN."""
    if not dsn or not dsn.strip():
        return DatabaseCheck(ok=False, latency_ms=None,
                             error="database DSN is not configured")
    if not dsn.startswith("postgresql"):
        return DatabaseCheck(ok=False, latency_ms=None,
                             error="database DSN must use a postgresql scheme")
    start = time.perf_counter()
    try:
        conn = psycopg.connect(_to_psycopg_dsn(dsn),
                               connect_timeout=timeout_s)  # type: ignore[arg-type]  # noqa: E501
        # Stub types connect_timeout as str|int|None but the runtime accepts a
        # float (verified: refused-port probe fails closed as "unreachable",
        # never as a timeout-value error). Keep float for sub-second budgets.
    except Exception:
        # Static reason: psycopg errors embed host/user/password details.
        return DatabaseCheck(ok=False, latency_ms=None,
                             error="database unreachable")
    try:
        conn.execute("SELECT 1").fetchall()
        latency_ms = (time.perf_counter() - start) * 1000.0
        return DatabaseCheck(ok=True, latency_ms=round(latency_ms, 2),
                             error=None)
    except Exception:
        return DatabaseCheck(ok=False, latency_ms=None,
                             error="database query failed")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def readiness(database_url: str,
              timeout_s: float = DEFAULT_PROBE_TIMEOUT_S) -> dict[str, Any]:
    """Build the /readyz body. Secret-free by construction (no DSN in/out)."""
    db = check_database(database_url, timeout_s)
    ready = db.ok
    body: dict[str, Any] = {
        "service": SERVICE_NAME,
        "status": "ready" if ready else "not-ready",
        "spec": SPEC_ID,
        "checks": {
            "database": {"ok": db.ok, "latency_ms": db.latency_ms,
                         "error": db.error},
        },
    }
    return body
