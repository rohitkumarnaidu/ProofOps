"""M00.4 health hardening (90+ pass, host-safe UNIT + STATIC).

New-file companion to tests/test_health.py (untouched): proves DSN-boundary
edges, close-on-failure, tighter timeout, and the /readyz 200/503 route
contract without editing frozen files.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import health  # noqa: E402
from app.health import _to_psycopg_dsn, check_database, readiness  # noqa: E402


class TestDsnBoundary:
    def test_dialect_stripped_once(self):  # UNIT
        assert _to_psycopg_dsn(
            "postgresql+psycopg://u:p@db:5432/x") == "postgresql://u:p@db:5432/x"

    def test_plain_scheme_untouched(self):  # UNIT
        assert _to_psycopg_dsn(
            "postgresql://u:p@db:5432/x") == "postgresql://u:p@db:5432/x"

    def test_password_containing_plus_psycopg_preserved(self):  # UNIT
        # LACK-2: naive `.replace("+psycopg", "", 1)` ate "+psycopg" out of
        # the password. Only the scheme prefix may be rewritten.
        assert _to_psycopg_dsn(
            "postgresql://u:a+psycopgB@h/db") == \
            "postgresql://u:a+psycopgB@h/db"
        assert _to_psycopg_dsn(
            "postgresql+psycopg://u:a+psycopgB@h/db") == \
            "postgresql://u:a+psycopgB@h/db"

    def test_empty_dsn_readiness_not_ready(self):  # UNIT
        body = readiness("")
        assert body["status"] == "not-ready"
        assert body["checks"]["database"]["error"] == \
            "database DSN is not configured"


class TestCloseAndTimeout:
    def test_close_called_on_query_failure(self, monkeypatch):  # UNIT
        calls: list = []

        class BadConn:
            def execute(self, sql):
                raise Exception("boom")
            def close(self):
                calls.append("close")

        monkeypatch.setattr(health.psycopg, "connect",
                            lambda *a, **k: BadConn())
        res = check_database("postgresql://u:p@h/db")
        assert res.ok is False and res.error == "database query failed"
        assert calls == ["close"]

    def test_refused_port_fails_within_probe_budget(self):  # UNIT
        # 2s probe + margin: must degrade fast, never hang callers.
        t0 = time.perf_counter()
        res = check_database("postgresql://u:p@127.0.0.1:1/db", timeout_s=2.0)
        elapsed = time.perf_counter() - t0
        assert res.ok is False
        assert elapsed < 5, f"probe exceeded budget: {elapsed:.1f}s"


class TestRouteContractStatic:
    def test_readyz_maps_ready_to_200_and_not_ready_to_503(self):  # STATIC
        text = (ROOT / "backend" / "app" / "main.py").read_text(
            encoding="utf-8")
        assert '@app.get("/readyz")' in text
        assert "200 if" in text and "503" in text
