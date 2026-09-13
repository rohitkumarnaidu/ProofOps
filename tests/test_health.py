"""M00.4 health checks & readiness (host-safe UNIT + SECURITY).

health.py imports psycopg only (present on host), never fastapi — so these
run on ANY host Python. Route status codes (/readyz 200/503) are proven live
in tests/test_health_runtime.py (host fastapi is broken by design).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import health  # noqa: E402
from app.health import (  # noqa: E402
    check_database,
    readiness,
)

FAKE_PASSWORD = "hunter2-fake-db-pass"


class _FakeConn:
    def __init__(self, calls: list):
        self._calls = calls

    def execute(self, sql: str):
        self._calls.append(sql)
        return self

    def fetchall(self):
        return [(1,)]

    def close(self):
        self._calls.append("close")


def _patch_connect(monkeypatch: pytest.MonkeyPatch, seen: dict,
                   exc: Exception | None = None):
    def fake(conninfo: str = "", **kwargs):
        seen["conninfo"] = conninfo
        seen["kwargs"] = kwargs
        if exc is not None:
            raise exc
        return _FakeConn(seen.setdefault("calls", []))
    monkeypatch.setattr(health.psycopg, "connect", fake)


DSN = "postgresql+psycopg://proofops:hunter2-fake-db-pass@db:5432/proofops"


class TestPositive:
    def test_ready_path(self, monkeypatch):  # UNIT
        seen: dict = {}
        _patch_connect(monkeypatch, seen)
        res = check_database(DSN, timeout_s=2.0)
        assert res.ok is True and res.error is None
        assert res.latency_ms is not None and res.latency_ms >= 0
        assert "+psycopg" not in seen["conninfo"], "dialect must be converted"
        assert seen["kwargs"].get("connect_timeout") == 2.0, \
            "bounded timeout must reach the driver"
        assert "SELECT 1" in seen["calls"] and "close" in seen["calls"]

    def test_readiness_body_shape(self, monkeypatch):  # UNIT
        seen: dict = {}
        _patch_connect(monkeypatch, seen)
        body = readiness(DSN)
        assert body == {
            "service": "proofops-api",
            "status": "ready",
            "spec": "PS03_FINAL_SPEC_V2",
            "checks": {"database": {"ok": True,
                                    "latency_ms": body["checks"]["database"]["latency_ms"],
                                    "error": None}},
        }

    def test_check_is_frozen_value(self, monkeypatch):  # UNIT
        seen: dict = {}
        _patch_connect(monkeypatch, seen)
        res = check_database(DSN)
        with pytest.raises(Exception, match="cannot assign|frozen|Frozen"):
            res.ok = False  # type: ignore[misc]


class TestNegative:
    def test_empty_dsn(self):  # UNIT
        for bad in ("", "   "):
            res = check_database(bad)
            assert res.ok is False and res.latency_ms is None
            assert "not configured" in (res.error or "")

    def test_bad_scheme(self):  # UNIT
        res = check_database("sqlite:///x.db")
        assert res.ok is False
        assert "postgresql" in (res.error or "")

    def test_refused_port_fails_fast(self):  # UNIT
        # Nothing listens on 1: must fail closed quickly, not hang.
        t0 = time.perf_counter()
        res = check_database("postgresql://u:p@127.0.0.1:1/db", timeout_s=2.0)
        elapsed = time.perf_counter() - t0
        assert res.ok is False and res.error == "database unreachable"
        assert elapsed < 10, f"probe hung: {elapsed:.1f}s"

    def test_driver_error_sanitized(self, monkeypatch):  # UNIT
        seen: dict = {}
        _patch_connect(monkeypatch, seen,
                       exc=Exception("password authentication failed for "
                                     f"user proofops password={FAKE_PASSWORD}"))
        res = check_database(DSN)
        assert res.ok is False
        assert res.error == "database unreachable"
        assert FAKE_PASSWORD not in (res.error or "")

    def test_query_error_sanitized(self, monkeypatch):  # UNIT
        class BadConn(_FakeConn):
            def execute(self, sql: str):
                raise Exception(f"syntax near '{FAKE_PASSWORD}'")
        monkeypatch.setattr(health.psycopg, "connect",
                            lambda *a, **k: BadConn([]))
        res = check_database(DSN)
        assert res.ok is False and res.error == "database query failed"


class TestSecurity:
    def test_no_secret_in_body(self, monkeypatch):  # SECURITY
        seen: dict = {}
        _patch_connect(monkeypatch, seen)
        blob = repr(readiness(DSN))
        assert FAKE_PASSWORD not in blob
        assert "DATABASE_URL" not in blob and "APPROVAL_SECRET" not in blob

    def test_no_secret_in_failures(self):  # SECURITY
        res = check_database("mysql://root:hunter2-fake@h/db")
        assert "hunter2-fake" not in repr(res)

    def test_not_ready_shape(self, monkeypatch):  # SECURITY
        seen: dict = {}
        _patch_connect(monkeypatch, seen, exc=Exception("down"))
        body = readiness("postgresql://u:hunter2-fake@h/db")
        assert body["status"] == "not-ready"
        assert body["checks"]["database"] == {
            "ok": False, "latency_ms": None, "error": "database unreachable"}
        assert "hunter2-fake" not in repr(body)
