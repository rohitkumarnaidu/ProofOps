"""M00.4 readiness live proofs (RUNTIME: real daemon only).

/readyz 200/503 codes, dependency-down matrix (db stop/start), healthz
stability across it all, restart recovery, log hygiene. Skipped honestly
without a daemon — never counted as a pass. Leaves the stack UP + healthy.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SECRET_URI_RE = re.compile(r"://[^@\s]+@")


def _scrub(text: str) -> str:
    return _SECRET_URI_RE.sub("://<REDACTED>@", text)


def _daemon_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=30).returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _daemon_ok(), reason="no docker daemon; live readiness unprovable")


def _compose(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", *args], capture_output=True,
                          text=True, cwd=ROOT, timeout=timeout)


def _get(path: str, timeout: int = 15) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(f"http://localhost:8000{path}",
                                    timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _health(svc: str) -> str:
    cid = subprocess.run(["docker", "compose", "ps", "-q", svc],
                         capture_output=True, text=True, cwd=ROOT,
                         timeout=30).stdout.strip().splitlines()
    if not cid:
        return "missing"
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Health.Status}}", cid[0]],
        capture_output=True, text=True, timeout=30)
    return out.stdout.strip() or "missing"


def _wait_all_healthy(timeout_s: int = 240) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if all(_health(s) == "healthy" for s in ("db", "api", "ui")):
            return
        time.sleep(2)
    pytest.fail("stack did not converge to 3x healthy")


def _ensure_up() -> None:
    proc = _compose("up", "-d", timeout=240)
    assert proc.returncode == 0, _scrub(proc.stderr[-800:])
    _wait_all_healthy()


class TestReadinessLive:
    def test_ready_when_db_up(self):  # RUNTIME
        _ensure_up()
        code, body = _get("/readyz")
        assert code == 200, body
        assert body["status"] == "ready"
        assert body["checks"]["database"]["ok"] is True
        assert body["checks"]["database"]["latency_ms"] is not None
        assert "DATABASE_URL" not in json.dumps(body)

    def test_not_ready_when_db_down(self):  # RUNTIME
        # The M00.3-pinned gap, closed: /readyz goes 503 while /healthz stays
        # 200 (liveness vs readiness split, by design).
        try:
            _ensure_up()
            assert _compose("stop", "db", timeout=120).returncode == 0
            deadline = time.time() + 60
            seen_503 = False
            while time.time() < deadline:
                code, body = _get("/readyz", timeout=10)
                if code == 503 and body["status"] == "not-ready":
                    seen_503 = True
                    break
                time.sleep(2)
            assert seen_503, "readyz never went 503 with db down"
            hcode, hbody = _get("/healthz")
            assert hcode == 200 and hbody["status"] == "ok"
            assert body["checks"]["database"]["error"] == "database unreachable"
        finally:
            assert _compose("start", "db", timeout=180).returncode == 0
            _wait_all_healthy()
            code, body = _get("/readyz")
            assert code == 200 and body["status"] == "ready"

    def test_readyz_shape_exact(self):  # RUNTIME
        _ensure_up()
        _, body = _get("/readyz")
        assert set(body) == {"service", "status", "spec", "checks"}
        assert set(body["checks"]) == {"database"}
        assert set(body["checks"]["database"]) == {"ok", "latency_ms", "error"}

    def test_ready_after_api_restart(self):  # RUNTIME
        try:
            assert _compose("restart", "api", timeout=120).returncode == 0
            _wait_all_healthy()
            code, body = _get("/readyz")
            assert code == 200 and body["status"] == "ready"
        finally:
            _ensure_up()

    def test_health_logs_sane(self):  # RUNTIME
        _ensure_up()
        _get("/readyz")
        logs = _compose("logs", "--tail", "20", "api").stdout
        assert "Traceback" not in logs
        for marker in ("sk-", "change-me", "dev-key-change-me",
                       "proofops-dev-only"):
            assert marker not in logs, f"secret marker in logs: {marker}"
