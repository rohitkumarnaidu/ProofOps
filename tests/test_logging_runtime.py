"""M00.5 logging live proofs (RUNTIME: real daemon only).

Container log shape (structured single-line records), startup-line presence,
default-INFO behavior, secret hygiene. Skipped honestly without a daemon —
never counted as a pass. Leaves the stack UP + healthy.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

LINE_RE = re.compile(
    r"ts=\S+ level=(DEBUG|INFO|WARNING|ERROR) logger=\S+ msg=.*")


def _daemon_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=30).returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _daemon_ok(), reason="no docker daemon; live log shape unprovable")


def _compose(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", *args], capture_output=True,
                          text=True, cwd=ROOT, timeout=timeout)


def _api_logs(tail: int = 60) -> str:
    return _compose("logs", "--no-log-prefix", "--tail", str(tail),
                    "api").stdout


class TestLoggingLive:
    def test_startup_line_structured(self):  # RUNTIME
        logs = _api_logs(80)
        matches = [ln for ln in logs.splitlines()
                   if "proofops api starting" in ln]
        assert matches, "expected M00.5 startup line in api logs"
        assert LINE_RE.search(matches[0]), matches[0]
        assert "env=" in matches[0] and "level=" in matches[0]

    def test_server_booted_and_app_lines_structured(self):  # RUNTIME
        logs = _api_logs(80)
        # Server booted (uvicorn keeps its own formatter — boundary documented
        # in docs/LOGGING.md; uvicorn never emits secrets at INFO).
        assert "Uvicorn running on" in logs or "Started server process" in logs
        app_lines = [ln for ln in logs.splitlines()
                     if "proofops api starting" in ln or "logger=app." in ln
                     or "logger=uvicorn" in ln and "level=" in ln]
        assert app_lines, "no structured application lines found"
        for ln in app_lines:
            assert LINE_RE.search(ln), ln

    def test_default_info_suppresses_debug(self):  # RUNTIME
        logs = _api_logs(200)
        assert not re.search(r"level=DEBUG", logs), \
            "DEBUG records must not appear at default INFO level"

    def test_no_secret_markers_in_logs(self):  # RUNTIME
        logs = _api_logs(200)
        assert "Traceback" not in logs
        for marker in ("sk-", "change-me", "dev-key-change-me",
                       "proofops-dev-only", "://", "password="):
            # "://" appears in uvicorn startup ("http://0.0.0.0:8000") —
            # only credentialed URIs (user:pass@) are forbidden.
            if marker == "://":
                assert not re.search(r"://[^/\s]+:[^/\s@]+@", logs), \
                    "credentialed URI in logs"
            else:
                assert marker not in logs, f"secret marker in logs: {marker}"
