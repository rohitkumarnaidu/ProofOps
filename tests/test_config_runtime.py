"""M00.2 supported-runtime proofs (live container).

Runs real checks INSIDE the supported runtime (python:3.12-slim api service):
snapshot redaction against the process's own secrets, production fail-closed,
.env->compose->process->Settings value flow, restart stability, exact health
body, and load-timing bounds. Honestly SKIPPED when no docker daemon exists —
a skip here is reported, never counted as a pass.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _daemon_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True,
                              timeout=30)
        return proc.returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _daemon_ok(),
    reason="no docker daemon; the container is the supported runtime")


def _exec(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "exec", "-T"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += ["api", *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT,
                          timeout=120)


def _snapshot() -> dict:
    proc = _exec("python", "-c",
                 "from app.config import get_settings;"
                 "import json; print(json.dumps(get_settings().snapshot()))")
    assert proc.returncode == 0, proc.stderr[-1000:]
    return json.loads(proc.stdout)


def _container_env(*names: str) -> dict[str, str]:
    # Bare `printenv` dumps full K=V (multi-arg form prints values only, and
    # exits 1 on any missing var — both unusable here). Absence of a name is
    # itself evidence (default path). Secret values stay in test memory only.
    wanted = set(names)
    proc = _exec("printenv")
    assert proc.returncode == 0, proc.stderr[-500:]
    out: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k in wanted:
                out[k] = v
    return out


def _wait_healthy(timeout_s: int = 90) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("http://localhost:8000/healthz",
                                        timeout=3) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(2)
    pytest.fail("api did not return healthy in time")


class TestContainerConfig:
    def test_live_snapshot_redacted(self):  # RUNTIME
        snap = _snapshot()
        for secret_field in ("LYZR_API_KEY", "APPROVAL_SECRET",
                             "POSTGRES_PASSWORD", "PROOFOPS_API_KEY"):
            assert snap[secret_field] == "<REDACTED>", secret_field
        assert "DATABASE_URL" not in snap
        # The process's OWN secret values must not appear in its snapshot.
        env = _container_env("APPROVAL_SECRET", "POSTGRES_PASSWORD",
                             "LYZR_API_KEY", "PROOFOPS_API_KEY")
        blob = json.dumps(snap)
        for k, v in env.items():
            if v.strip():
                assert v not in blob, f"live {k} leaked into snapshot"

    def test_live_production_fail_closed(self):  # RUNTIME
        proc = _exec("python", "-c",
                     "from app.config import load_settings; load_settings()",
                     env={"APP_ENV": "production"})
        assert proc.returncode != 0, "production with dev secrets must fail"
        assert "ConfigurationError" in proc.stderr
        assert "sk-" not in proc.stderr

    def test_values_reach_app(self):  # RUNTIME (Step 6 integration contract)
        # .env -> compose -> process env -> Settings: env-provided values must
        # arrive intact; keys absent from env must resolve to documented safe
        # defaults (both paths proven live in one test).
        snap = _snapshot()
        env = _container_env("EXECUTOR", "POLICY_VERSION",
                             "APPROVAL_TTL_SECONDS", "SEED_SEED",
                             "SEED_VARIANT", "APP_ENV", "LOG_LEVEL")
        for key in ("EXECUTOR", "POLICY_VERSION", "SEED_VARIANT",
                    "APPROVAL_TTL_SECONDS", "SEED_SEED"):
            assert key in env, f"{key} should arrive via .env/compose"
            assert str(snap[key]) == env[key], key
        for key, default in (("APP_ENV", "development"),
                             ("LOG_LEVEL", "INFO")):
            if key not in env:
                assert snap[key] == default, f"{key} default path broken"
            else:
                assert str(snap[key]) == env[key], key

    def test_restart_keeps_config(self):  # RUNTIME
        before = _snapshot()
        fp_before = _exec("python", "-c",
                          "from app.config import get_settings;"
                          "print(get_settings().fingerprint())").stdout.strip()
        subprocess.run(["docker", "compose", "restart", "api"],
                       capture_output=True, cwd=ROOT, timeout=120)
        _wait_healthy()
        after = _snapshot()
        assert after == before, "restart must not change effective config"
        assert len(fp_before) == 64

    def test_health_body_exact_and_clean(self):  # RUNTIME
        with urllib.request.urlopen("http://localhost:8000/healthz",
                                    timeout=10) as r:
            body = json.loads(r.read().decode("utf-8"))
        assert body == {"status": "ok", "service": "proofops-api",
                        "spec": "PS03_FINAL_SPEC_V2"}
        assert "<REDACTED>" not in json.dumps(body)

    def test_load_timing_bounds(self):  # RUNTIME (Step 11, evidence only)
        proc = _exec("python", "-c",
                     "import time; from app.config import load_settings;"
                     "t0=time.perf_counter(); load_settings(); cold=time.perf_counter()-t0;"
                     "from app.config import get_settings;"
                     "t0=time.perf_counter(); get_settings(); warm=time.perf_counter()-t0;"
                     "print(f'{cold:.4f} {warm:.4f}')")
        assert proc.returncode == 0, proc.stderr[-500:]
        cold, warm = (float(x) for x in proc.stdout.split())
        assert cold < 5.0, f"cold load suspiciously slow: {cold}s"
        assert warm <= cold, "cached load must not be slower than cold load"
