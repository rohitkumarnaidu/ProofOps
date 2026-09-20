"""M00.3 compose/service-runtime live proofs (RUNTIME: real daemon only).

Matrix: clean start, per-service restarts, full restart, DB-down/API-down
behavior, persistence across container recreation, live port mapping, log
hygiene. Honestly SKIPPED without a daemon — never counted as passed.

Each mutating test restores the stack (try/finally); the file leaves the
stack UP and healthy for human verification.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Failure diagnostics must never echo connection strings: a failing psycopg
# call prints the full DATABASE_URL (password included) to stderr. Redact
# URI credentials in every assertion message in this file.
_SECRET_URI_RE = re.compile(r"://[^@\s]+@")


def _scrub(text: str) -> str:
    return _SECRET_URI_RE.sub("://<REDACTED>@", text)


def _assert_ok(proc: subprocess.CompletedProcess, what: str) -> None:
    assert proc.returncode == 0, f"{what} failed: {_scrub(proc.stderr[-800:])}"


def _daemon_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=30).returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _daemon_ok(), reason="no docker daemon; live runtime unprovable")


def _compose(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", *args], capture_output=True,
                          text=True, cwd=ROOT, timeout=timeout)


def _exec(svc: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", svc, *args],
        capture_output=True, text=True, cwd=ROOT, timeout=timeout)


def _cid(svc: str) -> str:
    proc = _compose("ps", "-q", svc)
    ids = proc.stdout.strip().splitlines()
    assert proc.returncode == 0 and ids, \
        f"no container for {svc}: {_scrub(proc.stderr[-300:])}"
    return ids[0]


def _health(svc: str) -> str:
    # A momentarily absent container is "missing" (keep polling), never a
    # crash: the daemon can hiccup between kill and policy restart.
    try:
        cid = _cid(svc)
    except AssertionError:
        return "missing"
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Health.Status}}", cid],
        capture_output=True, text=True, timeout=30)
    return out.stdout.strip() or "missing"


def _started_at(svc: str) -> str:
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.StartedAt}}", _cid(svc)],
        capture_output=True, text=True, timeout=30)
    return out.stdout.strip()


def _wait_all_healthy(timeout_s: int = 240) -> float:
    t0 = time.time()
    deadline = t0 + timeout_s
    while time.time() < deadline:
        if all(_health(s) == "healthy" for s in ("db", "api", "ui")):
            return time.time() - t0
    pytest.fail("stack did not converge to 3x healthy "
                f"(db={_health('db')} api={_health('api')} ui={_health('ui')})")


def _api_body() -> dict:
    with urllib.request.urlopen("http://localhost:8000/healthz",
                                timeout=10) as r:
        assert r.status == 200
        return json.loads(r.read().decode("utf-8"))


def _ui_status() -> int:
    with urllib.request.urlopen("http://localhost:5173/",
                                timeout=10) as r:
        return r.status


def _ensure_up() -> None:
    proc = _compose("up", "-d", timeout=240)
    assert proc.returncode == 0, _scrub(proc.stderr[-1000:])
    _wait_all_healthy()


class TestRuntimeMatrix:
    def test_clean_start_converges(self):  # RUNTIME
        t0 = time.time()
        try:
            down = _compose("down", timeout=180)
            assert down.returncode == 0, _scrub(down.stderr[-1000:])
            _ensure_up()
        finally:
            _ensure_up()  # never leave the stack down
        assert (time.time() - t0) < 600, "clean start unreasonably slow"
        assert _api_body()["service"] == "proofops-api"
        assert _ui_status() == 200

    def test_startup_ordering(self):  # RUNTIME
        # depends_on/service_healthy must order creation: db first, ui last.
        _ensure_up()
        assert _started_at("db") <= _started_at("api") <= _started_at("ui"), \
            "creation order violated (expected db <= api <= ui)"

    def test_api_restart_recovery(self):  # RUNTIME
        try:
            assert _compose("restart", "api", timeout=120).returncode == 0
            _wait_all_healthy()
            assert _api_body()["status"] == "ok"
        finally:
            _ensure_up()

    def test_ui_restart_recovery(self):  # RUNTIME
        try:
            assert _compose("restart", "ui", timeout=120).returncode == 0
            _wait_all_healthy()
            assert _ui_status() == 200
        finally:
            _ensure_up()

    def test_db_restart_recovery(self):  # RUNTIME
        try:
            assert _compose("restart", "db", timeout=180).returncode == 0
            _wait_all_healthy()
            # Skeleton api has no DB code path: it stays servable across a DB
            # restart. Deep readiness is M00.4 scope; this pins current behavior.
            assert _api_body()["status"] == "ok"
        finally:
            _ensure_up()

    def test_full_restart_cycle(self):  # RUNTIME
        try:
            assert _compose("restart", timeout=240).returncode == 0
            elapsed = _wait_all_healthy()
            assert elapsed < 300
            assert _api_body()["status"] == "ok" and _ui_status() == 200
        finally:
            _ensure_up()


class TestFailureInjection:
    def test_db_down_api_liveness_honest(self):  # RUNTIME
        # /healthz is liveness-only in the skeleton: with db stopped it still
        # answers. Recorded (not hidden) as the M00.4 deep-readiness gap.
        try:
            assert _compose("stop", "db", timeout=120).returncode == 0
            time.sleep(3)
            assert _api_body()["status"] == "ok"
        finally:
            assert _compose("start", "db", timeout=180).returncode == 0
            _wait_all_healthy()

    def test_api_down_ui_static(self):  # RUNTIME
        # The M00.1 stub UI has no runtime API dependency: it serves while api
        # is down. Pinned as current contract (M19 owns real wiring).
        try:
            assert _compose("stop", "api", timeout=120).returncode == 0
            time.sleep(3)
            assert _ui_status() == 200
        finally:
            assert _compose("start", "api", timeout=180).returncode == 0
            _wait_all_healthy()


class TestPersistence:
    def test_data_survives_container_recreation(self):  # RUNTIME
        # Named volume pgdata must survive `down` (containers removed) + `up`.
        # Uses the db local socket (trust auth inside the container) so the
        # test does NOT depend on ambient .env/volume password agreement —
        # volume-init passwords are sticky by postgres design (see COMPOSE.md).
        # Scratch table only; dropped in finally. Never touches dev data.
        seed = _exec("db", "psql", "-U", "proofops", "-d", "proofops",
                     "-v", "ON_ERROR_STOP=1", "-c",
                     "DROP TABLE IF EXISTS m003_probe; "
                     "CREATE TABLE m003_probe (k TEXT PRIMARY KEY, v TEXT); "
                     "INSERT INTO m003_probe VALUES ('m003','persisted');")
        try:
            _ensure_up()
            _assert_ok(seed, "persistence seed")
            _assert_ok(_compose("down", timeout=180), "compose down")
            _ensure_up()
            check = _exec("db", "psql", "-U", "proofops", "-d", "proofops",
                          "-v", "ON_ERROR_STOP=1", "-tAc",
                          "SELECT v FROM m003_probe WHERE k='m003';")
            _assert_ok(check, "persistence read-back")
            assert check.stdout.strip() == "persisted"
        finally:
            _exec("db", "psql", "-U", "proofops", "-d", "proofops",
                  "-v", "ON_ERROR_STOP=1", "-c",
                  "DROP TABLE IF EXISTS m003_probe;")
            _ensure_up()


class TestIsolatedFreshProject:
    # Step 9/12: a temporary project (-p) proves clean-init behavior without
    # touching developer state. Falsifiable claim under test: the ambient
    # .env/volume password drift comes ONLY from the old volume, so a fresh
    # volume + current .env must agree (psycopg connect succeeds).
    PROJECT = "proofops-m003-verify"

    @classmethod
    def _p(cls, *args: str, timeout: int = 300) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "compose", "-p", cls.PROJECT,
             "-f", "docker-compose.yml", *args],
            capture_output=True, text=True, cwd=ROOT, timeout=timeout)

    @classmethod
    def _p_exec(cls, svc: str, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "compose", "-p", cls.PROJECT, "-f", "docker-compose.yml",
             "exec", "-T", svc, *args],
            capture_output=True, text=True, cwd=ROOT, timeout=120)

    def _wait_iso_healthy(self, timeout_s: int = 240) -> None:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                with urllib.request.urlopen("http://localhost:8000/healthz",
                                            timeout=3) as r:
                    if r.status == 200:
                        return
            except Exception:
                time.sleep(3)
        pytest.fail("isolated project did not become healthy")

    def test_isolated_fresh_build_start_recreate_destroy(self):  # RUNTIME
        try:
            _assert_ok(_compose("down", timeout=180), "park main stack")
            _assert_ok(self._p("build", "--no-cache"), "isolated fresh build")
            _assert_ok(self._p("up", "-d"), "isolated fresh start")
            self._wait_iso_healthy()
            # Fresh volume + current .env agree: password auth works here, so
            # the ambient drift is old-volume-only, not a contract defect.
            seed = self._p_exec(
                "api", "python", "-c",
                "import os, psycopg; url = os.environ['DATABASE_URL'].replace("
                "'+psycopg', '', 1); c = psycopg.connect(url);"
                "c.execute('CREATE TABLE iso_probe (k TEXT PRIMARY KEY);');"
                "c.execute(\"INSERT INTO iso_probe VALUES ('fresh');\");"
                "c.commit();"
                "print(c.execute('SELECT * FROM iso_probe').fetchone()[0]);"
                "c.close()")
            _assert_ok(seed, "isolated fresh-init auth + roundtrip")
            assert seed.stdout.strip() == "fresh"
            vols = subprocess.run(["docker", "volume", "ls", "--format",
                                   "{{.Name}}"], capture_output=True, text=True,
                                  timeout=30).stdout
            assert f"{self.PROJECT}_pgdata" in vols, "isolated volume missing"
            assert "lyzrcloudagent_pgdata" in vols, \
                "main volume must be untouched by isolation"
            _assert_ok(self._p("down", "-v", timeout=180), "isolated destroy")
            vols_after = subprocess.run(
                ["docker", "volume", "ls", "--format", "{{.Name}}"],
                capture_output=True, text=True, timeout=30).stdout
            assert f"{self.PROJECT}_pgdata" not in vols_after, \
                "isolated down -v must destroy its volume"
            assert "lyzrcloudagent_pgdata" in vols_after, \
                "main volume must survive isolated teardown"
        finally:
            self._p("down", "-v", timeout=180)  # never leak the temp project
            _ensure_up()  # main stack back for human verification


class TestLiveContract:
    def test_published_ports_live(self):  # RUNTIME
        # Live mapping proof (not YAML text): ask the daemon itself.
        assert _compose("port", "api", "8000").stdout.strip() == "0.0.0.0:8000"
        # M19b: ui serves unprivileged 8080 (was port 80 pre-M19b).
        assert _compose("port", "ui", "8080").stdout.strip() == "0.0.0.0:5173"
        assert _compose("port", "db", "5432").stdout.strip() == "0.0.0.0:5433"

    def test_logs_accessible_and_sane(self):  # RUNTIME
        for svc in ("api", "db", "ui"):
            proc = _compose("logs", "--tail", "30", svc)
            assert proc.returncode == 0 and proc.stdout.strip(), \
                f"{svc}: logs must be accessible and non-empty"
        api_logs = _compose("logs", "--tail", "30", "api").stdout
        assert "Traceback" not in api_logs, "api log shows crash traceback"

    def test_logs_secret_free(self):  # RUNTIME (SECURITY)
        blob = "".join(_compose("logs", "--tail", "30", s).stdout
                       for s in ("api", "db", "ui"))
        for marker in ("sk-", "change-me", "dev-key-change-me",
                       "proofops-dev-only"):
            assert marker not in blob, f"secret marker in logs: {marker}"

    def test_config_quiet_is_safe_path(self):  # RUNTIME
        assert _compose("config", "--quiet", timeout=60).returncode == 0

    def test_image_has_no_env_file(self):  # RUNTIME (SECURITY)
        # .env must never be baked into the image (nor shipped in context).
        proc = _exec("api", "ls", "-la", "/app")
        _assert_ok(proc, "list /app")
        assert ".env" not in proc.stdout.split(), \
            f".env leaked into image: {proc.stdout}"

    def test_restart_policy_reported_live(self):  # RUNTIME
        # Daemon-reported restart policy on all three (stronger than YAML).
        # LIMITATION (verified, not assumed): on this host's Docker Desktop
        # 29.6.2, a SIGKILLed api stayed Exited(137)/Restarts=0 for 25s+ on a
        # FRESH container — daemon-initiated resurrection is NOT observed here
        # (possible Desktop quirk; M00.7 must confirm on Linux dockerd). Manual
        # restart/stop/start/down/up recovery is proven by the matrix tests.
        for svc in ("db", "api", "ui"):
            out = subprocess.run(
                ["docker", "inspect", "-f",
                 "{{.HostConfig.RestartPolicy.Name}}", _cid(svc)],
                capture_output=True, text=True, timeout=30)
            assert out.stdout.strip() == "unless-stopped", \
                f"{svc}: daemon reports {out.stdout.strip()!r}"

    def test_service_dns_paths(self):  # RUNTIME
        # Internal paths proven live: api→db TCP via service DNS (no host
        # exposure needed for inter-service traffic); ui→api HTTP-only; and
        # the ui container carries no DB credentials at all.
        _ensure_up()
        tcp = _exec("api", "python", "-c",
                    "import socket; s=socket.create_connection(('db',5432),"
                    "timeout=5); print('DB-TCP-OK'); s.close()")
        _assert_ok(tcp, "api to db service DNS")
        assert "DB-TCP-OK" in tcp.stdout
        http = _exec("ui", "wget", "-q", "-O", "-", "http://api:8000/healthz")
        _assert_ok(http, "ui to api service DNS")
        assert '"status":"ok"' in http.stdout.replace(" ", ""), \
            f"unexpected api body via service DNS: {http.stdout[:200]}"
        env = _exec("ui", "printenv")
        _assert_ok(env, "ui env dump")
        for token in ("POSTGRES", "DATABASE_URL", "APPROVAL_SECRET",
                      "LYZR_API_KEY"):
            assert token not in env.stdout, f"ui carries {token}"
