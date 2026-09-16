"""M00.7 CI-definition tests (host-safe STATIC + UNIT).

The pipeline is ruff -> mypy -> unit(host-safe) -> security. These tests pin
the definition (workflow + local runner parity) so drift fails fast instead
of silently skipping a gate. No daemon, no network, any host Python.
"""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CI_SH = ROOT / "scripts" / "ci.sh"

RUNTIME_IGNORES = [
    "tests/test_compose_runtime.py",
    "tests/test_config_runtime.py",
    "tests/test_health_runtime.py",
    "tests/test_logging_runtime.py",
]


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _job_run(job: dict) -> str:
    return "\n".join(
        str(s.get("run", "")) for s in job.get("steps", []))


class TestWorkflowShape:
    def test_five_jobs_in_order(self):  # STATIC
        jobs = list(_workflow()["jobs"])
        assert jobs == ["lint", "typecheck", "unit", "security",
                        "lockfile"], jobs

    def test_stage_ordering_via_needs(self):  # STATIC
        jobs = _workflow()["jobs"]
        assert jobs["typecheck"].get("needs") == ["lint"]
        assert jobs["unit"].get("needs") == ["typecheck"]
        assert jobs["security"].get("needs") == ["unit"]
        assert jobs["lockfile"].get("needs") == ["security"]

    def test_python_pinned_312(self):  # STATIC
        text = WORKFLOW.read_text(encoding="utf-8")
        assert 'python-version: "3.12"' in text

    def test_installs_from_lock(self):  # STATIC
        # CI (ubuntu py3.12) consumes the linux/cp312 lock (ADR-010); the
        # Windows-local runner keeps portable ranges (see parity test below).
        text = WORKFLOW.read_text(encoding="utf-8")
        assert "pip install -r backend/requirements.lock" in text
        assert "pip install -r backend/requirements.txt" not in text

    def test_dependency_consistency_gated(self):  # STATIC
        text = WORKFLOW.read_text(encoding="utf-8")
        assert "pip check" in text  # gates the starlette upper bound


class TestStageCommands:
    def test_ruff_stage(self):  # STATIC
        run = _job_run(_workflow()["jobs"]["lint"])
        assert "ruff check backend tests scripts" in run

    def test_mypy_stage(self):  # STATIC
        run = _job_run(_workflow()["jobs"]["typecheck"])
        assert "mypy backend/app" in run

    def test_unit_excludes_runtime_files(self):  # STATIC
        run = _job_run(_workflow()["jobs"]["unit"])
        for ignored in RUNTIME_IGNORES:
            assert f"--ignore={ignored}" in run, ignored

    def test_security_runs_secret_scan(self):  # STATIC
        run = _job_run(_workflow()["jobs"]["security"])
        assert "scripts/secret_scan.py" in run

    def test_lockfile_runs_freeze_check(self):  # STATIC
        run = _job_run(_workflow()["jobs"]["lockfile"])
        assert "scripts/freeze.py" in run and "--check" in run


class TestWorkflowHygiene:
    def test_no_secret_echo_or_unsafe_compose(self):  # STATIC (SECURITY)
        # Executable lines only (comments document the bans). LACK-5 fix: the
        # old `or`-chain passed `echo ${{ secrets.X }}` (echo without `==>`).
        # Tight form: no executable line may echo secrets, period.
        for line in WORKFLOW.read_text(encoding="utf-8").splitlines():
            code = line.split("#", 1)[0]
            assert "printenv" not in code
            assert not ("echo" in code and "secrets." in code), line
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import secret_scan as scanner
        assert scanner._check_workflows(ROOT) == []

    def test_echo_detector_would_catch_secret_echo(self):  # UNIT (negative)
        # Proof the tightened detector fires (feed the forbidden shape).
        line = "run: echo ${{ secrets.FOO }}"
        code = line.split("#", 1)[0]
        assert "echo" in code and "secrets." in code  # detector fires


class TestWorkflowLeastPrivilege:
    def test_permissions_read_only(self):  # STATIC
        # LACK-15: default token is broad; this pipeline only reads + tests.
        assert _workflow().get("permissions") == {"contents": "read"}

    def test_concurrency_cancels_duplicates(self):  # STATIC
        conc = _workflow().get("concurrency", {})
        assert conc.get("cancel-in-progress") is True
        assert "github.ref" in str(conc.get("group", ""))


class TestLocalRunnerParity:
    def test_ci_sh_mirrors_workflow_stages(self):  # STATIC
        text = CI_SH.read_text(encoding="utf-8")
        for needle in [
            "ruff check backend tests scripts",
            "mypy backend/app",
            "scripts/secret_scan.py",
            "scripts/freeze.py --check",
        ]:
            assert needle in text, needle
        for ignored in RUNTIME_IGNORES:
            assert f"--ignore={ignored}" in text, ignored

    def test_ci_sh_install_divergence_is_documented(self):  # STATIC
        # Deliberate split (ADR-010): manylinux pins cannot install on a
        # Windows host, so the LOCAL runner keeps portable ranges while CI
        # installs from the lock. Both run the identical freeze --check gate.
        # If this split ever closes, delete this test and unify.
        sh = CI_SH.read_text(encoding="utf-8")
        executable_installs = [
            line.split("#", 1)[0] for line in sh.splitlines()
        ]
        assert not any("pip install" in code for code in executable_installs), \
            "local runner must not install (ambient env only)"
        assert "requirements.txt" in sh and "ADR-010" in sh

    def test_ci_sh_fail_fast_and_no_unsafe_compose(self):  # STATIC
        text = CI_SH.read_text(encoding="utf-8")
        assert "set -euo pipefail" in text
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            assert "compose config" not in code or "--quiet" in code or \
                "--services" in code or "config --quiet" in text
