"""M00.7 lockfile-enforcer tests (host-safe UNIT + STATIC).

Proves scripts/freeze.py is trustworthy: real-files pass (today's lock
satisfies today's ranges), every failure mode fires, findings name names
only, and --generate refuses the drifted host interpreter.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import freeze  # noqa: E402


class TestPureFunctions:
    def test_normalize(self):  # UNIT
        assert freeze.normalize("PyYAML") == "pyyaml"
        assert freeze.normalize("typing_extensions") == "typing-extensions"
        assert freeze.normalize("psycopg-binary") == "psycopg-binary"

    def test_base_name_strips_extras_and_markers(self):  # UNIT
        assert freeze.normalize(freeze.base_name(
            "uvicorn[standard]>=0.30,<0.32")) == "uvicorn"
        assert freeze.normalize(freeze.base_name(
            'psycopg[binary]>=3.1,<4; python_version>"3"')) == "psycopg"

    def test_version_satisfies_boundaries(self):  # UNIT
        assert freeze.version_satisfies("0.119.1", ">=0.115,<0.120")
        assert not freeze.version_satisfies("0.120", ">=0.115,<0.120")
        assert not freeze.version_satisfies("0.114", ">=0.115,<0.120")
        assert freeze.version_satisfies("2.0.54", ">=2.0,<2.1")
        assert freeze.version_satisfies("1.11.2", ">=1.10,<1.12")

    def test_inline_comment_stripped(self):  # UNIT
        # The starlette line carries its rationale inline; pip ignores it and
        # so must the checker (first version of this script failed the real
        # file here — the test pins the fix).
        reqs = freeze.parse_requirements(
            "starlette>=0.40,<0.47  # blocks v1.x ABI break\n")
        assert reqs == [("starlette", ">=0.40,<0.47")]
        assert freeze.version_satisfies("0.46.2", reqs[0][1])

    def test_exotic_clause_fails_loud(self):  # UNIT (negative)
        try:
            freeze.version_satisfies("1.0", "~=1.0")
        except ValueError as exc:
            assert "human review" in str(exc)
        else:
            raise AssertionError("~= must fail loud, never silently approve")


class TestCheckLock:
    def test_real_files_pass(self):  # INTEGRATION
        req = (ROOT / "backend" / "requirements.txt").read_text(
            encoding="utf-8")
        lock = (ROOT / "backend" / "requirements.lock").read_text(
            encoding="utf-8")
        assert freeze.check_lock(req, lock) == []

    def test_missing_name_fails(self):  # UNIT (negative)
        findings = freeze.check_lock("newdep>=1.0,<2\n", "old==1.0\n")
        assert any("newdep" in f and "not locked" in f for f in findings)

    def test_out_of_range_fails(self):  # UNIT (negative)
        findings = freeze.check_lock(
            "fastapi>=0.115,<0.120\n", "fastapi==0.120\n")
        assert any("fastapi" in f and "outside" in f for f in findings)

    def test_unpinned_line_fails(self):  # UNIT (negative)
        findings = freeze.check_lock("a>=1,<2\n", "a>=1\n")
        assert findings  # not an exact pin

    def test_duplicate_fails(self):  # UNIT (negative)
        findings = freeze.check_lock("a>=1,<2\n", "a==1.0\na==1.1\n")
        assert any("duplicate" in f for f in findings)

    def test_findings_name_names_only(self):  # SECURITY
        findings = freeze.check_lock(
            "fastapi>=0.115,<0.120\n", "other==9.9\n")
        assert findings and "0.120" not in " ".join(findings)


class TestLockContent:
    def test_no_win32_only_leftovers(self):  # STATIC
        # colorama/tzdata resolved (host-marker evaluation) but are false on
        # linux — the lock's consumers are the container + ubuntu CI.
        locked = freeze.parse_lock(
            (ROOT / "backend" / "requirements.lock").read_text(
                encoding="utf-8"))
        assert "colorama" not in locked and "tzdata" not in locked

    def test_every_direct_dep_locked(self):  # STATIC
        req = (ROOT / "backend" / "requirements.txt").read_text(
            encoding="utf-8")
        locked = freeze.parse_lock(
            (ROOT / "backend" / "requirements.lock").read_text(
                encoding="utf-8"))
        for name, _spec in freeze.parse_requirements(req):
            assert name in locked, name


class TestGenerateGuard:
    def test_refuses_wrong_interpreter(self, tmp_path):  # UNIT
        # This host is 3.14 (or non-CPython-3.12 in CI-before-3.12): generate
        # must refuse instead of baking wrong wheels. Exit 2, never 0.
        if sys.version_info[:2] == (3, 12) and \
                sys.implementation.name == "cpython":
            return  # running on the truth itself; refusal untestable here
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "freeze.py"),
             "--generate", "--lock", str(tmp_path / "test.lock")],
            capture_output=True, text=True, timeout=120)
        assert proc.returncode == 2, proc.stdout + proc.stderr
        assert not (tmp_path / "test.lock").is_file()

    def test_check_cli_passes_on_real_files(self):  # INTEGRATION
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "freeze.py"), "--check"],
            capture_output=True, text=True, timeout=60,
            cwd=str(ROOT))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "LOCK CHECK PASS" in proc.stdout
