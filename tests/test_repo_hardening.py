"""M00.1 repo-structure hardening (90+ pass, host-safe STATIC).

New-file companion to tests/test_repo_structure.py (untouched): pins the
ADR-007 closes — spec-§44 README sections, 11-docs set, and the honest MOCK
frontend badge — without editing the frozen test.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


class TestReadmeSpec44:
    def test_diagram_present(self):  # STATIC
        body = _readme()
        assert "Architecture diagram" in body
        assert "Telemetry(" in body and "Control plane" in body

    def test_budget_table_provisional_no_numbers_claimed(self):  # STATIC
        body = _readme()
        assert "Budget table" in body
        assert "PROVISIONAL" in body
        assert "raw tokens" in body.lower()

    def test_benchmark_honesty(self):  # STATIC
        body = _readme()
        assert "Benchmark shot" in body
        assert "no " in body.lower() and "jsonl" in body.lower()

    def test_roadmap_present(self):  # STATIC
        body = _readme()
        assert "Roadmap" in body
        assert "M12" in body and "M22" in body

    def test_no_stale_foundation_only_claim(self):  # STATIC
        assert "M00.1 is foundation only" not in _readme()

    def test_wave_status_current(self):  # STATIC
        # Round-3 hunt: README claimed "M12-M22 are NOT STARTED" long after
        # M12-M19 landed. Wave status must name approved reality + point at
        # the registry, never a stale blanket claim.
        body = _readme()
        assert "are NOT STARTED" not in body  # stale blanket claim, see above
        assert "HUMAN_APPROVED" in body
        assert "approvals" in body and "audit" in body  # M19 routers exist


class TestElevenDocsSet:
    def test_spec44_docs_exist(self):  # STATIC
        for name in ("ARCHITECTURE.md", "API.md", "TESTING.md"):
            assert (ROOT / "docs" / name).is_file(), name


class TestFrontendBadge:
    def test_app_declares_modes_and_links_probes(self):  # STATIC
        # M19: honesty markers moved from the stub page into the app source
        # (badge component + API layer); same intent, new location.
        badges = (ROOT / "frontend" / "src" / "components" /
                  "badges.tsx").read_text(encoding="utf-8")
        assert "MOCK" in badges and "OFFLINE" in badges
        api = (ROOT / "frontend" / "src" / "api.ts").read_text(
            encoding="utf-8")
        assert "/healthz" in api
        assert "ProofOps" in (ROOT / "frontend" / "index.html").read_text(
            encoding="utf-8")


class TestShellHygiene:
    def test_gitattributes_pins_sh_to_lf(self):  # STATIC
        # LACK-14: ci.sh shipped CRLF (autocrlf), breaking the bash shebang.
        body = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        assert "*.sh text eol=lf" in body

    def test_ci_sh_is_lf_with_intact_shebang(self):  # STATIC
        raw = (ROOT / "scripts" / "ci.sh").read_bytes()
        assert b"\r" not in raw, "CRLF breaks bash (LACK-14)"
        assert raw.startswith(b"#!/usr/bin/env bash\n")
        assert "set -euo pipefail" in raw.decode("utf-8")


class TestTemplateFailClosed:
    @staticmethod
    def _template() -> dict[str, str]:
        keys: dict[str, str] = {}
        for line in (ROOT / ".env.example").read_text(
                encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                keys[k.strip()] = v.strip()
        return keys

    def test_db_password_ships_empty(self):  # STATIC
        # A template default here would silently share one password across
        # fresh setups — the exact failure the compose `:?` guard exists for.
        assert self._template().get("POSTGRES_PASSWORD") == ""

    def test_ids_ship_empty_secret_ships_placeholder(self):  # STATIC
        keys = self._template()
        assert keys.get("LYZR_API_KEY") == ""
        assert keys.get("LYZR_AGENT_ID") == ""
        assert "change-me" in keys.get("APPROVAL_SECRET", "")


class TestDependencyBounds:
    def test_every_requirement_has_lower_and_upper_bound(self):  # STATIC
        # Interim guard while ADR-010 (no lockfile) is open: with no freeze,
        # an unbounded line floats silently. Every pinned line needs BOTH
        # bounds; the lockfile removes this check's reason to exist.
        floating = []
        for line in (ROOT / "backend" / "requirements.txt").read_text(
                encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ">=" not in line or ",<" not in line:
                floating.append(line)
        assert not floating, f"floating requirements (need >= and <): {floating}"
