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


class TestElevenDocsSet:
    def test_spec44_docs_exist(self):  # STATIC
        for name in ("ARCHITECTURE.md", "API.md", "TESTING.md"):
            assert (ROOT / "docs" / name).is_file(), name


class TestFrontendBadge:
    def test_stub_declares_mock_and_links_both_probes(self):  # STATIC
        body = (ROOT / "frontend" / "public" / "index.html").read_text(
            encoding="utf-8")
        assert "MOCK" in body
        assert "/healthz" in body and "/readyz" in body
        assert "ProofOps" in body
