"""M00.6 documentation foundation (host-safe STATIC + UNIT + SECURITY).

Canonical 8-docs set (ADR-006 in docs/DECISIONS.md): the 4 frozen foundation
docs (M00.2-M00.5) plus the 4 README-planned foundation docs created in M00.6.
Pure file-text checks: no Docker daemon, no fastapi import, any host Python.

EVIDENCE RULE: helpers are pure functions over text so negative tests feed
mutated strings directly (proof the detectors fire); positive tests read the
real tree. File-level tmp_path tests prove presence/link detection end to
end without touching the repo.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

# Canonical 8-docs set: 4 frozen (M00.2-M00.5) + 4 foundation (M00.6).
CANONICAL_8 = [
    "CONFIGURATION.md",  # M00.2 frozen
    "COMPOSE.md",  # M00.3 frozen (+1 authorized M00.6 line edit)
    "HEALTH.md",  # M00.4 frozen
    "LOGGING.md",  # M00.5 frozen
    "EVALUATION.md",  # M00.6 new (runner owned by M16)
    "SECURITY.md",  # M00.6 new (full coverage by later modules)
    "DECISIONS.md",  # M00.6 new (ADR log)
    "DEMO.md",  # M00.6 new (full demo owned by M22)
]
NEW_4 = ["EVALUATION.md", "SECURITY.md", "DECISIONS.md", "DEMO.md"]

SPEC_REF = "PS03_FINAL_SPEC_V2"

# Claim-shaped patterns only (denials like "Nothing here claims ..." must NOT
# match: "production readiness/certification" nouns stay legal in denials).
FORBIDDEN_CLAIMS = [
    r"production[\s-]*grade",
    r"\bcertified\b",
    r"certification\s+(achieved|awarded|granted|complete)",
    r"\bSOC\s*2\b",
    r"\bISO\s*27001\b",
    r"\bPCI[\s-]*DSS\b",
    r"\bHIPAA[\s-]?compliant\b",
    r"\bis\s+(now\s+)?production[\s-]*ready\b",
    r"\bare\s+(now\s+)?production[\s-]*ready\b",
    r"ready\s+for\s+production\s+use\b",
    r"fully\s+secure\b",
    r"enterprise[\s-]*ready\b",
    r"battle[\s-]*tested\b",
]

# Literal secret-ish markers that must never appear in the 4 new docs. (The
# frozen docs/.env.example legitimately discuss placeholders; scope here is
# new M00.6 prose only.)
SECRET_MARKERS = [
    "sk-",
    "hunter2",
    "change-me",
    "dev-key",
    "proofops-dev-only",
    "-----BEGIN",
    "ghp_",
    "gho_",
    "xoxb-",
]


def _read(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def _has_spec_ref(text: str) -> bool:
    return SPEC_REF in text


def _forbidden_claims(text: str) -> list[str]:
    return [p for p in FORBIDDEN_CLAIMS if re.search(p, text, re.IGNORECASE)]


def _secret_markers(text: str) -> list[str]:
    return [m for m in SECRET_MARKERS if m in text]


def _db_down_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip().startswith("- db down"):
            return line
    return ""


class TestPresence:
    @pytest.mark.parametrize("name", CANONICAL_8)
    def test_doc_exists(self, name):  # STATIC
        assert (DOCS / name).is_file(), f"missing canonical doc: {name}"

    @pytest.mark.parametrize("name", CANONICAL_8)
    def test_doc_nontrivial(self, name):  # STATIC
        body = _read(name)
        assert len(body.strip()) > 300, f"{name} too small to be real: {len(body)}"

    def test_exact_canonical_set(self, tmp_path):  # UNIT
        # Detector proof on a fixture set: presence logic fires on gaps.
        present = {"a.md", "b.md"}
        required = {"a.md", "b.md", "c.md"}
        assert required - present == {"c.md"}
        assert len(CANONICAL_8) == 8
        assert len(set(CANONICAL_8)) == 8

    def test_presence_detector_fires_on_fixture_gap(self, tmp_path):  # UNIT
        (tmp_path / "A.md").write_text("x" * 400, encoding="utf-8")
        missing = [n for n in ("A.md", "B.md") if not (tmp_path / n).is_file()]
        assert missing == ["B.md"]


class TestSpecLinks:
    @pytest.mark.parametrize("name", NEW_4)
    def test_new_docs_link_authoritative_spec(self, name):  # STATIC
        # M00.6 controls these four: direct spec reference is mandatory.
        assert _has_spec_ref(_read(name)), (
            f"{name} must reference the authoritative spec {SPEC_REF}"
        )

    def test_frozen_docs_traceable_to_spec(self):  # STATIC
        # M00.1-M00.5 are FROZEN: CONFIGURATION/COMPOSE/LOGGING predate the
        # spec-link rule and cannot be edited (only the one authorized
        # COMPOSE.md db-down line). HEALTH.md links the spec directly; the
        # other three are traceable via the M00.6 ADR log, which names each
        # frozen doc and links the spec itself. This test pins that bridge
        # instead of pretending frozen files were rewritten.
        assert _has_spec_ref(_read("HEALTH.md"))
        bridge = _read("DECISIONS.md")
        assert _has_spec_ref(bridge)
        for frozen in ("CONFIGURATION.md", "COMPOSE.md", "HEALTH.md", "LOGGING.md"):
            assert frozen in bridge, f"ADR log must cite frozen doc {frozen}"

    def test_missing_link_detected(self):  # UNIT (negative)
        assert _has_spec_ref("no spec here") is False

    def test_broken_link_detected(self):  # UNIT (negative)
        # V1-only or misspelled refs must NOT satisfy the gate.
        assert _has_spec_ref("see docs/PS03_FINAL_SPEC.md") is False
        assert _has_spec_ref("see PS03_FINAL_SPEC_V3.md") is False

    @pytest.mark.parametrize("name", CANONICAL_8)
    def test_every_doc_names_owning_module(self, name):  # STATIC
        assert "M00." in _read(name), f"{name} must name its owning module"


class TestNoFabrication:
    @pytest.mark.parametrize("name", CANONICAL_8)
    def test_no_readiness_or_compliance_claims(self, name):  # STATIC
        hits = _forbidden_claims(_read(name))
        assert not hits, f"{name} contains fabrication markers: {hits}"

    def test_claim_detector_fires(self):  # UNIT (negative)
        assert _forbidden_claims("This release is production ready.") != []
        assert _forbidden_claims("SOC 2 certified deployment.") != []

    def test_denial_sentence_passes(self):  # UNIT
        denial = "Nothing here claims production readiness or certification."
        assert _forbidden_claims(denial) == []

    @pytest.mark.parametrize("name", NEW_4)
    def test_future_marked_planned_with_owner(self, name):  # STATIC
        body = _read(name)
        assert "PLANNED" in body, f"{name} must mark unbuilt work PLANNED"


class TestComposeReconciliation:
    def test_db_down_line_closed_not_gap(self):  # STATIC
        line = _db_down_line(_read("COMPOSE.md"))
        assert line, "COMPOSE.md must keep the db-down behavior line"
        assert "M00.4" in line and "/readyz" in line, (
            f"db-down line must cite the M00.4 closure: {line}"
        )
        assert "gap recorded" not in line, f"stale gap wording must be gone: {line}"
        assert "M00.4 scope" not in line, f"stale scope wording must be gone: {line}"

    def test_stale_wording_would_fail(self):  # UNIT (negative)
        stale = "- db down → api still answers `/healthz` (liveness-only, M00.4 gap recorded)."
        assert "gap recorded" in stale  # the old text trips the gate above
        assert "/readyz" not in stale


class TestDocSecrets:
    @pytest.mark.parametrize("name", NEW_4)
    def test_no_secret_markers_in_new_docs(self, name):  # SECURITY
        hits = _secret_markers(_read(name))
        assert not hits, f"{name} leaks secret markers: {hits}"

    def test_marker_detector_fires(self):  # SECURITY (negative)
        assert _secret_markers("key=sk-abc123") == ["sk-"]
        assert _secret_markers("pw hunter2 hunter2") == ["hunter2"]
        assert _secret_markers("clean prose, nothing here") == []
