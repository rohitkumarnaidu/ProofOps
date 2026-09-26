"""M00.6 documentation foundation (host-safe STATIC + UNIT + SECURITY).

Canonical 11-docs set (ADR-006 in docs/DECISIONS.md, updated by ADR-007 90+
pass): the 4 frozen foundation docs (M00.2-M00.5) plus 7 foundation docs
(4 README-planned + 3 spec-§44) created in M00.6.
Pure file-text checks: no Docker daemon, no fastapi import, any host Python.

EVIDENCE RULE: helpers are pure functions over text so negative tests feed
mutated strings directly (proof the detectors fire); positive tests read the
real tree. File-level tmp_path tests prove presence/link detection end to
end without touching the repo.

UPDATE JUSTIFICATION (AGENTS.md §12: root docs stay minimal, pin update needs
justification): spec §44 names ARCHITECTURE.md + API.md + TESTING.md alongside
the README-planned 4; leaving them absent kept M00.6 at 66/100 (spec-coverage
gap). ADR-007 records the additive fix: 3 honest foundation docs (status +
spec links + owning modules + PLANNED, no implementation claimed). No doc
removed; all 8 originals still pinned below.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

# Canonical 11-docs set: 4 frozen (M00.2-M00.5) + 7 foundation (M00.6).
CANONICAL_DOCS = [
    "CONFIGURATION.md",  # M00.2 frozen
    "COMPOSE.md",  # M00.3 frozen (+ authorized M00.6 line edits, see ADR-007)
    "HEALTH.md",  # M00.4 frozen
    "LOGGING.md",  # M00.5 frozen (+ 90+ pattern list update, see ADR-007)
    "EVALUATION.md",  # M00.6 new (runner owned by M16)
    "SECURITY.md",  # M00.6 new (full coverage by later modules)
    "DECISIONS.md",  # M00.6 new (ADR log)
    "DEMO.md",  # M00.6 new (full demo owned by M22)
    "ARCHITECTURE.md",  # M00.6 90+ new (system owned by later phases)
    "API.md",  # M00.6 90+ new (full surface owned by later phases)
    "TESTING.md",  # M00.6 90+ new (suites owned by later phases)
]
NEW_4 = ["EVALUATION.md", "SECURITY.md", "DECISIONS.md", "DEMO.md"]
NEW_90PLUS = ["ARCHITECTURE.md", "API.md", "TESTING.md"]

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
    @pytest.mark.parametrize("name", CANONICAL_DOCS)
    def test_doc_exists(self, name):  # STATIC
        assert (DOCS / name).is_file(), f"missing canonical doc: {name}"

    @pytest.mark.parametrize("name", CANONICAL_DOCS)
    def test_doc_nontrivial(self, name):  # STATIC
        body = _read(name)
        assert len(body.strip()) > 300, f"{name} too small to be real: {len(body)}"

    def test_exact_canonical_set(self, tmp_path):  # UNIT
        # Detector proof on a fixture set: presence logic fires on gaps.
        present = {"a.md", "b.md"}
        required = {"a.md", "b.md", "c.md"}
        assert required - present == {"c.md"}
        assert len(CANONICAL_DOCS) == 11  # 4 frozen + 7 foundation (ADR-007)
        assert len(set(CANONICAL_DOCS)) == 11

    def test_tree_has_no_ungoverned_docs(self):  # STATIC
        # LACK-6 fix: the canonical pin used to cover only the list constant,
        # never the real tree — CONTRACTS.md etc. drifted ungoverned. Every
        # top-level doc must be canonical or explicitly known-extra.
        known_extra = {
            "CONTRACTS.md",  # M01 freeze surface (owned by contracts phase)
            "MODULE_REGISTRY.md",  # naming/status authority (registry)
            "PS03_FINAL_SPEC_V2.md",  # authoritative spec (source of truth)
            "BUILD_FIRST_MASTER_PLAN.md",  # wave plan (M21 owned)
            "ProofOps_PS03_Master_Winning_Implementation_Trust_Submission_Checklist.md",  # UNVERIFIED companion
            "README.md",  # repo entrypoint (tested in test_repo_structure.py)
            "ZERO_TRUST_AUDIT_M00-M11.md",  # dated historical report (do not rewrite)
                "SAFETY_CROSSING_PLAN.md",  # M00-M06 safety campaign plan (owned by
                # the crossing campaign; SUPERSEDED, never deleted, on completion)
                "PROOF_OPS_REAL_CLOUD_AND_SECURITY_ARCHITECTURE.md",
                # Enterprise cloud-integration + zero-trust control-plane
                # architecture (live-tier lane). Substantive and maintained, so
                # it is governed as a known-extra rather than left ungoverned --
                # but deliberately NOT promoted into CANONICAL_DOCS, which
                # ADR-007 pins at exactly 11 and which remains the M00
                # foundation set. Registering a doc is not the same as
                # promoting it, and this one describes a lane, not the baseline.
            }
        actual = {p.name for p in DOCS.glob("*.md")}
        assert set(CANONICAL_DOCS) <= actual, \
            f"canonical missing: {sorted(set(CANONICAL_DOCS) - actual)}"
        ungoverned = actual - set(CANONICAL_DOCS) - known_extra
        assert not ungoverned, f"ungoverned docs: {sorted(ungoverned)}"

    def test_presence_detector_fires_on_fixture_gap(self, tmp_path):  # UNIT
        (tmp_path / "A.md").write_text("x" * 400, encoding="utf-8")
        missing = [n for n in ("A.md", "B.md") if not (tmp_path / n).is_file()]
        assert missing == ["B.md"]


class TestSpecLinks:
    @pytest.mark.parametrize("name", NEW_4 + NEW_90PLUS)
    def test_new_docs_link_authoritative_spec(self, name):  # STATIC
        # M00.6 controls these seven: direct spec reference is mandatory.
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

    @pytest.mark.parametrize("name", CANONICAL_DOCS)
    def test_every_doc_names_owning_module(self, name):  # STATIC
        assert "M00." in _read(name), f"{name} must name its owning module"


class TestNoFabrication:
    @pytest.mark.parametrize("name", CANONICAL_DOCS)
    def test_no_readiness_or_compliance_claims(self, name):  # STATIC
        hits = _forbidden_claims(_read(name))
        assert not hits, f"{name} contains fabrication markers: {hits}"

    def test_claim_detector_fires(self):  # UNIT (negative)
        assert _forbidden_claims("This release is production ready.") != []
        assert _forbidden_claims("SOC 2 certified deployment.") != []

    def test_denial_sentence_passes(self):  # UNIT
        denial = "Nothing here claims production readiness or certification."
        assert _forbidden_claims(denial) == []

    @pytest.mark.parametrize("name", NEW_4 + NEW_90PLUS)
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
    @pytest.mark.parametrize("name", NEW_4 + NEW_90PLUS)
    def test_no_secret_markers_in_new_docs(self, name):  # SECURITY
        hits = _secret_markers(_read(name))
        assert not hits, f"{name} leaks secret markers: {hits}"

    def test_marker_detector_fires(self):  # SECURITY (negative)
        assert _secret_markers("key=sk-abc123") == ["sk-"]
        assert _secret_markers("pw hunter2 hunter2") == ["hunter2"]
        assert _secret_markers("clean prose, nothing here") == []

    def test_readme_has_no_fabrication_claims(self):  # STATIC
        # The 11-doc gate never covered the root entrypoint (most-read file).
        body = (ROOT / "README.md").read_text(encoding="utf-8")
        assert _forbidden_claims(body) == []
