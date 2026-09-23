"""M05 evidence-service hardening (90+ pass, host-safe UNIT + SECURITY).

Proves the interim-audit P1 closures: grounded (not just member) coverage,
empty-RCA denial, computed (not hardcoded) trust, deterministic packs,
and an enforcing pack verifier. Grounding gate: MUST-CITE coverage must be
measurable at 1.0 with teeth (stale/LOW/unsealed citations deny).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "telemetry"))

import gen  # noqa: E402
from app.contracts.enums import ClaimClass, SourceType, TrustLevel  # noqa: E402
from app.contracts.evidence import Evidence  # noqa: E402
from app.contracts.hypothesis import Claim  # noqa: E402
from app.services.evidence import (  # noqa: E402
    STALE_AFTER_S,
    capture_evidence,
    must_cite_coverage,
    verify_evidence_pack,
)
from app.services.predigest import build_evidence_pack  # noqa: E402


def _ev(evidence_id: str, **over) -> Evidence:
    base = dict(incident_id="i", source_type=SourceType.LOG,
                source_id="s", ref="r", hash="h" * 16,
                freshness_s=10.0, relevance=0.9, trust=TrustLevel.MED)
    base.update(over)
    return Evidence(evidence_id=evidence_id, **base)


def _claim(text: str, ids: list, cls=ClaimClass.MUST_CITE) -> Claim:
    return Claim(text=text, evidence_ids=ids, claim_class=cls)


class TestGroundedCoverage:
    def test_empty_claims_deny(self):  # SECURITY
        assert must_cite_coverage([], set()) == 0.0
        assert must_cite_coverage([], {"ev-1"},
                                  {"ev-1": _ev("ev-1")}) == 0.0

    def test_advisory_only_may_publish(self):  # UNIT
        claims = [_claim("c", [], ClaimClass.SHOULD_CITE)]
        assert must_cite_coverage(claims, set()) == 1.0

    def test_stale_citation_denies_legacy_path(self):  # SECURITY
        # LEGACY-PATH (primitive backward-compat): membership-only coverage
        # (evidence_by_id=None) still measures 1.0 for member ids. This
        # primitive behavior is preserved; the fail-closed default lives one
        # layer up (reporter.run_report / pipeline.draft_rca deny a None
        # mapping unless legacy_draft=True is passed explicitly).
        claims = [_claim("root cause", ["ev-1"])]
        old = _ev("ev-1", freshness_s=STALE_AFTER_S + 1)
        assert must_cite_coverage(claims, {"ev-1"}, {"ev-1": old}) == 0.0
        assert must_cite_coverage(claims, {"ev-1"}) == 1.0  # legacy path

    def test_low_trust_citation_denies(self):  # SECURITY
        claims = [_claim("root cause", ["ev-1"])]
        shady = _ev("ev-1", trust=TrustLevel.LOW)
        assert must_cite_coverage(claims, {"ev-1"}, {"ev-1": shady}) == 0.0

    def test_unsealed_citation_denies(self):  # SECURITY
        # Canonical Evidence cannot even HOLD an empty hash (model rejects),
        # so unsealed input arrives as a foreign duck: deny via the hash
        # check, never crash on attribute access.
        from types import SimpleNamespace
        claims = [_claim("root cause", ["ev-1"])]
        bare = SimpleNamespace(freshness_s=10.0, trust=TrustLevel.MED,
                               hash="")
        assert must_cite_coverage(claims, {"ev-1"}, {"ev-1": bare}) == 0.0

    def test_missing_from_map_denies(self):  # SECURITY
        claims = [_claim("root cause", ["ev-1"])]
        assert must_cite_coverage(claims, {"ev-1"}, {}) == 0.0

    def test_fresh_med_sealed_counts(self):  # UNIT
        claims = [_claim("a", ["ev-1"]), _claim("b", ["ev-9"])]
        by_id = {"ev-1": _ev("ev-1"), "ev-9": _ev("ev-9")}
        assert must_cite_coverage(claims, {"ev-1", "ev-9"}, by_id) == 1.0
        assert must_cite_coverage(claims, {"ev-1"}, by_id) == 0.5

    def test_malformed_containers_fail_loud(self):  # SECURITY
        with pytest.raises(ValueError):
            must_cite_coverage("claims?", set())  # type: ignore
        with pytest.raises(ValueError):
            must_cite_coverage([], ["ev-1"])  # type: ignore
        with pytest.raises(ValueError):
            must_cite_coverage([], set(), evidence_by_id=[])  # type: ignore

    def test_unreadable_claim_denies_not_crashes(self):  # SECURITY
        class Broken:
            claim_class = ClaimClass.MUST_CITE

            @property
            def evidence_ids(self):
                raise RuntimeError("boom")

        assert must_cite_coverage([Broken()], {"x"}, {}) == 0.0  # type: ignore


class TestPackVerifier:
    def _pack(self, scenario="bad-deploy", variant="NOISY", seed=3):
        return build_evidence_pack(
            "inc-1", gen.generate(scenario, variant, seed))

    def test_valid_packs_verify(self):  # UNIT
        for scenario in ("bad-deploy", "crashloop-oom", "injection"):
            assert verify_evidence_pack(self._pack(scenario)) is True

    def test_oversized_and_malformed_fail(self):  # SECURITY
        pack = self._pack()
        many = dict(pack, evidence=list(pack["evidence"]) * 20)
        assert verify_evidence_pack(many) is False  # >32 items
        big = dict(pack)
        big["evidence"] = [dict(e, ref="x" * 513)
                           for e in pack["evidence"][:1]]
        assert verify_evidence_pack(big) is False  # ref >512
        # Empty pack is well-formed (shape+budget verify, not the grounding
        # gate — an empty pack simply grounds nothing; must_cite_coverage
        # denies it separately).
        assert verify_evidence_pack({}) is True
        assert verify_evidence_pack("pack?") is False
        assert verify_evidence_pack(None) is False
        assert verify_evidence_pack(
            {"evidence": [{"not": "evidence"}]}) is False

    def test_all_scenarios_within_budget(self):  # UNIT
        from app.services.evidence import pack_size_tokens_estimate
        for scenario in sorted(gen.SCENARIOS):
            pack = self._pack(scenario, "NOISY", 5)
            assert pack_size_tokens_estimate(pack) <= 6000, scenario
            assert verify_evidence_pack(pack) is True, scenario


class TestPackDeterminism:
    def test_same_bundle_identical_pack(self):  # UNIT
        a = build_evidence_pack(
            "inc-1", gen.generate("bad-deploy", "NOISY", 3))
        b = build_evidence_pack(
            "inc-1", gen.generate("bad-deploy", "NOISY", 3))
        assert a == b  # byte-identical: ids, ts, trust all derived

    def test_hashes_and_ids_stable_without_wall_clock(self):  # UNIT
        # Ts-less input (adversarial shape): timestamps fall back to arrival
        # time (differ per build), but ids+hashes derive from content and
        # MUST be stable — otherwise caching (M20) breaks on every rebuild.
        tele = {"logs": [
            {"service": "web", "level": "ERROR", "msg": "boom trace=1"}]}
        a = build_evidence_pack("inc-1", tele)
        b = build_evidence_pack("inc-1", tele)
        assert len(a["evidence"]) == len(b["evidence"]) == 1
        assert a["evidence"][0]["hash"] == b["evidence"][0]["hash"]
        assert a["evidence"][0]["evidence_id"] == \
            b["evidence"][0]["evidence_id"]

    def test_empty_telemetry_no_evidence_no_crash(self):  # UNIT
        bare = build_evidence_pack("inc-1", {"logs": [], "metrics": []})
        assert bare["evidence"] == []


class TestComputedTrust:
    def test_multi_pod_signature_is_high(self):  # SECURITY
        tele = {"logs": [
            {"ts": 1000 + i, "service": "web", "pod": f"web-{i % 2 + 1}",
             "level": "ERROR", "msg": "disk_full trace=1", "trace_id": "t"}
            for i in range(6)]}
        pack = build_evidence_pack("inc-1", tele)
        assert pack["evidence"][0]["trust"] == "high"

    def test_single_pod_signature_is_med(self):  # SECURITY
        tele = {"logs": [
            {"ts": 1000 + i, "service": "web", "pod": "web-1",
             "level": "ERROR", "msg": "disk_full trace=1", "trace_id": "t"}
            for i in range(6)]}
        pack = build_evidence_pack("inc-1", tele)
        assert pack["evidence"][0]["trust"] == "med"

    def test_metric_and_deploy_are_med(self):  # UNIT
        pack = build_evidence_pack(
            "inc-1", gen.generate("bad-deploy", "NORMAL", 3))
        by_source = {e["source_id"]: e["trust"] for e in pack["evidence"]}
        assert by_source["error_rate"] == "med"
        assert pack["evidence"][-1]["trust"] == "med"  # deploy, single src

    def test_freshness_derived_not_hardcoded(self):  # UNIT
        # Detection-anchored: bad-deploy seed 3 has first alert at base and
        # deploy at base-300 -> deploy freshness is exactly 300.0 (was: wall
        # input or hardcoded 60/300 constants).
        pack = build_evidence_pack(
            "inc-1", gen.generate("bad-deploy", "NORMAL", 3))
        by_source = {e["source_id"]: e["freshness_s"]
                     for e in pack["evidence"]}
        assert by_source["error_rate"] == 0.0  # aggregate convention
        deploy = [e for e in pack["evidence"]
                  if e["source_id"] == "dep-3"]
        assert deploy and deploy[0]["freshness_s"] == 300.0
        assert all(e["freshness_s"] >= 0 for e in pack["evidence"])
        bare = build_evidence_pack("inc-1", {"logs": [], "metrics": []})
        assert bare["evidence"] == []


class TestCaptureEdges:
    def test_auto_id_and_ts(self):  # UNIT
        e = capture_evidence("i", "log", "s", "r", "content")
        assert len(e.evidence_id) == 32 and e.ts.tzinfo is not None

    def test_trust_string_coerced_unknown_rejected(self):  # SECURITY
        e = capture_evidence("i", "log", "s", "r", "c", trust="high")
        assert e.trust is TrustLevel.HIGH
        with pytest.raises(ValueError):
            capture_evidence("i", "log", "s", "r", "c", trust="omniscient")


class TestLegacyDefaultDeny:
    """Fail-closed default: None mapping without legacy_draft=True raises."""

    def _disabled(self):
        from agents import lyzr_client as LC
        return LC.LyzrClient(LC.ClientConfig())

    def test_reporter_denies_legacy_by_default(self):  # SECURITY
        from agents import reporter as reporter_mod
        from agents import session as session_mod
        from agents.schemas import OutputRejected
        claims = [_claim("root cause", ["ev-1"])]
        with pytest.raises(OutputRejected) as exc:
            reporter_mod.run_report(
                "inc-1", ["t1"], "v23 caused it.", claims, {"ev-1"},
                ["rollback"], ["canary"], self._disabled(),
                session_mod.SessionStore())
        assert "legacy_draft" in str(exc.value) or "evidence_by_id" in str(
            exc.value)

    def test_reporter_legacy_opt_in_proceeds(self):  # UNIT (legacy path)
        from agents import reporter as reporter_mod
        from agents import session as session_mod
        claims = [_claim("root cause", ["ev-1"])]
        out = reporter_mod.run_report(
            "inc-1", ["t1"], "v23 caused it.", claims, {"ev-1"},
            ["rollback"], ["canary"], self._disabled(),
            session_mod.SessionStore(), legacy_draft=True)
        assert out.gated is False

    def test_draft_rca_denies_legacy_by_default(self):  # SECURITY
        from app.services import pipeline as pipeline_mod
        from agents import session as session_mod
        claims = [_claim("root cause", ["ev-1"])]
        with pytest.raises(pipeline_mod.PipelineFailed) as exc:
            pipeline_mod.draft_rca(
                "inc-1", None, None, "v23 caused it.", claims, ["t0"],
                ["rollback"], ["canary"], {"ev-1"}, self._disabled(),
                session_mod.SessionStore())
        assert "evidence_by_id" in str(exc.value) or "hardened" in str(
            exc.value)
