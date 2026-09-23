"""M05/M06 tests: evidence service + taxonomy + bundle + matrix sweep.

Registry verify methods:
- M05: field+ref, hash-validity, staleness-escalate, trust agreement,
  pack budget, MUST-CITE coverage gate.
- M06: shell/param rejects (pre-policy), allowlist completeness,
  matrix-vs-bundle consistency, bundle version/rule refs, 40+ ALLOW/
  ESCALATE/DENY regressions, unknown/exception->DENY, most-restrictive
  wins, blast thresholds, env matrix, version+rule linkage.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "telemetry"))

import gen  # noqa: E402

from app.contracts import Action, params_hash  # noqa: E402
from app.contracts.enums import ACTION_TYPES, TrustLevel  # noqa: E402
from app.contracts.evidence import Evidence  # noqa: E402
from app.contracts.hypothesis import Claim  # noqa: E402
from app.services.evidence import (  # noqa: E402
    STALE_AFTER_S,
    capture_evidence,
    content_hash,
    is_stale,
    must_cite_coverage,
    pack_size_tokens_estimate,
    trust_for,
)
from app.services.policy import (  # noqa: E402
    evaluate,
    load_bundle,
    load_matrix,
    validate_bundle,
)
from app.services.predigest import build_evidence_pack  # noqa: E402
from app.services.validator import (  # noqa: E402
    READ_TYPES,
    validate_action,
)

BUNDLE = load_bundle()
MATRIX = load_matrix()
APPROVER = {"role": "approver", "id": "sre-1"}
VIEWER = {"role": "viewer", "id": "obs-1"}
BLAST_SMALL = {"scope": "deploy", "replicas": 2, "traffic_pct": 10}


def act(**over) -> Action:
    base = dict(incident_id="inc-1", agent_id="planner",
                action_type="read", resource_type="deployment",
                resource_id="web", environment="mock", parameters={},
                reason="r", evidence_ids=["ev-1"],
                runbook_id="bad-deploy-rollback", runbook_version="1.2.0",
                expected_outcome="o", verification_plan=["v"])
    base.update(over)
    return Action(**base)


def ev(action, actor=APPROVER, blast=BLAST_SMALL, sev="P1"):
    return evaluate(action, actor, {"environment": action.environment},
                    sev, blast, BUNDLE, MATRIX)


# ------------------------------------------------------- M05.1/M05.2 capture+hash
class TestCapture:
    def test_hash_binds_content(self):  # UNIT (M05.2 hash-validity)
        e = capture_evidence("inc-1", "log", "svc", "line 42",
                             "boom traceback")
        assert isinstance(e, Evidence) and len(e.hash) == 64
        assert e.hash == content_hash("boom traceback")
        assert capture_evidence("inc-1", "log", "svc", "line 42",
                                "different").hash != e.hash

    def test_bytes_and_str_hash(self):  # UNIT
        assert content_hash(b"abc") == content_hash("abc")
        assert len(content_hash(b"abc")) == 64
        with pytest.raises(ValueError):
            content_hash(123)  # type: ignore

    def test_defaults_fresh_med(self):  # UNIT (M05.1 field+ref)
        e = capture_evidence("inc-1", "metric", "m", "row 7", "0.18")
        assert e.trust is TrustLevel.MED and e.relevance == 1.0
        assert e.freshness_s == 0.0 and e.incident_id == "inc-1"

    def test_unknown_source_rejected(self):  # UNIT
        with pytest.raises(ValueError):
            capture_evidence("inc-1", "telepathy", "s", "r", "c")


# ------------------------------------------------------- M05.3/M05.4 freshness+trust
class TestFreshnessTrust:
    def test_stale_boundary(self):  # UNIT (M05.3 staleness)
        fresh = capture_evidence("i", "log", "s", "r", "c", freshness_s=60.0)
        old = capture_evidence("i", "log", "s", "r", "c",
                               freshness_s=STALE_AFTER_S + 1)
        assert is_stale(fresh) is False
        assert is_stale(old) is True
        assert is_stale(fresh, max_age_s=30.0) is True  # tighter bound

    def test_trust_matrix(self):  # UNIT (M05.4 agreement)
        assert trust_for(True, True) is TrustLevel.HIGH
        assert trust_for(True, False) is TrustLevel.MED
        assert trust_for(False, True) is TrustLevel.LOW
        assert trust_for(False, False) is TrustLevel.LOW


# ------------------------------------------------------- M05.5 pack budget
class TestPackBudget:
    def test_canonical_pack_and_budget(self):  # UNIT (M05.5)
        tele = gen.generate("bad-deploy", "NOISY", 3)
        pack = build_evidence_pack("inc-1", tele)
        assert pack_size_tokens_estimate(pack) <= 6000
        assert len(pack["top_errors"]) <= 5
        for item in pack["evidence"]:
            ev = Evidence.model_validate(item)  # canonical shape
            assert ev.incident_id == "inc-1" and len(ev.hash) == 64

    def test_estimate_is_documented_heuristic(self):  # UNIT
        assert pack_size_tokens_estimate({}) == 0
        assert pack_size_tokens_estimate({"a": "x" * 400}) >= 100


# ------------------------------------------------------- M05.6 coverage gate
# LEGACY-PATH NOTE: membership-only coverage (evidence_by_id=None) is the
# backward-compatible primitive. It is preserved here; the fail-closed
# default lives one layer up (reporter.run_report / pipeline.draft_rca deny
# a None mapping unless legacy_draft=True is passed explicitly).
class TestCoverageLegacyPath:
    def test_full_and_partial_legacy_path(self):  # UNIT (M05.6 gate)
        claims = [Claim(text="a", evidence_ids=["ev-1"]),
                  Claim(text="b", evidence_ids=["ev-9"])]
        assert must_cite_coverage(claims, {"ev-1", "ev-2"}) == 0.5
        assert must_cite_coverage(claims, {"ev-1", "ev-9"}) == 1.0

    def test_non_must_never_gates(self):  # UNIT
        claims = [Claim(text="c", evidence_ids=[], claim_class="SHOULD-CITE"),
                  Claim(text="d", evidence_ids=[], claim_class="OPTIONAL")]
        assert must_cite_coverage(claims, set()) == 1.0  # vacuous open

    def test_empty_claims_deny(self):  # SECURITY (M05.6 gate)
        # P1 closure (was: vacuous-open 1.0): an RCA with NO claims at all
        # carries no evidence and must never pass the publish gate. Non-empty
        # claim lists with zero MUST-CITE claims still score 1.0 (above).
        assert must_cite_coverage([], set()) == 0.0


class TestCoverageDefaultDeny:
    """Fail-closed default: None mapping without legacy_draft=True raises."""

    def _disabled(self):
        import sys as _sys
        from pathlib import Path as _Path
        _root = _Path(__file__).resolve().parents[1]
        if str(_root) not in _sys.path:
            _sys.path.insert(0, str(_root))
        from agents import lyzr_client as LC
        return LC.LyzrClient(LC.ClientConfig())

    def test_reporter_denies_legacy_by_default(self):  # SECURITY
        from agents import reporter as reporter_mod
        from agents import session as session_mod
        from agents.schemas import OutputRejected
        claims = [Claim(text="a", evidence_ids=["ev-1"])]
        with pytest.raises(OutputRejected) as exc:
            reporter_mod.run_report(
                "inc-1", ["t1"], "v23 caused it.", claims, {"ev-1"},
                ["rollback"], ["canary"], self._disabled(),
                session_mod.SessionStore())
        assert "legacy_draft" in str(exc.value) or "evidence_by_id" in str(
            exc.value)

    def test_draft_rca_denies_legacy_by_default(self):  # SECURITY
        from agents import session as session_mod
        from app.services import pipeline as pipeline_mod
        claims = [Claim(text="a", evidence_ids=["ev-1"])]
        with pytest.raises(pipeline_mod.PipelineFailed):
            pipeline_mod.draft_rca(
                "inc-1", None, None, "v23 caused it.", claims, ["t0"],
                ["rollback"], ["canary"], {"ev-1"}, self._disabled(),
                session_mod.SessionStore())

    def test_reporter_legacy_opt_in_proceeds(self):  # UNIT (legacy path)
        from agents import reporter as reporter_mod
        from agents import session as session_mod
        claims = [Claim(text="a", evidence_ids=["ev-1"])]
        out = reporter_mod.run_report(
            "inc-1", ["t1"], "v23 caused it.", claims, {"ev-1"},
            ["rollback"], ["canary"], self._disabled(),
            session_mod.SessionStore(), legacy_draft=True)
        assert out.gated is False


# ------------------------------------------------------- M06.2 taxonomy
class TestTaxonomy:
    def test_matrix_covers_allowlist_exactly(self):  # UNIT (M06.2/M06.3)
        assert set(MATRIX["tiers"]) == set(ACTION_TYPES)

    def test_every_tier_has_all_envs(self):  # UNIT
        for atype, tiers in MATRIX["tiers"].items():
            assert set(tiers) == {"mock", "dev", "staging", "prod"}, atype
            assert set(tiers.values()) <= {"GREEN", "YELLOW", "RED"}, atype

    def test_validator_sets_within_allowlist(self):  # UNIT
        assert READ_TYPES <= set(ACTION_TYPES)

    def test_reversible_matches_matrix(self):  # UNIT
        assert set(MATRIX["reversible"]) == {"restart_pod",
                                             "scale_deployment",
                                             "rolling_restart",
                                             "rollback_deployment",
                                             "patch_config"}


# ------------------------------------------------------- M06.4 bundle schema
class TestBundleSchema:
    def test_shipped_bundle_valid(self):  # UNIT (M06.4 version/rule refs)
        assert validate_bundle(BUNDLE) == []
        assert BUNDLE["policy_version"] == "v1"

    @pytest.mark.parametrize("mutate", [
        lambda b: b.pop("policy_version"),
        lambda b: b.update(deny_rules=[]),
        lambda b: b.update(deny_rules=None),
        lambda b: b.update(deny_rules=[{"id": "X"}]),
        lambda b: b["deny_rules"].append({"id": "X", "when": {"color": "red"}}),
        lambda b: b["deny_rules"].append({"id": "X",
                                          "when": {"action_type": "teleport"}}),
        lambda b: b["deny_rules"].append({"id": "X",
                                          "when": {"environment": "moon"}}),
        lambda b: b.update(escalate_obligations="hitl-approval"),
    ])
    def test_malformed_bundle_rejected(self, mutate):  # UNIT
        import copy
        bad = copy.deepcopy(BUNDLE)
        mutate(bad)
        assert validate_bundle(bad), "malformed bundle must produce errors"

    def test_non_object_rejected(self):  # UNIT
        assert validate_bundle(None) and validate_bundle("bundle")

    def test_invalid_bundle_denies_at_engine(self):  # SECURITY
        d = evaluate(act(), APPROVER, {"environment": "mock"}, "P1",
                     BLAST_SMALL, {"deny_rules": None}, MATRIX)
        assert d.decision == "DENY" and d.rule_id == "DENY-invalid-bundle"
        d2 = evaluate(act(), APPROVER, {"environment": "mock"}, "P1",
                      BLAST_SMALL, BUNDLE, {"nope": 1})
        assert d2.decision == "DENY" and d2.rule_id == "DENY-invalid-matrix"


# ------------------------------------------------------- M06.5 72-case matrix sweep
EXPECTED_DECISION = {"GREEN": "ALLOW", "YELLOW": "ESCALATE", "RED": "DENY"}


class TestMatrixSweep:
    @pytest.mark.parametrize("atype", list(ACTION_TYPES))
    @pytest.mark.parametrize("env", ["mock", "dev", "staging", "prod"])
    def test_matrix_regression(self, atype, env):  # 72 regressions (M06.5)
        tier = MATRIX["tiers"][atype][env]
        d = ev(act(action_type=atype, environment=env))
        assert d.decision == EXPECTED_DECISION[tier], (atype, env, tier)
        assert d.policy_version == "v1" and d.rule_id  # M06.10 linkage
        assert d.effective_risk == tier

    def test_count_sanity(self):  # UNIT
        assert len(ACTION_TYPES) == 18  # sweep is 18x4 = 72 cases


# ------------------------------------------------------- M06.6/M06.7/M06.8/M06.9
class TestPolicySemantics:
    def test_default_deny_unknown_shape(self):  # UNIT (M06.6)
        a = act()
        object.__setattr__(a, "parameters", "doom")  # smuggled past schema
        d = ev(a)
        assert d.decision == "DENY"

    def test_most_restrictive_wins(self):  # UNIT (M06.7)
        # delete_pod/prod is RED by matrix AND matches no DENY rule text for
        # pods, yet the explicit DENY-prod-delete-pod rule fires first.
        d = ev(act(action_type="delete_pod", environment="prod"))
        assert d.decision == "DENY" and d.rule_id == "DENY-prod-delete-pod"

    def test_blast_thresholds(self):  # UNIT (M06.8)
        small = ev(act(action_type="scale_deployment", environment="staging"),
                   blast={"replicas": 4, "traffic_pct": 50})
        assert "blast-review" not in small.obligations
        big_replicas = ev(
            act(action_type="scale_deployment", environment="staging"),
            blast={"replicas": 5, "traffic_pct": 10})
        assert "blast-review" in big_replicas.obligations
        big_traffic = ev(
            act(action_type="scale_deployment", environment="staging"),
            blast={"replicas": 1, "traffic_pct": 51})
        assert "blast-review" in big_traffic.obligations

    def test_env_aware_divergence(self):  # UNIT (M06.9)
        assert ev(act(action_type="restart_pod",
                      environment="mock")).decision == "ALLOW"
        assert ev(act(action_type="restart_pod",
                      environment="prod")).decision == "ESCALATE"
        assert ev(act(action_type="delete_pod",
                      environment="mock")).decision == "ESCALATE"
        assert ev(act(action_type="delete_pod",
                      environment="prod")).decision == "DENY"

    def test_audit_linkage_always_present(self):  # UNIT (M06.10)
        for atype, env in [("read", "prod"), ("rollback_deployment", "prod"),
                           ("shell", "mock")]:
            d = ev(act(action_type=atype, environment=env))
            assert d.policy_version and d.rule_id and d.message is not None
            assert d.ttl_seconds >= 0

    def test_params_hash_scope_binding(self):  # UNIT
        assert params_hash({"a": 1}) != params_hash({"a": 2})
        assert params_hash({"a": 1}) == params_hash({"a": 1})


# ------------------------------------------------------- security
class TestSecurity:
    def test_validator_shell_never_passes(self):  # SECURITY (M06.1)
        errs = validate_action(act(action_type="shell",
                                   parameters={"cmd": "echo hi"}))
        assert any("shell" in e for e in errs)

    def test_validator_metachar_and_sql(self):  # SECURITY
        bad = act(action_type="read",
                  parameters={"q": "a;b", "w": "x|y", "e": "DROP TABLE t"})
        errs = validate_action(bad)
        assert len(errs) == 3

    def test_engine_never_raises(self):  # SECURITY
        d = evaluate(act(), APPROVER, {}, "P1", BLAST_SMALL, None, None)
        assert d.decision in ("ALLOW", "ESCALATE", "DENY")
        d2 = evaluate(None, None, None, None, None, None, None)  # type: ignore
        assert d2.decision == "DENY"
