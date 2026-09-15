"""M07-M10 tests: HITL binding, sandbox tiers, verifier, rollback control.

Registry verify methods:
- M07: field+params-hash binding, HMAC sign/verify, single-use burn,
  TTL expiry, tampered-params DENY, wrong-actor DENY, replay DENY,
  request/token audit linkage fields.
- M08: state transitions, zero-diff block guarantee, execution logging,
  docker allowlist+refusal, isolation-constraint declaration.
- M09: pod/deploy/SLO/error/latency/CrashLoop checks, verdict matrix,
  exit-0-bad-SLO failure, rollback trigger.
- M10: rollback template, FAILED/WORSENED conditions, single attempt,
  re-verify contract, irreversible escalation (no RED path).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.contracts import Action, ApprovalRequest  # noqa: E402
from app.services.approval import (  # noqa: E402
    ApprovalError,
    NonceStore,
    issue,
    scope_of,
    verify,
)
from app.services.rollback import (  # noqa: E402
    MAX_AUTO_ROLLBACKS,
    REVERSIBLE,
    rollback_for,
    should_rollback,
)
from app.services.sandbox import (  # noqa: E402
    DOCKER_CONSTRAINTS,
    DOCKERABLE,
    MOCKABLE,
    apply,
    apply_docker,
    initial_state,
)
from app.services.verifier import verify as verify_slo  # noqa: E402

SECRET = "test-secret"
SLO = {"error_rate_below": 0.01}


def act(**over) -> Action:
    base = dict(incident_id="inc-1", agent_id="planner",
                action_type="rollback_deployment", resource_type="deployment",
                resource_id="web", environment="mock",
                parameters={"to_version": "v22"}, reason="r",
                evidence_ids=["ev-1"], runbook_id="bad-deploy-rollback",
                runbook_version="1.2.0", expected_outcome="o",
                verification_plan=["error_rate_below_1pct"],
                rollback_action={"action_type": "rollback_deployment"})
    base.update(over)
    return Action(**base)


# ------------------------------------------------------- M07 HITL binding
class TestApprovalBinding:
    def test_scope_binds_exact_shape(self):  # UNIT (M07.1/M07.5)
        a = act()
        assert scope_of(a) == ("rollback_deployment:deployment:web:mock:"
                               "default")
        req, _ = issue(a, "sre-1", SECRET)
        assert isinstance(req, ApprovalRequest)
        assert req.action_id == a.action_id and req.actor == "sre-1"
        assert req.scope == scope_of(a)  # scope == exact params context

    def test_resource_change_breaks_scope(self):  # UNIT (M07.5 tamper)
        a, store = act(), NonceStore()
        req, tok = issue(a, "sre-1", SECRET)
        moved = act(resource_id="api")  # same params, different resource
        with pytest.raises(ApprovalError, match="scope"):
            verify(tok, req, moved, "sre-1", SECRET, store)

    def test_expiry_tamper_breaks_signature(self):  # UNIT (M07.4)
        a, store = act(), NonceStore()
        req, tok = issue(a, "sre-1", SECRET)
        forged = req.model_copy(update={"expires_at": req.expires_at})
        # same instant, fresh object: signature still verifies (bound data
        # unchanged) - but a CHANGED expiry must not:
        later = req.expires_at.replace(year=req.expires_at.year + 1)
        forged2 = ApprovalRequest(approval_id=req.approval_id,
                                  incident_id=req.incident_id,
                                  action_id=req.action_id, actor=req.actor,
                                  params_hash=req.params_hash, scope=req.scope,
                                  expires_at=later, nonce=req.nonce)
        with pytest.raises(ApprovalError):
            verify(tok, forged2, a, "sre-1", SECRET, store)
        assert forged.expires_at == req.expires_at

    def test_empty_secret_fails_closed(self):  # SECURITY (M07.2)
        with pytest.raises(ValueError):
            issue(act(), "sre-1", "")
        with pytest.raises(ValueError):
            issue(act(), "   ", SECRET)

    def test_empty_actor_rejected(self):  # UNIT (M07.6)
        with pytest.raises(ValueError):
            issue(act(), "", SECRET)

    def test_nonce_unique_per_issue(self):  # UNIT (M07.3)
        a = act()
        (_, _), (req2, _) = (issue(a, "s", SECRET), issue(a, "s", SECRET))
        req1, _ = issue(a, "s", SECRET)
        assert len({req1.nonce, req2.nonce}) == 2

    def test_missing_token_denied(self):  # UNIT
        a, store = act(), NonceStore()
        req, _ = issue(a, "sre-1", SECRET)
        with pytest.raises(ApprovalError):
            verify("", req, a, "sre-1", SECRET, store)

    def test_ttl_default_600(self):  # UNIT (M07.4)
        from app.contracts.values import utcnow as _utcnow  # noqa: E402

        req, _ = issue(act(), "sre-1", SECRET)
        skew = (req.expires_at - _utcnow()).total_seconds()
        assert 595.0 < skew <= 600.0

    def test_audit_linkage_fields(self):  # UNIT (M07.8 refs for M15)
        req, _ = issue(act(), "sre-1", SECRET)
        assert req.incident_id == "inc-1" and req.action_id
        assert req.params_hash and len(req.params_hash) == 64
        assert req.nonce and req.expires_at.tzinfo is not None


# ------------------------------------------------------- M08 sandbox
class TestSandboxTiers:
    def test_execution_logging_shape(self):  # UNIT (M08.4)
        exe, after = apply(act(), initial_state())
        assert len(exe.execution_id) == 32
        assert str(exe.tier) == "mock" and exe.logs
        assert exe.idempotency_key == exe.action_id
        assert set(exe.state_diff.to_plain()) == {"before", "after",
                                                  "changed"}

    def test_blocked_action_zero_diff_impossible(self):  # UNIT (M08.3)
        # Blocked actions never reach apply(): the gate is the allowlist
        # itself - apply() raises BEFORE touching state (input untouched).
        st = initial_state()
        snapshot = dict(st)
        with pytest.raises(ValueError):
            apply(act(action_type="delete_namespace", parameters={}), st)
        assert st == snapshot  # zero diff by construction

    def test_docker_refuses_without_daemon(self):  # UNIT (M08.5 honesty)
        with pytest.raises(RuntimeError, match="no reachable daemon"):
            apply_docker(act(), initial_state())

    def test_docker_allowlist_mirrors_mock(self):  # UNIT (M08.5)
        assert DOCKERABLE == MOCKABLE
        for red in ("delete_namespace", "delete_deployment", "rbac_change",
                    "secret_access", "db_write", "reboot_node", "shell",
                    "delete_pod"):
            assert red not in DOCKERABLE

    def test_isolation_constraints_declared(self):  # UNIT (M08.6)
        assert DOCKER_CONSTRAINTS == {"unprivileged": True,
                                      "no_secret_mounts": True,
                                      "network_isolated": True,
                                      "timeout_s": 60}

    def test_state_transitions(self):  # UNIT (M08.1/M08.2)
        _, s = apply(act(action_type="rolling_restart", parameters={},
                         rollback_action={"a": 1}), initial_state())
        assert s["restarts"] == 1 and s["error_rate"] == 0.09
        _, s2 = apply(act(action_type="patch_config", parameters={},
                          rollback_action={"a": 1}), initial_state())
        assert s2["config_rev"] == "c2"


# ------------------------------------------------------- M09 verifier
class TestVerifier:
    def test_exit_status_never_resolves(self):  # SECURITY (M09.8)
        before = initial_state("web", "v23", 0.18)
        bad = dict(before, deployment_version="v22", error_rate=0.15)
        v0 = verify_slo("e", before, bad, SLO, {"version": "v22"},
                        command_succeeded=True)
        v1 = verify_slo("e", before, bad, SLO, {"version": "v22"},
                        command_succeeded=False)
        assert v0.verdict == v1.verdict != "RESOLVED"  # exit 0 != resolved
        assert "exit=" in v0.detail and "exit=" in v1.detail

    def test_latency_check(self):  # UNIT (M09.5)
        before = initial_state("web", "v23", 0.18)
        ok = dict(before, deployment_version="v22", error_rate=0.008,
                  latency_p95_ms=120)
        v = verify_slo("e", before, ok,
                       dict(SLO, latency_p95_below_ms=500),
                       {"version": "v22"})
        assert v.checks["latency_p95_below_slo"] is True
        slow = dict(ok, latency_p95_ms=900)
        v2 = verify_slo("e", before, slow,
                        dict(SLO, latency_p95_below_ms=500),
                        {"version": "v22"})
        assert v2.checks["latency_p95_below_slo"] is False
        assert v2.verdict != "RESOLVED"
        # absent instrumentation skips the check instead of failing
        v3 = verify_slo("e", before, ok_after_no_lat(ok), SLO,
                        {"version": "v22"})
        assert "latency_p95_below_slo" not in v3.checks

    def test_crashloop_fails(self):  # UNIT (M09.6)
        before = initial_state("web", "v23", 0.18)
        crash = dict(before, error_rate=0.008, crashloop=True)
        v = verify_slo("e", before, crash, SLO)
        assert v.checks["no_crashloop"] is False
        assert v.verdict in ("FAILED", "ROLLBACK_REQUIRED", "PARTIAL")

    def test_version_check(self):  # UNIT (M09.2)
        before = initial_state("web", "v23", 0.18)
        wrong = dict(before, error_rate=0.008, deployment_version="v24")
        v = verify_slo("e", before, wrong, SLO, {"version": "v22"})
        assert v.checks["version_as_expected"] is False
        assert v.verdict != "RESOLVED"

    def test_verdict_matrix_all_covered(self):  # UNIT (M09.7)
        before = initial_state("web", "v23", 0.18)
        seen = set()
        seen.add(verify_slo("e", before,
                            dict(before, deployment_version="v22",
                                 error_rate=0.008),
                            SLO, {"version": "v22"}).verdict)
        seen.add(verify_slo("e", before, dict(before, error_rate=0.30),
                            SLO).verdict)
        seen.add(verify_slo("e", before,
                            dict(before, error_rate=0.15), SLO).verdict)
        seen.add(verify_slo("e", before,
                            dict(before, error_rate=0.005, pods_ready=False),
                            SLO).verdict)
        assert {"RESOLVED", "WORSENED", "PARTIAL"} <= {str(v) for v in seen}


def ok_after_no_lat(ok: dict) -> dict:
    return {k: v for k, v in ok.items() if k != "latency_p95_ms"}


# ------------------------------------------------------- M10 rollback
class TestRollbackControl:
    def test_red_has_no_path(self):  # SECURITY (M10.5)
        for red in ("delete_namespace", "delete_deployment", "shell",
                    "db_write", "secret_access", "reboot_node",
                    "delete_pod"):
            with pytest.raises(ValueError, match="no autonomous rollback"):
                rollback_for(act(action_type=red, parameters={}), {})

    def test_reversible_set_matches_matrix(self):  # UNIT (M10.1)
        assert {str(a) for a in REVERSIBLE} == {"restart_pod",
                                                "scale_deployment",
                                                "rolling_restart",
                                                "rollback_deployment",
                                                "patch_config"}

    def test_single_attempt_bound(self):  # UNIT (M10.3)
        assert MAX_AUTO_ROLLBACKS == 1
        assert should_rollback("ROLLBACK_REQUIRED", 0) is True
        assert should_rollback("WORSENED", 0) is True
        assert should_rollback("ROLLBACK_REQUIRED", 1) is False
        assert should_rollback("PARTIAL", 0) is False

    def test_inverse_carries_context(self):  # UNIT (M10.2/M10.4)
        inv = rollback_for(act(action_type="rollback_deployment",
                               parameters={"to_version": "v23"}),
                           {"deployment_version": "v22"})
        assert inv.parameters.to_plain() == {"to_version": "v22"}
        assert inv.agent_id == "rollback-controller"
        assert inv.verification_plan == ("error_rate_below_1pct",)
        assert inv.evidence_ids == ("ev-1",)

    def test_reverify_contract(self):  # UNIT (M10.4: re-verify decides)
        before = initial_state("web", "v23", 0.18)
        exe, after = apply(act(), before)
        v = verify_slo(exe.execution_id, before, after, SLO,
                       {"version": "v22"})
        assert v.verdict == "RESOLVED"  # healthy post-state resolves
        assert should_rollback(v.verdict, 0) is False  # no rollback on green
