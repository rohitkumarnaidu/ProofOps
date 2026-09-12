"""Execution-half tests: HITL crypto, sandbox transitions, verifier, rollback."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.schemas import Action  # noqa: E402
from app.services.approval import NonceStore, issue, verify, ApprovalError  # noqa: E402
from app.services.rollback import rollback_for, should_rollback  # noqa: E402
from app.services.sandbox import MOCKABLE, apply, initial_state  # noqa: E402
from app.services.verifier import verify as verify_slo  # noqa: E402

SECRET = "test-secret"
SLO = {"error_rate_below": 0.01}


def act(**over) -> Action:
    base = dict(incident_id="inc-1", agent_id="planner",
                action_type="rollback_deployment", resource_type="deployment",
                resource_id="web", environment="mock", parameters={"to_version": "v22"},
                reason="r", evidence_ids=["ev-1"], runbook_id="bad-deploy-rollback",
                runbook_version="1.2.0", expected_outcome="o",
                verification_plan=["error_rate_below_1pct"],
                rollback_action={"action_type": "rollback_deployment"})
    base.update(over)
    return Action(**base)


# --- HITL ---------------------------------------------------------------------
def test_hitl_happy_path():
    a = act()
    req, tok = issue(a, "sre-1", SECRET)
    out = verify(tok, req, a, "sre-1", SECRET, NonceStore())
    assert out.approval_id == req.approval_id


def test_hitl_replay_denied():
    a, store = act(), NonceStore()
    req, tok = issue(a, "sre-1", SECRET)
    verify(tok, req, a, "sre-1", SECRET, store)
    with pytest.raises(ApprovalError, match="replayed"):
        verify(tok, req, a, "sre-1", SECRET, store)


def test_hitl_tampered_signature_denied():
    a, store = act(), NonceStore()
    req, _ = issue(a, "sre-1", SECRET)
    with pytest.raises(ApprovalError, match="signature"):
        verify("0" * 64, req, a, "sre-1", SECRET, store)


def test_hitl_wrong_actor_denied():
    a, store = act(), NonceStore()
    req, tok = issue(a, "sre-1", SECRET)
    with pytest.raises(ApprovalError, match="actor"):
        verify(tok, req, a, "intruder", SECRET, store)


def test_hitl_param_change_denied():
    a, store = act(), NonceStore()
    req, tok = issue(a, "sre-1", SECRET)
    a2 = act(parameters={"to_version": "v99-evil"})
    with pytest.raises(ApprovalError, match="parameters"):
        verify(tok, req, a2, "sre-1", SECRET, store)


def test_hitl_expired_denied():
    a, store = act(), NonceStore()
    req, tok = issue(a, "sre-1", SECRET, ttl_seconds=-1)
    with pytest.raises(ApprovalError, match="expired"):
        verify(tok, req, a, "sre-1", SECRET, store)


def test_hitl_wrong_secret_denied():
    a, store = act(), NonceStore()
    req, tok = issue(a, "sre-1", SECRET)
    with pytest.raises(ApprovalError):
        verify(tok, req, a, "sre-1", "other-secret", store)


# --- sandbox -------------------------------------------------------------------
def test_rollback_mutates_state_demo_numbers():
    st = initial_state("web", "v23", 0.18)
    exe, after = apply(act(), st)
    assert after["deployment_version"] == "v22"
    assert after["error_rate"] == 0.008
    assert exe.state_diff["changed"]["deployment_version"] == \
        {"before": "v23", "after": "v22"}
    assert st["deployment_version"] == "v23"  # input snapshot untouched


def test_scale_and_restart_transitions():
    st = initial_state()
    _, s2 = apply(act(action_type="scale_deployment", parameters={"replicas": 5},
                      rollback_action={"a": 1}), st)
    assert s2["replicas"] == 5
    _, s3 = apply(act(action_type="restart_pod", parameters={},
                      rollback_action={"a": 1}), s2)
    assert s3["restarts"] == 1 and s3["pods_ready"] is True


def test_reads_zero_diff():
    st = initial_state()
    exe, _ = apply(act(action_type="logs", parameters={}), st)
    assert exe.state_diff["changed"] == {}


def test_red_never_executable_in_mock():
    for t in ["delete_namespace", "shell", "db_write", "secret_access"]:
        assert t not in MOCKABLE
        with pytest.raises(ValueError):
            apply(act(action_type=t, parameters={}), initial_state())


# --- verifier -------------------------------------------------------------------
def test_verify_resolved_and_failed():
    before = initial_state("web", "v23", 0.18)
    ok_after = dict(before, deployment_version="v22", error_rate=0.008)
    v = verify_slo("e1", before, ok_after, SLO, {"version": "v22"})
    assert v.verdict == "RESOLVED" and all(v.checks.values())
    # exit-0-with-bad-SLO is FAILED, never resolved (RULE 07)
    bad_after = dict(before, deployment_version="v22", error_rate=0.15)
    v2 = verify_slo("e2", before, bad_after, SLO, {"version": "v22"})
    assert v2.verdict in ("FAILED", "ROLLBACK_REQUIRED")


def test_verify_worsened_and_partial():
    before = initial_state("web", "v23", 0.05)
    worse = dict(before, error_rate=0.30)
    assert verify_slo("e", before, worse, SLO).verdict == "WORSENED"
    partial = dict(before, error_rate=0.005, pods_ready=False)
    assert verify_slo("e", before, partial, SLO).verdict == "PARTIAL"


# --- rollback --------------------------------------------------------------------
def test_rollback_inverse_and_single_attempt():
    a = act(action_type="scale_deployment", parameters={"replicas": 8},
            rollback_action={"a": 1})
    inv = rollback_for(a, {"replicas": 3})
    assert inv.parameters == {"replicas": 3}
    assert inv.agent_id == "rollback-controller"
    assert should_rollback("FAILED", 0) is True
    assert should_rollback("FAILED", 1) is False
    assert should_rollback("RESOLVED", 0) is False
