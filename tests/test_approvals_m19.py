"""M19a approvals: request/approve/reject/expire over M07 (host-safe).

Commit A backend half (M19.4 Safety Gate API): pure functions only, no HTTP.
Role checks are demo-grade (M21 owns the guard matrix); crypto is M07-real.
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.routers import approvals as AP  # noqa: E402 (M19a router)
from app.services.audit import AuditChain  # noqa: E402 (M15 chain)

SECRET = "m19-test-secret"


@pytest.fixture(autouse=True)
def _clean():
    AP.reset_demo_state()
    yield
    AP.reset_demo_state()


def _action(**over):
    base = {"incident_id": "inc-1", "agent_id": "planner",
            "action_type": "rollback_deployment",
            "resource_type": "deployment", "resource_id": "web",
            "environment": "mock", "parameters": {"to_version": "v22"},
            "reason": "Roll back web to v22.", "evidence_ids": ["ev-1"],
            "runbook_id": "bad-deploy-rollback", "runbook_version": "1.2.0",
            "expected_outcome": "Spike clears.",
            "verification_plan": ["deployment_version_expected"],
            "rollback_action": {"action_type": "rollback_deployment"}}
    base.update(over)
    return base


def _request(actor="sre-1", secret=SECRET, ttl=600, chain=None, **over):
    return AP.request_approval(_action(**over), actor, secret,
                               ttl_seconds=ttl, chain=chain)


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

def test_request_ok():
    out = _request()
    assert out["status"] == "pending" and out["token"]
    assert "action_id" in out["scope"] or "rollback" in out["scope"]
    view = AP.approval_view(out["approval_id"])
    assert view["status"] == "pending"
    assert 590 < view["seconds_remaining"] <= 600


def test_request_rejects_garbage_action():
    with pytest.raises(ValueError):
        _request(action_type="nuke_it")
    with pytest.raises(ValueError):
        AP.request_approval("not-a-mapping", "sre-1", SECRET)


def test_request_rejects_shell_action():
    with pytest.raises(ValueError):
        _request(action_type="shell", parameters={"cmd": "x"})


def test_request_rejects_blank_actor_secret():
    with pytest.raises(ValueError):
        _request(actor="  ")
    with pytest.raises(ValueError):
        _request(secret="")


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------

def test_approve_happy():
    out = _request()
    view = AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                               "approver", SECRET)
    assert view["status"] == "approved"


def test_approve_wrong_role():
    out = _request()
    with pytest.raises(AP.ApprovalDenied):
        AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                            "viewer", SECRET)
    assert AP.http_status(AP.ApprovalDenied("x")) == 403


def test_approve_tampered_token_and_actor():
    out = _request()
    with pytest.raises(AP.ApprovalDenied):
        AP.approve_approval(out["approval_id"], "sre-1", out["token"] + "x",
                            "approver", SECRET)
    with pytest.raises(AP.ApprovalDenied):
        AP.approve_approval(out["approval_id"], "intruder", out["token"],
                            "approver", SECRET)


def test_approve_expired_is_410():
    out = _request(ttl=600)
    AP.sweep_approvals(time.time() + 3601)
    assert AP.approval_view(out["approval_id"])["status"] == "expired"
    with pytest.raises(AP.ApprovalExpired):
        AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                            "approver", SECRET)
    assert AP.http_status(AP.ApprovalExpired("x")) == 410


def test_approve_idempotent_cached():
    out = _request()
    first = AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                                "approver", SECRET, idempotency_key="k1")
    second = AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                                 "approver", SECRET, idempotency_key="k1")
    assert first["duplicate"] is False and second["duplicate"] is True
    assert second["status"] == "approved"
    with pytest.raises(ValueError):
        AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                            "approver", SECRET, idempotency_key="  ")


def test_second_approve_without_key_denied():
    out = _request()
    AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                        "approver", SECRET)
    with pytest.raises(AP.ApprovalDenied):
        AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                            "approver", SECRET)


# ---------------------------------------------------------------------------
# Reject + sweep + audit
# ---------------------------------------------------------------------------

def test_reject_flow():
    out = _request()
    view = AP.reject_approval(out["approval_id"], "sre-1", "approver",
                              reason="too risky")
    assert view["status"] == "denied"
    with pytest.raises(AP.ApprovalDenied):
        AP.reject_approval(out["approval_id"], "sre-1", "viewer")


def test_unknown_id_404():
    with pytest.raises(AP.ApprovalMissing):
        AP.approval_view("nope")
    assert AP.http_status(AP.ApprovalMissing("x")) == 404
    assert AP.http_status(AP.ApprovalReplayed("x")) == 409
    assert AP.http_status(ValueError("x")) == 422


def test_audit_events_linked():
    chain = AuditChain(incident_id="inc-1")
    out = _request(chain=chain)
    AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                        "approver", SECRET, chain=chain)
    out2 = _request(chain=chain)
    AP.reject_approval(out2["approval_id"], "sre-1", "approver",
                       reason="nope", chain=chain)
    assert len(chain.by_approval(out["approval_id"])) == 2  # request+approve
    assert len(chain.by_approval(out2["approval_id"])) == 2  # request+deny
    assert chain.verify()["valid"] is True


def test_sweep_returns_expired_ids():
    AP.request_approval(_action(), "sre-1", SECRET, ttl_seconds=600)
    assert AP.sweep_approvals(time.time() + 3601) != []


def test_main_wires_approvals_router():
    import ast as _ast
    root = Path(__file__).resolve().parents[1]
    src = (root / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert "approvals" in src
    tree = _ast.parse(src)
    assert sum(1 for n in _ast.walk(tree) if isinstance(n, _ast.Call)
               and getattr(n.func, "attr", "") == "include_router") >= 3
