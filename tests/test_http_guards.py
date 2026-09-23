"""HTTP guard matrix: every mutating handler requires X-API-Key (P1 closure).

Pure functions stay key-free (unit-testable); the http_* translation layer
enforces auth_mod.guard_http. Settings are monkeypatched so no env is read.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.routers import approvals as AP  # noqa: E402
from app.routers import audit as audit_router  # noqa: E402
from app.routers import eval as eval_router  # noqa: E402
from app.routers import runs  # noqa: E402

KEY = "test-key-123"


@pytest.fixture
def _keys(monkeypatch):
    import app.config as cfg
    monkeypatch.setattr(
        cfg, "get_settings",
        lambda: SimpleNamespace(PROOFOPS_API_KEY=KEY,
                                APPROVAL_SECRET="test-secret-123"))


@pytest.fixture(autouse=True)
def _clean():
    runs.reset_demo_state()
    AP.reset_demo_state()
    audit_router.reset_demo_state()
    yield
    runs.reset_demo_state()
    AP.reset_demo_state()
    audit_router.reset_demo_state()


def _exc_status(exc_info):
    return exc_info.value.status_code


def test_runs_create_and_sweep_require_key(_keys):
    with pytest.raises(Exception) as exc:
        runs.http_create(runs.CreateBody(incident_id="inc-1"))
    assert _exc_status(exc) == 401
    with pytest.raises(Exception) as exc:
        runs.http_create(runs.CreateBody(incident_id="inc-1"),
                         x_api_key="wrong")
    assert _exc_status(exc) == 403
    view = runs.http_create(runs.CreateBody(incident_id="inc-1"),
                            x_api_key=KEY)
    assert view["state"] == "NEW"
    with pytest.raises(Exception) as exc:
        runs.http_sweep("inc-1", runs.SweepBody(now=1700000000.0))
    assert _exc_status(exc) == 401
    out = runs.http_sweep("inc-1", runs.SweepBody(now=1700000000.0),
                          x_api_key=KEY)
    assert out["incident_id"] == "inc-1"


def test_approvals_request_requires_key(_keys):
    action = {"incident_id": "inc-1", "agent_id": "planner",
              "action_type": "rollback_deployment",
              "resource_type": "deployment", "resource_id": "web",
              "environment": "mock", "parameters": {"to_version": "v22"},
              "reason": "Roll back web to v22.", "evidence_ids": ["ev-1"],
              "runbook_id": "bad-deploy-rollback",
              "runbook_version": "1.2.0",
              "expected_outcome": "Spike clears.",
              "verification_plan": ["deployment_version_expected"],
              "rollback_action": {"action_type": "rollback_deployment"}}
    with pytest.raises(Exception) as exc:
        AP.http_request(AP.ApprovalBody(action=action, actor="sre-1"))
    assert _exc_status(exc) == 401
    out = AP.http_request(AP.ApprovalBody(action=action, actor="sre-1"),
                          x_api_key=KEY)
    assert out["status"] == "pending" and out["token"]


def test_audit_emit_requires_key(_keys):
    body = audit_router.EmitBody(event_type="transition", actor="s",
                                 result="a->b")
    with pytest.raises(Exception) as exc:
        audit_router.http_emit("inc-1", body)
    assert _exc_status(exc) == 401
    event = audit_router.http_emit("inc-1", body, x_api_key=KEY)
    assert event["seq"] == 1


def test_eval_smoke_requires_key(_keys):
    with pytest.raises(Exception) as exc:
        eval_router.http_smoke(eval_router.SmokeBody(confirm=True))
    assert _exc_status(exc) == 401
    with pytest.raises(Exception) as exc:
        eval_router.http_smoke(eval_router.SmokeBody(confirm=False),
                               x_api_key=KEY)
    assert _exc_status(exc) == 400


def test_advance_approve_reject_require_key(_keys):
    # The three most critical mutating handlers: key-absence asserted here
    # so a future guard deletion fails the suite (R4 closure).
    runs.http_create(runs.CreateBody(incident_id="inc-1"), x_api_key=KEY)
    with pytest.raises(Exception) as exc:
        runs.http_advance("inc-1", runs.AdvanceBody(to="TRIAGING"))
    assert _exc_status(exc) == 401
    view = runs.http_advance("inc-1", runs.AdvanceBody(to="TRIAGING"),
                             x_api_key=KEY)
    assert view["state"] == "TRIAGING"

    action = {"incident_id": "inc-1", "agent_id": "planner",
              "action_type": "rollback_deployment",
              "resource_type": "deployment", "resource_id": "web",
              "environment": "mock", "parameters": {"to_version": "v22"},
              "reason": "Roll back web to v22.", "evidence_ids": ["ev-1"],
              "runbook_id": "bad-deploy-rollback",
              "runbook_version": "1.2.0",
              "expected_outcome": "Spike clears.",
              "verification_plan": ["deployment_version_expected"],
              "rollback_action": {"action_type": "rollback_deployment"}}
    issued = AP.http_request(AP.ApprovalBody(action=action, actor="sre-1"),
                             x_api_key=KEY)
    deny_body = AP.DecideBody(actor="sre-1", token=issued["token"],
                              role="approver")
    with pytest.raises(Exception) as exc:
        AP.http_approve(issued["approval_id"], deny_body)
    assert _exc_status(exc) == 401
    with pytest.raises(Exception) as exc:
        AP.http_reject(issued["approval_id"], deny_body)
    assert _exc_status(exc) == 401
    ok = AP.http_approve(issued["approval_id"], deny_body, x_api_key=KEY)
    assert ok["status"] == "approved"
