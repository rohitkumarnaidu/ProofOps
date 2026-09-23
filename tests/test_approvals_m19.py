"""M19a approvals: request/approve/reject/expire over M07 (host-safe).

Commit A backend half (M19.4 Safety Gate API): pure functions only, no HTTP.
Role checks are demo-grade (M21 owns the guard matrix); crypto is M07-real.
"""
import sys
import json
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


# ---------------------------------------------------------------------------
# P0/P1 closures: HMAC-bound permits, rejection audit, durable nonces
# ---------------------------------------------------------------------------

def test_verified_permit_binds_stored_approval():
    out = _request()
    AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                        "approver", SECRET)
    permit = AP.verified_permit(out["approval_id"], out["token"], "sre-1",
                                SECRET, now=time.time())
    assert permit.token_ref == out["approval_id"]
    assert permit.auto is False
    # Same approval never mints twice (derived-nonce single-use).
    with pytest.raises(AP.ApprovalReplayed):
        AP.verified_permit(out["approval_id"], out["token"], "sre-1",
                           SECRET, now=time.time())


def test_verified_permit_rejects_forgery_and_pending():
    out = _request()
    with pytest.raises(AP.ApprovalDenied):
        # Pending (not human-approved) requests cannot bind permits.
        AP.verified_permit(out["approval_id"], out["token"], "sre-1",
                           SECRET, now=time.time())
    AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                        "approver", SECRET)
    with pytest.raises(AP.ApprovalDenied):
        AP.verified_permit(out["approval_id"], out["token"] + "x", "sre-1",
                           SECRET, now=time.time())
    with pytest.raises(AP.ApprovalDenied):
        AP.verified_permit(out["approval_id"], out["token"], "intruder",
                           SECRET, now=time.time())


def test_rejected_verify_emits_audit():
    chain = AuditChain(incident_id="inc-1")
    out = _request(chain=chain)
    with pytest.raises(AP.ApprovalDenied):
        AP.approve_approval(out["approval_id"], "sre-1", out["token"] + "x",
                            "approver", SECRET, chain=chain)
    kinds = [e.event_type for e in chain.events]
    assert "approval.rejected" in kinds
    assert chain.verify()["valid"] is True


def test_nonce_store_file_roundtrip(tmp_path):
    from app.services import approval as svc
    path = tmp_path / "nonces.jsonl"
    first = svc.NonceStore(path)
    assert first.persistent is True
    assert first.degraded is False
    assert first.consume("n1") is True
    second = svc.NonceStore(path)
    assert second.consume("n1") is False  # burn survives restart
    assert svc.NonceStore().persistent is False
    assert svc.NonceStore().consume("n1") is True  # memory-only default


def test_nonce_store_evicts_oldest_first(tmp_path, monkeypatch):
    from app.services import approval as svc
    monkeypatch.setattr(svc.NonceStore, "MAX_NONCES", 3)
    path = tmp_path / "nonces.jsonl"
    store = svc.NonceStore(path)
    for nonce in ("n1", "n2", "n3", "n4"):
        assert store.consume(nonce) is True
    revived = svc.NonceStore(path)
    assert revived.consume("n1") is True  # oldest evicted, replayable again
    assert revived.consume("n4") is False  # newest retained


# ---------------------------------------------------------------------------
# P1: incident-bound permits (approval for A cannot authorize run B)
# ---------------------------------------------------------------------------

def test_verified_permit_rejects_incident_mismatch():
    out = _request(incident_id="inc-A")
    AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                        "approver", SECRET)
    with pytest.raises(AP.ApprovalDenied) as exc:
        AP.verified_permit(out["approval_id"], out["token"], "sre-1",
                           SECRET, now=time.time(),
                           expected_incident="inc-B")
    assert "incident mismatch" in str(exc.value)
    # Mismatch burns nothing: the same-incident mint still works after.
    permit = AP.verified_permit(out["approval_id"], out["token"], "sre-1",
                                SECRET, now=time.time(),
                                expected_incident="inc-A")
    assert permit.token_ref == out["approval_id"]


def test_verified_permit_same_incident_ok_and_unbound_compat():
    out = _request(incident_id="inc-A")
    AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                        "approver", SECRET)
    permit = AP.verified_permit(out["approval_id"], out["token"], "sre-1",
                                SECRET, now=time.time(),
                                expected_incident="inc-A")
    assert permit.token_ref == out["approval_id"]
    # Blank/None expected_incident keeps legacy unbound behavior.
    out2 = _request(incident_id="inc-B")
    AP.approve_approval(out2["approval_id"], "sre-1", out2["token"],
                        "approver", SECRET)
    for blank in (None, "", "   "):
        permit2 = AP.verified_permit(
            out2["approval_id"], out2["token"], "sre-1", SECRET,
            now=time.time(), expected_incident=blank)
        assert permit2.token_ref == out2["approval_id"]
        # Each approval mints once; re-mint needs a fresh approval.
        out2 = _request(incident_id="inc-B")
        AP.approve_approval(out2["approval_id"], "sre-1", out2["token"],
                            "approver", SECRET)


# ---------------------------------------------------------------------------
# Lane 2 loop 4: REQUESTS file persistence (var/approvals.json)
# ---------------------------------------------------------------------------

def test_store_roundtrip_resume_approve():
    """Restart resume via the default path: approve works on reloaded req."""
    out = _request()
    assert AP.STORE_PATH.is_file()  # request auto-saves
    AP.REQUESTS.clear()  # simulate restart: memory gone, file survives
    view = AP.approval_view(out["approval_id"])  # auto-loads from file
    assert view["status"] == "pending"
    # Crypto continuity: the original token verifies against the reloaded
    # request+action (HMAC binds action_id/actor/params/scope/expiry/nonce).
    approved = AP.approve_approval(out["approval_id"], "sre-1", out["token"],
                                   "approver", SECRET)
    assert approved["status"] == "approved"


def test_store_save_load_tmp_path(tmp_path):
    path = tmp_path / "approvals.json"
    out = _request()
    AP.save_store(path)
    assert path.is_file()
    AP.REQUESTS.clear()
    loaded = AP.load_store(path)
    assert loaded == [out["approval_id"]]
    assert AP.approval_view(out["approval_id"])["status"] == "pending"
    assert AP.REQUESTS[out["approval_id"]]["evidence_ids"] == ["ev-1"]


def test_store_corrupt_raises_no_partial(tmp_path):
    path = tmp_path / "approvals.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        AP.load_store(path)
    assert AP.REQUESTS == {}
    path.write_text(json.dumps(
        {"a1": {"request": {}, "action": {},
                "status": "pending", "evidence_ids": []}}),
        encoding="utf-8")
    with pytest.raises(ValueError):
        AP.load_store(path)
    assert AP.REQUESTS == {}  # fail-closed: no partial load


def test_store_no_partial_on_mixed_file(tmp_path):
    out = _request()
    path = tmp_path / "approvals.json"
    AP.save_store(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["bogus"] = {"status": "pending"}  # missing request/action
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        AP.load_store(path)
    assert set(AP.REQUESTS) == {out["approval_id"]}  # live dict untouched


def test_reset_clears_memory_and_file():
    out = _request()
    assert AP.STORE_PATH.is_file()
    AP.reset_demo_state()
    assert AP.REQUESTS == {}
    assert not AP.STORE_PATH.exists()
    with pytest.raises(AP.ApprovalMissing):
        AP.approval_view(out["approval_id"])
