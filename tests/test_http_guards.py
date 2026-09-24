"""HTTP guard matrix: every mutating handler requires X-API-Key (P1 closure).

Pure functions stay key-free (unit-testable); the http_* translation layer
enforces auth_mod.guard_http. Settings are monkeypatched so no env is read.
"""
import sys
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.routers import approvals as AP  # noqa: E402
from app.routers import audit as audit_router  # noqa: E402
from app.routers import auth as auth_mod  # noqa: E402 (Lane 1 identity)
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


# ---------------------------------------------------------------------------
# Lane 1 (identity): per-key store, bootstrap fallback, server-side roles
# ---------------------------------------------------------------------------

def _store_entry(key, key_id="key-1", owner="sre-alice",
                 roles=("approver",)):
    return {"key_id": key_id,
            "key_sha256": hashlib.sha256(key.encode("utf-8")).hexdigest(),
            "owner": owner, "roles": list(roles)}


def _write_store(path, entries):
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def test_identity_store_known_resolves_unknown_rejected(tmp_path, _keys):
    store = _write_store(tmp_path / "api_keys.json",
                         [_store_entry("real-key-abc")])
    ident = auth_mod.resolve_identity("real-key-abc", KEY, store_path=store)
    assert ident == {"key_id": "key-1", "owner": "sre-alice",
                     "roles": ["approver"]}
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.resolve_identity("no-such-key", KEY, store_path=store)
    assert auth_mod.http_status(auth_mod.KeyRejected("x")) == 403


def test_identity_fallback_bootstrap_when_store_absent(tmp_path, _keys):
    missing = tmp_path / "no-such-store.json"
    ident = auth_mod.resolve_identity(KEY, KEY, store_path=missing)
    assert ident == {"key_id": "bootstrap", "owner": "bootstrap",
                     "roles": []}
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.resolve_identity("wrong", KEY, store_path=missing)
    with pytest.raises(auth_mod.KeyMissing):
        auth_mod.resolve_identity(None, KEY, store_path=missing)
    with pytest.raises(auth_mod.KeyMissing):
        auth_mod.resolve_identity("   ", KEY, store_path=missing)


def test_identity_corrupt_store_fails_closed(tmp_path, _keys):
    bad = tmp_path / "api_keys.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        auth_mod.resolve_identity("anything", KEY, store_path=bad)
    bad.write_text(json.dumps(
        [{"key_id": "k1", "owner": "sre-alice"}]), encoding="utf-8")
    with pytest.raises(ValueError):
        auth_mod.resolve_identity("anything", KEY, store_path=bad)
    bad.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    with pytest.raises(ValueError):
        auth_mod.load_key_store(bad)


def test_identity_example_shape_loads_and_gates(tmp_path, _keys):
    root = Path(__file__).resolve().parents[1]
    example = root / "var" / "api_keys.json.example"
    assert example.is_file(), "var/api_keys.json.example template missing"
    assert "FAKE" in example.read_text(encoding="utf-8"), \
        "placeholder hashes must be loudly marked FAKE"
    copy = tmp_path / "api_keys.json"
    copy.write_bytes(example.read_bytes())
    entries = auth_mod.load_key_store(copy)
    assert isinstance(entries, list) and len(entries) >= 1
    owners = [entry["owner"] for entry in entries]
    assert any("sre-alice" in owner for owner in owners)
    for entry in entries:
        assert len(entry["key_sha256"]) == 64
        assert isinstance(entry["roles"], list)
    # Fake hashes match nothing: unknown key -> 403 against example shape.
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.resolve_identity("any-presented-key", KEY, store_path=copy)
    # Same shape with a real entry: known key -> identity resolved.
    live = list(entries) + [_store_entry("live-key-9", key_id="live-9",
                                         owner="sre-live")]
    _write_store(copy, live)
    ident = auth_mod.resolve_identity("live-key-9", KEY, store_path=copy)
    assert (ident["key_id"], ident["owner"]) == ("live-9", "sre-live")


def test_guard_http_returns_identity_and_keeps_matrix(tmp_path, _keys,
                                                     monkeypatch):
    class HTTPExc(Exception):
        def __init__(self, status_code=500, detail=""):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    # Hermetic: force the bootstrap fallback regardless of repo var/ state.
    monkeypatch.setattr(auth_mod, "KEY_STORE_PATH",
                        tmp_path / "absent.json")
    ident = auth_mod.guard_http(KEY, lambda: KEY, HTTPExc)
    assert ident == {"key_id": "bootstrap", "owner": "bootstrap",
                     "roles": []}
    with pytest.raises(HTTPExc) as exc:
        auth_mod.guard_http(None, lambda: KEY, HTTPExc)
    assert exc.value.status_code == 401
    with pytest.raises(HTTPExc) as exc:
        auth_mod.guard_http("wrong", lambda: KEY, HTTPExc)
    assert exc.value.status_code == 403
    # Blank keys never touch config (M21b host-safe pin still holds).
    def _boom():
        raise AssertionError("settings must not load for blank keys")
    with pytest.raises(HTTPExc) as exc:
        auth_mod.guard_http("  ", _boom, HTTPExc)
    assert exc.value.status_code == 401


def test_key_role_subset_gate():
    # Bootstrap (no roles): legacy behavior, any asserted role passes here
    # (per-endpoint gates still apply downstream).
    auth_mod.check_key_role([], "approver")
    auth_mod.check_key_role([], "viewer")
    auth_mod.check_key_role(None, "admin")
    # Key with roles: claimed role must be a subset (element) of them.
    auth_mod.check_key_role(["approver"], "approver")
    auth_mod.check_key_role(["approver", "admin"], "admin")
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.check_key_role(["approver"], "admin")
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.check_key_role(["approver", "viewer"], "admin")
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.check_key_role(["approver"], "Viewer")  # exact match only
    assert auth_mod.http_status(auth_mod.KeyRejected("x")) == 403
