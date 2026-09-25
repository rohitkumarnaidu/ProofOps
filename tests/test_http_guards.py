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
                     "roles": ["approver"], "mode": "per_key"}
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.resolve_identity("no-such-key", KEY, store_path=store)
    assert auth_mod.http_status(auth_mod.KeyRejected("x")) == 403


def test_identity_fallback_bootstrap_when_store_absent(tmp_path, _keys):
    missing = tmp_path / "no-such-store.json"
    ident = auth_mod.resolve_identity(KEY, KEY, store_path=missing)
    assert ident == {"key_id": "bootstrap", "owner": "bootstrap",
                     "roles": [], "mode": "bootstrap"}
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
                     "roles": [], "mode": "bootstrap"}
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


# ---------------------------------------------------------------------------
# Loop F: the resolved identity must be AUTHORITATIVE, not decorative.
# ---------------------------------------------------------------------------

def _per_key(monkeypatch, tmp_path, entries):
    """Point the auth gate at a real per-key store and return its path."""
    store = _write_store(tmp_path / "api_keys.json", entries)
    monkeypatch.setattr(auth_mod, "KEY_STORE_PATH", store)
    return store


def test_require_role_reads_server_roles_not_client_claims():
    approver = {"key_id": "k-1", "owner": "alice", "roles": ["approver"],
                "mode": "per_key"}
    viewer = {"key_id": "k-2", "owner": "bob", "roles": ["viewer"],
              "mode": "per_key"}
    auth_mod.require_role(approver, "approver", "admin")
    # A viewer is denied the approval gate, and cannot widen it by claiming
    # a role: the allowed set is server code.
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.require_role(viewer, "approver", "admin")
    # A viewer may still read: the read gate lists viewer explicitly.
    auth_mod.require_role(viewer, "viewer", "approver", "admin")
    # An empty per-key role list is an unprivileged key, never a wildcard.
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.require_role({"key_id": "k-3", "owner": "c", "roles": [],
                               "mode": "per_key"}, "admin")
    # Bootstrap keeps demo compatibility but is labeled, and the caller can
    # switch it off.
    auth_mod.require_role({"key_id": "bootstrap", "owner": "bootstrap",
                           "roles": [], "mode": "bootstrap"}, "admin")
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.require_role({"key_id": "bootstrap", "owner": "bootstrap",
                               "roles": [], "mode": "bootstrap",
                               "bootstrap_permits": False}, "admin")
    with pytest.raises(ValueError):
        auth_mod.require_role(approver)


def test_principal_is_key_id_and_view_reports_mode(_keys):
    ident = auth_mod.resolve_identity(
        "k", "k", store_path=_tmp_store(_store_entry("k")))
    assert auth_mod.principal(ident) == "key-1"
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.principal({"owner": "alice"})
    view = auth_mod.identity_view({"key_id": "k-1", "owner": "alice",
                                   "roles": ["approver", "admin"],
                                   "mode": "per_key"})
    assert view == {"key_id": "k-1", "owner": "alice",
                    "roles": ["admin", "approver"], "mode": "per_key",
                    "server_enforced": True}
    demo = auth_mod.identity_view({"key_id": "bootstrap", "owner": "bootstrap",
                                   "roles": [], "mode": "bootstrap"})
    assert demo["server_enforced"] is False, \
        "a bootstrap credential must never be presented as enforced identity"


def _tmp_store(entry):
    import tempfile
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8")
    json.dump([entry], handle)
    handle.close()
    return Path(handle.name)


def test_viewer_key_cannot_mutate_runs_even_claiming_admin(_keys, tmp_path,
                                                          monkeypatch):
    """The P0: a viewer key could previously call any mutating endpoint.

    Authorization now reads the key's stored roles; the body has no role
    field at all, so there is nothing for a client to escalate with.
    """
    _per_key(monkeypatch, tmp_path,
             [_store_entry("viewer-key", key_id="k-view", owner="bob",
                           roles=("viewer",))])
    with pytest.raises(Exception) as exc:
        runs.http_create(runs.CreateBody(incident_id="inc-rbac"),
                         x_api_key="viewer-key")
    assert _exc_status(exc) == 403
    assert "inc-rbac" not in runs.REPO_STORE
    with pytest.raises(Exception) as exc:
        eval_router.http_smoke(eval_router.SmokeBody(confirm=True),
                               x_api_key="viewer-key")
    assert _exc_status(exc) == 403


def test_operator_key_can_mutate_runs(_keys, tmp_path, monkeypatch):
    _per_key(monkeypatch, tmp_path,
             [_store_entry("op-key", key_id="k-op", owner="dana",
                           roles=("operator",))])
    view = runs.http_create(runs.CreateBody(incident_id="inc-op"),
                            x_api_key="op-key")
    assert view["state"] == "NEW"


def _rbac_action(**over):
    base = {"action_id": "act-rbac", "incident_id": "inc-rbac",
            "agent_id": "planner", "action_type": "rollback_deployment",
            "resource_type": "deployment", "resource_id": "web",
            "environment": "mock", "parameters": {"to_version": "v22"},
            "reason": "Roll back web to v22.", "evidence_ids": ["ev-rbac"],
            "runbook_id": "bad-deploy-rollback", "runbook_version": "1.2.0",
            "expected_outcome": "Spike clears.",
            "verification_plan": ["deployment_version_expected"],
            "rollback_action": {"action_type": "rollback_deployment"}}
    base.update(over)
    return base

def test_body_actor_cannot_impersonate_another_key_owner(_keys, tmp_path,
                                                         monkeypatch):
    """The P0: the actor was a free-text body field, so any key could act as
    any named actor. It is now proven against the key's registered owner."""
    _per_key(monkeypatch, tmp_path,
             [_store_entry("alice-key", key_id="k-alice", owner="sre-alice",
                           roles=("approver",))])
    action = _rbac_action(action_id="act-imp", incident_id="inc-imp",
                          evidence_ids=["ev-imp"])
    # Claiming another named actor is rejected outright.
    with pytest.raises(Exception) as exc:
        AP.http_request(AP.ApprovalBody(action=action, actor="sre-victim"),
                        x_api_key="alice-key")
    assert _exc_status(exc) == 403
    # Omitting the actor is fine: it is derived from the key.
    issued = AP.http_request(AP.ApprovalBody(action=action),
                             x_api_key="alice-key")
    assert issued["identity_mode"] == "per_key"
    assert AP.approval_view(issued["approval_id"])["requester_key_id"] \
        == "k-alice"
    assert AP.approval_view(issued["approval_id"])["actor"] == "sre-alice"


def test_per_key_self_approval_denied_and_distinct_approver_allowed(
        _keys, tmp_path, monkeypatch):
    """The P0: self-approval was the default, so one key could raise and
    approve its own action. On the per-key path the requester key and the
    approver key must differ, with no override."""
    _per_key(monkeypatch, tmp_path, [
        _store_entry("alice-key", key_id="k-alice", owner="sre-alice",
                     roles=("approver",)),
        _store_entry("bob-key", key_id="k-bob", owner="sre-bob",
                     roles=("approver",)),
    ])
    action = _rbac_action(action_id="act-sod", incident_id="inc-sod",
                          evidence_ids=["ev-sod"])
    issued = AP.http_request(AP.ApprovalBody(action=action),
                             x_api_key="alice-key")
    token = issued["token"]
    approve_id = issued["approval_id"]
    # Same key tries to approve its own request -> denied, nothing burned.
    with pytest.raises(Exception) as exc:
        AP.http_approve(approve_id, AP.DecideBody(token=token),
                        x_api_key="alice-key")
    assert _exc_status(exc) == 403
    assert "separation of duties" in str(exc.value.detail)
    assert AP.approval_view(approve_id)["status"] == "pending"
    # A different authorized key completes it, and the view proves four-eyes.
    decided = AP.http_approve(approve_id, AP.DecideBody(token=token),
                              x_api_key="bob-key")
    assert decided["status"] == "approved"
    assert decided["decided_by"] == "k-bob"
    assert decided["requester_key_id"] == "k-alice"
    assert decided["sod"] == "enforced"
    assert decided["identity_mode"] == "per_key"


def test_per_key_approve_without_complete_identity_denies(_keys):
    """A per-key decision with no requester key recorded cannot be judged, so
    it is denied rather than silently treated as four-eyes compliant."""
    AP.REQUESTS.clear()
    issued = AP.request_approval(
        _rbac_action(action_id="act-x", incident_id="inc-x",
                     evidence_ids=["ev-x"]),
        "sre-alice", "test-secret-123", requester_key_id="",
        identity_mode="per_key")
    with pytest.raises(AP.ApprovalDenied):
        AP.approve_approval(issued["approval_id"], "sre-alice",
                            issued["token"], "", "test-secret-123",
                            approver_key_id="k-alice",
                            identity_mode="per_key")


def test_bootstrap_identity_is_labeled_not_enforced(_keys):
    """The demo fallback must not claim four-eyes control it never applied."""
    issued = AP.http_request(
        AP.ApprovalBody(action=_rbac_action(action_id="act-boot",
                                            incident_id="inc-boot",
                                            evidence_ids=["ev-b"]),
                        actor="sre-1"), x_api_key=KEY)
    view = AP.approval_view(issued["approval_id"])
    assert view["identity_mode"] == "bootstrap"
    assert view["sod"] == "not_enforced_bootstrap"
    assert view["requester_key_id"] == "bootstrap"


def test_audit_append_requires_a_write_role(_keys, tmp_path, monkeypatch):
    """A viewer must not be able to write hash-valid approval/policy events.

    The chain is exported as proof, so with only a key-presence check any
    authenticated key could append a record that verify() then accepts.
    """
    _per_key(monkeypatch, tmp_path, [
        _store_entry("viewer-key", key_id="k-view", owner="bob",
                     roles=("viewer",)),
        _store_entry("op-key", key_id="k-op", owner="dana", roles=("operator",)),
    ])
    audit_router.reset_demo_state()
    with pytest.raises(Exception) as exc:
        audit_router.http_emit("inc-forged", audit_router.EmitBody(
            event_type="transition", action_id="act-1", result="forged"),
            x_api_key="viewer-key")
    assert _exc_status(exc) == 403
    # Nothing was written: the chain for that incident does not even exist.
    with pytest.raises(Exception) as missing:
        audit_router.http_view("inc-forged")
    assert _exc_status(missing) == 404
    # A write-capable key may still append, and the actor is its own key id.
    event = audit_router.http_emit("inc-forged", audit_router.EmitBody(
        event_type="transition", action_id="act-1", result="real"),
        x_api_key="op-key")
    assert event["actor"] == "k-op"
    assert audit_router.http_verify("inc-forged")["valid"] is True


def test_key_store_refuses_two_keys_for_one_owner(tmp_path, _keys):
    """Separation of duties compares key ids, so one human must not hold two
    keys -- otherwise k-laptop + k-desktop passes four-eyes on its own."""
    store = _write_store(tmp_path / "dup-owner.json", [
        _store_entry("k1", key_id="k-laptop", owner="sre-alice"),
        _store_entry("k2", key_id="k-desktop", owner="sre-alice"),
    ])
    with pytest.raises(ValueError) as exc:
        auth_mod.load_key_store(store)
    assert "duplicate owner" in str(exc.value)
    with pytest.raises(ValueError):
        auth_mod.resolve_identity("k1", KEY, store_path=store)


def test_per_key_permit_requires_a_deciding_principal(_keys):
    """A per-key approval with no recorded decider must not mint the FSM
    credential that authorizes execution."""
    AP.reset_demo_state()
    issued = AP.request_approval(
        _rbac_action(action_id="act-nodec", incident_id="inc-nodec",
                     evidence_ids=["ev-nodec"]),
        "sre-alice", "test-secret-123", requester_key_id="k-alice",
        identity_mode="per_key")
    entry = AP.REQUESTS[issued["approval_id"]]
    entry["status"] = "approved"
    with pytest.raises(AP.ApprovalDenied) as exc:
        AP.verified_permit(issued["approval_id"], issued["token"],
                           "sre-alice", "test-secret-123")
    assert "deciding principal" in str(exc.value)


def test_request_mode_is_not_laundered_by_the_approver(_keys, tmp_path,
                                                       monkeypatch):
    """A bootstrap request approved by a per-key key must still read as a
    bootstrap-origin request, not a server-enforced one."""
    _per_key(monkeypatch, tmp_path,
             [_store_entry("bob-key", key_id="k-bob", owner="sre-bob",
                           roles=("approver",))])
    AP.reset_demo_state()
    issued = AP.request_approval(
        _rbac_action(action_id="act-launder", incident_id="inc-launder",
                     evidence_ids=["ev-launder"]),
        "sre-1", "test-secret-123", requester_key_id="bootstrap",
        identity_mode="bootstrap")
    entry = AP.REQUESTS[issued["approval_id"]]
    entry["status"] = "approved"
    entry["decided_by"] = "k-bob"
    view = AP.approval_view(issued["approval_id"])
    assert view["identity_mode"] == "bootstrap", \
        "the request's origin mode must survive the decision"
    assert view["decided_by"] == "k-bob"
    assert view["sod"] == "not_enforced_bootstrap"
