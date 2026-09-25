"""M15 audit: chain + verify + export + linkage + labels (host-safe).

Single-commit M15 lane (M15.1-M15.6): pure service tests, no HTTP. Router
pure fns + wiring pins included; tamper cases use white-box event surgery
with model re-validation (the same shape an attacker would need to beat).
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.contracts.audit import AuditEvent  # noqa: E402 (M01.14)
from app.routers import audit as audit_router  # noqa: E402 (M15b router)
from app.services import audit as A  # noqa: E402 (M15 chain)
from app.services import fsm as fsm_svc  # noqa: E402 (M14 records)

ROOT = Path(__file__).resolve().parents[1]

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
    audit_router.reset_demo_state()
    yield
    audit_router.reset_demo_state()


def _chain(n=3):
    chain = A.AuditChain(incident_id="inc-1")
    for i in range(n):
        chain.emit("transition", actor="control-plane",
                   result=f"NEW->TRIAGING try={i}")
    return chain


def _tamper(chain, idx, **over):
    ev = chain._events[idx]
    chain._events[idx] = AuditEvent.model_validate(
        {**ev.model_dump(), **over})


# ---------------------------------------------------------------------------
# M15.1 emission completeness
# ---------------------------------------------------------------------------

def test_seq_monotonic_genesis():
    chain = A.AuditChain(incident_id="inc-1")
    first = chain.emit("transition", actor="s", result="a->b")
    second = chain.emit("transition", actor="s", result="b->c")
    assert (first.seq, second.seq) == (1, 2)
    assert first.prev_hash == "" and second.prev_hash == first.curr_hash
    assert len(chain) == 2 and chain.events[0].incident_id == "inc-1"


def test_blank_ids_rejected():
    chain = A.AuditChain(incident_id="inc-1")
    with pytest.raises(Exception):
        chain.emit("", actor="s", result="x")
    with pytest.raises(Exception):
        chain.emit("transition", actor="  ", result="x")
    with pytest.raises(Exception):
        A.AuditChain(incident_id="  ")


@pytest.mark.parametrize("event_type,kwargs", [
    ("policy.decision", {"actor": "p", "action_id": "a"}),
    ("approval.approve", {"actor": "h"}),
    ("execution.finish", {"actor": "x", "action_id": "a"}),
    ("transition", {"actor": "s"}),
    ("verification.verdict", {"actor": "v", "execution_id": "e"}),
])
def test_required_extras_rejected(event_type, kwargs):
    with pytest.raises(A.AuditError):
        A.AuditChain(incident_id="inc-1").emit(event_type, **kwargs)


def test_required_extras_accepted():
    chain = A.AuditChain(incident_id="inc-1")
    chain.emit("policy.decision", actor="p", action_id="a",
               policy={"version": "v1", "rule": "r1", "result": "DENY"})
    chain.emit("approval.approve", actor="h", approval_id="ap-1")
    chain.emit("execution.finish", actor="x", action_id="a",
               execution_id="e1", result="ok")
    assert chain.verify()["valid"] is True


def test_open_type_passes_base_only():
    chain = A.AuditChain(incident_id="inc-1")
    out = chain.emit("custom.note", actor="s", result="free-form")
    assert out.seq == 1


def test_bad_charset_type_rejected():
    with pytest.raises(A.AuditError):
        A.AuditChain(incident_id="inc-1").emit("BAD TYPE!", actor="s")


def test_policy_snapshot_shape_enforced():
    chain = A.AuditChain(incident_id="inc-1")
    with pytest.raises(A.AuditError):
        chain.emit("policy.decision", actor="p", action_id="a",
                   policy={"version": "v1"})


# ---------------------------------------------------------------------------
# M15.2 hash chain
# ---------------------------------------------------------------------------

def test_links_recompute():
    chain = _chain(3)
    for i, event in enumerate(chain.events):
        prev = chain.events[i - 1].curr_hash if i else ""
        assert event.curr_hash == A.link(prev, event)
    assert len({e.curr_hash for e in chain.events}) == 3


def test_chains_independent_genesis():
    first = _chain(1).events[0]
    second = _chain(1).events[0]
    assert first.prev_hash == second.prev_hash == ""
    # uuid event_ids: identical content still yields unique hashes.
    assert first.curr_hash != second.curr_hash
    assert first.event_id != second.event_id


# ---------------------------------------------------------------------------
# M15.3 verification + tamper detection
# ---------------------------------------------------------------------------

def test_verify_valid_chain():
    verdict = _chain(4).verify()
    assert verdict == {"valid": True, "checked": 4, "first_bad_seq": None,
                       "reason": ""}
    assert A.AuditChain(incident_id="inc-1").verify()["checked"] == 0


def test_tamper_result_detected():
    chain = _chain(3)
    _tamper(chain, 1, result="forged")
    verdict = chain.verify()
    assert verdict["valid"] is False and verdict["first_bad_seq"] == 2
    assert verdict["reason"] == "hash"


def test_tamper_prev_detected():
    chain = _chain(3)
    _tamper(chain, 2, prev_hash="0" * 64)
    verdict = chain.verify()
    assert verdict["valid"] is False and verdict["first_bad_seq"] == 3
    assert verdict["reason"] == "prev-link"


def test_swap_detected():
    chain = _chain(3)
    chain._events[0], chain._events[1] = chain._events[1], chain._events[0]
    assert chain.verify()["valid"] is False


def test_foreign_event_detected():
    chain = _chain(2)
    other = A.AuditChain(incident_id="inc-2")
    other.emit("transition", actor="s", result="x")
    chain._events.append(other.events[0])
    verdict = chain.verify()
    assert verdict["valid"] is False


# ---------------------------------------------------------------------------
# M15.4 AIMS label honesty
# ---------------------------------------------------------------------------

def test_trace_link_shape():
    link = A.trace_link("inc-1", "inc-1")
    assert link["kind"] == "aims-trace-link"
    assert link["verified"] is False and "Studio UI" in link["note"]
    with pytest.raises(A.AuditError):
        A.trace_link("", "inc-1")


def test_custom_rows_never_labeled_aims():
    exported = _chain(2).export()
    assert exported["origin"] == "custom-hash-chain"
    assert all("aims" not in str(e).lower() or "never labeled AIMS" in str(e)
               for e in exported["events"])
    assert exported["origin"] != "aims"


# ---------------------------------------------------------------------------
# M15.5 export
# ---------------------------------------------------------------------------

def test_export_shape_and_valid_bool():
    exported = _chain(2).export()
    assert set(exported) == {"origin", "incident_id", "exported_at", "valid",
                             "checked", "events"}
    assert exported["valid"] is True and len(exported["events"]) == 2


def test_export_after_tamper_invalid():
    chain = _chain(2)
    _tamper(chain, 0, result="forged")
    exported = chain.export()
    assert exported["valid"] is False and exported["checked"] == 0


# ---------------------------------------------------------------------------
# M15.6 linkage
# ---------------------------------------------------------------------------

def test_linkage_filters():
    chain = A.AuditChain(incident_id="inc-1")
    chain.emit("execution.start", actor="x", action_id="a1",
               execution_id="e1", result="go")
    chain.emit("approval.approve", actor="h", approval_id="ap-1")
    chain.emit("execution.finish", actor="x", action_id="a1",
               execution_id="e1", result="ok", evidence_ids=["ev-1"])
    assert len(chain.by_action("a1")) == 2
    assert len(chain.by_approval("ap-1")) == 1
    assert len(chain.by_execution("e1")) == 2
    assert len(chain.by_evidence("ev-1")) == 1
    assert chain.by_action("nope") == []


# ---------------------------------------------------------------------------
# M14-record adapter
# ---------------------------------------------------------------------------

def test_record_fsm_walk():
    run = fsm_svc.new_run("inc-1", now=1700000000.0)
    for state in ("TRIAGING", "CORRELATED", "INVESTIGATING", "DIAGNOSING",
                  "PLANNED", "POLICY_CHECK"):
        fsm_svc.advance(run, state, now=1700000000.0)
    fsm_svc.advance(run, "BLOCKED", reason="RED proposed",
                    now=1700000000.0)
    fsm_svc.handoff(run, "triage", "diagnostic", ["sig:x"])
    fsm_svc.execute_once(run, "a1", "e1", lambda: 1)
    fsm_svc.execute_once(run, "a1", "e1", lambda: 2)
    records = fsm_svc.audit_records(run)
    chain = A.AuditChain(incident_id="inc-1")
    assert A.record_fsm(chain, records) == len(records) == 9
    assert chain.verify()["valid"] is True
    assert len(chain.by_execution("e1")) == 1


def test_adapter_rejects_unknown_record():
    chain = A.AuditChain(incident_id="inc-1")
    with pytest.raises(A.AuditError):
        A.record_fsm(chain, [{"type": "nope"}])


# ---------------------------------------------------------------------------
# Router pure fns + wiring
# ---------------------------------------------------------------------------

def test_router_emit_view_verify_export(_keys):
    event = audit_router.http_emit("inc-1", audit_router.EmitBody(
        event_type="transition", actor="s", result="a->b"),
        x_api_key=KEY)
    assert event["seq"] == 1
    view = audit_router.http_view("inc-1")
    assert view["valid"] is True and len(view["events"]) == 1
    assert audit_router.http_verify("inc-1")["checked"] == 1
    exported = audit_router.http_export("inc-1")
    assert exported["origin"] == "custom-hash-chain"
    with pytest.raises(Exception):
        audit_router.http_view("inc-nope")


def test_router_emit_actor_is_server_derived_not_client_asserted(_keys):
    """The chain records who the SERVER resolved, never the caller's claim.

    A blank actor is filled from the authenticated principal, and a mismatched
    claim survives only as a labelled annotation -- so an API-key holder can no
    longer write a correctly hashed event attributed to another actor.
    """
    audit_router.reset_demo_state()
    filled = audit_router.http_emit("inc-actor", audit_router.EmitBody(
        event_type="transition", result="a->b"), x_api_key=KEY)
    assert filled["actor"] == "bootstrap", filled["actor"]
    claimed = audit_router.http_emit("inc-actor", audit_router.EmitBody(
        event_type="transition", actor="sre-victim", result="a->b"),
        x_api_key=KEY)
    assert claimed["actor"] == "bootstrap (claimed sre-victim)", \
        claimed["actor"]


def test_router_emit_requires_key(_keys):
    with pytest.raises(Exception) as exc:
        audit_router.http_emit("inc-1", audit_router.EmitBody(
            event_type="transition", actor="s", result="a->b"))
    assert exc.value.status_code == 401


def test_persisted_chain_is_readable_after_a_memory_wipe(tmp_path, _keys,
                                                         monkeypatch):
    """A restart empties CHAINS but not the file; reads must still find it.

    Found by running the container: with the reader looking only at memory, a
    persisted chain 404'd after `docker compose restart`, so the operator was
    told there was no proof of a decision that had actually been recorded.
    """
    audit_router.reset_demo_state()
    monkeypatch.setattr(audit_router, "_VAR_DIR", tmp_path)
    audit_router.http_emit("inc-restart", audit_router.EmitBody(
        event_type="transition", actor="s", result="a->b"), x_api_key=KEY)
    assert audit_router.http_view("inc-restart")["checked"] == 1

    # Simulate the restart: memory gone, file intact.
    audit_router.CHAINS.clear()
    view = audit_router.http_view("inc-restart")
    assert view["valid"] is True
    assert view["checked"] == 1
    assert len(view["events"]) == 1
    assert audit_router.http_verify("inc-restart")["valid"] is True
    assert len(audit_router.http_export("inc-restart")["events"]) == 1
    # A genuinely unknown incident still 404s: no empty chain is fabricated,
    # which would make verify() vacuously true over zero events.
    with pytest.raises(Exception) as exc:
        audit_router.http_view("inc-never-existed")
    assert exc.value.status_code == 404


def test_main_wires_audit_router():
    import ast as _ast
    src = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    tree = _ast.parse(src)
    assert any(isinstance(n, _ast.Call)
               and getattr(n.func, "attr", "") == "include_router"
               for n in _ast.walk(tree))
    assert "audit" in src


# ---------------------------------------------------------------------------
# P1: file persistence (chains survive restarts, tamper-evident reload)
# ---------------------------------------------------------------------------

def test_chain_save_load_roundtrip(tmp_path):
    chain = A.AuditChain(incident_id="inc-1")
    chain.emit("transition", actor="s", result="a->b")
    chain.emit("transition", actor="s", result="b->c")
    path = tmp_path / "audit-inc-1.jsonl"
    chain.save(path)
    assert path.is_file()
    revived = A.AuditChain.load("inc-1", path)
    assert [e.curr_hash for e in revived.events] == \
        [e.curr_hash for e in chain.events]
    assert revived.verify()["valid"] is True


def test_chain_file_rejects_bad_identity(tmp_path):
    with pytest.raises(A.AuditError):
        A.AuditChain(incident_id="../evil").save(tmp_path / "x.jsonl")
    with pytest.raises(A.AuditError):
        A.AuditChain.load("../evil", tmp_path / "x.jsonl")
    chain = A.AuditChain(incident_id="inc-1")
    chain.emit("transition", actor="s", result="a->b")
    path = tmp_path / "audit-inc-1.jsonl"
    chain.save(path)
    with pytest.raises(A.AuditError):
        A.AuditChain.load("inc-2", path)  # owner mismatch


def test_chain_file_tamper_rejected(tmp_path):
    import json as _json
    chain = A.AuditChain(incident_id="inc-1")
    chain.emit("transition", actor="s", result="a->b")
    chain.emit("transition", actor="s", result="b->c")
    path = tmp_path / "audit-inc-1.jsonl"
    chain.save(path)
    rows = [_json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines()]
    rows[0]["result"] = "forged"
    path.write_text("\n".join(_json.dumps(r) for r in rows) + "\n",
                    encoding="utf-8")
    with pytest.raises(A.AuditError):
        A.AuditChain.load("inc-1", path)
    path.write_text("{not json\n", encoding="utf-8")
    with pytest.raises(A.AuditError):
        A.AuditChain.load("inc-1", path)


def test_router_file_persistence_and_reset(_keys):
    incident = "inc-filepersist"
    event = audit_router.http_emit(incident, audit_router.EmitBody(
        event_type="transition", actor="s", result="a->b"),
        x_api_key=KEY)
    assert event["seq"] == 1
    path = audit_router._chain_path(incident)
    assert path is not None and path.is_file()
    # Simulate restart: drop memory only, reload must recover from disk.
    audit_router.CHAINS.clear()
    assert incident not in audit_router.CHAINS
    reloaded = audit_router.get_or_create_chain(incident)
    assert [e.curr_hash for e in reloaded.events] == [event["curr_hash"]]
    assert reloaded.verify()["valid"] is True
    # Tampered file never silently starts empty.
    import json as _json
    rows = [_json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines()]
    rows[0]["result"] = "forged"
    path.write_text("\n".join(_json.dumps(r) for r in rows) + "\n",
                    encoding="utf-8")
    audit_router.CHAINS.clear()
    with pytest.raises(A.AuditError):
        audit_router.get_or_create_chain(incident)
    # Reset clears both layers (memory + files).
    audit_router.reset_demo_state()
    assert incident not in audit_router.CHAINS
    assert not path.is_file()
