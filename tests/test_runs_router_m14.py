"""M14b router: pure-function tests + wiring pins (host-safe, no TestClient).

The crippled host cannot run starlette TestClient, so HTTP translation is
tested at the pure layer; FastAPI wiring is asserted structurally (AST over
main.py) and the Dockerfile COPY pins guard container boot (agents/ must
ship -- routers import it at main-import time).
"""
import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.routers import runs  # noqa: E402 (M14b router)
from app.services.fsm import InvalidTransition, PermitRejected  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
NOW = 1700000000.0


@pytest.fixture(autouse=True)
def _clean():
    from app.routers import approvals as _ap
    runs.reset_demo_state()
    _ap.reset_demo_state()
    yield
    runs.reset_demo_state()
    _ap.reset_demo_state()


SECRET = "m14-test-secret"


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


def _bound_approval(secret=SECRET, actor="sre-1", incident_id="inc-1",
                    **over):
    """Real HMAC-bound credential: request -> human approve -> bind."""
    from app.routers import approvals as _ap
    over.setdefault("incident_id", incident_id)
    issued = _ap.request_approval(_action(**over), actor, secret)
    _ap.approve_approval(issued["approval_id"], actor, issued["token"],
                         "approver", secret)
    return {"approval_id": issued["approval_id"], "token": issued["token"],
            "actor": actor}


def _to_policy(incident="inc-1"):
    runs.create_run(incident, now=NOW)
    for state in ("TRIAGING", "CORRELATED", "INVESTIGATING", "DIAGNOSING",
                  "PLANNED", "POLICY_CHECK"):
        runs.advance_run(incident, state, now=NOW)
    return incident


# ---------------------------------------------------------------------------
# Pure run lifecycle
# ---------------------------------------------------------------------------

def test_create_get_duplicate():
    runs.create_run("inc-1", now=NOW)
    assert runs.run_view(runs.get_run("inc-1"))["state"] == "NEW"
    with pytest.raises(Exception) as exc:
        runs.create_run("inc-1", now=NOW)
    assert runs.http_status(exc.value) == 409
    with pytest.raises(Exception) as exc:
        runs.get_run("inc-nope")
    assert runs.http_status(exc.value) == 404


def test_advance_view_and_history():
    runs.create_run("inc-1", now=NOW)
    view = runs.advance_run("inc-1", "TRIAGING", reason="go",
                            refs=["alert:a1"], now=NOW)
    assert view["state"] == "TRIAGING" and view["duplicate"] is False
    assert view["history"][0]["to"] == "TRIAGING"


def test_advance_no_skip_maps_409():
    _to_policy()
    with pytest.raises(Exception) as exc:
        runs.advance_run("inc-1", "EXECUTING", now=NOW)
    assert isinstance(exc.value, InvalidTransition)
    assert runs.http_status(exc.value) == 409


def test_advance_permit_flow_and_expiry_410():
    _to_policy()
    view = runs.advance_run("inc-1", "APPROVED",
                            approval=_bound_approval(incident_id="inc-1"),
                            approval_secret=SECRET, now=NOW)
    assert view["permit_pending"] is True
    view = runs.advance_run("inc-1", "EXECUTING", now=NOW)
    assert view["state"] == "EXECUTING"

    # Forged client permits are never accepted (P0-1: no self-authorization).
    _to_policy("inc-2")
    with pytest.raises(Exception) as exc:
        runs.advance_run("inc-2", "APPROVED",
                         approval={"action_id": "a1", "params_hash": "p1",
                                   "expires_at": NOW + 3600.0,
                                   "token_ref": "tok-1"},
                         approval_secret=SECRET, now=NOW)
    assert isinstance(exc.value, PermitRejected)
    assert runs.http_status(exc.value) == 403

    # No secret, no APPROVED.
    with pytest.raises(Exception) as exc:
        runs.advance_run("inc-2", "APPROVED",
                         approval=_bound_approval(incident_id="inc-2"),
                         now=NOW)
    assert isinstance(exc.value, PermitRejected)

    # Unapproved (pending) requests cannot bind permits.
    from app.routers import approvals as _ap
    issued = _ap.request_approval(_action(incident_id="inc-2"), "sre-1",
                                  SECRET)
    with pytest.raises(Exception) as exc:
        runs.advance_run("inc-2", "APPROVED",
                         approval={"approval_id": issued["approval_id"],
                                   "token": issued["token"], "actor": "sre-1"},
                         approval_secret=SECRET, now=NOW)
    assert isinstance(exc.value, PermitRejected)

    # One approval mints at most one permit (derived-nonce single-use).
    bound = _bound_approval(incident_id="inc-3")
    _to_policy("inc-3")
    runs.advance_run("inc-3", "APPROVED", approval=bound,
                     approval_secret=SECRET, now=NOW)
    _to_policy("inc-4")
    with pytest.raises(Exception) as exc:
        runs.advance_run("inc-4", "APPROVED", approval=bound,
                         approval_secret=SECRET, now=NOW)
    assert isinstance(exc.value, PermitRejected)

    # Expired permits still map to 410 at the HTTP boundary.
    assert runs.http_status(PermitRejected("approval expired")) == 410


def test_approved_edge_binds_incident():
    """P1: approval for inc-A cannot authorize inc-B (PermitRejected)."""
    _to_policy("inc-A")
    _to_policy("inc-B")
    bound_a = _bound_approval(incident_id="inc-A")
    view = runs.advance_run("inc-A", "APPROVED", approval=bound_a,
                            approval_secret=SECRET, now=NOW)
    assert view["permit_pending"] is True
    with pytest.raises(Exception) as exc:
        runs.advance_run("inc-B", "APPROVED", approval=bound_a,
                         approval_secret=SECRET, now=NOW)
    assert isinstance(exc.value, PermitRejected)
    assert "mismatch" in str(exc.value).lower()
    assert runs.http_status(exc.value) == 403
    # Same-incident flow still works on the other run.
    view_b = runs.advance_run("inc-B", "APPROVED",
                              approval=_bound_approval(incident_id="inc-B"),
                              approval_secret=SECRET, now=NOW)
    assert view_b["permit_pending"] is True


def test_advance_idempotency_cached():
    runs.create_run("inc-1", now=NOW)
    first = runs.advance_run("inc-1", "TRIAGING", idempotency_key="k1",
                             now=NOW)
    second = runs.advance_run("inc-1", "TRIAGING", idempotency_key="k1",
                              now=NOW)
    assert first["duplicate"] is False and second["duplicate"] is True
    assert len(runs.get_run("inc-1").history) == 1
    with pytest.raises(Exception):
        runs.advance_run("inc-1", "CORRELATED", idempotency_key="  ", now=NOW)


def test_sweep_fn():
    runs.create_run("inc-1", now=NOW)
    runs.advance_run("inc-1", "TRIAGING", now=NOW)
    out = runs.sweep_run("inc-1", NOW + 61.0)
    assert out["escalated"] is True and out["state"] == "ESCALATED"


def test_error_mapping():
    assert runs.http_status(ValueError("x")) == 400
    assert runs.http_status(Exception("x")) == 500


def test_permit_shape_rejected():
    runs.create_run("inc-1", now=NOW)
    with pytest.raises(Exception):
        runs.advance_run("inc-1", "TRIAGING", approval={"nope": 1}, now=NOW)
    _to_policy("inc-9")
    with pytest.raises(Exception):
        runs.advance_run("inc-9", "APPROVED", approval=None,
                         approval_secret=SECRET, now=NOW)


# ---------------------------------------------------------------------------
# Agent execution through pure fns (scripted clients, no network)
# ---------------------------------------------------------------------------

class _Fake:
    def __init__(self, payload=None):
        self.payload = payload

    def mode_for(self, agent):
        return "CONNECTED" if self.payload is not None else "DISABLED"

    def chat(self, agent, session_id, message):
        from agents import lyzr_client as LC
        return LC.ClientResult("CONNECTED", agent, session_id, self.payload,
                               "", 1, "PS03-Governed")


def _disabled():
    from agents import lyzr_client as LC
    return LC.LyzrClient(LC.ClientConfig())


def test_triage_fn_disabled_and_live():
    alerts = [{"service": "web", "env": "prod", "signature": "http_5xx_spike",
               "error_rate": 0.18, "slo_breach": True, "deploy_id": "d1"}]
    out = runs.triage_run(runs.SESSIONS, _disabled(), "inc-1", alerts, "d1")
    assert out["severity"] == "P1" and out["fallback"] is True
    from app.services import correlator
    fp = correlator.fingerprint("web", "http_5xx_spike", "prod", "d1")
    out = runs.triage_run(runs.SESSIONS, _Fake(
        {"incident_id": "inc-1", "severity": "P2", "fingerprint": fp,
         "owner": "o", "signals": [], "evidence_ids": []}), "inc-1", alerts)
    assert out["severity"] == "P2" and out["fallback"] is False


def test_diagnose_plan_report_fns():
    from app.services.predigest import build_evidence_pack
    tele = {"alerts": [{"id": "a1"}],
            "logs": [{"level": "ERROR", "msg": "http_5xx_spike trace=1"}],
            "metrics": [], "deploys": [], "traces": [],
            "topology": {"depends_on": []}}
    pack = build_evidence_pack("inc-1", tele)
    diag = runs.diagnose_run(runs.SESSIONS, _disabled(), "inc-1", "web",
                             "prod", pack)
    assert diag["verdict"] == "INSUFFICIENT_EVIDENCE"

    known = tuple(e["evidence_id"] for e in pack["evidence"][:2])
    hyp = {"text": "v23 regression", "confidence": 0.9,
           "supporting": list(known), "contradicting": [], "test_tool": "",
           "test_args": {}, "test_result": "", "status": "SUPPORTED"}
    diag_live = runs.diagnose_run(runs.SESSIONS, _Fake(
        {"incident_id": "inc-1", "hypotheses": [hyp, dict(hyp, text="surge",
                                                          confidence=0.3)],
         "runbook_id": "bad-deploy-rollback", "runbook_version": "1.2.0",
         "verdict": "PINNED"}), "inc-1", "web", "prod", pack)
    assert diag_live["verdict"] == "PINNED"

    plan = runs.plan_run(runs.SESSIONS, _Fake(
        {"action_type": "rollback_deployment",
         "parameters": {"to_version": "v22"}, "risk_level": "YELLOW",
         "reason": "Roll back web to v22.", "expected_outcome": "Spike clears.",
         "verification_plan": ["deployment_version_expected"],
         "rollback_action": None}), "inc-1", diag_live,
        {"type": "deployment", "id": "web", "environment": "mock"}, known)
    assert plan["action"]["action_type"] == "rollback_deployment"

    claims = [{"text": "v23 caused it", "evidence_ids": [known[0]],
               "claim_class": "MUST-CITE"}]
    # Pure-fn draft test: explicit legacy opt-in (visible, not default).
    # Publication hardening lives in pipeline.publish_rca (hardened-only).
    rca = runs.report_run(runs.SESSIONS, _disabled(), "inc-1",
                          ["t0 triage"], "v23 caused it.", claims, list(known),
                          ["rollback"], ["canary"], legacy_draft=True)
    assert rca["gated"] is False


def test_build_client_modes():
    client = runs.build_client("", {}, "PS03-Governed")
    assert client.mode_for("triage") == "DISABLED"
    cfg = SimpleNamespace(LYZR_API_KEY="k", LYZR_AGENT_TRIAGE_ID="a",
                          LYZR_AGENT_DIAGNOSTIC_ID="b",
                          LYZR_AGENT_PLANNER_ID="c",
                          LYZR_AGENT_REPORTER_ID="d",
                          LYZR_RAI_POLICY="PS03-Governed")
    ids = {"triage": cfg.LYZR_AGENT_TRIAGE_ID,
           "diagnostic": cfg.LYZR_AGENT_DIAGNOSTIC_ID,
           "planner": cfg.LYZR_AGENT_PLANNER_ID,
           "reporter": cfg.LYZR_AGENT_REPORTER_ID}
    assert runs.build_client(cfg.LYZR_API_KEY, ids,
                             cfg.LYZR_RAI_POLICY).mode_for("triage") \
        == "CONNECTED"


# ---------------------------------------------------------------------------
# Wiring pins (structural, host-safe)
# ---------------------------------------------------------------------------

def test_main_wires_runs_router():
    tree = ast.parse((ROOT / "backend" / "app" / "main.py").read_text(
        encoding="utf-8"))
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and getattr(n.func, "attr", "") == "include_router"]
    assert calls, "main.py must include_router (runs)"
    src = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert "runs" in src


def test_router_defines_runs_prefix():
    src = (ROOT / "backend" / "app" / "routers" / "runs.py").read_text(
        encoding="utf-8")
    assert 'prefix="/runs"' in src


def test_dockerfile_ships_agents():
    # Compose builds the ROOT Dockerfile (repo-root context), which must COPY
    # agents/ (routers import it at boot). backend/Dockerfile builds with a
    # backend/ context and cannot reach ../agents -- untouched by design.
    lines = (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("COPY") and "agents" in line
               for line in lines), \
        "Dockerfile must COPY agents/ (routers import it at boot)"


# ---------------------------------------------------------------------------
# Lane 2 loop 4: REPO_STORE file persistence (var/runs.json)
# ---------------------------------------------------------------------------

def _to_approved(incident):
    _to_policy(incident)
    bound = _bound_approval(incident_id=incident)
    view = runs.advance_run(incident, "APPROVED", approval=bound,
                            approval_secret=SECRET, now=NOW)
    assert view["permit_pending"] is True
    return incident


def test_store_roundtrip_resume_advance(tmp_path):
    """Restart resume: history intact, pending permit still drives EXECUTING."""
    _to_approved("inc-rt")
    before = runs.run_view(runs.get_run("inc-rt"))
    path = tmp_path / "runs.json"
    runs.save_store(path)
    assert path.is_file()
    runs.REPO_STORE.clear()  # simulate restart: memory gone, file survives
    loaded = runs.load_store(path)
    assert loaded == ["inc-rt"]
    after = runs.run_view(runs.get_run("inc-rt"))
    assert after["history"] == before["history"]
    assert after["permit_pending"] is True
    assert after["replans"] == before["replans"]
    cont = runs.advance_run("inc-rt", "EXECUTING", now=NOW)
    assert cont["state"] == "EXECUTING"
    assert len(cont["history"]) == len(before["history"]) + 1
    assert cont["permit_pending"] is False


def test_store_auto_resume_default_path():
    runs.create_run("inc-auto", now=NOW)
    assert runs.STORE_PATH.is_file()  # create auto-saves
    runs.REPO_STORE.clear()  # simulate restart
    run = runs.get_run("inc-auto")  # auto-load on miss
    assert run.state == "NEW"
    with pytest.raises(runs.RepoExists):
        runs.create_run("inc-auto", now=NOW)  # persisted id not clobbered


def test_store_corrupt_raises_no_partial(tmp_path):
    path = tmp_path / "runs.json"
    path.write_text("{nope", encoding="utf-8")
    with pytest.raises(ValueError):
        runs.load_store(path)
    assert runs.REPO_STORE == {}
    path.write_text(json.dumps(
        {"inc-1": {"incident_id": "inc-1", "state": "NOPE",
                   "history": [], "handoffs": [], "suppressions": [],
                   "replans": 0, "rolled_back": False, "permit": None,
                   "consumed_refs": [], "entered_at": {}}}),
        encoding="utf-8")
    with pytest.raises(ValueError):  # unknown state rejected by constructor
        runs.load_store(path)
    assert runs.REPO_STORE == {}  # fail-closed: no partial load


def test_store_no_partial_on_mixed_file(tmp_path):
    runs.create_run("inc-keep", now=NOW)
    path = tmp_path / "runs.json"
    runs.save_store(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["bogus"] = {"incident_id": "bogus"}  # missing required keys
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        runs.load_store(path)
    assert set(runs.REPO_STORE) == {"inc-keep"}  # live dict untouched


def test_store_payload_excludes_http_idem_cache(tmp_path):
    """IDEM_RESPONSES stays a memory-only HTTP cache (documented choice)."""
    runs.create_run("inc-1", now=NOW)
    runs.advance_run("inc-1", "TRIAGING", idempotency_key="k1", now=NOW)
    assert runs.IDEM_RESPONSES  # cache populated, but must not persist
    path = tmp_path / "runs.json"
    runs.save_store(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert set(raw["inc-1"]) == {"incident_id", "state", "history",
                                 "handoffs", "suppressions", "replans",
                                 "rolled_back", "permit", "consumed_refs",
                                 "entered_at"}


def test_reset_clears_memory_and_file():
    runs.create_run("inc-1", now=NOW)
    assert runs.STORE_PATH.is_file()
    runs.reset_demo_state()
    assert runs.REPO_STORE == {}
    assert not runs.STORE_PATH.exists()
    with pytest.raises(runs.RepoMissing):
        runs.get_run("inc-1")
