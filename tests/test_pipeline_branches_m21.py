"""M21b branches: rollback + degradation + RCA + audit + eval + guards.

Commit B (closes M21): same deterministic fixtures, real services. The
rollback path ends ESCALATED after exactly one attempt (mock cannot heal
pool exhaustion by rescaling); degradation spends zero LLM calls.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents import session as session_mod  # noqa: E402 (M13.7)
from agents.lyzr_client import ClientResult  # noqa: E402 (M13.1 shape)
from app.contracts.hypothesis import Claim  # noqa: E402 (M01.5)
from app.routers import auth as auth_mod  # noqa: E402 (M21b matrix)
from app.routers.runs import HTTPException as HTTPExc  # noqa: E402 (shape)
from app.services import eval as eval_svc  # noqa: E402 (M16 grades)
from app.services import pipeline as P  # noqa: E402 (M21 conductor)
from app.services import correlator, predigest  # noqa: E402 (M04/M05)
from app.services.audit import AuditChain  # noqa: E402 (M15 chain)

import telemetry.gen as gen  # noqa: E402 (M02 fixtures)


class Scripted:
    def __init__(self, payload=None):
        self.payload = payload

    def mode_for(self, agent):
        return "CONNECTED" if self.payload is not None else "DISABLED"

    def chat(self, agent, session_id, message):
        assert self.payload is not None, "chat called while DISABLED"
        return ClientResult("CONNECTED", agent, session_id, self.payload,
                            "", 1, "PS03-Governed")


def _tele(scenario="bad-deploy"):
    return gen.public_bundle(gen.generate(scenario, "NORMAL", 42))


def _pack_ids(scenario="bad-deploy"):
    pack = predigest.build_evidence_pack("inc-1", _tele(scenario))
    return [e["evidence_id"] for e in pack["evidence"][:2]]


def _triage(severity="P1", service="web", signature="http_5xx_spike"):
    return {"incident_id": "inc-1", "severity": severity,
            "fingerprint": correlator.fingerprint(service, signature,
                                                  "prod", ""),
            "owner": f"{service}-oncall", "signals": [], "evidence_ids": []}


def _diagnosis(known, runbook="bad-deploy-rollback", version="1.2.0"):
    hyp = {"text": "cause-a", "confidence": 0.9,
           "supporting": list(known), "contradicting": [],
           "test_tool": "", "test_args": {}, "test_result": "",
           "status": "SUPPORTED"}
    return {"incident_id": "inc-1",
            "hypotheses": [hyp, dict(hyp, text="cause-b", confidence=0.3)],
            "runbook_id": runbook, "runbook_version": version,
            "verdict": "PINNED"}


def _plan(action="rollback_deployment", params=None):
    return {"action_type": action,
            "parameters": params if params is not None
            else {"to_version": "v22"},
            "risk_level": "YELLOW", "reason": "Fix it.",
            "expected_outcome": "Spike clears.",
            "verification_plan": ["error_rate_below_1pct"],
            "rollback_action": {"action_type": action}}


def _clients(scenario="bad-deploy", service="web", signature="http_5xx_spike",
             severity="P1", runbook="bad-deploy-rollback",
             version="1.2.0", plan=None):
    known = _pack_ids(scenario)
    payloads = {"triage": _triage(severity, service, signature),
                "diagnostic": _diagnosis(known, runbook, version),
                "planner": plan or _plan()}
    return {agent: Scripted(payload) for agent, payload in payloads.items()}


def _alerts(service="web", signature="http_5xx_spike", err=0.18):
    return [{"service": service, "env": "prod", "signature": signature,
             "error_rate": err, "slo_breach": True, "deploy_id": "d1"}]


def _resource(service="web"):
    return {"type": "deployment", "id": service, "environment": "mock"}


def _approval():
    return {"secret": "m21-test-secret", "actor": "sre-1"}


# ---------------------------------------------------------------------------
# Rollback path: FAILED -> one attempt -> FAILED -> ESCALATED
# ---------------------------------------------------------------------------

def test_rollback_once_then_escalated():
    tele = _tele("db-exhaust")
    plan = _plan(action="scale_deployment", params={"replicas": 4})
    plan["verification_plan"] = ["pool_wait_drained"]
    clients = _clients(scenario="db-exhaust", service="api",
                       signature="db_pool_exhausted", severity="P2",
                       runbook="db-pool-saturation", version="1.1.0",
                       plan=plan)
    report = P.run_pipeline("inc-1", _alerts("api", "db_pool_exhausted",
                                             0.07),
                            tele, "api", "prod", _resource("api"), clients,
                            session_mod.SessionStore(),
                            approval=_approval())
    assert report["path"] == "escalated"
    assert report["rolled_back"] is True
    assert report["verdicts"] == ["ROLLBACK_REQUIRED", "ROLLBACK_REQUIRED"]
    assert report["states"].count("ROLLBACK") == 1
    assert report["states"].count("VERIFYING") == 2
    assert report["states"][-1] == "ESCALATED"


# ---------------------------------------------------------------------------
# Degradation: DISABLED clients spend nothing, stall honestly
# ---------------------------------------------------------------------------

def test_degraded_no_spend_stalled():
    store = session_mod.SessionStore()
    clients = {agent: Scripted(None)
               for agent in ("triage", "diagnostic", "planner")}
    with pytest.raises(P.PipelineStalled) as exc:
        P.run_pipeline("inc-1", _alerts(), _tele(), "web", "prod",
                       _resource(), clients, store, approval=_approval())
    assert exc.value.run.state == "ESCALATED"
    for agent in ("triage", "diagnostic"):
        assert store.get("inc-1", agent).llm_calls == 0
    assert store.get("inc-1", "planner") is None  # never reached


# ---------------------------------------------------------------------------
# RCA from pipeline artifacts (gated + ungated)
# ---------------------------------------------------------------------------

def _happy():
    tele = _tele()
    report = P.run_pipeline("inc-1", _alerts(), tele, "web", "prod",
                            _resource(), _clients(),
                            session_mod.SessionStore(),
                            approval=_approval())
    assert report["path"] == "resolved"
    return tele, report


def test_rca_ungated_on_valid_ids():
    tele, report = _happy()
    assert tele is not None
    claims = [Claim(text="v23 caused it",
                    evidence_ids=[report["evidence_ids"][0]],
                    claim_class="MUST-CITE")]
    rows = [f"t{i} {s}" for i, s in enumerate(report["states"])]
    out = P.draft_rca("inc-1", report["run"], None, "v23 caused it.",
                      claims, rows, ["rollback to v22"], ["canary"],
                      set(report["evidence_ids"]), Scripted(None),
                      session_mod.SessionStore())
    assert out.gated is False


def test_rca_gated_on_unknown_ids():
    _, report = _happy()
    claims = [Claim(text="v23 caused it", evidence_ids=["ev-NOPE"],
                    claim_class="MUST-CITE")]
    rows = [f"t{i} {s}" for i, s in enumerate(report["states"])]
    out = P.draft_rca("inc-1", report["run"], None, "v23 caused it.",
                      claims, rows, ["rollback"], ["canary"],
                      set(report["evidence_ids"]), Scripted(None),
                      session_mod.SessionStore())
    assert out.gated is True and "coverage" in out.gate_reason


# ---------------------------------------------------------------------------
# Audit: transitions + approvals recorded, chain valid
# ---------------------------------------------------------------------------

def test_audit_records_full_walk():
    from app.services import fsm as fsm_svc
    chain = AuditChain(incident_id="inc-1")
    tele = _tele()
    report = P.run_pipeline("inc-1", _alerts(), tele, "web", "prod",
                            _resource(), _clients(),
                            session_mod.SessionStore(),
                            approval=_approval(), chain=chain)
    kinds = [e.event_type for e in chain.events]
    assert kinds.count("transition") == len(report["states"])
    assert any(e.event_type == "approval.approve" for e in chain.events)
    assert chain.verify()["valid"] is True
    assert fsm_svc.audit_records(report["run"])[0]["type"] == "transition"


def test_audit_records_blocked_walk():
    chain = AuditChain(incident_id="inc-1")
    clients = _clients(plan=_plan(action="delete_namespace", params={}))
    with pytest.raises(P.PipelineBlocked):
        P.run_pipeline("inc-1", _alerts(), _tele(), "web", "prod",
                       _resource(), clients, session_mod.SessionStore(),
                       approval=_approval(), chain=chain)
    assert any("BLOCKED" in e.result for e in chain.events
               if e.event_type == "transition")
    assert chain.verify()["valid"] is True


# ---------------------------------------------------------------------------
# Eval bridge: run -> trace -> grades -> scorecard link
# ---------------------------------------------------------------------------

def test_eval_bridge_graded_and_linked():
    tele, report = _happy()
    harness = eval_svc.mock_trace()
    trace = P.to_eval_trace(report, tele, harness["budgets"],
                            harness["retrieval"], harness["hallucination"],
                            harness["prompt"], harness["latencies"])
    checked = eval_svc.check_trace(trace)
    grades = eval_svc.grade(checked, {"allowed": ["rollback_deployment"],
                                      "forbidden": ["delete_namespace"]})
    assert all(g.passed for g in grades), \
        [g.detail for g in grades if not g.passed]
    html = eval_svc.render_scorecard("m21 bridge", [{
        "run_id": report["execution_id"], "case_id": "bad-deploy/NORMAL/42",
        "config": "pipeline", "passed": True,
        "gates": {"C1": {"passed": True}}, "rubric_total": 86.0,
        "jsonl_ref": "runs/r1.jsonl#L1"}])
    assert f'data-run-id="{report["execution_id"]}"' in html


# ---------------------------------------------------------------------------
# Guard matrix: key gate unit + handler wiring pins
# ---------------------------------------------------------------------------

def test_check_api_key_matrix():
    auth_mod.check_api_key("k", "k")
    with pytest.raises(auth_mod.KeyMissing):
        auth_mod.check_api_key(None, "k")
    with pytest.raises(auth_mod.KeyMissing):
        auth_mod.check_api_key("  ", "k")
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.check_api_key("wrong", "k")
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.check_api_key("k", "")
    assert auth_mod.http_status(auth_mod.KeyMissing("x")) == 401
    assert auth_mod.http_status(auth_mod.KeyRejected("x")) == 403


def test_guard_without_settings_touch():
    def _boom():
        raise AssertionError("settings must not load for blank keys")

    with pytest.raises(HTTPExc) as exc:
        auth_mod.guard_http(None, _boom, HTTPExc)
    assert exc.value.status_code == 401


def test_mutating_handlers_call_guard():
    root = Path(__file__).resolve().parents[1]
    runs_src = (root / "backend" / "app" / "routers" / "runs.py").read_text(
        encoding="utf-8")
    approvals = (root / "backend" / "app" / "routers" / "approvals.py").read_text(
        encoding="utf-8")
    assert "guard_http" in runs_src and "x_api_key" in runs_src
    assert "guard_http" in approvals
    assert approvals.count("_require_key(") >= 2
