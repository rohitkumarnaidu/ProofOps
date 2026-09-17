"""M21a pipeline: happy + RED + stalled paths (host-safe, mock tiers).

Commit A (conductor + 3 paths): scripted clients (same ClientResult shape,
zero network), real services throughout, deterministic bad-deploy fixture.
Rollback/degradation/RCA/audit/eval/guards land in commit B.
"""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents import session as session_mod  # noqa: E402 (M13.7)
from agents.lyzr_client import ClientResult  # noqa: E402 (M13.1 shape)
from app.services import pipeline as P  # noqa: E402 (M21a conductor)
from app.services import correlator, predigest  # noqa: E402 (M04/M05)

import telemetry.gen as gen  # noqa: E402 (M02 fixtures)


class Scripted:
    """Per-agent scripted client (deterministic golden payloads)."""

    def __init__(self, payload=None):
        self.payload = payload
        self.calls = []

    def mode_for(self, agent):
        return "CONNECTED" if self.payload is not None else "DISABLED"

    def chat(self, agent, session_id, message):
        self.calls.append(agent)
        assert self.payload is not None, "chat called while DISABLED"
        return ClientResult("CONNECTED", agent, session_id, self.payload,
                            "", 1, "PS03-Governed")


def _tele():
    return gen.public_bundle(gen.generate("bad-deploy", "NORMAL", 42))


def _alerts():
    return [{"service": "web", "env": "prod",
             "signature": "http_5xx_spike", "error_rate": 0.18,
             "slo_breach": True, "deploy_id": "d1"}]


def _pack_ids():
    pack = predigest.build_evidence_pack("inc-1", _tele())
    return pack, [e["evidence_id"] for e in pack["evidence"][:2]]


def _triage_payload():
    return {"incident_id": "inc-1", "severity": "P1",
            "fingerprint": correlator.fingerprint(
                "web", "http_5xx_spike", "prod", ""),
            "owner": "web-oncall", "signals": ["web:http_5xx_spike"],
            "evidence_ids": []}


def _diagnosis_payload(known):
    hyp = {"text": "v23 regression", "confidence": 0.9,
           "supporting": list(known), "contradicting": [],
           "test_tool": "", "test_args": {}, "test_result": "",
           "status": "SUPPORTED"}
    return {"incident_id": "inc-1",
            "hypotheses": [hyp, dict(hyp, text="surge", confidence=0.3)],
            "runbook_id": "bad-deploy-rollback",
            "runbook_version": "1.2.0", "verdict": "PINNED"}


def _plan_payload(**over):
    base = {"action_type": "rollback_deployment",
            "parameters": {"to_version": "v22"}, "risk_level": "YELLOW",
            "reason": "Roll back web to v22.", "expected_outcome": "Spike clears.",
            "verification_plan": ["deployment_version_expected"],
            "rollback_action": {"action_type": "rollback_deployment"}}
    base.update(over)
    return base


def _clients(**over):
    _, known = _pack_ids()
    payloads = {"triage": _triage_payload(),
                "diagnostic": _diagnosis_payload(known),
                "planner": _plan_payload()}
    payloads.update(over)
    return {agent: Scripted(payload)
            for agent, payload in payloads.items()}


def _resource():
    return {"type": "deployment", "id": "web", "environment": "mock"}


def _approval():
    return {"secret": "m21-test-secret", "actor": "sre-1"}


# ---------------------------------------------------------------------------
# Happy path: seed -> ESCALATE -> approve -> execute -> RESOLVED
# ---------------------------------------------------------------------------

def test_happy_path_resolved():
    tele = _tele()
    before = copy.deepcopy(tele)
    report = P.run_pipeline("inc-1", _alerts(), tele, "web", "prod",
                            _resource(), _clients(),
                            session_mod.SessionStore(),
                            approval=_approval())
    assert report["path"] == "resolved"
    assert report["states"] == ["TRIAGING", "CORRELATED", "INVESTIGATING",
                                "DIAGNOSING", "PLANNED", "POLICY_CHECK",
                                "AWAITING_APPROVAL", "APPROVED", "EXECUTING",
                                "VERIFYING", "RESOLVED"]
    assert report["decision"] == "ESCALATE"
    assert report["action_type"] == "rollback_deployment"
    assert report["verdict"] == "RESOLVED"
    assert report["evidence_ids"] and report["rolled_back"] is False
    assert tele == before  # pipeline never mutates telemetry (DATA)


def test_ground_truth_absent_from_pipeline_input():
    tele = _tele()
    blob = json.dumps(tele)
    assert "expected_cause" not in blob and "config regression" not in blob


# ---------------------------------------------------------------------------
# RED path: destructive proposal blocked, audited, zero effect
# ---------------------------------------------------------------------------

def test_red_proposal_blocked_with_state():
    tele = _tele()
    before = copy.deepcopy(tele)
    clients = _clients(planner=_plan_payload(
        action_type="delete_namespace",
        parameters={}, reason="routine cleanup"))
    with pytest.raises(P.PipelineBlocked) as exc:
        P.run_pipeline("inc-1", _alerts(), tele, "web", "prod",
                       _resource(), clients, session_mod.SessionStore(),
                       approval=_approval())
    run = exc.value.run
    assert run.state == "BLOCKED"
    assert "EXECUTING" not in [r.to for r in run.history]
    assert "allowlist" in str(exc.value)
    assert tele == before  # zero effect: inputs untouched, nothing executed


# ---------------------------------------------------------------------------
# Stalled path: ESCALATE without approval config
# ---------------------------------------------------------------------------

def test_escalate_without_approval_stalls():
    with pytest.raises(P.PipelineStalled) as exc:
        P.run_pipeline("inc-1", _alerts(), _tele(), "web", "prod",
                       _resource(), _clients(), session_mod.SessionStore(),
                       approval=None)
    assert exc.value.run.state == "AWAITING_APPROVAL"


def test_missing_client_is_pipeline_failure():
    with pytest.raises(P.PipelineFailed):
        P.run_pipeline("inc-1", _alerts(), _tele(), "web", "prod",
                       _resource(), {},
                       session_mod.SessionStore(), approval=_approval())
