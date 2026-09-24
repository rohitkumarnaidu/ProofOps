"""M13 agents: KB/memory + A1-A4 behavior + prompts + chain (host-safe).

Commit 2 of the M13 lane (M13.2-M13.5/M13.9/M13.10): live reasoning runs
through a scripted FakeClient (same ClientResult shape, no network); the
DISABLED path runs with the real client minus keys. No test touches the
network or needs credentials.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents import diagnostic as A2  # noqa: E402 (M13.3)
from agents import kb  # noqa: E402 (M13.9 collections)
from agents import lyzr_client as LC  # noqa: E402 (M13.1 modes)
from agents import memory as mem  # noqa: E402 (M13.10 memory)
from agents import planner as A3  # noqa: E402 (M13.4)
from agents import reporter as A4  # noqa: E402 (M13.5)
from agents import session as sess  # noqa: E402 (M13.7 sessions)
from agents import tools as tools_mod  # noqa: E402 (M13 ACL, Lane 4 L1)
from agents import triage as A1  # noqa: E402 (M13.2)
from agents.memory import GLOBAL_CONTEXT  # noqa: E402
from agents.schemas import BudgetExceeded, OutputRejected  # noqa: E402
from app.contracts.hypothesis import Claim  # noqa: E402 (M01.5)
from app.services import correlator  # noqa: E402 (M04 parity)
from app.services.predigest import build_evidence_pack  # noqa: E402 (M05.5)

PROMPTS = Path(__file__).resolve().parents[1] / "agents" / "prompts"
SECTIONS = ["## IDENTITY", "## ROLE", "## OBJECTIVE", "## SCOPE",
            "## INPUT CONTRACT", "## TRUSTED DATA", "## UNTRUSTED DATA",
            "## OUTPUT SCHEMA", "## EVIDENCE RULES", "## TOOL RULES",
            "## SAFETY RULES", "## FORBIDDEN BEHAVIOR",
            "## UNCERTAINTY RULES", "## ESCALATION CONDITIONS",
            "## STOP CONDITIONS", "## FAILURE BEHAVIOR"]


class FakeClient:
    """Scripted stand-in: same ClientResult shape, zero network."""

    def __init__(self, payload=None):
        self.payload = payload
        self.calls: list[tuple[str, str]] = []

    def mode_for(self, agent):
        return "CONNECTED" if self.payload is not None else "DISABLED"

    def chat(self, agent, session_id, message):
        self.calls.append((agent, session_id))
        assert self.payload is not None, "chat called while DISABLED"
        return LC.ClientResult("CONNECTED", agent, session_id,
                               self.payload, "", 1, "PS03-Governed")


def _disabled():
    return LC.LyzrClient(LC.ClientConfig())


def _alerts():
    return [{"service": "web", "env": "prod", "signature": "http_5xx_spike",
             "error_rate": 0.18, "slo_breach": True, "deploy_id": "d1"}]


def _pack():
    tele = {"alerts": [{"id": "a1"}],
            "logs": [{"level": "ERROR", "msg": "http_5xx_spike trace=1"}],
            "metrics": [{"name": "error_rate", "value": 0.01},
                        {"name": "error_rate", "value": 0.18}],
            "deploys": [{"deploy_id": "d1", "from_v": "v22", "to_v": "v23",
                         "author": "ci-bot"}],
            "traces": [{"trace_id": "t1"}],
            "topology": {"depends_on": ["db"]}}
    return build_evidence_pack("inc-1", tele)


def _hyp(text="cause-a", conf=0.8, supporting=("ev-1",)):
    return {"text": text, "confidence": conf, "supporting": list(supporting),
            "contradicting": [], "test_tool": "", "test_args": {},
            "test_result": "", "status": "SUPPORTED"}


# ---------------------------------------------------------------------------
# M13.9 KB
# ---------------------------------------------------------------------------

def test_collections_pinned():
    assert kb.collections() == {"runbooks": "runbooks-v*", "history": "history"}


def test_build_index_seeds():
    docs = kb.build_index()
    assert len(docs) == 5
    assert all(d.source_type == "runbook" for d in docs)


def test_kb_query_top_hit_and_threshold():
    docs = kb.build_index()
    hits = kb.kb_query("web prod http_5xx_spike", docs, service="web")
    assert hits and hits[0].doc_id.startswith("bad-deploy-rollback@")
    assert kb.kb_query("zebra quantum telescope", docs) == []


def test_kb_query_validation():
    with pytest.raises(ValueError):
        kb.kb_query("  ", kb.build_index())
    with pytest.raises(ValueError):
        kb.build_index(runbook_ids=[])


# ---------------------------------------------------------------------------
# M13.10 memory
# ---------------------------------------------------------------------------

def test_memory_add_recall():
    m = mem.WorkingMemory(incident_id="inc-1")
    m.add("error_rate 0.18 after deploy v23", "ev-1")
    m.add("unrelated lunch menu", "ev-2")
    found = m.recall("error_rate deploy", k=1)
    assert len(found) == 1 and found[0].source == "ev-1"


def test_memory_cap_drops_oldest():
    m = mem.WorkingMemory(incident_id="inc-1")
    for i in range(55):
        m.add(f"fact {i}", f"ev-{i}")
    assert len(m.facts) == 50
    assert m.facts[0].text == "fact 5"


def test_memory_validation():
    m = mem.WorkingMemory(incident_id="inc-1")
    with pytest.raises(ValueError):
        m.add("", "ev-1")
    with pytest.raises(ValueError):
        m.recall("  ")
    with pytest.raises(ValueError):
        m.recall("x", k=0)
    with pytest.raises(ValueError):
        mem.CognisInterface("")


def test_cognis_honest_mode():
    ci = mem.CognisInterface("inc-1")
    assert ci.mode == "local"
    rec = ci.attach()
    assert rec["cognis"] == "local" and rec["global_context"] is True


def test_global_context():
    assert "evidence-first" in GLOBAL_CONTEXT and "policy decides" in GLOBAL_CONTEXT


# ---------------------------------------------------------------------------
# M13.2 triage
# ---------------------------------------------------------------------------

def test_fallback_p1_prod_spike():
    out = A1.run_triage(_alerts(), "inc-1", _disabled(), sess.SessionStore(),
                        deploy_id="d1", evidence_ids=("ev-1",))
    assert out.severity == "P1" and out.fallback is True
    assert out.evidence_ids == ["ev-1"] and out.owner == "web-oncall"


def test_fallback_p1_security_like():
    alerts = [{"service": "web", "env": "prod",
               "signature": "suspicious_log_instruction", "error_rate": 0.001,
               "slo_breach": False, "deploy_id": ""}]
    out = A1.run_triage(alerts, "inc-1", _disabled(), sess.SessionStore())
    assert out.severity == "P1"


def test_fallback_p2_degraded_and_p3_staging():
    deg = [{"service": "api", "env": "prod", "signature": "slow_burn",
            "error_rate": 0.01, "slo_breach": False, "deploy_id": ""}]
    assert A1.run_triage(deg, "inc-1", _disabled(),
                         sess.SessionStore()).severity == "P2"
    stg = [{"service": "web", "env": "staging", "signature": "http_5xx_spike",
            "error_rate": 0.2, "slo_breach": True, "deploy_id": ""}]
    assert A1.run_triage(stg, "inc-1", _disabled(),
                         sess.SessionStore()).severity == "P3"


def test_empty_alerts_refused():
    with pytest.raises(ValueError):
        A1.run_triage([], "inc-1", _disabled(), sess.SessionStore())


def test_fingerprint_shape_and_stability():
    store = sess.SessionStore()
    first = A1.run_triage(_alerts(), "inc-1", _disabled(), store, deploy_id="d1")
    second = A1.run_triage(_alerts(), "inc-1", _disabled(), store, deploy_id="d1")
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 16
    assert first.fingerprint == correlator.fingerprint(
        "web", "http_5xx_spike", "prod", "d1")


def test_wrong_incident_echo_rejected():
    fp = correlator.fingerprint("web", "http_5xx_spike", "prod", "d1")
    fake = FakeClient({"incident_id": "inc-X", "severity": "P1",
                       "fingerprint": fp, "owner": "o", "signals": [],
                       "evidence_ids": []})
    with pytest.raises(OutputRejected):
        A1.run_triage(_alerts(), "inc-1", fake, sess.SessionStore())


# ---------------------------------------------------------------------------
# M13.3 diagnostic
# ---------------------------------------------------------------------------

def test_fallback_insufficient_with_lead():
    out = A2.run_diagnose("inc-1", "web", "prod", _pack(), _disabled(),
                          sess.SessionStore())
    assert out.verdict == "INSUFFICIENT_EVIDENCE" and out.fallback is True
    assert out.runbook_id == "bad-deploy-rollback"
    assert out.hypotheses[0].confidence == 0.5


def test_live_pin_happy_path():
    pack = _pack()
    known = [e["evidence_id"] for e in pack["evidence"]][:2]
    fake = FakeClient({"incident_id": "inc-1",
                       "hypotheses": [_hyp("deploy v23 regression", 0.9,
                                           tuple(known)),
                                      _hyp("traffic surge", 0.3, tuple(known))],
                       "runbook_id": "bad-deploy-rollback",
                       "runbook_version": "1.2.0", "verdict": "PINNED"})
    out = A2.run_diagnose("inc-1", "web", "prod", pack, fake,
                          sess.SessionStore())
    assert out.verdict == "PINNED" and len(out.hypotheses) == 2


def test_unknown_citation_rejected():
    pack = _pack()
    fake = FakeClient({"incident_id": "inc-1",
                       "hypotheses": [_hyp("x", 0.9, ("ev-NOPE",)),
                                      _hyp("y", 0.4, ())],
                       "runbook_id": "bad-deploy-rollback",
                       "runbook_version": "1.2.0", "verdict": "PINNED"})
    with pytest.raises(OutputRejected):
        A2.run_diagnose("inc-1", "web", "prod", pack, fake,
                        sess.SessionStore())


def test_diagnose_wrong_incident_rejected():
    fake = FakeClient({"incident_id": "inc-X", "hypotheses": [],
                       "runbook_id": "", "runbook_version": "",
                       "verdict": "INSUFFICIENT_EVIDENCE"})
    with pytest.raises(OutputRejected):
        A2.run_diagnose("inc-1", "web", "prod", _pack(), fake,
                        sess.SessionStore())


def test_pack_without_signature_rejected():
    with pytest.raises(ValueError):
        A2.run_diagnose("inc-1", "web", "prod", {"evidence": []},
                        _disabled(), sess.SessionStore())


# ---------------------------------------------------------------------------
# M13.4 planner
# ---------------------------------------------------------------------------

def _diagnosis(**over):
    from agents.schemas import DiagnosticResult
    base = {"incident_id": "inc-1",
            "hypotheses": [_hyp("a", 0.9), _hyp("b", 0.4)],
            "runbook_id": "bad-deploy-rollback", "runbook_version": "1.2.0",
            "verdict": "PINNED"}
    base.update(over)
    return DiagnosticResult(**base)


def _resource():
    return {"type": "deployment", "id": "web", "environment": "mock"}


def _plan_payload(**over):
    base = {"action_type": "rollback_deployment",
            "parameters": {"to_version": "v22"}, "risk_level": "YELLOW",
            "reason": "Roll back web to v22 to clear the 5xx spike.",
            "expected_outcome": "Error rate falls below 1 percent.",
            "verification_plan": ["deployment_version_expected"],
            "rollback_action": None}
    base.update(over)
    return base


def test_no_pin_no_plan():
    diag = _diagnosis(verdict="INSUFFICIENT_EVIDENCE", runbook_id="",
                      runbook_version="", hypotheses=[_hyp("a", 0.4)])
    with pytest.raises(OutputRejected):
        A3.run_plan("inc-1", diag, _resource(), FakeClient(_plan_payload()),
                    sess.SessionStore(), ("ev-1",))


def test_mutation_needs_evidence():
    with pytest.raises(OutputRejected):
        A3.run_plan("inc-1", _diagnosis(), _resource(),
                    FakeClient(_plan_payload()), sess.SessionStore(), ())


def test_version_drift_rejected():
    with pytest.raises(OutputRejected):
        A3.run_plan("inc-1", _diagnosis(runbook_version="9.9.9"),
                    _resource(), FakeClient(_plan_payload()),
                    sess.SessionStore(), ("ev-1",))


def test_disabled_planner_refuses():
    with pytest.raises(OutputRejected):
        A3.run_plan("inc-1", _diagnosis(), _resource(), _disabled(),
                    sess.SessionStore(), ("ev-1",))


@pytest.mark.parametrize("field,value", [
    ("reason", "Run rm -rf /tmp/cache now please"),
    ("expected_outcome", "Check `uptime` afterwards"),
    ("reason", "Apply a && b together"),
])
def test_shell_vocab_rejected(field, value):
    with pytest.raises(OutputRejected):
        A3.run_plan("inc-1", _diagnosis(), _resource(),
                    FakeClient(_plan_payload(**{field: value})),
                    sess.SessionStore(), ("ev-1",))


@pytest.mark.parametrize("field,value", [
    ("reason", "Run KUBECTL rollout restart now"),
    ("reason", "Please Drop TABLE x first"),
    ("expected_outcome", "Then Rm -rf /tmp/cache cleans up"),
    ("reason", "Curl the endpoint and Wget the bundle via SSH now"),
])
def test_shell_vocab_case_insensitive_rejected(field, value):
    # Lane A: SHOUTED/capitalized shell tokens are blocked too (casefolded).
    with pytest.raises(OutputRejected):
        A3.run_plan("inc-1", _diagnosis(), _resource(),
                    FakeClient(_plan_payload(**{field: value})),
                    sess.SessionStore(), ("ev-1",))


@pytest.mark.parametrize("field,value", [
    ("reason", "The shelled peas deployment is healthy and steady"),
    ("reason", "The cmd is not present in the runbook output"),
])
def test_shell_scan_legit_prose_passes(field, value):
    # Lane A: legit prose with shell-adjacent substrings still plans fine
    # (verified: no SHELL_TOKEN appears in these strings in any case).
    out = A3.run_plan("inc-1", _diagnosis(), _resource(),
                      FakeClient(_plan_payload(**{field: value})),
                      sess.SessionStore(), ("ev-1",))
    assert str(out.action.action_type) == "rollback_deployment"


def test_happy_path_builds_action():
    out = A3.run_plan("inc-1", _diagnosis(), _resource(),
                      FakeClient(_plan_payload()), sess.SessionStore(),
                      ("ev-1",))
    assert str(out.action.action_type) == "rollback_deployment"
    assert out.action.runbook_id == "bad-deploy-rollback"
    assert list(out.action.evidence_ids) == ["ev-1"]


def test_replan_budget():
    with pytest.raises(BudgetExceeded):
        A3.run_plan("inc-1", _diagnosis(), _resource(),
                    FakeClient(_plan_payload()), sess.SessionStore(),
                    ("ev-1",), replans_used=3)


# ---------------------------------------------------------------------------
# M13.5 reporter
# ---------------------------------------------------------------------------

def _claims():
    return [Claim(text="v23 caused the spike", evidence_ids=["ev-1"],
                  claim_class="MUST-CITE")]


def test_blameless_lint_rejects():
    with pytest.raises(OutputRejected):
        A4.run_report("inc-1", ["t1"], "The engineer at fault delayed.",
                      _claims(), {"ev-1"}, ["rolled back"], ["add alert"],
                      _disabled(), sess.SessionStore(), legacy_draft=True)


def test_low_coverage_gates():
    out = A4.run_report("inc-1", ["t1"], "v23 caused it.", _claims(),
                        {"ev-OTHER"}, ["rolled back"], ["add alert"],
                        _disabled(), sess.SessionStore(), legacy_draft=True)
    assert out.gated is True and "coverage" in out.gate_reason


def test_full_coverage_ungated_disabled():
    claims = _claims()
    out = A4.run_report("inc-1", ["t1 row"], "v23 caused it.", claims,
                        {"ev-1"}, ["rolled back"], ["add alert"],
                        _disabled(), sess.SessionStore(), legacy_draft=True)
    assert out.gated is False
    assert "inc-1" in out.summary
    assert out.claim_ids == [claims[0].claim_id]


def test_empty_timeline_rejected():
    with pytest.raises(OutputRejected):
        A4.run_report("inc-1", [], "r", _claims(), {"ev-1"}, [], [],
                      _disabled(), sess.SessionStore(), legacy_draft=True)


def test_live_summary_linted():
    fake = FakeClient({"summary": "The team was negligent here."})
    with pytest.raises(OutputRejected):
        A4.run_report("inc-1", ["t1"], "v23 caused it.", _claims(), {"ev-1"},
                      ["r"], ["p"], fake, sess.SessionStore(),
                      legacy_draft=True)


# ---------------------------------------------------------------------------
# Prompts: S8.3 section gates
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["triage", "diagnostic", "planner", "reporter"])
def test_prompt_sections(name):
    text = (PROMPTS / f"{name}.md").read_text(encoding="utf-8")
    for section in SECTIONS:
        assert section in text, f"{name}.md missing {section}"


def test_prompt_role_markers():
    planner = (PROMPTS / "planner.md").read_text(encoding="utf-8")
    assert "NO tools" in planner and "shell vocabulary" in planner
    assert "INSUFFICIENT_EVIDENCE" in (PROMPTS / "diagnostic.md").read_text(
        encoding="utf-8")
    assert "get_topology" in (PROMPTS / "triage.md").read_text(encoding="utf-8")
    assert "blameless" in (PROMPTS / "reporter.md").read_text(
        encoding="utf-8").lower()


# ---------------------------------------------------------------------------
# Wave-4 exit preview: A1 -> A4 chain on a seeded Evidence Pack
# ---------------------------------------------------------------------------

def test_chain_triage_to_rca():
    store = sess.SessionStore()
    fp = correlator.fingerprint("web", "http_5xx_spike", "prod", "d1")
    tri = A1.run_triage(_alerts(), "inc-1", FakeClient(
        {"incident_id": "inc-1", "severity": "P1", "fingerprint": fp,
         "owner": "web-oncall", "signals": ["web:http_5xx_spike"],
         "evidence_ids": ["ev-1"]}), store, deploy_id="d1",
        evidence_ids=("ev-1",))
    assert tri.severity == "P1" and tri.fallback is False

    pack = _pack()
    known = tuple(e["evidence_id"] for e in pack["evidence"][:2])
    diag = A2.run_diagnose("inc-1", "web", "prod", pack, FakeClient(
        {"incident_id": "inc-1",
         "hypotheses": [_hyp("v23 regression", 0.9, known),
                        _hyp("surge", 0.3, known)],
         "runbook_id": "bad-deploy-rollback", "runbook_version": "1.2.0",
         "verdict": "PINNED"}), store)
    assert diag.verdict == "PINNED"

    plan = A3.run_plan("inc-1", diag, _resource(),
                       FakeClient(_plan_payload()), store, known)
    assert str(plan.action.action_type) == "rollback_deployment"

    claims = [Claim(text="v23 caused the spike", evidence_ids=[known[0]],
                    claim_class="MUST-CITE")]
    rca = A4.run_report("inc-1", ["t0 triage P1", "t1 rollback v22"],
                        "v23 caused it.", claims, set(known),
                        ["rollback to v22"], ["pin canary"],
                        _disabled(), store, legacy_draft=True)
    assert rca.gated is False and rca.root_cause == "v23 caused it."


def test_reporter_denies_legacy_by_default():
    # Fail-closed default: None mapping without legacy_draft=True raises.
    with pytest.raises(OutputRejected) as exc:
        A4.run_report("inc-1", ["t1"], "v23 caused it.", _claims(), {"ev-1"},
                      ["rolled back"], ["add alert"],
                      _disabled(), sess.SessionStore())
    assert "legacy_draft" in str(exc.value) or "evidence_by_id" in str(
        exc.value)


# ---------------------------------------------------------------------------
# Lane 4: agent power L0->L1 (self-initiated READS) + triage verdict
# ---------------------------------------------------------------------------

def _pinned_payload(known, **over):
    base = {"incident_id": "inc-1",
            "hypotheses": [_hyp("deploy v23 regression", 0.9, tuple(known)),
                           _hyp("traffic surge", 0.3, tuple(known))],
            "runbook_id": "bad-deploy-rollback",
            "runbook_version": "1.2.0", "verdict": "PINNED"}
    base.update(over)
    return base


def test_l1_diagnostic_folds_runbook_excerpt():
    tools_mod.clear_providers()
    tools_mod.reset_tool_counts()
    pack = _pack()
    known = [e["evidence_id"] for e in pack["evidence"]][:2]
    store = sess.SessionStore()
    out = A2.run_diagnose("inc-1", "web", "prod", pack,
                          FakeClient(_pinned_payload(known)), store)
    assert out.verdict == "PINNED"
    for h in out.hypotheses:
        assert h.test_tool == "fetch_runbook"
        assert dict(h.test_args) == {"runbook_id": "bad-deploy-rollback"}
        assert "bad-deploy-rollback@1.2.0" in h.test_result
        assert len(h.test_result) <= A2.RUNBOOK_EXCERPT_CHARS
    # Budgets: exactly 1 LLM call (the chat) + 1 tool call (the self-read).
    assert store.get("inc-1", "diagnostic").llm_calls == 1
    assert tools_mod.tool_calls("diagnostic") == 1
    tools_mod.reset_tool_counts()


def test_l1_diagnostic_degrades_without_provider(monkeypatch):
    from agents.schemas import ToolUnavailable  # noqa: E402 (Lane 4 L1)

    def _no_provider(agent, tool, args):
        raise ToolUnavailable(
            f"no provider registered for {tool!r} (not hallucinated)")

    monkeypatch.setattr(tools_mod, "invoke", _no_provider)
    pack = _pack()
    known = [e["evidence_id"] for e in pack["evidence"]][:2]
    out = A2.run_diagnose("inc-1", "web", "prod", pack,
                          FakeClient(_pinned_payload(known)),
                          sess.SessionStore())
    # Degraded but valid: validated model output lands unchanged, untested.
    assert out.verdict == "PINNED" and len(out.hypotheses) == 2
    assert all(h.test_tool == "" and h.test_result == ""
               for h in out.hypotheses)


def test_l1_diagnostic_degrades_on_tool_budget():
    tools_mod.clear_providers()
    tools_mod.reset_tool_counts()
    for _ in range(5):
        tools_mod.invoke("diagnostic", "fetch_runbook",
                         {"runbook_id": "bad-deploy-rollback"})
    pack = _pack()
    known = [e["evidence_id"] for e in pack["evidence"]][:2]
    store = sess.SessionStore()
    out = A2.run_diagnose("inc-1", "web", "prod", pack,
                          FakeClient(_pinned_payload(known)), store)
    # Budget-denied read degrades: diagnosis still lands, chat still counted.
    assert out.verdict == "PINNED"
    assert all(h.test_tool == "" and h.test_result == ""
               for h in out.hypotheses)
    assert store.get("inc-1", "diagnostic").llm_calls == 1
    assert tools_mod.tool_calls("diagnostic") == 5  # denial consumes none
    tools_mod.reset_tool_counts()


def test_l1_diagnostic_preserves_model_tests():
    tools_mod.clear_providers()
    tools_mod.reset_tool_counts()
    pack = _pack()
    known = [e["evidence_id"] for e in pack["evidence"]][:2]
    probed = _hyp("probed cause", 0.6, tuple(known))
    probed.update({"test_tool": "get_logs",
                   "test_args": {"service": "web", "window": "15m",
                                 "limit": 5},
                   "test_result": "saw 5xx in window"})
    payload = _pinned_payload(known, hypotheses=[
        probed, _hyp("traffic surge", 0.3, tuple(known))])
    out = A2.run_diagnose("inc-1", "web", "prod", pack, FakeClient(payload),
                          sess.SessionStore())
    # Model-run test untouched; untested hypothesis enriched.
    assert out.hypotheses[0].test_tool == "get_logs"
    assert out.hypotheses[0].test_result == "saw 5xx in window"
    assert out.hypotheses[1].test_tool == "fetch_runbook"
    assert "bad-deploy-rollback@1.2.0" in out.hypotheses[1].test_result
    tools_mod.reset_tool_counts()


def test_l1_diagnostic_skips_without_pin():
    tools_mod.clear_providers()
    tools_mod.reset_tool_counts()
    fake = FakeClient({"incident_id": "inc-1", "hypotheses": [],
                       "runbook_id": "", "runbook_version": "",
                       "verdict": "INSUFFICIENT_EVIDENCE"})
    out = A2.run_diagnose("inc-1", "web", "prod", _pack(), fake,
                          sess.SessionStore())
    assert out.verdict == "INSUFFICIENT_EVIDENCE"
    assert tools_mod.tool_calls("diagnostic") == 0  # no id: no fetch
    tools_mod.reset_tool_counts()


def test_l1_triage_blocked_no_provider_no_carrier():
    # BLOCKED (reported, not implemented): triage has no pinned runbook_id
    # (it proposes severity/owner, never pins), so fetch_runbook has nothing
    # fitting to fetch; its natural reads have no providers...
    from agents.schemas import ToolUnavailable  # noqa: E402 (Lane 4 L1)
    from agents.schemas import TriageResult  # noqa: E402 (Lane 4 L1)

    tools_mod.clear_providers()
    tools_mod.reset_tool_counts()
    with pytest.raises(ToolUnavailable):
        tools_mod.invoke("triage", "fetch_alerts", {"incident_id": "inc-1"})
    # ...and TriageResult (extra=forbid) offers no honest carrier for a
    # runbook excerpt: signals are observables, evidence_ids are ID links.
    assert set(TriageResult.model_fields) == {
        "incident_id", "severity", "fingerprint", "owner", "signals",
        "evidence_ids", "fallback", "agent", "model_tier"}
    assert TriageResult.model_config.get("extra") == "forbid"
    tools_mod.reset_tool_counts()
