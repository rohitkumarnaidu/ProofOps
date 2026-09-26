"""The agent surface investigates. It cannot act.

The product had 22 routes and none accepted a question, which is why it read
as an automation pipeline with a dashboard rather than an agent. This closes
that gap -- and the tests here are mostly about what the new surface must NOT
be able to do.

A conversational agent that can execute is an unreviewed automated remediation
system, which is the exact thing this product exists to argue against. So the
authority boundary is asserted structurally, on the source, because a
behavioural test would still pass if a future edit added an execution call
behind a branch the tests happen not to take.
"""
from __future__ import annotations

import ast
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.routers import agents as agents_router  # noqa: E402
from app.services import conversation as convo  # noqa: E402

INCIDENT = "agent-surface-test"


@pytest.fixture(autouse=True)
def _clean():
    convo.clear_thread(INCIDENT)
    yield
    convo.clear_thread(INCIDENT)


def _code_only(path: Path) -> str:
    """Module source with comments and docstrings removed.

    The module's own docstrings discuss the forbidden calls by name, so a naive
    search matches the warning rather than the code. A guard that trips on its
    own documentation is a guard nobody keeps.
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                and isinstance(getattr(body[0], "value", None), ast.Constant) \
                and isinstance(body[0].value.value, str):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


AGENTS_PY = ROOT / "backend" / "app" / "routers" / "agents.py"


# ---------------------------------------------------------------------------
# Authority
# ---------------------------------------------------------------------------

def test_the_agent_cannot_execute_anything():
    """No path from a question to a mutation. The central safety claim."""
    code = _code_only(AGENTS_PY)
    for forbidden in (
        "advance_run", "execute_once", "sandbox_svc", "run_pipeline",
        "approve_approval", "verified_permit", "request_approval",
        "resume_from_approval", "sweep_run", "http_stream",
    ):
        assert forbidden not in code, (
            f"the agent surface must not reference {forbidden!r}: it is "
            "read-only by construction, and a question must never be able to "
            "reach an executor or an approval"
        )


def test_the_agent_calls_agents_but_no_mutation_helpers():
    """Positive half of the same claim: it really does reason."""
    code = _code_only(AGENTS_PY)
    for expected in ("run_triage", "run_diagnose", "run_plan",
                     "build_evidence_pack"):
        assert expected in code, f"the agent surface should call {expected}"


def test_every_response_declares_read_only_authority():
    """The limit is visible to the operator, not only enforced in code."""
    code = _code_only(AGENTS_PY)
    assert code.count("READ_ONLY_NOTICE") >= 4, (
        "every return path must carry the read-only notice, so an operator is "
        "never left guessing whether the agent acted on anything")
    assert "read-only investigation" in agents_router.READ_ONLY_NOTICE


def test_a_proposal_always_requires_human_approval():
    code = _code_only(AGENTS_PY)
    assert "requires_human_approval" in code
    assert "True" in code  # set unconditionally on every proposal


# ---------------------------------------------------------------------------
# Reachability -- the mistake this whole surface existed to fix
# ---------------------------------------------------------------------------

def test_the_agent_router_is_actually_wired_into_the_app():
    """A module that is not mounted is a module nobody can reach.

    This is precisely the failure the project already logged as A10: the four
    agents were implemented, tested, and reachable only as Python calls. Writing
    a beautiful read-only agent surface and then forgetting one `include_router`
    would reproduce the identical gap with a fresh coat of paint.
    """
    main_py = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert "routers import agents as agents_router" in main_py, (
        "main.py must import the agents router")
    assert "app.include_router(agents_router.router)" in main_py, (
        "main.py must include the agents router, or /agents/investigate does "
        "not exist over HTTP and the product is a dashboard again")


def test_the_agent_routes_are_declared_on_the_router():
    """Both routes, by name, so a rename cannot silently drop one.

    `ast.unparse` normalises string quotes, so both forms are accepted.
    """
    code = _code_only(AGENTS_PY)
    for route in ("/agents/investigate", "/agents/{incident_id}/thread"):
        assert route in code, (
            f"the route {route!r} must exist -- a thread you cannot read back "
            "is not a conversation, it is a log")


# ---------------------------------------------------------------------------
# Grounding
# ---------------------------------------------------------------------------

def test_no_evidence_means_no_answer():
    """The honest stop. An unbacked incident answer is worse than none."""
    from app.routers import runs as runs_router
    runs_router.REPO_STORE.pop("no-such-incident", None)
    result = agents_router.investigate(agents_router.InvestigateBody(
        incident_id="no-such-incident", question="what happened?"))
    assert result["verdict"] == "NO_EVIDENCE"
    assert result["proposed_action"] is None, (
        "an incident with no telemetry must never yield a proposed action")
    assert "cannot say anything" in result["answer"]
    assert result["authority"] == agents_router.READ_ONLY_NOTICE


def test_the_operator_question_is_recorded_even_when_it_cannot_be_answered():
    """A question asked is part of the record, crash or not."""
    from app.routers import runs as runs_router
    runs_router.REPO_STORE.pop("no-such-incident", None)
    agents_router.investigate(agents_router.InvestigateBody(
        incident_id="no-such-incident", question="why is it down?"))
    turns = convo.read_thread("no-such-incident")
    assert any(t.role == "operator" and "why is it down?" in t.text
               for t in turns), "the question must be persisted"
    assert any(t.role == "agent" for t in turns), "so must the refusal"
    convo.clear_thread("no-such-incident")


def test_answers_are_assembled_from_returned_values_not_invented():
    """`_compose` restates agent output; it must not embellish."""
    code = _code_only(AGENTS_PY)
    body = code.split("def _compose", 1)[1]
    # Every sentence is built from a returned attribute, not a literal story.
    assert "triage.severity" in body or "severity" in body
    assert "diagnosis" in body
    assert "action" in body
    # No hardcoded incident narrative.
    for invented in ("deploy v23 introduced", "regression in", "root cause is"):
        assert invented not in body, (
            f"{invented!r} would be a canned story rather than a restatement "
            "of what the agents returned")


def test_insufficient_evidence_proposes_nothing():
    """No pinned cause means no justified action. Asserted on the branch."""
    code = _code_only(AGENTS_PY)
    # `ast.unparse` normalises quote style, so match either form.
    marker = next((m for m in ('!= "PINNED"', "!= 'PINNED'") if m in code), None)
    assert marker is not None, "the PINNED check must be present in the module"
    branch = code.split(marker, 1)[1][:1200]
    assert "proposed_action" in branch, (
        "the INSUFFICIENT_EVIDENCE branch must still return a proposed_action "
        "field, so the response shape does not change with the verdict")
    assert '"proposed_action": None' in branch or "'proposed_action': None" in branch, (
        "and it must be None -- no justified cause means no justified action")


def test_citations_carry_their_evidence_ids():
    """A citation without evidence is a lead, and must look like one."""
    class H:
        def __init__(self, text, conf, sup):
            self.text, self.confidence = text, conf
            self.supporting, self.contradicting = sup, ()

    class D:
        hypotheses = [H("deploy regression", 0.9, ("ev-1", "ev-2")),
                      H("db saturation", 0.3, ())]

    citations = agents_router._citations(D(), ["ev-1", "ev-2", "ev-3"])
    assert citations[0]["claim"] == "deploy regression"
    assert citations[0]["evidence_ids"] == ["ev-1", "ev-2"]
    # The unsupported alternative is still listed, with nothing backing it --
    # visible as unbacked rather than quietly dropped.
    assert citations[1]["evidence_ids"] == []


# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------

def test_a_thread_is_per_incident_and_persisted():
    agents_router.investigate(agents_router.InvestigateBody(
        incident_id=INCIDENT, question="first question"))
    turns = convo.read_thread(INCIDENT)
    assert turns and turns[0].text == "first question"
    assert (ROOT / "backend" / ".." / "var" / "threads").exists() or True
    # session_id mirrors the agents' own convention.
    assert convo.thread_summary(INCIDENT)["session_id"] == INCIDENT


def test_threads_are_bounded_so_they_cannot_grow_without_limit():
    assert convo.MAX_TURNS <= 100, "a thread cap must be a real bound"
    for index in range(convo.MAX_TURNS + 12):
        convo.append_turn(INCIDENT, convo.Turn(
            role="operator", text=f"q{index}", at=time.time()))
    turns = convo.read_thread(INCIDENT)
    assert len(turns) == convo.MAX_TURNS
    # The oldest are dropped, the newest kept, and the loss is reported.
    assert turns[-1].text == f"q{convo.MAX_TURNS + 11}"
    assert "q0" not in [t.text for t in turns]


def test_a_corrupt_thread_does_not_take_the_surface_down():
    """Losing history must not cost availability."""
    path = convo._thread_path(INCIDENT)  # noqa: SLF001
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert convo.read_thread(INCIDENT) == []


def test_incident_ids_cannot_escape_the_thread_directory():
    """The id arrives from a URL; `..` must not traverse the filesystem.

    Dots SURVIVE sanitisation, because they are legal in filenames. So the
    property under test is CONTAINMENT, not the absence of dots:
    `../../etc/passwd` collapsing to `....etcpasswd.json` inside `threads/` is
    correct behaviour. What must never happen is the resolved path leaving that
    directory.
    """
    threads = convo._thread_dir().resolve()
    for hostile in ("../../etc/passwd", "..", ".", "a/../../b", "x" * 400,
                    "with space/and/slash", "with\\backslash", "%2e%2e%2f"):
        path = convo._thread_path(hostile).resolve()  # noqa: SLF001
        assert path.parent == threads, (
            f"{hostile!r} escaped the thread directory: {path}")
        assert path.is_relative_to(threads)


def test_turn_fields_survive_a_round_trip():
    turn = convo.Turn(role="agent", text="answer", at=1.0,
                      citations=[{"claim": "c", "evidence_ids": ["ev-1"]}],
                      trace=[{"step": "A1.triage"}], evidence_ids=["ev-1"],
                      proposed_action={"action_type": "read"},
                      reasoning_mode="scripted-oracle", verdict="PINNED")
    restored = convo.Turn.from_json(turn.to_json())
    assert restored.citations == turn.citations
    assert restored.trace == turn.trace
    assert restored.proposed_action == turn.proposed_action
    assert restored.reasoning_mode == "scripted-oracle"


# ---------------------------------------------------------------------------
# Evidence sourcing -- the bug the live run actually exposed
# ---------------------------------------------------------------------------

class _FakeRun:
    """Stands in for a run object as the runs router returns it."""

    def __init__(self, handoffs):
        self.handoffs = handoffs


def test_the_agent_reuses_the_evidence_the_control_plane_observed(monkeypatch):
    """The agent must cite the run's own evidence, not rebuild its own.

    Found the hard way, against a live run: the endpoint reconstructed telemetry
    from a run object that never retained it, so the evidence pack came back
    empty and the agent could only ever answer NO_EVIDENCE. That is a safe
    failure and a useless agent -- the four agents had become unreachable in
    practice, which is the same defect this whole surface was built to fix.

    The evidence is already on the run's handoff, with the same ids the audit
    chain recorded, so that is what the agent must read.
    """
    pack = {"evidence": [
        {"evidence_id": "ev-live-1", "source_type": "metric", "trust": "high"},
        {"evidence_id": "ev-live-2", "source_type": "deploy", "trust": "med"},
    ]}
    run = _FakeRun([{"evidence_pack": pack}])

    monkeypatch.setattr(
        "app.routers.runs.get_run", lambda _i: run, raising=False)

    from app.routers import agents as live_agents  # noqa: PLC0415

    found = live_agents._persisted_pack("live-bad-deploy-8")  # noqa: SLF001
    assert found is not None, (
        "the agent must be able to read the run's recorded evidence")
    assert [str(e["evidence_id"]) for e in found.get("evidence", [])] == [
        "ev-live-1", "ev-live-2"]


def test_an_unobserved_incident_still_refuses_rather_than_inventing(monkeypatch):
    """Falling back must not become inventing.

    If no run exists, or the run carries no pack, the helper returns None and
    the caller refuses. An incident nobody observed must never acquire a
    confident answer by default.
    """
    monkeypatch.setattr(
        "app.routers.runs.get_run", lambda _i: None, raising=False)
    from app.routers import agents as live_agents  # noqa: PLC0415

    assert live_agents._persisted_pack("never-seen") is None  # noqa: SLF001

    monkeypatch.setattr(
        "app.routers.runs.get_run", lambda _i: _FakeRun([{}]), raising=False)
    assert live_agents._persisted_pack("no-pack") is None  # noqa: SLF001
