"""Zero-trust tests for the agent surface's frontend.

Every assertion here exists to stop a specific, already-observed failure from
coming back. The product shipped a fully implemented, fully tested set of four
agents that no operator could reach; the frontend half of that gap is that a
view gets built, looks convincing, and quietly offers a button that executes
something. These tests fail if that regresses.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VIEW = ROOT / "frontend" / "src" / "views" / "AgentsView.tsx"
API = ROOT / "frontend" / "src" / "api.ts"
APP = ROOT / "frontend" / "src" / "App.tsx"


def _code(path: Path) -> str:
    """Source with comments and doc comments stripped.

    Comment text is not behaviour. Asserting on prose in a comment is how a test
    suite starts passing while the code does nothing -- so the prose is removed
    and only the executable surface remains.
    """
    src = path.read_text(encoding="utf-8")
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


# ---------------------------------------------------------------------------
# Authority -- the property that must not be negotiable
# ---------------------------------------------------------------------------

#: Every API namespace the client exposes. A view may touch the one that owns
#: its job; reaching for any other is how a read-only screen grows a side effect.
_ALL_NAMESPACES = (
    "metaApi",
    "authApi",
    "identityApi",
    "runsApi",
    "approvalsApi",
    "auditApi",
    "evalApi",
    "orchestratorApi",
    "agentsApi",
)


def test_the_agent_view_offers_no_mutation_control():
    """The agent screen must not be able to act.

    This is the whole point of the surface: an operator may investigate and may
    see what the agent would do, but every route to real authority stays on the
    Safety Gate, where a human approves deliberately.

    Asserting on the *absence of another API namespace* rather than on English
    words matters here. An earlier version of this test banned the substring
    "execute" and immediately failed on the view's own copy -- "cannot approve
    or execute anything" -- which is exactly the copy the rule wants. Behaviour
    is pinned by the calls a view can make, not by the prose around them.
    """
    code = _code(VIEW)
    for namespace in _ALL_NAMESPACES:
        if namespace == "agentsApi":
            continue
        assert f"{namespace}." not in code, (
            f"the read-only agent view must not call {namespace} -- acting "
            "belongs on the Safety Gate, not in a conversation")


def test_the_view_cannot_reach_a_raw_mutating_verb():
    """No hand-rolled fetch with a mutating verb, bypassing the typed client."""
    code = _code(VIEW)
    for verb in ('method: "PUT"', 'method: "DELETE"', 'method: "PATCH"'):
        assert verb not in code, (
            f"{verb} in the agent view would be an ungoverned mutation")


def test_the_api_client_only_ever_reads_or_asks():
    """The agent client cannot smuggle a mutation in through the api module."""
    code = _code(API)
    agent_block = code.split("export const agentsApi")[-1]
    assert "method: \"POST\"" in agent_block, "asking a question is a POST"
    # One POST (the question). Nothing else may mutate.
    assert agent_block.count("method:") == 1, (
        "agentsApi may only POST the question; any other verb would be a "
        "mutation smuggled in behind a read-only surface")


# ---------------------------------------------------------------------------
# Truthfulness -- the answer is not the proof
# ---------------------------------------------------------------------------

def test_the_reasoning_mode_is_always_visible():
    """`scripted-oracle` must be on screen.

    The default reasoning path is a scripted oracle, not a live model. If that
    badge is ever dropped, the demo starts implying live model reasoning that is
    not happening -- which is the single most dishonest thing this product could
    do to a judge.
    """
    code = _code(VIEW)
    assert "reasoning_mode" in code, "the reasoning mode must be rendered"


def test_a_proposal_is_always_labelled_as_requiring_approval():
    """A proposal must never be presented as something that happened."""
    code = _code(VIEW)
    assert "proposed_action" in code
    assert "requires_human_approval" in code
    assert "Nothing has been executed" in code, (
        "the proposal card must state plainly that nothing ran")


def test_evidence_ids_are_surfaced_and_absence_is_called_out():
    """Evidence is the proof, so its absence must be visible too.

    A turn with no evidence is the dangerous case: it looks like an answer. So
    the view must render the ids when they exist and say so plainly when they do
    not, rather than rendering nothing either way.
    """
    code = _code(VIEW)
    assert "evidence_ids" in code
    assert "No evidence ids support this turn" in code, (
        "an unevidenced turn must be labelled, not silently rendered")


def test_a_refusal_is_rendered_as_a_refusal():
    """NO_EVIDENCE must read as a refusal, not as a failure to load.

    Refusing without evidence is the correct behaviour of a grounded agent. The
    UI must not dress it up as an error, or every honest refusal will read as a
    broken product and get 'fixed' by removing the grounding.
    """
    code = _code(VIEW)
    assert "NO_EVIDENCE" in code
    assert "declined to answer" in code


# ---------------------------------------------------------------------------
# Reachability -- the gap that started all of this
# ---------------------------------------------------------------------------

def test_the_agent_view_is_routed():
    code = _code(APP)
    assert 'from "./views/AgentsView"' in code, "the view must be imported"
    assert 'path="/agents"' in code, (
        "the agent view must be routed, or it is another unreachable module")


def test_the_api_bindings_match_the_backend_contract():
    """Client and server must agree on the two routes and their shapes."""
    code = _code(API)
    assert '"/agents/investigate"' in code
    assert "/agents/${encodeURIComponent(incidentId)}/thread" in code
    assert "incident_id" in code and "question" in code


def test_the_backend_actually_serves_those_routes():
    """Server-side half of the contract.

    The client cannot be right about a route the server does not mount, and the
    original failure was precisely a correct module that was never wired.
    """
    main_py = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert "app.include_router(agents_router.router)" in main_py


@pytest.mark.parametrize(
    "name",
    ["AgentsView.tsx"],
)
def test_the_view_uses_the_shared_primitives(name):
    """New UI goes through the design system, not ad-hoc markup.

    The cockpit was unified onto semantic primitives so contrast, focus rings and
    spacing are decided once. A view that hand-rolls its own buttons and cards
    quietly reintroduces every problem that consolidation removed.
    """
    code = _code(ROOT / "frontend" / "src" / "views" / name)
    for primitive in ("Panel", "StatusPill", "ErrorState", "EmptyState"):
        assert primitive in code, f"{name} must use the shared {primitive}"
