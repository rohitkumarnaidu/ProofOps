"""M14 core: states, transitions, retries, approval branch (host-safe).

Commit A of the M14 lane (M14.1/M14.2/M14.3/M14.7 + BLOCKED terminal):
pure service tests, no HTTP, clock-injected. Timeouts/idempotency/handoffs/
failure branches land in commit B.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.contracts.enums import FSM_STATES, IncidentStatus  # noqa: E402
from app.services import fsm  # noqa: E402 (M14 canonical FSM)
from app.services.fsm import (  # noqa: E402
    FsmError,
    InvalidTransition,
    Permit,
    PermitRejected,
    advance,
    new_run,
)

NOW = 1700000000.0


def _permit(**over):
    base = {"action_id": "a1", "params_hash": "p1",
            "expires_at": NOW + 3600.0, "token_ref": "tok-1"}
    base.update(over)
    return Permit(**base)


def _walk(run, *states, **kw):
    for state in states:
        advance(run, state, now=NOW, **kw)
    return run


# ---------------------------------------------------------------------------
# M14.1 FSM definition
# ---------------------------------------------------------------------------

def test_states_match_frozen_vocabulary_both_directions():
    assert len(fsm.STATES) == 18
    assert set(fsm.STATES) == set(FSM_STATES)
    assert {s.value for s in IncidentStatus} == set(FSM_STATES)


def test_new_run_opens():
    run = new_run("inc-1", now=NOW)
    assert run.state == "NEW" and run.entered_at["NEW"] == NOW
    assert run.history == [] and run.replans == 0


def test_bad_open_rejected():
    with pytest.raises(FsmError):
        new_run("", now=NOW)


# ---------------------------------------------------------------------------
# M14.2 transitions
# ---------------------------------------------------------------------------

def test_happy_walk_to_policy_check():
    run = new_run("inc-1", now=NOW)
    _walk(run, "TRIAGING", "CORRELATED", "INVESTIGATING", "DIAGNOSING",
          "PLANNED", "POLICY_CHECK")
    assert run.state == "POLICY_CHECK"
    assert [r.seq for r in run.history] == [1, 2, 3, 4, 5, 6]


def test_skip_ahead_rejected():
    run = new_run("inc-1", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "EXECUTING", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "RESOLVED", now=NOW)


def test_unknown_state_rejected():
    run = new_run("inc-1", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "FLYING", now=NOW)


def test_history_records_reason_and_refs():
    run = new_run("inc-1", now=NOW)
    advance(run, "TRIAGING", reason="alerts firing", refs=["alert:a1"],
            now=NOW)
    rec = run.history[0]
    assert (rec.frm, rec.to, rec.reason, rec.refs, rec.forced) == \
        ("NEW", "TRIAGING", "alerts firing", ["alert:a1"], False)


def test_blank_refs_rejected():
    run = new_run("inc-1", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "TRIAGING", refs=[""], now=NOW)


# ---------------------------------------------------------------------------
# M14.3 bounded retries
# ---------------------------------------------------------------------------

def _to_planned():
    run = new_run("inc-1", now=NOW)
    _walk(run, "TRIAGING", "CORRELATED", "INVESTIGATING", "DIAGNOSING",
          "PLANNED")
    return run


def test_two_replans_ok_third_rejected():
    run = _to_planned()
    advance(run, "DIAGNOSING", now=NOW)
    advance(run, "PLANNED", now=NOW)
    advance(run, "DIAGNOSING", now=NOW)
    assert run.replans == 2
    advance(run, "PLANNED", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "DIAGNOSING", now=NOW)


# ---------------------------------------------------------------------------
# M14.7 approval branch (no-skip)
# ---------------------------------------------------------------------------

def test_no_skip_policy_check_to_executing():
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "EXECUTING", now=NOW)


def test_executing_without_permit_rejected():
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    advance(run, "APPROVED", permit=_permit(), now=NOW)
    run.permit = None  # simulate lost credential (must not execute)
    with pytest.raises(PermitRejected):
        advance(run, "EXECUTING", now=NOW)


def test_permit_flow_green_auto_to_verifying():
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    advance(run, "APPROVED", permit=_permit(auto=True), now=NOW)
    assert advance(run, "EXECUTING", now=NOW) == "EXECUTING"
    assert run.permit is None  # consumed (single-use)
    assert advance(run, "VERIFYING", now=NOW) == "VERIFYING"


def test_hitl_path_awaits_then_approves():
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    advance(run, "AWAITING_APPROVAL", now=NOW)
    assert advance(run, "APPROVED", permit=_permit(token_ref="tok-9"),
                   now=NOW) == "APPROVED"


def test_expired_permit_rejected():
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    with pytest.raises(PermitRejected):
        advance(run, "APPROVED", permit=_permit(expires_at=NOW - 1), now=NOW)


def test_replayed_token_ref_rejected():
    run = _to_planned()
    run.consumed_refs.add("tok-1")
    advance(run, "POLICY_CHECK", now=NOW)
    with pytest.raises(PermitRejected):
        advance(run, "APPROVED", permit=_permit(token_ref="tok-1"), now=NOW)


def test_permit_on_wrong_edge_rejected():
    run = new_run("inc-1", now=NOW)
    with pytest.raises(PermitRejected):
        advance(run, "TRIAGING", permit=_permit(), now=NOW)


def test_permit_shape_validated():
    with pytest.raises(PermitRejected):
        Permit(action_id="", params_hash="p", expires_at=NOW + 1,
               token_ref="t")


# ---------------------------------------------------------------------------
# M14.8 failure branch: BLOCKED (terminal, reasoned)
# ---------------------------------------------------------------------------

def test_blocked_needs_reason_and_is_terminal():
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "BLOCKED", now=NOW)
    advance(run, "BLOCKED", reason="RED delete_namespace proposed", now=NOW)
    assert run.state == "BLOCKED"
    with pytest.raises(InvalidTransition):
        advance(run, "ESCALATED", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "TRIAGING", now=NOW)
