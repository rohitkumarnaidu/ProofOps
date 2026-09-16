"""M14 branches: timeouts, idempotency, handoffs, failure paths (host-safe).

Commit B service half (M14.4/M14.5/M14.6/M14.8): clock-injected, no HTTP.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services import fsm  # noqa: E402 (M14 canonical FSM)
from app.services.fsm import (  # noqa: E402
    FsmError,
    InvalidTransition,
    advance,
    execute_once,
    handoff,
    new_run,
    sweep,
)

NOW = 1700000000.0


def _permit(**over):
    base = {"action_id": "a1", "params_hash": "p1",
            "expires_at": NOW + 3600.0, "token_ref": "tok-1"}
    base.update(over)
    return fsm.Permit(**base)


def _to_planned():
    run = new_run("inc-1", now=NOW)
    for state in ("TRIAGING", "CORRELATED", "INVESTIGATING", "DIAGNOSING",
                  "PLANNED"):
        advance(run, state, now=NOW)
    return run


def _to_verifying(auto=True):
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    advance(run, "APPROVED", permit=_permit(auto=auto), now=NOW)
    advance(run, "EXECUTING", now=NOW)
    advance(run, "VERIFYING", now=NOW)
    return run


# ---------------------------------------------------------------------------
# M14.4 timeouts (clock-injected sweep)
# ---------------------------------------------------------------------------

def test_stage_timeout_escalates():
    run = new_run("inc-1", now=NOW)
    advance(run, "TRIAGING", now=NOW)
    assert sweep(run, NOW + 30.0) is False
    assert sweep(run, NOW + 61.0) is True
    assert run.state == "ESCALATED"
    forced = run.history[-1]
    assert forced.forced is True and forced.reason == "ttl-expired:TRIAGING"


def test_approval_timeout_default_and_demo():
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    advance(run, "AWAITING_APPROVAL", now=NOW)
    assert sweep(run, NOW + 599.0) is False
    assert sweep(run, NOW + 601.0) is True
    run2 = _to_planned()
    advance(run2, "POLICY_CHECK", now=NOW)
    advance(run2, "AWAITING_APPROVAL", now=NOW)
    assert sweep(run2, NOW + 601.0,
                 approval_ttl=fsm.DEMO_APPROVAL_TTL_S) is False
    assert sweep(run2, NOW + 901.0,
                 approval_ttl=fsm.DEMO_APPROVAL_TTL_S) is True


def test_terminals_and_untimed_exempt():
    run = _to_planned()
    advance(run, "POLICY_CHECK", now=NOW)
    advance(run, "BLOCKED", reason="deny", now=NOW)
    assert sweep(run, NOW + 10**6) is False
    run2 = _to_verifying()
    assert sweep(run2, NOW + 10**6) is False  # exec/verify TTLs are M08/M09


def test_bad_ttl_rejected():
    run = new_run("inc-1", now=NOW)
    advance(run, "TRIAGING", now=NOW)
    with pytest.raises(FsmError):
        sweep(run, NOW + 100.0, stage_ttl=0.0)


# ---------------------------------------------------------------------------
# M14.5 idempotency
# ---------------------------------------------------------------------------

def test_duplicate_returns_cached_fn_runs_once():
    run = new_run("inc-1", now=NOW)
    calls: list[str] = []
    first, dup1 = execute_once(run, "a1", "e1", calls.append, "x")
    second, dup2 = execute_once(run, "a1", "e1", calls.append, "x")
    assert (dup1, dup2) == (False, True)
    assert first == second is None and calls == ["x"]
    assert run.suppressions == [{"action_id": "a1", "execution_id": "e1"}]


def test_distinct_keys_independent():
    run = new_run("inc-1", now=NOW)
    execute_once(run, "a1", "e1", lambda: 1)
    value, dup = execute_once(run, "a1", "e2", lambda: 2)
    assert (value, dup) == (2, False)


def test_blank_keys_rejected():
    run = new_run("inc-1", now=NOW)
    with pytest.raises(FsmError):
        execute_once(run, "", "e1", lambda: 1)
    with pytest.raises(FsmError):
        execute_once(run, "a1", "  ", lambda: 1)


# ---------------------------------------------------------------------------
# M14.6 agent handoffs
# ---------------------------------------------------------------------------

def test_valid_handoffs():
    run = new_run("inc-1", now=NOW)
    rec = handoff(run, "triage", "diagnostic", ["sig:web:http_5xx"])
    assert rec["to"] == "diagnostic" and len(run.handoffs) == 1
    handoff(run, "diagnostic", "planner", ["diag:inc-1"])


def test_reporter_intake_is_case_file_not_handoff():
    run = new_run("inc-1", now=NOW)
    with pytest.raises(FsmError):
        handoff(run, "planner", "reporter", ["plan:a1"])


def test_handoff_validation():
    run = new_run("inc-1", now=NOW)
    with pytest.raises(FsmError):
        handoff(run, "manager", "diagnostic", ["x"])
    with pytest.raises(FsmError):
        handoff(run, "triage", "diagnostic", [])
    with pytest.raises(FsmError):
        handoff(run, "triage", "diagnostic", [" "])


# ---------------------------------------------------------------------------
# M14.8 failure branches (rollback-once, escalate, RCA, audit)
# ---------------------------------------------------------------------------

def test_rollback_once_then_resolved():
    run = _to_verifying()
    advance(run, "ROLLBACK", reason="error_rate still high", now=NOW)
    assert run.rolled_back is True
    advance(run, "VERIFYING", now=NOW)
    assert advance(run, "RESOLVED", now=NOW) == "RESOLVED"


def test_second_rollback_rejected_escalate_instead():
    run = _to_verifying()
    advance(run, "ROLLBACK", reason="first failure", now=NOW)
    advance(run, "VERIFYING", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "ROLLBACK", reason="second failure", now=NOW)
    assert advance(run, "ESCALATED", reason="rollback failed", now=NOW) \
        == "ESCALATED"


def test_escalated_continues_to_rca():
    run = _to_verifying()
    advance(run, "ESCALATED", reason="worsened", now=NOW)
    assert advance(run, "RCA_PENDING", now=NOW) == "RCA_PENDING"


def test_rca_and_audit_need_refs_and_are_terminal():
    run = _to_verifying()
    advance(run, "RESOLVED", now=NOW)
    advance(run, "RCA_PENDING", now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "RCA_PUBLISHED", now=NOW)
    advance(run, "RCA_PUBLISHED", refs=["rca:inc-1"], now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "AUDITED", now=NOW)
    advance(run, "AUDITED", refs=["audit:inc-1"], now=NOW)
    with pytest.raises(InvalidTransition):
        advance(run, "NEW", now=NOW)


def test_audit_records_shape():
    run = new_run("inc-1", now=NOW)
    advance(run, "TRIAGING", reason="go", refs=["alert:a1"], now=NOW)
    handoff(run, "triage", "diagnostic", ["sig:x"])
    execute_once(run, "a1", "e1", lambda: 1)
    execute_once(run, "a1", "e1", lambda: 2)
    kinds = [r["type"] for r in fsm.audit_records(run)]
    assert kinds == ["transition", "handoff", "duplicate-suppressed"]
    assert fsm.audit_records(run)[0]["forced"] is False
