"""An approved action executes. It is never re-planned.

The gap this closes
-------------------
The worker drove incidents to AWAITING_APPROVAL and stopped. A human approved
in the Safety Gate, and nothing happened: the run sat there forever. The
product's most important control was a dead end, which is exactly why it read
as a mock.

The tempting fix, and why it is wrong
-------------------------------------
Re-running `run_pipeline` with the approval supplied. `run_pipeline` starts at
NEW and re-runs A3, so the action it produces on the second pass need not be
the action a human reviewed. An approval is bound to one `action_id` and one
exact parameter hash; re-planning silently swaps what was authorized for
something else. Every log line would still look correct, and the HITL guarantee
would be gone.

So `resume_from_approval` is a separate entry point that takes the action as a
parameter and structurally cannot author one. These tests pin that, plus the
execution, verification and rollback behaviour that follows.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.contracts.action import Action  # noqa: E402
from app.routers import audit as audit_router  # noqa: E402
from app.routers import runs as runs_router  # noqa: E402
from app.services import fsm as fsm_svc  # noqa: E402
from app.services import orchestrator as orch_mod  # noqa: E402
from app.services import pipeline as pipeline_mod  # noqa: E402

INCIDENT = "resume-test"


@pytest.fixture(autouse=True)
def _clean():
    for store in (runs_router.REPO_STORE, audit_router.CHAINS):
        for key in list(store):
            if key.startswith(INCIDENT):
                store.pop(key, None)
    yield
    for store in (runs_router.REPO_STORE, audit_router.CHAINS):
        for key in list(store):
            if key.startswith(INCIDENT):
                store.pop(key, None)


def _bundle(seed: int = 7) -> dict:
    sys.path.insert(0, str(ROOT / "telemetry"))
    import gen as telemetry_gen  # type: ignore[import-not-found]
    return telemetry_gen.generate("bad-deploy", "NORMAL", seed)


def _full_action(incident: str, plan: dict, resource: dict) -> Action:
    """Complete an oracle plan into a real Action.

    `oracle_payloads` returns what the *pin* chooses (action type, parameters,
    risk, verification plan). A3 fills in the rest -- incident, agent,
    resource, runbook pin, evidence -- when it runs. Resume takes an already
    complete Action, so the test has to build the same object the planner
    would have produced.
    """
    from app.services import orchestrator as orch
    pin = orch.ORACLE["bad-deploy"]
    payload = dict(plan)
    payload.update({
        "incident_id": incident,
        "agent_id": "A3-planner",
        "resource_type": resource.get("type", "deployment"),
        "resource_id": str(resource.get("id", "checkout-api")),
        "environment": str(resource.get("environment", "mock")),
        "evidence_ids": ["ev-resume-test-1"],
        "runbook_id": pin["runbook_id"],
        "runbook_version": pin["runbook_version"],
    })
    return Action.model_validate(payload)


def _stalled_run():
    """Drive a real incident to AWAITING_APPROVAL and return (worker, run, action)."""
    worker = orch_mod.Orchestrator(auto_generate=False)
    worker.submit(INCIDENT, "bad-deploy", _bundle(), source="test")
    worker._process_sync(worker._queue.get_nowait())
    run = runs_router.REPO_STORE[INCIDENT]
    assert run.state == "AWAITING_APPROVAL"
    _, _, plan, extra = orch_mod.oracle_payloads("bad-deploy", _bundle(), INCIDENT)
    return worker, run, _full_action(INCIDENT, plan, extra["resource"]), extra


def _permit(action: Action):
    """Mint a permit the way the approvals service really mints one.

    Uses the real `approval.issue` so the params hash and scope are the genuine
    ones. A hand-rolled permit in a test would pass while the production
    binding was broken, which is precisely the class of bug these tests exist
    to catch.
    """
    from app.config import get_settings
    from app.services import approval as approval_svc
    secret = str(get_settings().APPROVAL_SECRET)
    request, token = approval_svc.issue(action, "approver-1", secret)
    return fsm_svc.Permit(
        action_id=action.action_id,
        params_hash=request.params_hash,
        expires_at=request.expires_at.timestamp(),
        token_ref=token,
        auto=False,
    )


def _code_only(func) -> str:
    """Executable source with docstrings and comments removed.

    Necessary because these docstrings *explain* the exact calls that must not
    appear, so a naive search matches the warning instead of the code. A guard
    that trips on its own documentation is a guard nobody keeps.
    """
    import ast
    import textwrap
    source = textwrap.dedent(inspect.getsource(func))
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Module)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    lines = source.splitlines(keepends=True)
    kept = [line for line in lines if not line.lstrip().startswith("#")]
    stripped = "".join(kept)
    tree = ast.parse(stripped)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Module)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


# ---------------------------------------------------------------------------
# The structural guarantee
# ---------------------------------------------------------------------------

def test_resume_cannot_author_an_action():
    """It must take the action, never build one. Asserted on the signature.

    If a future edit adds an A3/planner call inside this function, the product
    would execute something no human approved -- and the signature is the only
    place that fact is visible.
    """
    signature = inspect.signature(pipeline_mod.resume_from_approval)
    params = set(signature.parameters)
    assert "action" in params, "the approved action must be an explicit input"
    assert "permit" in params, "an APPROVED edge requires a human permit"
    # Nothing that could re-plan.
    for forbidden in ("client", "clients", "diagnosis", "alerts", "triage"):
        assert forbidden not in params, (
            f"resume must not accept {forbidden!r}; anything that could re-plan "
            "belongs in the first pass, not after a human approved an action"
        )


def test_resume_never_calls_the_planner_or_the_pipeline():
    source = _code_only(pipeline_mod.resume_from_approval)
    for forbidden in ("run_pipeline", "A3.", "run_plan", "triage_mod",
                      "run_triage", "run_diagnose"):
        assert forbidden not in source, (
            f"resume_from_approval must not reference {forbidden!r}: the action "
            "under execution is the approved one, not a fresh plan"
        )


def test_resume_revalidates_the_approved_action():
    """An approval is not a waiver. Invalid or DENY'd actions still fail closed."""
    source = _code_only(pipeline_mod.resume_from_approval)
    assert "validate_action" in source, (
        "the approved action must be re-validated before it can execute")
    assert "policy_svc.evaluate" in source, (
        "the approved action must be re-checked against policy before execution")


# ---------------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------------

def test_approved_action_executes_verifies_and_resolves():
    """The whole point: approve -> execute -> verify -> resolved."""
    worker, run, action, extra = _stalled_run()
    chain = audit_router.get_or_create_chain(INCIDENT)

    report = pipeline_mod.resume_from_approval(
        INCIDENT, run, action, _permit(action),
        tele_public=_bundle(), resource=extra["resource"],
        severity=orch_mod._severity_for("bad-deploy", _bundle()),
        chain=chain)

    assert report["resumed"] is True
    states = [r.to for r in run.history]
    for expected in ("APPROVED", "EXECUTING", "VERIFYING"):
        assert expected in states, f"missing {expected} in {states}"
    assert run.state in ("RESOLVED", "ESCALATED"), f"ended in {run.state}"
    assert report["verdict"] in ("RESOLVED", "PARTIAL", "FAILED", "WORSENED",
                                 "ROLLBACK_REQUIRED", "ESCALATED")
    # The action executed is the action approved.
    assert report["action_id"] == action.action_id
    assert report["action_type"] == action.action_type


def test_the_executed_action_id_appears_in_the_audit_chain():
    chain = audit_router.get_or_create_chain(INCIDENT)
    _, run, action, extra = _stalled_run()
    pipeline_mod.resume_from_approval(
        INCIDENT, run, action, _permit(action),
        tele_public=_bundle(), resource=extra["resource"],
        severity=orch_mod._severity_for("bad-deploy", _bundle()),
        chain=chain)
    action_ids = {e.action_id for e in chain.events if e.action_id}
    assert action.action_id in action_ids, (
        "the chain must name the action that actually executed")
    assert chain.verify()["valid"] is True, "the chain must still verify"


def test_a_second_resume_does_not_execute_twice():
    """Exactly-once execution. A duplicate must be suppressed, not repeated.

    `execute_once` is the guard; this proves it survives a real double call,
    because a double execution would double-apply the remediation.
    """
    worker, run, action, extra = _stalled_run()
    chain = audit_router.get_or_create_chain(INCIDENT)
    kwargs = dict(tele_public=_bundle(), resource=extra["resource"],
                  severity=orch_mod._severity_for("bad-deploy", _bundle()),
                  chain=chain)
    first = pipeline_mod.resume_from_approval(INCIDENT, run, action,
                                              _permit(action), **kwargs)
    executions_before = len([e for e in chain.events
                             if e.event_type == "verification.verdict"])
    with pytest.raises(Exception):
        # A second APPROVED edge is illegal: the run is no longer at
        # AWAITING_APPROVAL, so the FSM must refuse it.
        pipeline_mod.resume_from_approval(INCIDENT, run, action,
                                          _permit(action), **kwargs)
    executions_after = len([e for e in chain.events
                            if e.event_type == "verification.verdict"])
    assert executions_after == executions_before, (
        "a repeated resume must not execute the action again")
    assert first["verdict"]


def test_resume_without_context_or_run_fails_closed():
    """Missing prerequisites must refuse, not invent.

    Either guard is correct: no captured context, or no run to advance. Both
    must fail closed and be reported, never papered over by re-planning.
    """
    worker = orch_mod.Orchestrator(auto_generate=False)
    _, _, plan, extra = orch_mod.oracle_payloads("bad-deploy", _bundle(), INCIDENT)
    action = _full_action(INCIDENT, plan, extra["resource"])

    # Nothing was ever submitted for this incident, so there is neither context
    # nor a run. The worker must refuse rather than start a fresh pipeline.
    worker.resume("no-such-incident", action, _permit(action))
    job = worker._resume_queue.get_nowait()
    worker._resume_sync(job)
    assert worker.stats.resume_failures == 1
    assert "resume failed" in worker.stats.last_outcome
    assert worker.stats.resumed == 0, "nothing may report a successful resume"


def test_resume_is_claimed_exactly_once():
    """Two approvals racing must not queue two resumes for one incident."""
    worker = orch_mod.Orchestrator(auto_generate=False)
    _, _, plan, extra2 = orch_mod.oracle_payloads("bad-deploy", _bundle(), INCIDENT)
    action = _full_action(INCIDENT, plan, extra2["resource"])
    permit = _permit(action)
    assert worker.resume(INCIDENT, action, permit) is True
    assert worker.resume(INCIDENT, action, permit) is False, (
        "a second resume for the same incident must be refused")
    assert worker._resume_queue.qsize() == 1


def test_the_resume_hook_does_not_break_approval_when_the_worker_is_down():
    """Approving must succeed even if no worker is running.

    The human decision is durably recorded. Turning a successful approval into
    an error because a background task is absent would be strictly worse than
    a run that waits.
    """
    from app.routers import approvals as approvals_mod
    source = _code_only(approvals_mod._trigger_resume)
    # Broad, deliberate swallow around the whole scheduling attempt.
    body = source.split("try:", 1)[1]
    assert "except Exception" in body, (
        "a failure to schedule a resume must not propagate into the approval "
        "response; the decision is already recorded")
    assert "logger.warning" in body, "and it must be recorded, not silently dropped"


def test_orchestrator_reports_resume_counters():
    """The state endpoint has to tell the truth about resumes."""
    worker = orch_mod.Orchestrator(auto_generate=False)
    assert worker.stats.resumed == 0
    assert worker.stats.resume_failures == 0
    for field in ("resumed", "resume_failures"):
        assert hasattr(worker.stats, field)
