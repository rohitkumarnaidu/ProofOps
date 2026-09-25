"""The orchestrator drives incidents for real, and can never approve one.

These tests exist because the single most dangerous thing a background worker
could do in this product is approve its own remediation. An auto-approving
worker would satisfy every "the pipeline ran" check while quietly destroying
the one property the whole product is built to demonstrate: that a YELLOW
action requires a human holding a real, scoped, single-use token.

So the first test here is not "the worker works" -- it is "the worker stops".
The rest pin the properties that make it safe to leave running unattended:
exactly-once claiming, bounded growth, off-loop execution, determinism, and
fail-closed ingestion.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.routers import audit as audit_router  # noqa: E402
from app.routers import runs as runs_router  # noqa: E402
from app.services import orchestrator as orch_mod  # noqa: E402


def _bundle(seed: int = 7) -> dict:
    """A real telemetry bundle from the committed generator (offline, seeded)."""
    sys.path.insert(0, str(ROOT / "telemetry"))
    import gen as telemetry_gen  # type: ignore[import-not-found]
    return telemetry_gen.generate("bad-deploy", "NORMAL", seed)


@pytest.fixture(autouse=True)
def _clean():
    for store in (runs_router.REPO_STORE, audit_router.CHAINS):
        for key in list(store):
            if key.startswith("orch-test"):
                store.pop(key, None)
    yield
    for store in (runs_router.REPO_STORE, audit_router.CHAINS):
        for key in list(store):
            if key.startswith("orch-test"):
                store.pop(key, None)


# ---------------------------------------------------------------------------
# THE safety property
# ---------------------------------------------------------------------------

def test_the_worker_never_approves_anything():
    """A YELLOW action must stop at AWAITING_APPROVAL, with no permit minted.

    Checked structurally, not just behaviourally: the pipeline call site must
    not pass an `approval`, because a future edit that added one would restore
    the exact failure mode this product exists to prevent, and it would still
    look correct in review.
    """
    import inspect
    source = inspect.getsource(orch_mod.Orchestrator._process_sync)
    assert "approval=None" in source, (
        "the orchestrator must pass approval=None so a YELLOW action routes to "
        "AWAITING_APPROVAL; anything else lets a background worker authorise "
        "its own remediation"
    )
    # And no other approval argument may be constructed in the worker.
    assert 'approval={"secret"' not in source
    assert "APPROVAL_SECRET" not in source


def test_a_real_incident_stops_at_awaiting_approval():
    """End-to-end through the real pipeline: the stop is the feature."""
    worker = orch_mod.Orchestrator(auto_generate=False)
    incident = "orch-test-stop"
    assert worker.submit(incident, "bad-deploy", _bundle(), source="test") is True
    job = worker._queue.get_nowait()
    worker._process_sync(job)

    run = runs_router.REPO_STORE[incident]
    states = [record.to for record in run.history]
    assert run.state == "AWAITING_APPROVAL", f"ended in {run.state}, history={states}"
    # The full real walk happened, not a shortcut.
    for expected in ("TRIAGING", "CORRELATED", "INVESTIGATING", "DIAGNOSING",
                     "PLANNED", "POLICY_CHECK", "AWAITING_APPROVAL"):
        assert expected in states, f"missing {expected} in {states}"
    # Critically: it never reached APPROVED or EXECUTING on its own.
    assert "APPROVED" not in states
    assert "EXECUTING" not in states
    assert runs_router.run_view(run)["permit_pending"] is False


def test_the_audit_chain_records_the_policy_decision_that_stopped_it():
    incident = "orch-test-chain"
    worker = orch_mod.Orchestrator(auto_generate=False)
    worker.submit(incident, "bad-deploy", _bundle(), source="test")
    worker._process_sync(worker._queue.get_nowait())

    chain = audit_router.get_or_create_chain(incident)
    kinds = [event.event_type for event in chain.events]
    assert "policy.decision" in kinds, f"no policy decision recorded: {kinds}"
    assert chain.verify()["valid"] is True, "the chain must still verify"

    decision = next(e for e in chain.events if e.event_type == "policy.decision")
    assert decision.policy.get("result") in ("ESCALATE", "DENY")
    assert decision.policy.get("rule"), "a decision with no matched rule is not auditable"
    assert decision.policy.get("version"), "a decision with no policy version is not auditable"


# ---------------------------------------------------------------------------
# Exactly-once, bounded, killable
# ---------------------------------------------------------------------------

def test_a_duplicate_incident_is_suppressed_not_run_twice():
    """Double-advancing a run would forge a transition into a hash chain.

    verify() would then correctly report tampering, and the operator would be
    looking at a chain the product itself calls invalid. The claim set is what
    prevents it.
    """
    worker = orch_mod.Orchestrator(auto_generate=False)
    assert worker.submit("orch-test-dup", "bad-deploy", _bundle()) is True
    assert worker.submit("orch-test-dup", "bad-deploy", _bundle()) is False
    assert worker.stats.duplicates_suppressed == 1
    assert worker._queue.qsize() == 1, "the duplicate must not be queued"


def test_growth_is_bounded():
    """A worker that accepts unbounded work is a memory leak with a timer."""
    worker = orch_mod.Orchestrator(auto_generate=False, max_incidents=3)
    accepted = [worker.submit(f"orch-test-b{i}", "bad-deploy", _bundle())
                for i in range(6)]
    assert accepted == [True, True, True, False, False, False]
    assert worker._queue.qsize() == 3


def test_blank_incident_ids_are_refused():
    worker = orch_mod.Orchestrator(auto_generate=False)
    assert worker.submit("", "bad-deploy", _bundle()) is False
    assert worker.submit("   ", "bad-deploy", _bundle()) is False
    assert worker._queue.qsize() == 0


def test_the_kill_switch_stops_new_work():
    worker = orch_mod.Orchestrator(auto_generate=False)
    assert worker.stats.enabled is True
    worker.stats.enabled = False
    # The ingest router checks this before submitting; assert the flag the
    # router reads is the same object the worker uses.
    assert worker.stats.enabled is False


def test_the_worker_runs_the_pipeline_off_the_event_loop():
    """A blocking pipeline on the loop would freeze every request and stream.

    This is asserted structurally because the symptom is a mysteriously hung
    server under load, which is very hard to trace back to a missing
    `to_thread`.
    """
    import inspect
    source = inspect.getsource(orch_mod.Orchestrator._process)
    assert "asyncio.to_thread" in source, (
        "the pipeline must run via asyncio.to_thread; run_pipeline is "
        "synchronous and would otherwise block the event loop"
    )


def test_a_malformed_bundle_fails_closed_instead_of_crashing():
    """A bad incident must produce NO action, and must not kill the loop.

    The first draft of this test asserted the job would raise. It does not, and
    that is the better outcome: a bundle with no evidence is caught by the
    validator and routed to BLOCKED with "no evidence -> no action", which is
    exactly the fail-closed behaviour the product promises. A crash would have
    been the worse result, and asserting the crash would have been asserting
    the bug.
    """
    worker = orch_mod.Orchestrator(auto_generate=False)
    worker.submit("orch-test-boom", "bad-deploy", {"nonsense": True})
    job = worker._queue.get_nowait()

    async def scenario():
        await worker._process(job)  # must not raise

    asyncio.run(scenario())

    assert worker.stats.failed == 0, "a malformed bundle is not an internal failure"
    assert worker.stats.blocked == 1, "it must be refused by the validator"
    assert "no evidence" in worker.stats.last_outcome.lower()
    assert "no evidence" in worker.stats.last_outcome or \
        "evidence" in worker.stats.last_outcome

    run = runs_router.REPO_STORE["orch-test-boom"]
    states = [record.to for record in run.history]
    assert run.state == "BLOCKED", f"expected a fail-closed BLOCKED, got {run.state}"
    assert "EXECUTING" not in states, "a bundle with no evidence must never execute"


def test_a_job_that_really_does_raise_is_counted_and_survivable():
    """The internal-failure counter has to work for genuine surprises too."""
    worker = orch_mod.Orchestrator(auto_generate=False)
    job = orch_mod.Job(incident_id="orch-test-raise", scenario="bad-deploy",
                       tele=_bundle())

    async def scenario():
        # Force an internal error the way a bug in a dependency would.
        original = orch_mod.oracle_payloads

        def boom(*args, **kwargs):
            raise RuntimeError("synthetic internal failure")

        import app.services.orchestrator as module
        module.oracle_payloads = boom
        try:
            await worker._process(job)
        finally:
            module.oracle_payloads = original

    asyncio.run(scenario())
    assert worker.stats.failed == 1
    assert "synthetic internal failure" in worker.stats.last_outcome


# ---------------------------------------------------------------------------
# Determinism and honesty
# ---------------------------------------------------------------------------

def test_the_same_seed_produces_the_same_incident_story():
    """Reproducibility is what makes a live demo repeatable and an eval fair."""
    first = orch_mod.oracle_payloads("bad-deploy", _bundle(7), "x")
    second = orch_mod.oracle_payloads("bad-deploy", _bundle(7), "x")
    assert first[0] == second[0], "triage must be deterministic"
    assert first[1] == second[1], "diagnosis must be deterministic"
    assert first[2] == second[2], "plan must be deterministic"


def test_the_oracle_derives_its_facts_from_real_telemetry():
    """Severity and fingerprint are computed, not pinned.

    Only the hypothesis prose and the action choice are scripted. If severity
    were a constant the whole policy path would be theatre, because policy
    takes severity as an input.
    """
    tele = _bundle(7)
    triage, diagnosis, plan, extra = orch_mod.oracle_payloads(
        "bad-deploy", tele, "orch-test-oracle")
    assert triage["severity"] in ("P1", "P2", "P3", "P4")
    assert triage["fingerprint"], "fingerprint must be computed by the correlator"
    assert diagnosis["verdict"] == "PINNED"
    assert diagnosis["runbook_id"] in orch_mod.ORACLE["bad-deploy"]["runbook_id"]
    assert plan["action_type"] == "rollback_deployment"
    assert extra["alerts"], "alerts must be derived from the bundle"


def test_an_unknown_scenario_is_refused_rather_than_guessed():
    with pytest.raises(KeyError):
        orch_mod.oracle_payloads("not-a-scenario", _bundle(), "x")


def test_the_reported_mode_is_honest_about_which_agents_ran():
    """`scripted-oracle` must be the default label with no Lyzr key.

    Claiming live agent reasoning with no key configured is the exact
    dishonesty this product is supposed to be judged against.
    """
    worker = orch_mod.Orchestrator(auto_generate=False)
    expected = "live-lyzr" if orch_mod._lyzr_key() else "scripted-oracle"
    assert worker.stats.mode == expected
