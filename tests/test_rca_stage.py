"""The post-incident stage: RCA_PENDING -> RCA_PUBLISHED -> AUDITED.

This stage did not exist. The FSM had always declared the edges, the A4
reporter and a gated publisher had always existed, and nothing called them --
so every run stopped at RESOLVED, no blameless postmortem was ever written,
the ``rca.publish`` audit event was never emitted, and the terminal ``AUDITED``
state was unreachable. The whole capability was dead code on no path.

These tests pin the properties that make it safe to turn on, because a publish
gate that can be talked into publishing an ungrounded postmortem is worse than
one that never runs:

  * publication is GATED, and below-coverage publication is denied, audited,
    and leaves the run at RCA_PENDING rather than claiming a document exists;
  * the evidence the gate judges against is measured from the evidence pack,
    never from the claims themselves, so a claim cannot ground itself;
  * the stage is RETRYABLE from RCA_PENDING -- a failure after the advance must
    not strand an incident forever;
  * publication is IDEMPOTENT -- a retry or a duplicate worker must not
    double-publish;
  * every RCA input is derived from banked artifacts, never invented.
"""
from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.routers import audit as audit_router  # noqa: E402
from app.routers import runs as runs_router  # noqa: E402
from app.services import fsm as fsm_svc  # noqa: E402
from app.services import pipeline as pipeline_mod  # noqa: E402

INCIDENT = "rca-test-1"


@pytest.fixture(autouse=True)
def _clean_state():
    audit_router.reset_demo_state()
    runs_router.reset_demo_state()
    yield
    audit_router.reset_demo_state()
    runs_router.reset_demo_state()


def _bundle(seed: int = 7) -> dict:
    sys.path.insert(0, str(ROOT / "telemetry"))
    import gen as telemetry_gen  # type: ignore[import-not-found]
    return telemetry_gen.generate("bad-deploy", "NORMAL", seed)


def _permit(action):
    """A permit minted the way the approvals service really mints one."""
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


def _full_action(incident: str, plan: dict, resource: dict):
    from app.contracts.action import Action
    from app.services import orchestrator as orch

    pin = orch.ORACLE["bad-deploy"]
    payload = dict(plan)
    payload.update({
        "incident_id": incident,
        "agent_id": "A3-planner",
        "resource_type": resource.get("type", "deployment"),
        "resource_id": str(resource.get("id", "checkout-api")),
        "environment": str(resource.get("environment", "mock")),
        "namespace": "default",
        "evidence_ids": ["ev-resume-test-1"],
        "runbook_id": pin["runbook_id"],
        "runbook_version": pin["runbook_version"],
        "expected_outcome": "mock-tier state change",
    })
    return Action(**payload)


def _resolved_run(incident_id: str = INCIDENT, *, with_evidence: bool = True):
    """A run walked to RESOLVED through the REAL pipeline.

    Built by driving the orchestrator to AWAITING_APPROVAL and then resuming
    with a real approval, rather than by hand-walking the FSM. That matters: a
    hand-walked run has no handoffs, no evidence pack and no verification
    results, so the RCA stage would be tested against a fixture that cannot
    occur in production and would pass while the real path failed.
    """
    from app.services import orchestrator as orch_mod

    worker = orch_mod.Orchestrator(auto_generate=False)
    worker.submit(incident_id, "bad-deploy", _bundle(), source="test")
    worker._process_sync(worker._queue.get_nowait())
    run = runs_router.REPO_STORE[incident_id]
    assert run.state == "AWAITING_APPROVAL"

    _, _, plan, extra = orch_mod.oracle_payloads(
        "bad-deploy", _bundle(), incident_id)
    action = _full_action(incident_id, plan, extra["resource"])
    report = pipeline_mod.resume_from_approval(
        incident_id, run, action, _permit(action),
        tele_public=_bundle(), resource=extra["resource"],
        severity=orch_mod._severity_for("bad-deploy", _bundle()),
        chain=audit_router.get_or_create_chain(incident_id))
    run = report["run"]
    runs_router.REPO_STORE[incident_id] = run
    assert run.state == "RESOLVED", f"setup did not reach RESOLVED ({run.state})"
    assert getattr(run, "execution_tier", ""), "setup produced no executor tier"
    assert getattr(run, "verification_results", []), "setup produced no verdict"

    if not with_evidence:
        # Strip the evidence pack so the publish gate has nothing to ground a
        # claim against. This is the fail-closed case, reached the same way a
        # run with a corrupt or empty pack would reach it.
        for handoff in run.handoffs:
            if "evidence_pack" in handoff:
                handoff["evidence_pack"] = []
    return run


# ---------------------------------------------------------------------------
# The happy path, and that it reaches the state that was previously unreachable
# ---------------------------------------------------------------------------

def test_a_resolved_run_reaches_audited_with_a_published_postmortem():
    run = _resolved_run()
    chain = audit_router.get_or_create_chain(INCIDENT)
    outcome = pipeline_mod.finalize_rca(INCIDENT, run, None, None, chain=chain)

    assert outcome["published"] is True
    assert run.state == "AUDITED", (
        "AUDITED is the FSM's terminal state and was unreachable before this "
        f"stage existed; the run stopped at {run.state}")
    states = [r.to for r in run.history]
    assert "RCA_PENDING" in states and "RCA_PUBLISHED" in states and \
        "AUDITED" in states

    document = getattr(run, "rca_report", None)
    assert isinstance(document, dict) and document
    assert document["gated"] is False
    assert document["agent"] == "reporter"
    assert document["summary"].strip()
    assert document["root_cause"].strip()
    assert document["claim_ids"], "a published postmortem must carry its claims"


def test_publication_emits_an_audited_rca_publish_event():
    run = _resolved_run()
    chain = audit_router.get_or_create_chain(INCIDENT)
    pipeline_mod.finalize_rca(INCIDENT, run, None, None, chain=chain)
    events = [e for e in chain.events if e.event_type.startswith("rca")]
    assert any(e.event_type == "rca.publish" for e in events), (
        "publication must be auditable; the rca.publish event is the record")
    assert chain.verify()["valid"] is True


def test_the_postmortem_is_derived_from_banked_artifacts_only():
    """Every RCA input must come from what the run recorded.

    A postmortem that invents its own timeline, cause or evidence would be the
    most dangerous artifact in the product, because it is the one an operator
    trusts when reconstructing an incident.
    """
    run = _resolved_run()
    chain = audit_router.get_or_create_chain(INCIDENT)
    inputs = pipeline_mod.rca_inputs_from_run(INCIDENT, run, chain)

    # The valid-evidence set is measured from the pack, never from the claims.
    assert inputs["valid_evidence_ids"], "the setup produced no evidence"
    assert set(inputs["evidence_by_id"]) == inputs["valid_evidence_ids"]
    for claim in inputs["claims"]:
        assert set(claim.evidence_ids) <= inputs["valid_evidence_ids"], (
            "a claim cited an id the measured evidence set does not contain; "
            "the gate would be vacuous")
    assert inputs["claims"], "a publishable postmortem must carry its claims"

    # The timeline is the chain's own record, so every row carries ts+actor+hash
    # as the RCA contract requires of a timeline row.
    assert inputs["timeline"], "no timeline was derived from the chain"
    assert "control-plane" in inputs["timeline"][0]
    # The runbook pin is the real one from the diagnostic result.
    prevention_text = " ".join(inputs["prevention"])
    assert "bad-deploy-rollback" in prevention_text, (
        "the pinned runbook must be carried into the postmortem")
    assert inputs["prevention"]


def test_prevention_notes_pass_the_blameless_lint():
    from agents.reporter import lint_report_fields

    run = _resolved_run()
    chain = audit_router.get_or_create_chain(INCIDENT)
    inputs = pipeline_mod.rca_inputs_from_run(INCIDENT, run, chain)
    hits = lint_report_fields({
        "root_cause": inputs["root_cause"],
        "timeline": inputs["timeline"],
        "remediation_log": inputs["remediation_log"],
        "prevention": inputs["prevention"],
    })
    assert not hits, f"the stage produced personal-blame prose: {hits}"


# ---------------------------------------------------------------------------
# Fail-closed: the gate must be able to refuse
# ---------------------------------------------------------------------------

def test_publication_is_denied_when_no_claim_can_be_grounded():
    """No evidence behind the claims means no postmortem.

    This is the MUST-CITE gate (invariant 15) and the reason the stage is
    safe to run at all. A run with no evidence pack produces claims that cite
    nothing, coverage is 0.0, and publication is denied.
    """
    run = _resolved_run(with_evidence=False)
    chain = audit_router.get_or_create_chain(INCIDENT)
    outcome = pipeline_mod.finalize_rca(INCIDENT, run, None, None, chain=chain)

    assert outcome["published"] is False, (
        "an ungrounded postmortem must not be published")
    assert outcome.get("denied") is True
    assert run.state == "RCA_PENDING", (
        f"a denied run must not claim publication; it is in {run.state}")
    assert getattr(run, "rca_report", None) is None, (
        "a denied run must not carry a document")
    kinds = [e.event_type for e in chain.events]
    assert "rca.publish" in kinds, "the denial must be audited"
    denied = [e for e in chain.events if e.event_type == "rca.publish"][0]
    assert "DENIED" in str(denied.result)


def test_a_denied_run_never_advances_to_rca_published_or_audited():
    run = _resolved_run(with_evidence=False)
    chain = audit_router.get_or_create_chain(INCIDENT)
    pipeline_mod.finalize_rca(INCIDENT, run, None, None, chain=chain)
    states = [r.to for r in run.history]
    assert "RCA_PUBLISHED" not in states
    assert "AUDITED" not in states


def test_stale_or_low_trust_evidence_cannot_ground_a_claim():
    """The gate checks freshness and trust -- not just id membership.

    A cited id that is a member of the valid set is NOT enough on the publish
    path. Stale or LOW-trust evidence denies the citation, so a postmortem
    cannot be grounded in evidence the gate has already judged unusable.

    The seal check is asserted as a CONTRACT property rather than a gate
    branch: ``Evidence.hash`` has min_length=1, so an unsealed record cannot
    even be constructed. The gate's `if not ev.hash` branch is therefore
    defence in depth behind a constraint that already prevents it, and this is
    the honest statement of that.
    """
    from app.contracts.evidence import Evidence
    from app.contracts.hypothesis import Claim
    from app.services.evidence import must_cite_coverage

    stale = Evidence(evidence_id="ev-stale", incident_id=INCIDENT,
                     source_type="metric", source_id="error_rate",
                     ts="2026-01-01T00:00:00+00:00", ref="r",
                     hash="b" * 64, freshness_s=10_000.0, relevance=0.9,
                     trust="med")
    claim = Claim(text="something happened", evidence_ids=("ev-stale",))
    assert must_cite_coverage([claim], {"ev-stale"}, {"ev-stale": stale}) == 0.0

    low = Evidence(evidence_id="ev-low", incident_id=INCIDENT,
                   source_type="metric", source_id="error_rate",
                   ts="2026-01-01T00:00:00+00:00", ref="r",
                   hash="c" * 64, freshness_s=1.0, relevance=0.9, trust="low")
    assert must_cite_coverage(
        [Claim(text="x", evidence_ids=("ev-low",))], {"ev-low"},
        {"ev-low": low}) == 0.0

    # The seal is enforced by the contract, not merely by the gate.
    with pytest.raises(Exception):
        Evidence(evidence_id="ev-unsealed", incident_id=INCIDENT,
                 source_type="metric", source_id="error_rate",
                 ts="2026-01-01T00:00:00+00:00", ref="r", hash="",
                 freshness_s=1.0, relevance=0.9, trust="med")


# ---------------------------------------------------------------------------
# Retry and idempotency: a stage that cannot be retried strands an incident
# ---------------------------------------------------------------------------

def test_a_run_parked_at_rca_pending_can_be_retried():
    """A failure AFTER the advance must not strand the incident forever.

    The stage advances to RCA_PENDING and then publishes. If publishing raises
    -- a blameless-lint hit, a transient reporter error -- the run is left at
    RCA_PENDING. An earlier version only accepted RESOLVED/ESCALVED as entry
    states, so that run could never be re-entered and could never be closed.
    """
    run = _resolved_run()
    fsm_svc.advance(run, "RCA_PENDING", reason="post-incident review",
                     now=1000.0)
    assert run.state == "RCA_PENDING"

    chain = audit_router.get_or_create_chain(INCIDENT)
    outcome = pipeline_mod.finalize_rca(INCIDENT, run, None, None, chain=chain)
    assert outcome["published"] is True
    assert run.state == "AUDITED"
    # And the retry must not have advanced twice.
    assert [r.to for r in run.history].count("RCA_PENDING") == 1


def test_republishing_is_idempotent():
    run = _resolved_run()
    chain = audit_router.get_or_create_chain(INCIDENT)
    first = pipeline_mod.finalize_rca(INCIDENT, run, None, None, chain=chain)
    assert first["published"] is True

    second = pipeline_mod.finalize_rca(INCIDENT, run, None, None, chain=chain)
    assert second["published"] is True
    assert second["idempotent"] is True
    assert second["report"] == first["report"]
    # No duplicate transitions, and no second publish event.
    states = [r.to for r in run.history]
    assert states.count("RCA_PUBLISHED") == 1
    assert states.count("AUDITED") == 1
    assert len([e for e in chain.events if e.event_type == "rca.publish"]) == 1


def test_the_stage_refuses_to_run_before_the_incident_finishes():
    run = runs_router.create_run("rca-early", now=1000.0)
    fsm_svc.advance(run, "TRIAGING", now=1000.0)
    chain = audit_router.get_or_create_chain("rca-early")
    outcome = pipeline_mod.finalize_rca("rca-early", run, None, None,
                                        chain=chain)
    assert outcome["published"] is False
    assert outcome["skipped"] is True
    assert "TRIAGING" in outcome["detail"]


# ---------------------------------------------------------------------------
# Durability: the postmortem must survive a restart
# ---------------------------------------------------------------------------

def test_the_published_postmortem_survives_the_run_store_round_trip(tmp_path):
    from app.routers import runs as router_mod

    run = _resolved_run()
    chain = audit_router.get_or_create_chain(INCIDENT)
    pipeline_mod.finalize_rca(INCIDENT, run, None, None, chain=chain)
    assert getattr(run, "rca_report", None)

    router_mod.REPO_STORE[INCIDENT] = run
    try:
        path = tmp_path / "runs.json"
        router_mod.save_store(path)
        router_mod.REPO_STORE.clear()
        router_mod.load_store(path)
        view = router_mod.run_view(router_mod.get_run(INCIDENT))
    finally:
        router_mod.REPO_STORE.pop(INCIDENT, None)

    assert view["rca_report"] is not None, (
        "the postmortem must survive a restart, or the RCA view shows nothing "
        "after the process restarts")
    assert view["rca_report"]["gated"] is False
    assert view["rca_report"]["root_cause"]


def test_run_view_reports_no_postmortem_as_null_not_as_an_empty_document():
    run = runs_router.create_run("rca-none", now=1000.0)
    view = runs_router.run_view(run)
    assert view["rca_report"] is None, (
        "'never published' must be null; an empty document would render as a "
        "postmortem that does not exist")


# ---------------------------------------------------------------------------
# The service the stage needs must be driven, not merely present
# ---------------------------------------------------------------------------

def test_the_orchestrator_actually_drives_the_rca_stage():
    """The gap was not a missing function; it was a missing CALL.

    ``draft_rca``/``publish_rca`` existed, the FSM edges existed, and the live
    path still stopped at RESOLVED. So the regression guard is on the CALLER.
    """
    from app.services import orchestrator as orch_mod

    source = inspect.getsource(orch_mod.Orchestrator._resume_sync)
    assert "finalize_rca" in source, (
        "the resume path must drive the post-incident stage, or every "
        "human-approved run stops at RESOLVED with no postmortem")
    # And a failure there must be recorded, not allowed to undo the fix.
    assert "rca_failures" in source


def test_the_rca_stage_persists_through_its_own_store_key():
    raw = (ROOT / "backend" / "app" / "routers" / "runs.py").read_text(
        encoding="utf-8")
    assert '"rca_report"' in raw, (
        "rca_report must be a declared optional store key, or it is silently "
        "dropped on load")
    stored = json.loads(json.dumps({"rca_report": {"gated": False}}))
    assert stored["rca_report"]["gated"] is False


def test_the_rca_endpoints_are_registered_and_write_gated():
    from app.routers import audit as ar

    if ar.router is None:  # pragma: no cover - host starlette drift
        pytest.skip("router construction requires the pinned container deps")
    paths = {(route.path, tuple(sorted(route.methods)))
             for route in ar.router.routes}
    assert ("/incidents/{incident_id}/rca", ("GET",)) in paths
    publish = [p for p in paths if p[0].endswith("/rca/publish")]
    assert publish and "POST" in publish[0][1], (
        "publishing appends to the exported proof chain, so it must be a "
        "write-gated POST")
    source = inspect.getsource(ar.http_rca_publish)
    assert "require_role" in source, (
        "the publish route must authorize a role server-side, not just "
        "require a key")
    assert "guard_http" in source
