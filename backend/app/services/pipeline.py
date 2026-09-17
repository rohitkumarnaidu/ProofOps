"""M21a pipeline conductor: deterministic incident runs end to end (service).

Ownership: M21 owns THIS FILE (``backend/app/services/pipeline.py``). Every
STAGE stays owned by its module: agents reason (M13); validator (M06.1),
policy (M06), sandbox (M08), verifier (M09) decide; FSM (M14) orders; M07
binds approvals; M11 loads runbooks; M12 retrieves; M05 packs. The conductor
sequences calls, threads artifacts, walks the canonical control flow, and
reports. It invents nothing.

Outcomes: "resolved" (verified fix) | "blocked" (safety denial, audited
BLOCKED) | "escalated" (human decision needed) | "stalled" (no basis to
continue -- caller escalates). Failures raise: PipelineBlocked (expected
red path), PipelineStalled (insufficient basis), PipelineFailed (bug
signal -- never an expected outcome).

Clients are injected (scripted for deterministic tests, live where keyed,
DISABLED degrades -- commit B proves the degraded path). Approval needs an
explicit secret+actor (no ambient authority). Budgets/ledger wiring,
rollback, RCA, audit emission, eval grading, and API guards land in
commit B; this half stops honestly at each boundary.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agents import diagnostic as A2  # noqa: E402 (M13.3)
from agents import planner as A3  # noqa: E402 (M13.4)
from agents import session as session_mod  # noqa: E402 (M13.7 sessions)
from agents import triage as A1  # noqa: E402 (M13.2)
from app.contracts.values import params_hash  # noqa: E402 (scope binding)
from app.services import fsm as fsm_svc  # noqa: E402 (M14 ordering)
from app.services import policy as policy_svc  # noqa: E402 (M06)
from app.services import predigest as predigest_svc  # noqa: E402 (M05.5)
from app.services import sandbox as sandbox_svc  # noqa: E402 (M08 mock)
from app.services import validator as validator_svc  # noqa: E402 (M06.1)
from app.services import verifier as verifier_svc  # noqa: E402 (M09)
from app.services.fsm import Permit  # noqa: E402 (M14 permits)
from app.services.runbooks import load_runbook  # noqa: E402 (M11)

DEMO_BLAST = {"scope": "deploy", "replicas": 2, "traffic_pct": 10}
APPROVER = {"role": "approver", "id": "sre-1"}


class PipelineError(Exception):
    """Base for pipeline outcomes that stop the run."""


class PipelineBlocked(PipelineError):
    """Safety denial (expected red path): BLOCKED, audited, no execution."""


class PipelineStalled(PipelineError):
    """No basis to continue (caller escalates, never improvises)."""


class PipelineFailed(PipelineError):
    """Unexpected failure (bug signal, never an expected outcome)."""


def _now(now: float | None) -> float:
    return time.time() if now is None else float(now)


def _permit_for(action: Any, auto: bool, now: float,
                token_ref: str) -> Permit:
    params = action.parameters
    plain = params.to_plain() if hasattr(params, "to_plain") else dict(params)
    return Permit(action_id=action.action_id,
                  params_hash=params_hash(plain),
                  expires_at=now + 300.0, token_ref=token_ref, auto=auto)


def run_pipeline(incident_id: str, alerts: Sequence[Mapping[str, Any]],
                 tele_public: Mapping[str, Any], service: str, env: str,
                 resource: Mapping[str, Any],
                 clients: Mapping[str, Any],
                 store: session_mod.SessionStore,
                 approval: Mapping[str, Any] | None = None,
                 blast: Mapping[str, Any] | None = None,
                 now: float | None = None) -> dict[str, Any]:
    """Walk one incident NEW -> VERIFYING outcome (M21a core).

    clients needs triage/diagnostic/planner entries (duck-typed like
    LyzrClient). approval {secret, actor} enables the HITL branch; without
    it an ESCALATE decision stalls. blast defaults to DEMO_BLAST (demo-scale
    assumption, recorded in the report).
    """
    for name in ("incident_id", "service", "env"):
        value = {"incident_id": incident_id, "service": service,
                 "env": env}[name]
        if not isinstance(value, str) or not value.strip():
            raise PipelineFailed(f"{name} must be a non-empty string")
    for key in ("triage", "diagnostic", "planner"):
        if key not in clients:
            raise PipelineFailed(f"missing {key} client")
    ts = _now(now)
    blast = dict(DEMO_BLAST if blast is None else blast)
    run = fsm_svc.new_run(incident_id, now=ts)

    def _stop(exc: PipelineError) -> PipelineError:
        exc.run = run  # type: ignore[attr-defined]
        return exc

    def _walk(*states: str) -> None:
        nonlocal ts
        for state in states:
            fsm_svc.advance(run, state, now=ts)

    _walk("TRIAGING")
    triage = A1.run_triage(list(alerts), incident_id, clients["triage"],
                           store)
    _walk("CORRELATED", "INVESTIGATING")
    pack = predigest_svc.build_evidence_pack(incident_id, dict(tele_public))
    evidence_ids = [str(e["evidence_id"]) for e in pack.get("evidence", [])]
    _walk("DIAGNOSING")
    diagnosis = A2.run_diagnose(incident_id, service, env, pack,
                                clients["diagnostic"], store)
    if diagnosis.verdict != "PINNED":
        _walk("ESCALATED")
        raise _stop(PipelineStalled(
            f"diagnosis {diagnosis.verdict} (caller escalates)"))
    _walk("PLANNED")
    try:
        plan = A3.run_plan(incident_id, diagnosis, resource,
                           clients["planner"], store, tuple(evidence_ids))
    except PipelineError:
        raise
    except Exception as exc:
        _walk("POLICY_CHECK")
        fsm_svc.advance(run, "BLOCKED",
                        reason=f"planner rejected: {exc}", now=ts)
        raise _stop(PipelineBlocked(f"planner rejected: {exc}")) from exc
    action = plan.action
    _walk("POLICY_CHECK")
    runbook = load_runbook(diagnosis.runbook_id)
    issues = validator_svc.validate_action(action, runbook)
    if issues:
        fsm_svc.advance(run, "BLOCKED",
                        reason=f"validator: {issues[0]}", now=ts)
        raise _stop(PipelineBlocked(f"validator rejected: {issues}"))
    bundle = policy_svc.load_bundle()
    matrix = policy_svc.load_matrix()
    decision = str(policy_svc.evaluate(
        action, dict(APPROVER), {"environment": resource.get("environment",
                                                             env)},
        str(triage.severity), blast, bundle, matrix).decision)
    if decision == "DENY":
        fsm_svc.advance(run, "BLOCKED", reason="policy DENY", now=ts)
        raise _stop(PipelineBlocked("policy DENY (audited BLOCKED)"))
    if decision == "ESCALATE":
        if approval is None:
            # Honest FSM route: wait for a human who never arrives in this
            # call (TTL sweep escalates later); the stall is the report.
            fsm_svc.advance(run, "AWAITING_APPROVAL", now=ts)
            raise _stop(PipelineStalled("ESCALATE without approval config "
                                        "(caller escalates)"))
        secret, actor = approval["secret"], approval["actor"]
        permit = _hitl_permit(action, secret, actor, ts)
        fsm_svc.advance(run, "AWAITING_APPROVAL", now=ts)
        fsm_svc.advance(run, "APPROVED", permit=permit, now=ts)
    else:
        permit = _permit_for(action, True, ts,
                             token_ref=f"auto-{action.action_id}")
        fsm_svc.advance(run, "APPROVED", permit=permit, now=ts)
    fsm_svc.advance(run, "EXECUTING", now=ts)
    execution_id = f"{incident_id}:{action.action_id}:1"
    deploys = list(tele_public.get("deploys", []))
    version = str(deploys[0].get("to_v", "v23")) if deploys else "v23"
    metrics = [float(m.get("value", 0.0))
               for m in tele_public.get("metrics", [])
               if isinstance(m, Mapping)]
    before = sandbox_svc.initial_state(
        service=service, version=version,
        error_rate=max(metrics) if metrics else 0.0)
    (applied, _dup) = fsm_svc.execute_once(
        run, action.action_id, execution_id, sandbox_svc.apply, action,
        before)
    _execution, after = applied
    fsm_svc.advance(run, "VERIFYING", now=ts)
    slo = dict(tele_public.get("slo", {"error_rate_below": 0.01}))
    expected = {}
    params = action.parameters
    plain_params = params.to_plain() if hasattr(params, "to_plain") \
        else dict(params)
    if "to_version" in plain_params:
        expected = {"version": str(plain_params["to_version"])}
    verdict = verifier_svc.verify(execution_id, before, after, slo,
                                  expected).verdict
    verdict_name = str(verdict.value if hasattr(verdict, "value")
                       else verdict)
    if verdict_name != "RESOLVED":
        _walk("ESCALATED")
        raise _stop(PipelineFailed(
            f"verification {verdict_name} (rollback lands in commit B)"))
    _walk("RESOLVED")
    return {"incident_id": incident_id, "path": "resolved",
            "states": [r.to for r in run.history],
            "severity": str(triage.severity), "decision": decision,
            "action_type": str(action.action_type),
            "execution_id": execution_id, "verdict": verdict_name,
            "evidence_ids": evidence_ids,
            "rolled_back": False, "run": run}


def _hitl_permit(action: Any, secret: str, actor: str,
                 now: float) -> Permit:
    """Request + approve through the approvals router pure fns (M19a)."""
    from app.routers import approvals as approvals_router
    dumped = action.model_dump(mode="json")
    issued = approvals_router.request_approval(dumped, actor, secret)
    view = approvals_router.approve_approval(
        issued["approval_id"], actor, issued["token"], "approver", secret)
    assert view["status"] == "approved"
    params = action.parameters
    plain = params.to_plain() if hasattr(params, "to_plain") else dict(params)
    return Permit(action_id=action.action_id,
                  params_hash=params_hash(plain), expires_at=now + 300.0,
                  token_ref=issued["approval_id"], auto=False)
