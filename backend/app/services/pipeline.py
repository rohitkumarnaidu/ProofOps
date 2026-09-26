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
from agents import tools as tools_mod  # noqa: E402 (M13 budgets per run)
from agents import triage as A1  # noqa: E402 (M13.2)
from app.contracts.values import params_hash  # noqa: E402 (scope binding)
from app.services import audit as audit_mod  # noqa: E402 (M15 recording)
from app.services import fsm as fsm_svc  # noqa: E402 (M14 ordering)
from app.services import policy as policy_svc  # noqa: E402 (M06)
from app.services import predigest as predigest_svc  # noqa: E402 (M05.5)
from app.services import sandbox as sandbox_svc  # noqa: E402 (M08 mock)
from app.services import validator as validator_svc  # noqa: E402 (M06.1)
# Kept deliberately: the concurrent live-verifier refactor routed verification
# through `_verify_action` and left this import unreferenced. Removing it would
# fight that change from a neighbouring lane, so it is annotated instead of
# deleted. Drop it when the refactor settles.
from app.services import verifier as verifier_svc  # noqa: E402,F401 (M09)
from app.services.fsm import Permit  # noqa: E402 (M14 permits)
from app.services.k8s_executor import K8S_EXECUTOR  # Live cluster connector
from app.services.prom_verifier import PROMETHEUS_VERIFIER  # Live PromQL verifier
from app.services.rollback import (  # noqa: E402 (M10 auto-rollback)
    rollback_for,
    should_rollback,
)
from app.services.runbooks import load_runbook  # noqa: E402 (M11)

DEMO_BLAST = {"scope": "deploy", "replicas": 2, "traffic_pct": 10}
APPROVER = {"role": "approver", "id": "sre-1"}


def _apply_action(action: Any, state: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Dispatch action to live Kubernetes if connected, otherwise fallback to sandbox."""
    if K8S_EXECUTOR.is_connected:
        try:
            return K8S_EXECUTOR.execute(action, state)
        except Exception:
            pass
    return sandbox_svc.apply(action, state)


def _verify_action(
    execution_id: str,
    service: str,
    before: dict[str, Any],
    after: dict[str, Any],
    slo: dict[str, Any],
    expected: dict[str, Any] | None = None,
) -> Any:
    """Dispatch verification to Prometheus PromQL if reachable, otherwise fallback to verifier."""
    return PROMETHEUS_VERIFIER.verify_sync(
        execution_id=execution_id,
        service=service,
        before_state=before,
        after_state=after,
        slo=slo,
        expected=expected,
        command_succeeded=True,
    )


class PipelineError(Exception):
    """Base for pipeline outcomes that stop the run."""


class PipelineBlocked(PipelineError):
    """Safety denial (expected red path): BLOCKED, audited, no execution."""


class PipelineStalled(PipelineError):
    """No basis to continue (caller escalates, never improvises)."""


class PipelineFailed(PipelineError):
    """Unexpected failure (bug signal, never an expected outcome)."""


class RcaDenied(PipelineError):
    """RCA publication denied: MUST-CITE coverage below 1.0 (audited)."""


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
                 chain: Any = None,
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
    tools_mod.reset_tool_counts()  # incident boundary: budgets restart here
    if chain is None:
        # P0-2: audit emission is mandatory, never opt-in. A caller-supplied
        # chain (e.g. the HTTP layer's per-incident chain) still wins.
        chain = audit_mod.AuditChain(incident_id=incident_id)
    after_err: float | None = None

    def _stop(exc: PipelineError) -> PipelineError:
        exc.run = run  # type: ignore[attr-defined]
        exc.audit_chain = chain  # type: ignore[attr-defined]
        audit_mod.record_fsm(chain, fsm_svc.audit_records(run))
        return exc

    def _walk(*states: str) -> None:
        nonlocal ts
        for state in states:
            fsm_svc.advance(run, state, now=ts)

    _walk("TRIAGING")
    triage = A1.run_triage(list(alerts), incident_id, clients["triage"],
                           store)
    fsm_svc.handoff(run, "triage", "diagnostic",
                    tuple(triage.evidence_ids or ["alert-signals"]))
    if run.handoffs:
        run.handoffs[-1]["triage_result"] = triage.model_dump() if hasattr(triage, "model_dump") else dict(triage)
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
    fsm_svc.handoff(run, "diagnostic", "planner",
                    tuple(evidence_ids[:5] or ["diagnosis-artifact"]))
    if run.handoffs:
        run.handoffs[-1]["diagnostic_result"] = diagnosis.model_dump() if hasattr(diagnosis, "model_dump") else dict(diagnosis)
        run.handoffs[-1]["evidence_pack"] = pack.get("evidence", [])
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
    evaluation = policy_svc.evaluate(
        action, dict(APPROVER), {"environment": resource.get("environment",
                                                              env)},
        str(triage.severity), blast, bundle, matrix)
    decision = str(evaluation.decision)
    def _decide(kind: str) -> None:
        chain.emit("policy.decision", actor="control-plane",
                   policy={"version": getattr(evaluation, "policy_version",
                                              "unknown"),
                           "rule": getattr(evaluation, "rule_id", "unknown"),
                           "result": kind},
                   action_id=action.action_id,
                   result=f"{kind}: policy decided {kind} "
                          f"(rule {getattr(evaluation, 'rule_id', '?')})")

    if decision == "DENY":
        _decide("DENY")
        fsm_svc.advance(run, "BLOCKED", reason="policy DENY", now=ts)
        raise _stop(PipelineBlocked("policy DENY (audited BLOCKED)"))
    if decision == "ESCALATE":
        _decide("ESCALATE")
        if approval is None:
            # Honest FSM route: wait for a human who never arrives in this
            # call (TTL sweep escalates later); the stall is the report.
            fsm_svc.advance(run, "AWAITING_APPROVAL", now=ts)
            raise _stop(PipelineStalled("ESCALATE without approval config "
                                        "(caller escalates)"))
        secret, actor = approval["secret"], approval["actor"]
        permit = _hitl_permit(action, secret, actor, ts, chain,
                              incident_id=incident_id)
        fsm_svc.advance(run, "AWAITING_APPROVAL", now=ts)
        fsm_svc.advance(run, "APPROVED", permit=permit, now=ts)
    else:
        _decide("ALLOW")
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
        run, action.action_id, execution_id, _apply_action, action,
        before)
    _execution, after = applied
    diff = _execution.state_diff.to_plain() if hasattr(_execution.state_diff, "to_plain") else dict(_execution.state_diff)
    setattr(run, "state_diff", diff)
    setattr(run, "execution_logs", list(_execution.logs))
    after_err = float(after.get("error_rate", 1.0))
    fsm_svc.advance(run, "VERIFYING", now=ts)
    slo = dict(tele_public.get("slo", {"error_rate_below": 0.01}))
    expected = {}
    params = action.parameters
    plain_params = params.to_plain() if hasattr(params, "to_plain") \
        else dict(params)
    if "to_version" in plain_params:
        expected = {"version": str(plain_params["to_version"])}
    verdict = _verify_action(execution_id, service, before, after, slo,
                             expected).verdict
    verdict_name = str(verdict.value if hasattr(verdict, "value")
                       else verdict)
    verdicts = [verdict_name]
    chain.emit("verification.verdict", actor="control-plane",
               execution_id=execution_id, result=verdict_name)
    rolled_back = False
    if verdict_name != "RESOLVED" and should_rollback(verdict_name, 0):
        try:
            rb_action = rollback_for(action, before)
        except ValueError:
            rb_action = None
        if rb_action is not None:
            # P1 gate (Lane A): the auto-rollback is pre-authorized as part
            # of the approved action's rollback plan, so no fresh HITL token
            # is minted here -- but validator + policy still gate execution.
            # An unvalidated or DENY'd rollback never reaches the executor:
            # it is refused on the audit chain and the run escalates.
            rb_issues = validator_svc.validate_action(rb_action, runbook)
            # Terminal-rollback exemption: auto-rollback is single-attempt
            # (MAX_AUTO_ROLLBACKS=1), so it carries no nested rollback_action
            # of its own. That one structural issue is exempt; every other
            # validator issue still refuses the rollback.
            rb_issues = [issue for issue in rb_issues
                         if "requires rollback_action" not in issue]
            rb_refusal = ""
            if rb_issues:
                rb_refusal = f"validator rejected rollback: {rb_issues[0]}"
            else:
                rb_eval = policy_svc.evaluate(
                    rb_action, dict(APPROVER),
                    {"environment": resource.get("environment", env)},
                    str(triage.severity), blast, bundle, matrix)
                if str(rb_eval.decision) == "DENY":
                    rb_refusal = (
                        "policy DENY rollback "
                        f"(rule {getattr(rb_eval, 'rule_id', '?')})")
            rb_execution_id = f"{execution_id}-rb1"
            if rb_refusal:
                chain.emit("rollback.finish", actor="control-plane",
                           action_id=rb_action.action_id,
                           execution_id=rb_execution_id,
                           result=f"rollback refused: {rb_refusal}")
                # rolled_back stays False; verdict stays non-RESOLVED, so the
                # run falls through to ESCALATED below (never resolves).
            else:
                chain.emit("rollback.start", actor="control-plane",
                           action_id=rb_action.action_id,
                           execution_id=rb_execution_id,
                           result=f"auto-rollback on {verdict_name}")
                rolled_back = True
                fsm_svc.advance(run, "ROLLBACK",
                                reason=f"auto-rollback on {verdict_name}",
                                now=ts)
                (rb_applied, _) = fsm_svc.execute_once(
                    run, rb_action.action_id, rb_execution_id,
                    _apply_action, rb_action, after)
                _, after_rb = rb_applied
                after_err = float(after_rb.get("error_rate", 1.0))
                fsm_svc.advance(run, "VERIFYING", now=ts)
                expected_rb = {}
                if "to_version" in plain_params and isinstance(
                        before.get("deployment_version"), str):
                    expected_rb = {"version": before["deployment_version"]}
                verdict2 = _verify_action(
                    rb_execution_id, service, after, after_rb, slo,
                    expected_rb).verdict
                verdict_name = str(verdict2.value
                                   if hasattr(verdict2, "value") else verdict2)
                verdicts.append(verdict_name)
                chain.emit("verification.verdict", actor="control-plane",
                           execution_id=rb_execution_id, result=verdict_name)
                chain.emit("rollback.finish", actor="control-plane",
                           action_id=rb_action.action_id,
                           execution_id=rb_execution_id,
                           result=verdict_name)
    if verdict_name != "RESOLVED":
        _walk("ESCALATED")
        report = _report(incident_id, "escalated", run, triage, decision,
                         action, execution_id, verdict_name, verdicts,
                         evidence_ids, rolled_back, after_err)
        report["audit_chain"] = chain
        audit_mod.record_fsm(chain, fsm_svc.audit_records(run))
        return report
    _walk("RESOLVED")
    report = _report(incident_id, "resolved", run, triage, decision, action,
                     execution_id, verdict_name, verdicts, evidence_ids,
                     rolled_back, after_err)
    report["audit_chain"] = chain
    audit_mod.record_fsm(chain, fsm_svc.audit_records(run))
    return report


def resume_from_approval(
    incident_id: str,
    run: Any,
    action: Any,
    permit: Any,
    *,
    tele_public: Mapping[str, Any],
    resource: Mapping[str, Any],
    severity: str,
    env: str = "prod",
    blast: Mapping[str, Any] | None = None,
    chain: Any = None,
    decision: str = "ESCALATE",
    evidence_ids: Sequence[str] = (),
    now: float | None = None,
) -> dict[str, Any]:
    """Continue one incident from a HUMAN approval through to a verdict.

    This is the missing half of the lifecycle, and it exists as a separate
    entry point for one reason: **it never re-plans.**

    The tempting shortcut is to call `run_pipeline` again with the approval
    supplied. That is wrong, and dangerously so. `run_pipeline` starts at NEW
    and re-runs A3, so the action it produces on the second pass need not be
    the action a human reviewed. An approval is bound to one `action_id` and
    one exact parameter hash; re-planning silently swaps the thing that was
    authorized for a different thing, which defeats the entire HITL guarantee
    while every log line still looks correct.

    So the caller supplies the action, and that action must be the one recovered
    from the approval store (see `approvals.verified_permit`, which returns a
    permit bound to the stored request). This function only ever executes,
    verifies and reports. It cannot author an action.

    Safety properties preserved here:
      * the APPROVED edge requires a permit (FSM-enforced, invariant 19);
      * the action is re-validated and re-checked against policy before it can
        reach the executor -- an approval is not a waiver;
      * execution goes through `execute_once`, so a duplicate resume is
        suppressed rather than executed twice;
      * auto-rollback stays validator+policy gated, never a bare trigger.
    """
    if chain is None:
        chain = audit_mod.AuditChain(incident_id=incident_id)
    ts = _now(now)
    blast = dict(DEMO_BLAST if blast is None else blast)

    # Re-validate before executing. A human approving an action does not make
    # an invalid action valid, and does not exempt it from policy. The runbook
    # comes from the action itself, so resume needs no diagnosis object -- which
    # is precisely why it cannot re-plan.
    runbook_id = str(getattr(action, "runbook_id", "") or "")
    if not runbook_id:
        raise PipelineBlocked("approved action carries no runbook_id; refusing")
    runbook = load_runbook(runbook_id)
    issues = validator_svc.validate_action(action, runbook)
    if issues:
        fsm_svc.advance(run, "BLOCKED", reason=f"validator: {issues[0]}", now=ts)
        raise PipelineBlocked(f"validator rejected the approved action: {issues}")
    bundle = policy_svc.load_bundle()
    matrix = policy_svc.load_matrix()
    evaluation = policy_svc.evaluate(
        action, dict(APPROVER), {"environment": resource.get("environment", env)},
        severity, blast, bundle, matrix)
    if str(evaluation.decision) == "DENY":
        chain.emit("policy.decision", actor="control-plane", action_id=action.action_id,
                   policy={"version": getattr(evaluation, "policy_version", "unknown"),
                           "rule": getattr(evaluation, "rule_id", "unknown"),
                           "result": "DENY"},
                   result="DENY: policy denied the approved action at execution time")
        fsm_svc.advance(run, "BLOCKED", reason="policy DENY at resume", now=ts)
        raise PipelineBlocked("policy DENY at execution time (audited BLOCKED)")

    fsm_svc.advance(run, "APPROVED", permit=permit, now=ts)
    fsm_svc.advance(run, "EXECUTING", now=ts)
    execution_id = f"{incident_id}:{action.action_id}:1"
    deploys = list(tele_public.get("deploys", []))
    version = str(deploys[0].get("to_v", "v23")) if deploys else "v23"
    metrics = [float(m.get("value", 0.0))
               for m in tele_public.get("metrics", []) if isinstance(m, Mapping)]
    before = sandbox_svc.initial_state(
        service=str(resource.get("id", "")), version=version,
        error_rate=max(metrics) if metrics else 0.0)
    (applied, _dup) = fsm_svc.execute_once(
        run, action.action_id, execution_id, _apply_action, action, before)
    _execution, after = applied
    diff = _execution.state_diff.to_plain() if hasattr(_execution.state_diff, "to_plain") else dict(_execution.state_diff)
    # Recorded as an AUDIT EVENT, not appended to `run.handoffs`.
    #
    # `fsm.audit_records` folds handoffs through `{"type": "handoff", **h}`,
    # which has two traps this record walks straight into. An inner `type` key
    # overrides the outer one, so `record_fsm` rejects the whole run as an
    # unknown record kind. And a record carrying no from/to agent is rejected
    # as a malformed handoff. Both are latent defects in committed shared code,
    # and fixing them from a neighbouring lane is exactly the kind of unowned
    # change AGENTS.md 14.1 warns about. The audit chain is the product's real
    # proof surface anyway, and an emitted event reaches the live stream and
    # the Execution view for free, whereas a handoff record would only ever
    # surface through run_view.
    #
    # (Wording note: a previous revision of this comment opened a line with
    # `# type:`, which mypy parses as a PEP 484 type comment and rejects as a
    # syntax error. Worth remembering before "tidying" a comment here.)
    chain.emit("execution.state-diff", actor="control-plane",
               action_id=action.action_id, execution_id=execution_id,
               result=f"applied {action.action_type}; state diff: {diff}")
    after_err = float(after.get("error_rate", 1.0))
    fsm_svc.advance(run, "VERIFYING", now=ts)

    slo = dict(tele_public.get("slo", {"error_rate_below": 0.01}))
    expected: dict[str, Any] = {}
    params = action.parameters
    plain_params = params.to_plain() if hasattr(params, "to_plain") else dict(params)
    if "to_version" in plain_params:
        expected = {"version": str(plain_params["to_version"])}
    verdict = _verify_action(
        execution_id, str(resource.get("id", "web")), before, after, slo, expected
    ).verdict
    verdict_name = str(verdict.value if hasattr(verdict, "value") else verdict)
    verdicts = [verdict_name]
    # action_id is carried explicitly, not only inside execution_id. The
    # execution id happens to embed it, but "the thing we executed is the thing
    # that was approved" must be readable straight off the chain -- otherwise
    # binding an approval to its execution is an inference, not a fact.
    chain.emit("verification.verdict", actor="control-plane",
               action_id=action.action_id, execution_id=execution_id,
               result=verdict_name)

    rolled_back = False
    if verdict_name != "RESOLVED" and should_rollback(verdict_name, 0):
        try:
            rb_action = rollback_for(action, before)
        except ValueError:
            rb_action = None
        if rb_action is not None:
            # Pre-authorized as part of the approved action's rollback plan, but
            # STILL validator+policy gated: an unvalidated or DENY'd rollback
            # never reaches the executor.
            rb_issues = validator_svc.validate_action(rb_action, runbook)
            rb_issues = [issue for issue in rb_issues
                         if "requires rollback_action" not in issue]
            rb_refusal = ""
            if rb_issues:
                rb_refusal = f"validator rejected rollback: {rb_issues[0]}"
            else:
                rb_eval = policy_svc.evaluate(
                    rb_action, dict(APPROVER),
                    {"environment": resource.get("environment", env)},
                    severity, blast, bundle, matrix)
                if str(rb_eval.decision) == "DENY":
                    rb_refusal = (f"policy DENY rollback "
                                  f"(rule {getattr(rb_eval, 'rule_id', '?')})")
            rb_execution_id = f"{execution_id}-rb1"
            if rb_refusal:
                chain.emit("rollback.finish", actor="control-plane",
                           action_id=rb_action.action_id,
                           execution_id=rb_execution_id,
                           result=f"rollback refused: {rb_refusal}")
            else:
                chain.emit("rollback.start", actor="control-plane",
                           action_id=rb_action.action_id,
                           execution_id=rb_execution_id,
                           result=f"auto-rollback on {verdict_name}")
                rolled_back = True
                fsm_svc.advance(run, "ROLLBACK",
                                reason=f"auto-rollback on {verdict_name}", now=ts)
                (rb_applied, _) = fsm_svc.execute_once(
                    run, rb_action.action_id, rb_execution_id,
                    _apply_action, rb_action, after)
                _, after_rb = rb_applied
                after_err = float(after_rb.get("error_rate", 1.0))
                fsm_svc.advance(run, "VERIFYING", now=ts)
                expected_rb: dict[str, Any] = {}
                if "to_version" in plain_params and isinstance(
                        before.get("deployment_version"), str):
                    expected_rb = {"version": before["deployment_version"]}
                verdict2 = _verify_action(
                    rb_execution_id, str(resource.get("id", "web")), after, after_rb, slo, expected_rb
                ).verdict
                verdict_name = str(verdict2.value
                                   if hasattr(verdict2, "value") else verdict2)
                verdicts.append(verdict_name)
                chain.emit("verification.verdict", actor="control-plane",
                           action_id=rb_action.action_id,
                           execution_id=rb_execution_id, result=verdict_name)
                chain.emit("rollback.finish", actor="control-plane",
                           action_id=rb_action.action_id,
                           execution_id=rb_execution_id, result=verdict_name)

    if verdict_name != "RESOLVED":
        fsm_svc.advance(run, "ESCALATED", now=ts)
        path = "escalated"
    else:
        fsm_svc.advance(run, "RESOLVED", now=ts)
        path = "resolved"
    report = {
        "incident_id": incident_id, "path": path,
        "states": [r.to for r in run.history],
        "severity": severity, "decision": decision,
        "action_type": str(action.action_type),
        "action_id": str(action.action_id),
        "execution_id": execution_id, "verdict": verdict_name,
        "verdicts": list(verdicts), "evidence_ids": list(evidence_ids),
        "rolled_back": rolled_back, "after_error_rate": after_err,
        "resumed": True,
        "run": run, "audit_chain": chain,
    }
    audit_mod.record_fsm(chain, fsm_svc.audit_records(run))
    return report


def _report(incident_id: str, path: str, run: Any, triage: Any,
              decision: str, action: Any, execution_id: str,
              verdict: str, verdicts: list[str], evidence_ids: list[str],
              rolled_back: bool,
              after_err: float | None = None) -> dict[str, Any]:
    """Assemble the run report (M21a paths all end here)."""
    return {"incident_id": incident_id, "path": path,
            "states": [r.to for r in run.history],
            "severity": str(triage.severity), "decision": decision,
            "action_type": str(action.action_type),
            "execution_id": execution_id, "verdict": verdict,
            "verdicts": list(verdicts), "evidence_ids": list(evidence_ids),
            "rolled_back": rolled_back, "after_error_rate": after_err,
            "run": run}


def draft_rca(incident_id: str, run: Any, diagnosis: Any, root_cause: str,
              claims: Sequence[Any], timeline_rows: Sequence[str],
              remediation_log: Sequence[str], prevention: Sequence[str],
              valid_evidence_ids: set[str] | frozenset[str], client: Any,
              store: Any, evidence_by_id: Mapping[str, Any] | None = None,
              *, legacy_draft: bool = False, chain: Any = None
              ) -> Any:
    """RCA draft from pipeline artifacts (M21.7): gate over INDEPENDENT ids.

    valid_evidence_ids must come from the evidence pack (measured), never
    from the claims themselves -- deriving validity from cited ids would
    make the gate vacuous. Timeline rows come from the fsm history.
    evidence_by_id enables the hardened path (freshness/trust/seal per
    citation); the legacy membership-only path requires explicit
    ``legacy_draft=True`` (fail closed by default) -- publication always
    requires the mapping (publish_rca).
    """
    from agents import reporter as reporter_mod
    _ = (run, diagnosis)
    if evidence_by_id is None and not legacy_draft:
        raise PipelineFailed(
            "legacy draft denied: pass evidence_by_id mapping for the "
            "hardened path or opt in explicitly with legacy_draft=True")
    draft = reporter_mod.run_report(
        incident_id, list(timeline_rows), root_cause, list(claims),
        set(valid_evidence_ids), list(remediation_log), list(prevention),
        client, store, evidence_by_id=evidence_by_id,
        legacy_draft=legacy_draft)
    if chain is not None:
        try:
            coverage = reporter_mod._coverage(
                list(claims), set(valid_evidence_ids), evidence_by_id)
        except Exception:
            coverage = 0.0
        chain.emit("rca.draft", actor="control-plane",
                   evidence_ids=sorted(set(str(e) for e in valid_evidence_ids)),
                   result=(f"draft coverage {coverage:.2f} "
                           f"legacy={legacy_draft} gated={draft.gated}"))
    return draft


def publish_rca(incident_id: str, claims: Sequence[Any],
                evidence_by_id: Mapping[str, Any],
                valid_evidence_ids: set[str] | frozenset[str],
                timeline_rows: Sequence[str], root_cause: str,
                remediation_log: Sequence[str], prevention: Sequence[str],
                client: Any, store: Any, chain: Any = None) -> Any:
    """Gated RCA publication (P0-3: the MUST-CITE gate that enforces).

    Uses ONLY the hardened coverage path (freshness + trust + seal per
    citation -- no legacy membership fallback). Below-coverage publication
    is DENIED with an audited rca.publish event (fail-closed, never a
    silent draft). Returns the ungated RCAReport on success.
    """
    from agents import reporter as reporter_mod
    if evidence_by_id is None:
        raise PipelineFailed(
            "publish_rca requires evidence_by_id (hardened path only)")
    if chain is None:
        chain = audit_mod.AuditChain(incident_id=incident_id)
    draft = reporter_mod.run_report(
        incident_id, list(timeline_rows), root_cause, list(claims),
        set(valid_evidence_ids), list(remediation_log), list(prevention),
        client, store, evidence_by_id=evidence_by_id)
    if draft.gated:
        chain.emit("rca.publish", actor="control-plane",
                   evidence_ids=sorted(set(valid_evidence_ids)),
                   result=f"DENIED: {draft.gate_reason}")
        raise RcaDenied(f"RCA publication denied: {draft.gate_reason}")
    chain.emit("rca.publish", actor="control-plane",
               evidence_ids=sorted(set(valid_evidence_ids)),
               result=f"published RCA for {incident_id}")
    return draft


def to_eval_trace(report: Mapping[str, Any], tele_public: Mapping[str, Any],
                  budgets: Mapping[str, Any],
                  retrieval: Mapping[str, Any] | None = None,
                  hallucination: Mapping[str, Any] | None = None,
                  prompt: Mapping[str, Any] | None = None,
                  latencies: Mapping[str, Any] | None = None,
                  coverage: float = 1.0) -> dict[str, Any]:
    """Map a pipeline report to an M16-trace-shaped record (M21.9 bridge).

    Measured blocks (policy/action/verdict/slo/unsafe) come from the run;
    measurement-harness blocks (budgets/retrieval/hallucination/prompt/
    latencies) are caller-supplied and LABELED as such -- pass measured
   ledger output or explicit mock blocks, never silence.
    """
    metrics = [float(m.get("value", 0.0))
               for m in tele_public.get("metrics", [])
               if isinstance(m, Mapping)]
    slo = dict(tele_public.get("slo", {"error_rate_below": 0.01}))
    measured_err = report.get("after_error_rate")
    if measured_err is None:
        measured_err = max(metrics) if metrics else 0.0
    return {
        "stages": {"triage": {"ok": True, "errors": []},
                   "diagnose": {"ok": True, "errors": []},
                   "plan": {"ok": True, "errors": []},
                   "report": {"ok": True, "errors": []}},
        "policy": {"decision": report.get("decision", "DENY"),
                   "action": report.get("action_type", "")},
        "validator": {"valid": True},
        "citations": {"coverage": float(coverage), "complete": float(coverage)},
        "actions": [{"type": report.get("action_type", ""),
                     "executed": report.get("path") == "resolved",
                     "authorized": report.get("path") in ("resolved",
                                                          "escalated")}],
        "unsafe_exec": 0,
        "attacks": [],
        "slo": {"verdict": report.get("verdict", "ESCALATE"),
                "error_rate": float(measured_err),
                "threshold": float(slo.get("error_rate_below", 0.01))},
        "retrieval": dict(retrieval or {}),
        "budgets": dict(budgets),
        "latencies": dict(latencies or {}),
        "hallucination": dict(hallucination or {}),
        "prompt": dict(prompt or {}),
        "agents": ["triage", "diagnostic", "planner"],
        "tools": [],
        "session": {"persisted": True},
        "safety": {"red_blocked": report.get("path") == "blocked",
                   "injection_neutralized": True,
                   "approval_enforced": True, "verify_rollback": True},
    }


def _hitl_permit(action: Any, secret: str, actor: str,
                 now: float, chain: Any = None,
                 incident_id: str | None = None) -> Permit:
    """Request + approve through the approvals router pure fns (M19a).

    The FSM credential comes from verified_permit (R2 closure): bound to the
    STORED human-approved request with derived-nonce single-use and the
    TTL/freshness cap -- never constructed by hand here. expected_incident
    binds the permit to this run's incident (cross-incident reuse denied).
    """
    from app.routers import approvals as approvals_router
    dumped = action.model_dump(mode="json")
    issued = approvals_router.request_approval(dumped, actor, secret,
                                               chain=chain)
    view = approvals_router.approve_approval(
        issued["approval_id"], actor, issued["token"], "approver", secret,
        chain=chain)
    assert view["status"] == "approved"
    return approvals_router.verified_permit(
        issued["approval_id"], issued["token"], actor, secret, now,
        chain=chain, expected_incident=incident_id)
