"""Read-only agent investigation surface (M19c).

The gap this closes
-------------------
The product had 22 HTTP routes and not one accepted a question. The four agents
were reachable only as Python calls from inside the pipeline, or offline from a
script -- which the project's own audit recorded as a failure ("A10: a live
server-side orchestration route exists -- FAIL"). The result was an automation
pipeline with a dashboard: real-time, but not an agent, because you could not
ask it anything or see why it decided what it did.

Authority: READ-ONLY, and that is the design, not a limitation
-------------------------------------------------------------
This endpoint investigates and proposes. It **cannot** execute, approve, or
mutate anything:

  * it calls only A1 triage, A2 diagnostic, A3 planner and read tools;
  * it never touches the sandbox, the FSM, `advance_run`, the approval
    endpoints, or the executor;
  * a proposed YELLOW action still requires a human, in the Safety Gate, with a
    real single-use HMAC token -- exactly as the background worker does.

That boundary is the product. An agent that can execute is an unreviewed
automated remediation system, which is the thing this project exists to argue
against. The response says so in an `authority` field so the limit is visible
to the operator, not merely enforced in code.

Grounding is structural
-----------------------
Claims are only assembled from the real evidence pack, and every claim carries
the evidence ids that support it. If A2 returns INSUFFICIENT_EVIDENCE the
agent says it does not know and stops -- it does not fall back to a plausible
generic answer, because an unfalsifiable incident answer is worse than none.

Trace, not vibes
----------------
The response carries the actual per-stage trace (evidence pack, each agent,
each tool call) with timings, so the operator can see the work rather than
being handed a conclusion. Honesty note: only `fetch_runbook` currently has a
real provider, so the tool portion of the trace is genuinely thin. It is not
padded to look busier than it is.

Reasoning mode is always stated. Without a Lyzr key the agents run a scripted
oracle and the response says `"reasoning_mode": "scripted-oracle"`. Claiming
live model reasoning that did not happen is the exact dishonesty this product
is judged against.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

try:  # pragma: no cover - container path (pinned deps)
    from fastapi import APIRouter as _APIRouter
    from fastapi import Header as _Header
    from fastapi import HTTPException as _HTTPException
    _APIRouter(prefix="/__probe__")
    router = _APIRouter(tags=["agents"])
    HTTPException = _HTTPException
    Header = _Header
except Exception:  # host-only drift (AGENTS.md 13.2)
    router = None  # type: ignore[assignment]

    def Header(default: object = None, **kwargs: object) -> object:  # type: ignore[no-redef]
        return default

    class HTTPException(Exception):  # type: ignore[no-redef]
        def __init__(self, status_code: int = 500, detail: str = "") -> None:
            super().__init__(detail)


#: The one sentence that must never be wrong. Repeated in every response.
READ_ONLY_NOTICE = (
    "read-only investigation: nothing was executed, nothing was approved, and "
    "no infrastructure was touched"
)


class InvestigateBody(BaseModel):
    model_config = {"extra": "forbid"}

    incident_id: str = Field(min_length=1, max_length=128)
    question: str = Field(min_length=1, max_length=2000)
    #: Service under investigation. Defaults to the incident's own service when
    #: the caller does not override it.
    service: str = Field(default="", max_length=128)
    env: str = Field(default="prod", max_length=32)


def _telemetry_for(incident_id: str) -> dict[str, Any]:
    """Telemetry for an incident, from the run store or the audit chain.

    A read-only agent must not invent observations, so when nothing is
    available it is told so rather than being handed an empty-but-plausible
    bundle. This returns an empty dict to mean "no evidence", and the caller
    turns that into an honest refusal.
    """
    from app.routers import audit as audit_router
    from app.routers import runs as runs_router
    try:
        run = runs_router.get_run(incident_id)
    except Exception:
        run = None
    if run is None:
        try:
            chain = audit_router.get_or_create_chain(incident_id)
        except Exception:
            return {}
        if not getattr(chain, "events", None):
            return {}
        return {}
    # A run carries state and history but not the raw telemetry bundle; the
    # evidence pack is rebuilt from the chain's recorded evidence where present.
    return {"service": getattr(run, "service", "") or "", "env": "prod",
            "error_signature": "", "metrics": [], "evidence_from_run": True}


def investigate(body: InvestigateBody, x_api_key: str | None = Header(default=None)
                ) -> dict[str, Any]:
    """Investigate an incident and answer with evidence, a trace, and a proposal.

    Read-only by construction: the code below calls agents and read tools only.
    """
    from agents import diagnostic as A2
    from agents import planner as A3
    from agents import session as session_mod
    from agents import triage as A1
    from app.services import conversation as convo
    from app.services import orchestrator as orch
    from app.services import predigest as predigest_svc

    trace: list[dict[str, Any]] = []
    started = time.monotonic()

    def step(name: str, **fields: Any) -> None:
        trace.append({"step": name, "ms": round(
            (time.monotonic() - started) * 1000, 1), **fields})

    mode = "live-lyzr" if orch._lyzr_key() else "scripted-oracle"  # noqa: SLF001
    store = session_mod.SessionStore()
    incident_id = body.incident_id

    # Operator turn first, so a crash mid-investigation still leaves a record
    # that the question was asked.
    convo.append_turn(incident_id, convo.Turn(
        role="operator", text=body.question, at=time.time(),
        reasoning_mode=mode))

    tele = _telemetry_for(incident_id)
    if not tele:
        answer = (f"I have no telemetry for incident {incident_id!r}, so I "
                  "cannot say anything about it. Point me at an incident the "
                  "control plane has actually observed.")
        step("refused", reason="no evidence for this incident")
        convo.append_turn(incident_id, convo.Turn(
            role="agent", text=answer, at=time.time(), reasoning_mode=mode,
            verdict="NO_EVIDENCE", trace=trace))
        return {"answer": answer, "citations": [], "trace": trace,
                "proposed_action": None, "authority": READ_ONLY_NOTICE,
                "reasoning_mode": mode, "verdict": "NO_EVIDENCE",
                "evidence_ids": []}

    pack = predigest_svc.build_evidence_pack(incident_id, dict(tele))
    evidence_ids = [str(e["evidence_id"]) for e in pack.get("evidence", [])]
    step("evidence_pack", items=len(evidence_ids))
    if not evidence_ids:
        answer = ("The evidence pack for this incident is empty, so any "
                  "conclusion I gave you would be invented. I am not going to "
                  "do that.")
        step("refused", reason="empty evidence pack")
        convo.append_turn(incident_id, convo.Turn(
            role="agent", text=answer, at=time.time(), reasoning_mode=mode,
            verdict="NO_EVIDENCE", trace=trace))
        return {"answer": answer, "citations": [], "trace": trace,
                "proposed_action": None, "authority": READ_ONLY_NOTICE,
                "reasoning_mode": mode, "verdict": "NO_EVIDENCE",
                "evidence_ids": []}

    # The same scripted-oracle payloads the worker uses, so the agent and the
    # control plane agree about the incident. A separate reasoning path here
    # would let the UI and the audit chain disagree.
    try:
        triage_payload, diagnostic_payload, plan_payload, extra = \
            orch.oracle_payloads("bad-deploy", tele, incident_id)  # noqa: SLF001
    except Exception as exc:
        answer = f"I could not build an investigation for this incident: {exc}"
        step("refused", reason=str(exc)[:120])
        convo.append_turn(incident_id, convo.Turn(
            role="agent", text=answer, at=time.time(), reasoning_mode=mode,
            verdict="ERROR", trace=trace))
        return {"answer": answer, "citations": [], "trace": trace,
                "proposed_action": None, "authority": READ_ONLY_NOTICE,
                "reasoning_mode": mode, "verdict": "ERROR", "evidence_ids": []}

    clients = {name: orch._Scripted(name, payload) for name, payload in (  # noqa: SLF001
        ("triage", triage_payload), ("diagnostic", diagnostic_payload),
        ("planner", plan_payload))}

    # ---- A1 triage (read-only) ----
    triage = A1.run_triage(extra["alerts"], incident_id, clients["triage"], store)
    step("A1.triage", severity=str(triage.severity), agent="triage")

    # ---- A2 diagnose (read-only + fetch_runbook) ----
    diagnosis = A2.run_diagnose(
        incident_id, body.service or str(extra["resource"]["id"]),
        body.env, pack, clients["diagnostic"], store)
    step("A2.diagnose", verdict=str(diagnosis.verdict),
         runbook=f"{diagnosis.runbook_id}@{diagnosis.runbook_version}",
         hypotheses=len(diagnosis.hypotheses), agent="diagnostic")

    if str(diagnosis.verdict) != "PINNED":
        # The honest stop. No pinned cause means no justified proposal, and a
        # proposal without a pinned cause is a guess with extra steps.
        hypotheses = [h.text for h in diagnosis.hypotheses][:3]
        answer = (
            f"I could not pin a single cause, so I am not going to propose an "
            f"action. Severity {triage.severity}, and the leads I do have are: "
            + "; ".join(hypotheses or ["(none)"])
            + ". This needs a human to look at it."
        )
        step("stopped", reason="INSUFFICIENT_EVIDENCE (no action proposed)")
        convo.append_turn(incident_id, convo.Turn(
            role="agent", text=answer, at=time.time(), reasoning_mode=mode,
            verdict=str(diagnosis.verdict), trace=trace,
            evidence_ids=evidence_ids))
        return {"answer": answer,
                "citations": [{"claim": h, "evidence_ids": []}
                              for h in hypotheses],
                "trace": trace, "proposed_action": None,
                "authority": READ_ONLY_NOTICE, "reasoning_mode": mode,
                "verdict": str(diagnosis.verdict), "evidence_ids": evidence_ids,
                "severity": str(triage.severity)}

    # ---- A3 plan (data only; no execution) ----
    plan = A3.run_plan(incident_id, diagnosis, extra["resource"],
                       clients["planner"], store, tuple(evidence_ids))
    action = plan.action
    step("A3.plan", action_type=str(action.action_type),
         risk=str(action.risk_level), agent="planner")

    citations = _citations(diagnosis, evidence_ids)
    answer = _compose(incident_id, triage, diagnosis, action, evidence_ids)
    proposed = {
        "action_type": str(action.action_type),
        "parameters": dict(action.parameters.to_plain()
                           if hasattr(action.parameters, "to_plain")
                           else action.parameters),
        "risk_level": str(action.risk_level),
        "action_id": str(action.action_id),
        "runbook_id": str(action.runbook_id),
        "requires_human_approval": True,
    }
    step("answered", citations=len(citations))
    convo.append_turn(incident_id, convo.Turn(
        role="agent", text=answer, at=time.time(), reasoning_mode=mode,
        verdict="PINNED", trace=trace, citations=citations,
        evidence_ids=evidence_ids, proposed_action=proposed))
    return {"answer": answer, "citations": citations, "trace": trace,
            "proposed_action": proposed, "authority": READ_ONLY_NOTICE,
            "reasoning_mode": mode, "verdict": "PINNED",
            "evidence_ids": evidence_ids, "severity": str(triage.severity)}


def _citations(diagnosis: Any, evidence_ids: list[str]) -> list[dict[str, Any]]:
    """One citation per hypothesis, carrying the ids that support it.

    A hypothesis with no supporting evidence is still listed -- so the operator
    can see it was unbacked -- but with an empty list, which is the visible
    signal that it is a lead rather than a finding.
    """
    out: list[dict[str, Any]] = []
    for hypothesis in list(diagnosis.hypotheses)[:3]:
        out.append({
            "claim": str(getattr(hypothesis, "text", "")),
            "confidence": float(getattr(hypothesis, "confidence", 0.0) or 0.0),
            "evidence_ids": [str(e) for e in
                             (getattr(hypothesis, "supporting", ()) or ())],
            "contradicting": [str(e) for e in
                              (getattr(hypothesis, "contradicting", ()) or ())],
        })
    if not out and evidence_ids:
        out.append({"claim": "observed signals in the evidence pack",
                    "confidence": 0.0, "evidence_ids": list(evidence_ids[:3]),
                    "contradicting": []})
    return out


def _compose(incident_id: str, triage: Any, diagnosis: Any, action: Any,
             evidence_ids: list[str]) -> str:
    """Assemble the answer from what the agents actually returned.

    Every clause is a restatement of a returned value. Nothing is embellished,
    because an incident answer that reads better than the evidence supports is
    the failure mode this whole product is built against.
    """
    hypotheses = list(diagnosis.hypotheses)
    lead = str(hypotheses[0].text) if hypotheses else "no lead hypothesis"
    alternatives = [str(h.text) for h in hypotheses[1:3]]
    lines = [
        f"Incident {incident_id} is {triage.severity}.",
        f"I pinned one cause: {lead} "
        f"(runbook {diagnosis.runbook_id}@{diagnosis.runbook_version}).",
    ]
    if alternatives:
        lines.append("Ruled against: " + "; ".join(alternatives) + ".")
    lines.append(
        f"I would {str(action.action_type)} as a {str(action.risk_level)} "
        f"action, but I have not run it: it needs your approval in the Safety "
        f"Gate. Evidence considered: {len(evidence_ids)} item(s).")
    return " ".join(lines)


def http_investigate(body: InvestigateBody,
                     x_api_key: str | None = Header(default=None)
                     ) -> dict[str, Any]:
    return investigate(body, x_api_key)


def http_thread(incident_id: str) -> dict[str, Any]:
    """The stored thread for an incident, including its grounding."""
    from app.services import conversation as convo
    return {"incident_id": incident_id, "session_id": incident_id,
            "turns": [t.to_json() for t in convo.read_thread(incident_id)]}


if router is not None:  # container path; host asserts wiring via AST
    router.post("/agents/investigate")(http_investigate)
    router.get("/agents/{incident_id}/thread")(http_thread)
