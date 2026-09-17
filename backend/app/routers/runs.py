"""M14b runs router: HTTP translation over the deterministic FSM (thin).

Ownership: M14 owns THIS ROUTER. Every decision lives in services/fsm.py
and agents/*; handlers validate shape, map errors to typed HTTP codes, and
pass through. No policy/crypto/execution logic here.

Deliberately NOT exposed (owning modules): approve/reject (M15 HITL API),
execute_action (M08 sandbox), auth guard matrix (M21 -- runs are in-memory
demo state with no infra side effects, and EXECUTING still demands a permit
credential in-body). Singletons REPO/STORE are demo-scope; persistence is
M21's job.

Pure functions (create_run/run_view/advance_run/sweep_run/triage_run/...)
carry all logic and are unit-tested without HTTP; the @router wrappers only
translate. (The crippled host cannot run starlette TestClient, so tests
target the pure layer plus an AST wiring assertion.)
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, Field

try:  # pragma: no cover - container path (pinned deps); host drift noted below
    from fastapi import APIRouter as _APIRouter
    from fastapi import HTTPException as _HTTPException
    _APIRouter(prefix="/__probe__")  # host starlette v1.x breaks construction
    router = _APIRouter(prefix="/runs", tags=["runs"])
    HTTPException = _HTTPException
except Exception:  # host-only drift: starlette v1.x vs pinned container deps
    # (AGENTS.md S13.2 -- host runs unit/structure tests only). Pure
    # functions below stay fully testable; routes register in the container.
    router = None  # type: ignore[assignment]

    class HTTPException(Exception):  # type: ignore[no-redef]
        def __init__(self, status_code: int = 500, detail: str = "") -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agents import diagnostic as A2  # noqa: E402 (M13.3)
from agents import lyzr_client as LC  # noqa: E402 (M13.1)
from agents import planner as A3  # noqa: E402 (M13.4)
from agents import reporter as A4  # noqa: E402 (M13.5)
from agents import session as session_mod  # noqa: E402 (M13.7)
from agents import triage as A1  # noqa: E402 (M13.2)
from agents.schemas import (  # noqa: E402 (M13.6)
    BudgetExceeded,
    DiagnosticResult,
    OutputRejected,
    parse_or_reject,
)
from app.contracts.hypothesis import Claim  # noqa: E402 (M01.5)
from app.services import fsm as fsm_svc  # noqa: E402 (M14a canonical FSM)
from app.services.fsm import (  # noqa: E402
    FsmError,
    IncidentRun,
    InvalidTransition,
    Permit,
    PermitRejected,
)

REPO_STORE: dict[str, IncidentRun] = {}
SESSIONS = session_mod.SessionStore()
IDEM_RESPONSES: dict[tuple[str, str, str], dict[str, Any]] = {}


class RepoExists(FsmError):
    """Duplicate incident open (HTTP 409)."""


class RepoMissing(FsmError):
    """Unknown incident id (HTTP 404)."""


def http_status(exc: Exception) -> int:
    """Fail-closed error mapping (spec S40 typed errors)."""
    if isinstance(exc, RepoMissing):
        return 404
    if isinstance(exc, (RepoExists, InvalidTransition)):
        return 409
    if isinstance(exc, PermitRejected):
        return 410 if "expired" in str(exc).lower() else 403
    if isinstance(exc, OutputRejected):
        return 422
    if isinstance(exc, BudgetExceeded):
        return 429
    if isinstance(exc, (FsmError, ValueError)):
        return 400
    return 500


def create_run(incident_id: str, now: float | None = None) -> IncidentRun:
    if incident_id in REPO_STORE:
        raise RepoExists(f"run already open: {incident_id}")
    run = fsm_svc.new_run(incident_id, now=now)
    REPO_STORE[incident_id] = run
    return run


def get_run(incident_id: str) -> IncidentRun:
    try:
        return REPO_STORE[incident_id]
    except KeyError as exc:
        raise RepoMissing(f"unknown incident: {incident_id}") from exc


def list_runs() -> list[dict[str, Any]]:
    """Queue summaries for the Command Center (M19a queue)."""
    return [{"incident_id": run.incident_id, "state": run.state,
             "history_len": len(run.history)}
            for run in REPO_STORE.values()]


def run_view(run: IncidentRun) -> dict[str, Any]:
    return {
        "incident_id": run.incident_id,
        "state": run.state,
        "replans": run.replans,
        "rolled_back": run.rolled_back,
        "permit_pending": run.permit is not None,
        "history": [{"seq": r.seq, "frm": r.frm, "to": r.to,
                     "reason": r.reason, "refs": list(r.refs),
                     "forced": r.forced, "at": r.at} for r in run.history],
        "handoffs": [dict(h) for h in run.handoffs],
        "audit_records": fsm_svc.audit_records(run),
    }


def _permit_from(payload: Mapping[str, Any] | None) -> Permit | None:
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise PermitRejected("permit must be a mapping")
    try:
        return Permit(action_id=str(payload["action_id"]),
                      params_hash=str(payload["params_hash"]),
                      expires_at=float(payload["expires_at"]),
                      token_ref=str(payload["token_ref"]),
                      auto=bool(payload.get("auto", False)))
    except (KeyError, TypeError, ValueError) as exc:
        raise PermitRejected(f"malformed permit: {exc}") from exc


def advance_run(incident_id: str, to: str, *, reason: str = "",
                refs: Sequence[str] = (),
                permit: Mapping[str, Any] | None = None,
                idempotency_key: str | None = None,
                now: float | None = None) -> dict[str, Any]:
    """Guarded transition with HTTP idempotency (M14.5 over HTTP)."""
    run = get_run(incident_id)
    if idempotency_key is not None:
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise FsmError("idempotency_key must be a non-empty string")
        cache_key = (incident_id, to, idempotency_key)
        if cache_key in IDEM_RESPONSES:
            cached = dict(IDEM_RESPONSES[cache_key])
            cached["duplicate"] = True
            return cached
    state = fsm_svc.advance(run, to, reason=reason, refs=list(refs),
                            permit=_permit_from(permit), now=now)
    view = run_view(run)
    view["duplicate"] = False
    if idempotency_key is not None:
        IDEM_RESPONSES[(incident_id, to, idempotency_key)] = dict(view)
    _ = state
    return view


def sweep_run(incident_id: str, now: float, stage_ttl: float | None = None,
              approval_ttl: float | None = None) -> dict[str, Any]:
    run = get_run(incident_id)
    kwargs: dict[str, float] = {}
    if stage_ttl is not None:
        kwargs["stage_ttl"] = float(stage_ttl)
    if approval_ttl is not None:
        kwargs["approval_ttl"] = float(approval_ttl)
    escalated = fsm_svc.sweep(run, float(now), **kwargs)
    view = run_view(run)
    view["escalated"] = escalated
    return view


def build_client(api_key: str, agent_ids: Mapping[str, str],
                 rai_policy: str = LC.RAI_POLICY_DEFAULT) -> LC.LyzrClient:
    """Server-side client from config values (keys never come from callers)."""
    return LC.LyzrClient(LC.ClientConfig(
        api_key=api_key, agent_ids=dict(agent_ids), rai_policy=rai_policy))


def triage_run(store: session_mod.SessionStore, client: Any,
               incident_id: str, alerts: list[Mapping[str, Any]],
               deploy_id: str = "") -> dict[str, Any]:
    out = A1.run_triage(alerts, incident_id, client, store,
                        deploy_id=deploy_id)
    return out.model_dump(mode="json")


def diagnose_run(store: session_mod.SessionStore, client: Any,
                 incident_id: str, service: str, env: str,
                 pack: Mapping[str, Any]) -> dict[str, Any]:
    out = A2.run_diagnose(incident_id, service, env, pack, client, store)
    return out.model_dump(mode="json")


def plan_run(store: session_mod.SessionStore, client: Any,
             incident_id: str, diagnosis: Mapping[str, Any],
             resource: Mapping[str, Any],
             evidence_ids: Sequence[str]) -> dict[str, Any]:
    parsed = parse_or_reject(DiagnosticResult, diagnosis)
    assert isinstance(parsed, DiagnosticResult)
    out = A3.run_plan(incident_id, parsed, resource, client, store,
                      tuple(str(e) for e in evidence_ids))
    return out.model_dump(mode="json")


def report_run(store: session_mod.SessionStore, client: Any,
               incident_id: str, timeline: Sequence[str], root_cause: str,
               claims: Sequence[Mapping[str, Any]],
               valid_evidence_ids: Sequence[str],
               remediation_log: Sequence[str],
               prevention: Sequence[str]) -> dict[str, Any]:
    claim_objs = [Claim(**dict(c)) for c in claims]
    out = A4.run_report(incident_id, list(timeline), root_cause, claim_objs,
                        set(str(e) for e in valid_evidence_ids),
                        list(remediation_log), list(prevention),
                        client, store)
    return out.model_dump(mode="json")


def reset_demo_state() -> None:
    """Test/demo helper: clear in-memory runs, sessions, idempotency."""
    REPO_STORE.clear()
    IDEM_RESPONSES.clear()
    SESSIONS.reset()


# ---------------------------------------------------------------------------
# Thin HTTP translation (shape validation + error mapping only)
# ---------------------------------------------------------------------------

class CreateBody(BaseModel):
    model_config = {"extra": "forbid"}
    incident_id: str = Field(min_length=1, max_length=128)
    now: float | None = None


class AdvanceBody(BaseModel):
    model_config = {"extra": "forbid"}
    to: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=1024)
    refs: list[str] = Field(default_factory=list, max_length=64)
    permit: dict[str, Any] | None = None
    idempotency_key: str | None = Field(default=None, max_length=128)


class SweepBody(BaseModel):
    model_config = {"extra": "forbid"}
    now: float
    stage_ttl: float | None = None
    approval_ttl: float | None = None


def _guarded(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        raise HTTPException(status_code=http_status(exc),
                            detail=str(exc)) from exc


def http_create(body: CreateBody) -> dict[str, Any]:
    run = _guarded(create_run, body.incident_id, body.now)
    return run_view(run)


def http_get(incident_id: str) -> dict[str, Any]:
    return _guarded(lambda: run_view(get_run(incident_id)))


def http_list() -> list[dict[str, Any]]:
    return _guarded(list_runs)


def http_advance(incident_id: str, body: AdvanceBody) -> dict[str, Any]:
    return _guarded(advance_run, incident_id, body.to, reason=body.reason,
                    refs=body.refs, permit=body.permit,
                    idempotency_key=body.idempotency_key)


def http_sweep(incident_id: str, body: SweepBody) -> dict[str, Any]:
    return _guarded(sweep_run, incident_id, body.now,
                    stage_ttl=body.stage_ttl,
                    approval_ttl=body.approval_ttl)


if router is not None:  # container path; host asserts wiring via AST
    router.post("", status_code=201)(http_create)
    router.get("")(http_list)
    router.get("/{incident_id}")(http_get)
    router.post("/{incident_id}/advance")(http_advance)
    router.post("/{incident_id}/sweep")(http_sweep)
