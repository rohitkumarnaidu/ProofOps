"""M14b runs router: HTTP translation over the deterministic FSM (thin).

Ownership: M14 owns THIS ROUTER. Every decision lives in services/fsm.py
and agents/*; handlers validate shape, map errors to typed HTTP codes, and
pass through. No policy/crypto/execution logic here.

Deliberately NOT exposed (owning modules): approve/reject (M15 HITL API),
execute_action (M08 sandbox). Mutating handlers require X-API-Key (M21
guard matrix); APPROVED additionally requires an HMAC-bound approval
(approval_id + token + actor verified against the STORED M07 request --
client JSON never mints permits, P0-1). Every accepted transition is
recorded into the incident audit chain (P0-2). Singletons REPO/STORE are
demo-scope; file-backed nonce durability is M07's job.

Pure functions (create_run/run_view/advance_run/sweep_run/triage_run/...)
carry all logic and are unit-tested without HTTP; the @router wrappers only
translate. (The crippled host cannot run starlette TestClient, so tests
target the pure layer plus an AST wiring assertion.)
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, Field

try:  # pragma: no cover - container path (pinned deps); host drift noted below
    from fastapi import APIRouter as _APIRouter
    from fastapi import Header as _Header
    from fastapi import HTTPException as _HTTPException
    _APIRouter(prefix="/__probe__")  # host starlette v1.x breaks construction
    router = _APIRouter(prefix="/runs", tags=["runs"])
    HTTPException = _HTTPException
    Header = _Header
except Exception:  # host-only drift: starlette v1.x vs pinned container deps
    # (AGENTS.md S13.2 -- host runs unit/structure tests only). Pure
    # functions below stay fully testable; routes register in the container.
    router = None  # type: ignore[assignment]

    def Header(default: object = None, **kwargs: object) -> object:  # type: ignore[no-redef]
        return default

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
    TransitionRecord,
)

REPO_STORE: dict[str, IncidentRun] = {}
SESSIONS = session_mod.SessionStore()
IDEM_RESPONSES: dict[tuple[str, str, str], dict[str, Any]] = {}

#: File-persistence for the run repo (Lane 2, hardening loop 4).
#: Sanitized constant -- callers never choose the production path; tests may
#: pass an explicit tmp path via the ``path`` parameter of save/load.
STORE_PATH = Path(__file__).resolve().parents[3] / "var" / "runs.json"

# NOTE (Lane 2): IDEM_RESPONSES (router-level HTTP cache) is intentionally
# NOT persisted -- it only replays identical HTTP bodies within a process.
# Likewise run.idem_store (FSM execute_once result cache) is NOT persisted:
# its values are opaque callback results that may not be JSON-serializable,
# and a cold cache after restart simply re-runs once under fresh
# verification + audit. FSM-level duplicate SUPPRESSION survives via
# run.suppressions (persisted below), which is the audit-grade record.


def _run_to_json(run: IncidentRun) -> dict[str, Any]:
    """Serialize one run: dataclasses.asdict + set->sorted-list (Lane 2)."""
    return {
        "incident_id": run.incident_id,
        "state": run.state,
        "history": [dataclasses.asdict(r) for r in run.history],
        "handoffs": [dict(h) for h in run.handoffs],
        "suppressions": [dict(s) for s in run.suppressions],
        "replans": run.replans,
        "rolled_back": run.rolled_back,
        "permit": dataclasses.asdict(run.permit)
        if run.permit is not None else None,
        "consumed_refs": sorted(run.consumed_refs),
        "entered_at": dict(run.entered_at),
    }


def _dict_list(raw: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list) \
            or any(not isinstance(h, Mapping) for h in raw):
        raise ValueError(f"run {name} must be a list of objects")
    return [dict(h) for h in raw]


def _record_from_json(item: Any) -> TransitionRecord:
    if not isinstance(item, Mapping):
        raise ValueError("history record must be an object")
    allowed = {"seq", "frm", "to", "reason", "refs", "forced", "at"}
    if set(item) - allowed:
        raise ValueError("history record holds unexpected keys")
    try:
        seq = item["seq"]
        frm = item["frm"]
        to = item["to"]
        reason = item["reason"]
        refs = item["refs"]
        forced = item["forced"]
        at = item["at"]
    except KeyError as exc:
        raise ValueError(f"history record missing {exc}") from exc
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValueError("history record seq must be an int")
    for name, value in (("frm", frm), ("to", to), ("reason", reason)):
        if not isinstance(value, str):
            raise ValueError(f"history record {name} must be a str")
    if not isinstance(refs, list) \
            or any(not isinstance(r, str) for r in refs):
        raise ValueError("history record refs must be a string list")
    if not isinstance(forced, bool):
        raise ValueError("history record forced must be a bool")
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        raise ValueError("history record at must be epoch seconds")
    return TransitionRecord(seq=seq, frm=frm, to=to, reason=reason,
                            refs=list(refs), forced=forced, at=float(at))


def _permit_from_json(raw: Any) -> Permit | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("run permit must be an object or null")
    allowed = {"action_id", "params_hash", "expires_at", "token_ref", "auto"}
    if set(raw) - allowed:
        raise ValueError("run permit holds unexpected keys")
    auto = raw.get("auto", False)
    if not isinstance(auto, bool):
        raise ValueError("run permit auto must be a bool")
    try:
        return Permit(action_id=raw["action_id"],
                      params_hash=raw["params_hash"],
                      expires_at=raw["expires_at"],
                      token_ref=raw["token_ref"], auto=auto)
    except KeyError as exc:
        raise ValueError(f"run permit missing {exc}") from exc
    except Exception as exc:  # PermitRejected on empty/shape garbage
        raise ValueError(f"run permit invalid: {exc}") from exc


def _run_from_json(payload: Any) -> IncidentRun:
    """Rebuild one run via constructors; ValueError on garbage (fail-closed).

    IncidentRun/Permit constructors enforce their own invariants (unknown
    state, blank ids, empty permit refs); scalar fields without constructor
    checks are validated explicitly above so tampered types cannot load.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("run entry must be an object")
    for key in ("incident_id", "state", "history", "handoffs",
                "suppressions", "replans", "rolled_back", "permit",
                "consumed_refs", "entered_at"):
        if key not in payload:
            raise ValueError(f"run entry missing {key!r}")
    if set(payload) - {"incident_id", "state", "history", "handoffs",
                        "suppressions", "replans", "rolled_back", "permit",
                        "consumed_refs", "entered_at"}:
        raise ValueError("run entry holds unexpected keys")
    raw_history = payload["history"]
    if not isinstance(raw_history, list):
        raise ValueError("run history must be a list")
    history = [_record_from_json(item) for item in raw_history]
    replans = payload["replans"]
    if isinstance(replans, bool) or not isinstance(replans, int) \
            or replans < 0:
        raise ValueError("run replans must be a non-negative int")
    rolled_back = payload["rolled_back"]
    if not isinstance(rolled_back, bool):
        raise ValueError("run rolled_back must be a bool")
    consumed = payload["consumed_refs"]
    if not isinstance(consumed, list) \
            or any(not isinstance(c, str) for c in consumed):
        raise ValueError("run consumed_refs must be a string list")
    entered = payload["entered_at"]
    if not isinstance(entered, Mapping):
        raise ValueError("run entered_at must be an object")
    entered_at: dict[str, float] = {}
    for key, value in entered.items():
        if not isinstance(key, str) or isinstance(value, bool) \
                or not isinstance(value, (int, float)):
            raise ValueError("run entered_at must map str -> epoch seconds")
        entered_at[key] = float(value)
    try:
        return IncidentRun(
            incident_id=payload["incident_id"],
            state=payload["state"],
            history=history,
            handoffs=_dict_list(payload["handoffs"], "handoffs"),
            suppressions=_dict_list(payload["suppressions"], "suppressions"),
            replans=replans,
            rolled_back=rolled_back,
            permit=_permit_from_json(payload["permit"]),
            consumed_refs=set(consumed),
            entered_at=entered_at,
        )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"run entry invalid: {exc}") from exc


def _read_store(path: Path) -> dict[str, IncidentRun]:
    """Validate the whole file into staged runs (no live-dict side effects).

    Raises ValueError on any corrupt entry (never partial); FileNotFoundError
    when missing; ValueError when unreadable. Key/entry incident mismatch
    fails closed (same discipline as the audit chain owner check).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError(f"runs file unreadable: {exc}") from exc
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"runs file corrupt: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("runs file corrupt: top-level object required")
    staged: dict[str, IncidentRun] = {}
    for incident_id, item in raw.items():
        run = _run_from_json(item)
        if incident_id != run.incident_id:
            raise ValueError(
                f"runs file key {incident_id!r} mismatches "
                f"entry {run.incident_id!r}")
        staged[incident_id] = run
    return staged


def save_store(path: str | Path | None = None) -> Path:
    """Persist REPO_STORE to JSON (atomic tmp+rename; Lane 2 loop 4)."""
    out = Path(path) if path is not None else STORE_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {iid: _run_to_json(run) for iid, run in REPO_STORE.items()}
    text = json.dumps(payload, sort_keys=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(out.parent),
        prefix=out.name + ".", suffix=".tmp", delete=False)
    try:
        tmp.write(text + "\n")
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.replace(tmp.name, out)
    except OSError:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    return out


def load_store(path: str | Path | None = None) -> list[str]:
    """Full restore of REPO_STORE (explicit load: validate-all, then replace).

    Raises ValueError on any garbage (fail-closed, never partial-load).
    """
    staged = _read_store(Path(path) if path is not None else STORE_PATH)
    REPO_STORE.clear()
    REPO_STORE.update(staged)
    return sorted(staged)


def _ensure_loaded(incident_id: str | None = None) -> None:
    """Auto-load on miss when the file exists (restart resume; Lane 2).

    Empty memory restores the whole file; a miss against warm memory merges
    file-only runs without clobbering live state. Corrupt files raise
    (fail-closed); a raced deletion stays memory-only.
    """
    if incident_id is not None and incident_id in REPO_STORE:
        return
    if not STORE_PATH.is_file():
        return
    if not REPO_STORE:
        try:
            load_store()
        except FileNotFoundError:
            pass  # raced deletion between is_file and read
        return
    if incident_id is None:
        return
    try:
        staged = _read_store(STORE_PATH)
    except FileNotFoundError:
        pass  # raced deletion between is_file and read
    else:
        for key, run in staged.items():
            REPO_STORE.setdefault(key, run)


def _save_best_effort() -> None:
    """Auto-save after mutations; durability must never fail the request."""
    try:
        save_store()
    except OSError:
        pass


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
    _ensure_loaded()
    if incident_id in REPO_STORE:
        raise RepoExists(f"run already open: {incident_id}")
    run = fsm_svc.new_run(incident_id, now=now)
    REPO_STORE[incident_id] = run
    _save_best_effort()
    return run


def get_run(incident_id: str) -> IncidentRun:
    try:
        return REPO_STORE[incident_id]
    except KeyError:
        pass
    _ensure_loaded(incident_id)
    try:
        return REPO_STORE[incident_id]
    except KeyError as exc:
        raise RepoMissing(f"unknown incident: {incident_id}") from exc


def list_runs() -> list[dict[str, Any]]:
    """Queue summaries for the Command Center (M19a queue)."""
    _ensure_loaded()
    return [{"incident_id": run.incident_id, "state": run.state,
             "history_len": len(run.history)}
            for run in REPO_STORE.values()]


#: Run-view projection: history targets that carry verification meaning.
#: Pure projection of banked records (Lane 3) -- VERIFYING/ROLLBACK entries
#: plus their outcomes. No verdict invented: each row is the stored
#: transition (seq/frm/to/reason/refs/at), only filtered.
_VERDICT_STATES = frozenset({"VERIFYING", "ROLLBACK", "RESOLVED", "ESCALATED"})


def verification_verdicts(run: IncidentRun) -> list[dict[str, Any]]:
    """Verification-relevant slice of banked history (projection only)."""
    return [{"seq": r.seq, "frm": r.frm, "to": r.to, "reason": r.reason,
             "refs": list(r.refs), "at": r.at} for r in run.history
            if r.to in _VERDICT_STATES]


def rollback_summary(run: IncidentRun) -> dict[str, bool]:
    """Rollback projection from banked flags (no new data).

    ``eligible`` mirrors the ExecutionView rule (VERIFYING/ROLLBACK state,
    single attempt not yet used); ``attempted`` is the stored
    ``rolled_back`` flag.
    """
    return {"eligible": run.state in ("VERIFYING", "ROLLBACK")
            and not run.rolled_back,
            "attempted": bool(run.rolled_back)}


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
        "verification_verdicts": verification_verdicts(run),
        "rollback": rollback_summary(run),
    }


def _record_fsm(incident_id: str, run: IncidentRun) -> int:
    """Chain every banked FSM record (P0-2: no silent transitions)."""
    from app.routers import audit as audit_router
    from app.services import audit as audit_mod
    chain = audit_router.get_or_create_chain(incident_id)
    return audit_mod.record_fsm(chain, fsm_svc.audit_records(run))


def advance_run(incident_id: str, to: str, *, reason: str = "",
                refs: Sequence[str] = (),
                approval: Mapping[str, Any] | None = None,
                approval_secret: str | None = None,
                idempotency_key: str | None = None,
                now: float | None = None) -> dict[str, Any]:
    """Guarded transition with HTTP idempotency (M14.5 over HTTP).

    APPROVED edges require an HMAC-bound approval: ``approval`` must carry
    ``approval_id`` + ``token`` + ``actor`` from a STORED, human-approved
    M07 request, verified with ``approval_secret``. Raw client permits are
    never accepted (P0-1: the client cannot authorize itself). Credentials
    on any other edge are rejected.
    """
    run = get_run(incident_id)
    if idempotency_key is not None:
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise FsmError("idempotency_key must be a non-empty string")
        cache_key = (incident_id, to, idempotency_key)
        if cache_key in IDEM_RESPONSES:
            cached = dict(IDEM_RESPONSES[cache_key])
            cached["duplicate"] = True
            return cached
    permit: Permit | None = None
    if to == "APPROVED":
        permit = _bound_permit(approval, approval_secret, now,
                               expected_incident=incident_id)
    elif approval is not None:
        raise PermitRejected("approval credential only valid on APPROVED")
    state = fsm_svc.advance(run, to, reason=reason, refs=list(refs),
                            permit=permit, now=now)
    _save_best_effort()
    view = run_view(run)
    view["duplicate"] = False
    if idempotency_key is not None:
        IDEM_RESPONSES[(incident_id, to, idempotency_key)] = dict(view)
    _ = state
    return view


def _bound_permit(approval: Mapping[str, Any] | None,
                  secret: str | None, now: float | None,
                  expected_incident: str | None = None) -> Permit:
    """Resolve an APPROVED credential via the stored M07 approval (P0-1).

    Every APPROVED edge binds to its own run's incident (P1): the target
    ``incident_id`` is threaded through as ``expected_incident`` so an
    approval minted for incident A cannot authorize incident B.
    ``None`` keeps the legacy unbound behavior for pure-helper callers.
    """
    from app.routers import approvals as approvals_router
    if not isinstance(approval, Mapping):
        raise PermitRejected(
            "APPROVED requires an HMAC-bound approval "
            "(approval_id + token + actor)")
    try:
        approval_id = str(approval["approval_id"])
        token = str(approval["token"])
        actor = str(approval["actor"])
    except KeyError as exc:
        raise PermitRejected(
            f"approval credential missing {exc} (no raw permits accepted)"
        ) from exc
    if not isinstance(secret, str) or not secret:
        raise PermitRejected("APPROVED requires the server approval secret")
    try:
        return approvals_router.verified_permit(
            approval_id, token, actor, secret, now,
            expected_incident=expected_incident)
    except Exception as exc:
        raise PermitRejected(f"approval binding failed: {exc}") from exc


def sweep_run(incident_id: str, now: float, stage_ttl: float | None = None,
              approval_ttl: float | None = None) -> dict[str, Any]:
    run = get_run(incident_id)
    kwargs: dict[str, float] = {}
    if stage_ttl is not None:
        kwargs["stage_ttl"] = float(stage_ttl)
    if approval_ttl is not None:
        kwargs["approval_ttl"] = float(approval_ttl)
    escalated = fsm_svc.sweep(run, float(now), **kwargs)
    _save_best_effort()
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
               prevention: Sequence[str],
               evidence_by_id: Mapping[str, Any] | None = None,
               legacy_draft: bool = False) -> dict[str, Any]:
    """A4 draft via the run layer (Lane-1 handoff: hardened by default).

    Draft-only helper: hardened coverage unless the caller explicitly opts
    into legacy_draft (visible, auditable choice). Publication always goes
    through pipeline.publish_rca (hardened-only).
    """
    claim_objs = [Claim(**dict(c)) for c in claims]
    out = A4.run_report(incident_id, list(timeline), root_cause, claim_objs,
                        set(str(e) for e in valid_evidence_ids),
                        list(remediation_log), list(prevention),
                        client, store, evidence_by_id=evidence_by_id,
                        legacy_draft=legacy_draft)
    return out.model_dump(mode="json")


def reset_demo_state() -> None:
    """Test/demo helper: clear in-memory runs, sessions, idempotency.

    Also deletes the persisted ``var/runs.json`` file so file state cannot
    leak across tests (same two-layer discipline as the audit router).
    Never call in production.
    """
    REPO_STORE.clear()
    IDEM_RESPONSES.clear()
    SESSIONS.reset()
    try:
        STORE_PATH.unlink(missing_ok=True)
    except OSError:
        pass


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
    approval: dict[str, Any] | None = None
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


def _require_key(x_api_key: str | None) -> None:
    from app.config import get_settings  # noqa: E402 (request-time only)
    from app.routers import auth as auth_mod
    auth_mod.guard_http(
        x_api_key, lambda: get_settings().PROOFOPS_API_KEY, HTTPException)


def http_create(body: CreateBody,
                x_api_key: str | None = Header(default=None)
                ) -> dict[str, Any]:
    _require_key(x_api_key)
    run = _guarded(create_run, body.incident_id, body.now)
    return run_view(run)


def http_get(incident_id: str) -> dict[str, Any]:
    return _guarded(lambda: run_view(get_run(incident_id)))


def http_list() -> list[dict[str, Any]]:
    return _guarded(list_runs)


def http_advance(incident_id: str, body: AdvanceBody,
                  x_api_key: str | None = Header(default=None)
                  ) -> dict[str, Any]:
    from app.config import get_settings  # noqa: E402 (request-time only)
    from app.routers import auth as auth_mod
    auth_mod.guard_http(
        x_api_key, lambda: get_settings().PROOFOPS_API_KEY, HTTPException)
    view = _guarded(advance_run, incident_id, body.to, reason=body.reason,
                    refs=body.refs, approval=body.approval,
                    approval_secret=get_settings().APPROVAL_SECRET,
                    idempotency_key=body.idempotency_key)
    _guarded(_record_fsm, incident_id, get_run(incident_id))
    return view


def http_sweep(incident_id: str, body: SweepBody,
               x_api_key: str | None = Header(default=None)
               ) -> dict[str, Any]:
    _require_key(x_api_key)
    view = _guarded(sweep_run, incident_id, body.now,
                    stage_ttl=body.stage_ttl,
                    approval_ttl=body.approval_ttl)
    _guarded(_record_fsm, incident_id, get_run(incident_id))
    return view


if router is not None:  # container path; host asserts wiring via AST
    router.post("", status_code=201)(http_create)
    router.get("")(http_list)
    router.get("/{incident_id}")(http_get)
    router.post("/{incident_id}/advance")(http_advance)
    router.post("/{incident_id}/sweep")(http_sweep)
