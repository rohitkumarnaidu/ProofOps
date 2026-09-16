"""M14 canonical FSM: the 14-stage incident lifecycle (service layer).

Ownership: M14 owns THIS FILE (``backend/app/services/fsm.py``). State
VOCABULARY is frozen M01.1/M01.2 (``IncidentStatus``/``FSM_STATES``) --
imported, never redefined. (Headline counts branch stages once, hence
"14-state"; the vocabulary holds all 18 branch states. The SET matches the
AGENTS.md S5 flow exactly; the numbering delta is a docs label, not a
behavior difference.)

No HTTP here (routers own the thin translation). No crypto (M07 owns
tokens), no policy evaluation (M06 owns), no execution (M08 owns), no audit
chain (M15 owns): the FSM takes STRUCTURAL credentials (permit objects,
gate refs) validated upstream and enforces ORDER + BOUNDS + NO-SKIP.

Fail-closed rules (any violation = reject, never reroute):
- unknown states, unknown edges, and terminal exits rejected;
- POLICY_CHECK -> EXECUTING is impossible (no-skip, S1.1-19): EXECUTING is
  reachable ONLY from APPROVED with an unconsumed, unexpired, stored permit;
- every EXECUTING has exactly one APPROVED permit behind it (GREEN auto and
  YELLOW token both flow through APPROVED, so the invariant is uniform);
- re-plans <= 2 (PLANNED -> DIAGNOSING back-edge, counted);
- rollback executes once (second VERIFYING -> ROLLBACK rejected);
- TTL sweep escalates timed-out agent stages and stale approvals;
- BLOCKED is terminal (a DENY never flows back toward execution);
- RCA_PUBLISHED/AUDITED require non-blank gate/audit refs (presence only;
  gate SEMANTICS belong to A4/M15/M18).
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
# Repo root for the top-level agents/ package (runtime CWD-independent).
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agents import AGENTS  # noqa: E402 (M13 workforce map, dep-free)
from app.contracts.enums import FSM_STATES  # noqa: E402 (frozen vocabulary)

STATES = FSM_STATES
TERMINAL = frozenset({"BLOCKED", "AUDITED"})

#: Structural edges (pure stage order; bounds/permits enforced separately).
TRANSITIONS: dict[str, frozenset[str]] = {
    "NEW": frozenset({"TRIAGING"}),
    "TRIAGING": frozenset({"CORRELATED", "ESCALATED"}),
    "CORRELATED": frozenset({"INVESTIGATING", "ESCALATED"}),
    "INVESTIGATING": frozenset({"DIAGNOSING", "ESCALATED"}),
    "DIAGNOSING": frozenset({"PLANNED", "ESCALATED"}),
    "PLANNED": frozenset({"POLICY_CHECK", "DIAGNOSING", "ESCALATED"}),
    "POLICY_CHECK": frozenset({"BLOCKED", "AWAITING_APPROVAL", "APPROVED"}),
    "BLOCKED": frozenset(),
    "AWAITING_APPROVAL": frozenset({"APPROVED", "ESCALATED"}),
    "APPROVED": frozenset({"EXECUTING"}),
    "EXECUTING": frozenset({"VERIFYING"}),
    "VERIFYING": frozenset({"RESOLVED", "ROLLBACK", "ESCALATED"}),
    "ROLLBACK": frozenset({"VERIFYING"}),
    "RESOLVED": frozenset({"RCA_PENDING"}),
    "ESCALATED": frozenset({"RCA_PENDING"}),
    "RCA_PENDING": frozenset({"RCA_PUBLISHED"}),
    "RCA_PUBLISHED": frozenset({"AUDITED"}),
    "AUDITED": frozenset(),
}

MAX_REPLANS = 2
STAGE_TTL_S = 60.0
APPROVAL_TTL_S = 600.0
DEMO_APPROVAL_TTL_S = 900.0

#: Stages with a TTL (agent work + human approval). Execution/verification
#: timeouts belong to M08/M09; NEW is caller-driven; terminals are exempt.
TTL_STAGES = frozenset({"TRIAGING", "CORRELATED", "INVESTIGATING",
                        "DIAGNOSING", "PLANNED"})

#: Agent artifact handoffs (control flow stays in TRANSITIONS; this governs
#: which agent may hand case artifacts to which). Reporter intake is the
#: verified case file, not an agent handoff -- planner -> reporter is
#: rejected by design (it would skip execution + verification).
HANDOFFS = frozenset({("triage", "diagnostic"), ("diagnostic", "planner")})


class FsmError(Exception):
    """Base for orchestration rejections (fail-closed, auditable)."""


class InvalidTransition(FsmError):
    """Unknown state, unknown edge, bound exhausted, or terminal exit."""


class PermitRejected(FsmError):
    """Missing, expired, mismatched, or replayed approval permit."""


@dataclass(frozen=True)
class Permit:
    """Structural approval credential (crypto verified upstream, M07).

    ``auto`` marks GREEN auto-permits vs human-token permits; both flow
    through APPROVED so the no-skip invariant stays uniform. Single-use is
    enforced per run via consumed token_refs.
    """

    action_id: str
    params_hash: str
    expires_at: float
    token_ref: str
    auto: bool = False

    def __post_init__(self) -> None:
        for name in ("action_id", "params_hash", "token_ref"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise PermitRejected(f"permit {name} must be non-empty")
        if (isinstance(self.expires_at, bool)
                or not isinstance(self.expires_at, (int, float))):
            raise PermitRejected("permit expires_at must be epoch seconds")

    def check_valid(self, now: float) -> None:
        if not self.expires_at > float(now):
            raise PermitRejected("permit expired")


@dataclass
class TransitionRecord:
    seq: int
    frm: str
    to: str
    reason: str
    refs: list[str]
    forced: bool
    at: float


@dataclass
class IncidentRun:
    """One incident's deterministic lifecycle (M14.1-M14.8)."""

    incident_id: str
    state: str = "NEW"
    history: list[TransitionRecord] = field(default_factory=list)
    handoffs: list[dict[str, Any]] = field(default_factory=list)
    suppressions: list[dict[str, str]] = field(default_factory=list)
    replans: int = 0
    rolled_back: bool = False
    permit: Permit | None = None
    consumed_refs: set[str] = field(default_factory=set)
    idem_store: dict[tuple[str, str], Any] = field(default_factory=dict)
    entered_at: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.incident_id, str) or not self.incident_id.strip():
            raise FsmError("incident_id must be a non-empty string")
        if self.state not in STATES:
            raise FsmError(f"unknown state: {self.state!r}")


def new_run(incident_id: str, now: float | None = None) -> IncidentRun:
    """Open a run in NEW (M14.1)."""
    run = IncidentRun(incident_id=incident_id)
    run.entered_at["NEW"] = _now(now)
    return run


def _now(now: float | None) -> float:
    return time.time() if now is None else float(now)


def _check_refs(refs: Sequence[str]) -> list[str]:
    cleaned: list[str] = []
    for ref in refs:
        if not isinstance(ref, str) or not ref.strip():
            raise InvalidTransition("refs must be non-empty strings")
        cleaned.append(ref)
    return cleaned


def _approve(run: IncidentRun, permit: Permit | None, now: float) -> None:
    """Store one approval permit (POLICY_CHECK/AWAITING -> APPROVED)."""
    if permit is None:
        raise PermitRejected("APPROVED requires a permit (no-skip)")
    if not isinstance(permit, Permit):
        raise PermitRejected("permit must be a Permit (validated upstream)")
    permit.check_valid(now)
    if permit.token_ref in run.consumed_refs:
        raise PermitRejected("permit token_ref already consumed (replay)")
    if run.permit is not None:
        raise PermitRejected("a permit is already pending for this run")
    run.permit = permit


def advance(run: IncidentRun, to: str, *, reason: str = "",
            refs: Sequence[str] = (), permit: Permit | None = None,
            now: float | None = None) -> str:
    """One guarded transition; returns the new state (M14.2/M14.7).

    Raises InvalidTransition (order/bounds) or PermitRejected (no-skip).
    Every accepted transition appends a history record for M15 chaining.
    """
    if not isinstance(run, IncidentRun):
        raise InvalidTransition("run must be an IncidentRun")
    if to not in STATES:
        raise InvalidTransition(f"unknown state: {to!r}")
    if run.state in TERMINAL:
        raise InvalidTransition(f"{run.state} is terminal (no edges out)")
    if to not in TRANSITIONS[run.state]:
        raise InvalidTransition(f"edge {run.state} -> {to} not allowed")
    if not isinstance(reason, str):
        raise InvalidTransition("reason must be str")
    ts = _now(now)
    clean_refs = _check_refs(refs)
    frm = run.state

    if to == "DIAGNOSING" and frm == "PLANNED":
        if run.replans >= MAX_REPLANS:
            raise InvalidTransition(f"re-plans exhausted (>{MAX_REPLANS})")
        run.replans += 1
    if to == "BLOCKED" and not reason.strip():
        raise InvalidTransition("BLOCKED requires a deny reason")
    if to == "APPROVED":
        _approve(run, permit, ts)
    elif permit is not None:
        raise PermitRejected("permit only valid on edges into APPROVED")
    if to == "EXECUTING":
        stored = run.permit
        if stored is None:
            raise PermitRejected(
                "EXECUTING without APPROVED permit (no-skip)")
        stored.check_valid(ts)
        run.consumed_refs.add(stored.token_ref)
        run.permit = None
    if to == "ROLLBACK":
        if run.rolled_back:
            raise InvalidTransition("rollback already attempted once")
        run.rolled_back = True
    if to in ("RCA_PUBLISHED", "AUDITED") and not clean_refs:
        raise InvalidTransition(f"{to} requires gate/audit refs")

    run.state = to
    run.entered_at[to] = ts
    run.history.append(TransitionRecord(seq=len(run.history) + 1, frm=frm,
                                       to=to, reason=reason,
                                       refs=clean_refs, forced=False, at=ts))
    return run.state


def sweep(run: IncidentRun, now: float, stage_ttl: float = STAGE_TTL_S,
          approval_ttl: float = APPROVAL_TTL_S) -> bool:
    """Escalate timed-out agent stages / stale approvals (M14.4).

    Clock-injected (no wall-clock reads): callers pass ``now``. Returns True
    when the run was force-escalated. Terminals and untimed stages are
    exempt; the forced record carries forced=True for M15.
    """
    now = float(now)
    if run.state in TERMINAL:
        return False
    if run.state == "AWAITING_APPROVAL":
        ttl = float(approval_ttl)
    elif run.state in TTL_STAGES:
        ttl = float(stage_ttl)
    else:
        return False
    if ttl <= 0:
        raise FsmError("ttl must be positive")
    entered = run.entered_at.get(run.state, now)
    if now - entered <= ttl:
        return False
    frm = run.state
    run.state = "ESCALATED"
    run.entered_at["ESCALATED"] = now
    run.history.append(TransitionRecord(
        seq=len(run.history) + 1, frm=frm, to="ESCALATED",
        reason=f"ttl-expired:{frm}", refs=[], forced=True, at=now))
    return True


def execute_once(run: IncidentRun, action_id: str, execution_id: str,
                 fn: Callable[..., Any], *args: Any, **kwargs: Any
                 ) -> tuple[Any, bool]:
    """Idempotent execution gate (M14.5): duplicates return cached results.

    Returns (result, duplicate). The wrapped fn runs AT MOST once per
    (action_id, execution_id); replays append a suppression record (audit
    hook for M15: 'duplicate-suppressed').
    """
    for name, value in (("action_id", action_id),
                        ("execution_id", execution_id)):
        if not isinstance(value, str) or not value.strip():
            raise FsmError(f"{name} must be a non-empty string")
    key = (action_id, execution_id)
    if key in run.idem_store:
        run.suppressions.append({"action_id": action_id,
                                 "execution_id": execution_id})
        return run.idem_store[key], True
    result = fn(*args, **kwargs)
    run.idem_store[key] = result
    return result, False


def handoff(run: IncidentRun, from_agent: str, to_agent: str,
            artifact_refs: Sequence[str]) -> dict[str, Any]:
    """Validated agent artifact handoff (M14.6): allowlisted pairs only."""
    if from_agent not in AGENTS:
        raise FsmError(f"unknown from_agent: {from_agent!r}")
    if to_agent not in AGENTS:
        raise FsmError(f"unknown to_agent: {to_agent!r}")
    if (from_agent, to_agent) not in HANDOFFS:
        raise FsmError(
            f"handoff {from_agent} -> {to_agent} not allowlisted "
            f"(reporter intake is the verified case file, not a handoff)")
    refs = _check_refs(artifact_refs)
    if not refs:
        raise FsmError("handoff needs non-empty artifact_refs")
    record = {"incident_id": run.incident_id, "from": from_agent,
              "to": to_agent, "refs": refs}
    run.handoffs.append(record)
    return record


def audit_records(run: IncidentRun) -> list[dict[str, Any]]:
    """Transition + handoff + suppression records for M15 chaining (M14.8)."""
    out: list[dict[str, Any]] = [
        {"type": "transition", "seq": r.seq, "frm": r.frm, "to": r.to,
         "reason": r.reason, "refs": list(r.refs), "forced": r.forced,
         "at": r.at}
        for r in run.history]
    out.extend({"type": "handoff", **h} for h in run.handoffs)
    out.extend({"type": "duplicate-suppressed", **s}
               for s in run.suppressions)
    return out
