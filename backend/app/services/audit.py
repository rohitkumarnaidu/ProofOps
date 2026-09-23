"""M15 custom hash audit: append-only SHA256 chain + verify + export (service).

Ownership: M15 owns THIS FILE (``backend/app/services/audit.py``). Event
SHAPE is frozen M01.14 (``AuditEvent`` + ``compute_hash``) -- imported, never
redeclared. This module owns emission completeness, seq assignment, chain
linking (curr = SHA256(prev + canonical-minus-curr)), verification,
export, linkage queries, the AIMS-link record, and the M14-record adapter.

Label honesty (AGENTS.md S10): everything here is CUSTOM-DETERMINISTIC
(origin "custom-hash-chain"). AIMS = Lyzr trace/observability where actually
supported; trace_link() records the incident->session link as UNVERIFIED and
no custom row is ever labeled AIMS. Tampering is DETECTABLE by construction:
verify() recomputes every link.

Fail-closed: unknown-but-wellformed event types pass base validation (open
operational set, contract); known types enforce their required refs; blank
ids, bad hashes, and oversized fields are rejected by the contract; the
store assigns seq (callers cannot order the past).
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from app.contracts.audit import AuditEvent  # noqa: E402 (M01.14 canonical)
from app.contracts.incident import FrozenDict  # noqa: E402 (M01.2 mapping)
from app.contracts.values import canonical_json  # noqa: E402 (canonical form)

ORIGIN = "custom-hash-chain"
GENESIS_PREV = ""

_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")

#: Required extras per known event type (M15.1 completeness). Open set:
#: wellformed unknown types pass with base fields only.
REQUIRED_EXTRAS: dict[str, tuple[str, ...]] = {
    "transition": ("result",),
    "tool.call": ("agent",),
    "policy.decision": ("policy", "action_id"),
    "approval.request": ("approval_id", "action_id"),
    "approval.approve": ("approval_id",),
    "approval.deny": ("approval_id",),
    "approval.expire": ("approval_id",),
    "approval.rejected": ("approval_id",),
    "permit.minted": ("approval_id", "action_id"),
    "execution.start": ("action_id", "execution_id"),
    "execution.finish": ("action_id", "execution_id"),
    "execution.duplicate-suppressed": ("action_id", "execution_id"),
    "verification.verdict": ("execution_id", "result"),
    "rollback.start": ("execution_id",),
    "rollback.finish": ("execution_id",),
    "handoff": ("agent", "result"),
    "rca.draft": ("result",),
    "rca.publish": ("result",),
    "eval.run": ("result",),
}

MAX_RESULT_CLIP = 1024


class AuditError(Exception):
    """Base for audit rejections (fail-closed, never silent)."""


#: File-persistence identity rule: the caller passes the path, but the
#: incident id embedded in the filename must match this (no traversal,
#: no spaces, bounded). Rejected ids raise AuditError (fail-closed).
_INCIDENT_FILE_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")


def sanitize_incident_id(incident_id: str) -> str:
    """Validate an incident id for file persistence (P1: no traversal).

    Returns the id unchanged when it matches ``[A-Za-z0-9_-]{1,128}``,
    else raises AuditError. Memory-only chains keep the looser
    non-blank rule; only the file layer enforces this.
    """
    if not isinstance(incident_id, str) \
            or not _INCIDENT_FILE_RE.fullmatch(incident_id):
        raise AuditError(
            "incident_id must match [A-Za-z0-9_-]{1,128} for file use")
    return incident_id


def _clip(value: str, limit: int = MAX_RESULT_CLIP) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def canonical_of(event: AuditEvent) -> str:
    """Canonical JSON of an event EXCLUDING curr_hash (self-hash excluded)."""
    dumped = event.model_dump(mode="json")
    dumped.pop("curr_hash", None)
    return canonical_json(dumped)


def link(prev_hash: str, event: AuditEvent) -> str:
    """Chain primitive via the contract hash (M01.14 compute_hash)."""
    return AuditEvent.compute_hash(prev_hash, canonical_of(event))


@dataclass
class AuditChain:
    """One incident's append-only chain (M15.1/M15.2)."""

    incident_id: str
    _events: list[AuditEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.incident_id, str) or not self.incident_id.strip():
            raise AuditError("incident_id must be a non-empty string")

    def __len__(self) -> int:
        return len(self._events)

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def _check_type(self, event_type: str) -> str:
        if not isinstance(event_type, str) or not _TYPE_RE.fullmatch(event_type):
            raise AuditError(
                "event_type must match [a-z0-9._-] (open operational set)")
        return event_type

    def emit(self, event_type: str, *, actor: str, agent: str = "",
             input_hash: str = "", evidence_ids: Sequence[str] = (),
             policy: Mapping[str, Any] | None = None, action_id: str = "",
             approval_id: str = "", execution_id: str = "",
             result: str = "") -> AuditEvent:
        """Append one event with assigned seq + computed link (M15.1/15.2)."""
        self._check_type(event_type)
        extras = {name: value for name, value in
                  (("result", result), ("agent", agent),
                   ("policy", policy), ("action_id", action_id),
                   ("approval_id", approval_id),
                   ("execution_id", execution_id))}
        for name in REQUIRED_EXTRAS.get(event_type, ()):
            value = extras[name]
            if value is None or (isinstance(value, str) and not value.strip()) \
                    or (isinstance(value, Mapping) and not len(value)):
                raise AuditError(
                    f"{event_type} requires non-empty {name}")
        prev = self._events[-1].curr_hash if self._events else GENESIS_PREV
        try:
            event = AuditEvent(
                seq=len(self._events) + 1, incident_id=self.incident_id,
                actor=actor, agent=agent, event_type=event_type,
                input_hash=input_hash, evidence_ids=tuple(evidence_ids),
                policy=FrozenDict(dict(policy)) if policy else FrozenDict(),
                action_id=action_id, approval_id=approval_id,
                execution_id=execution_id, result=result, prev_hash=prev,
                curr_hash="")
        except Exception as exc:
            raise AuditError(f"event rejected by contract: {exc}") from exc
        linked = AuditEvent.model_validate(
            {**event.model_dump(), "curr_hash": link(prev, event)})
        self._events.append(linked)
        return linked

    def verify(self) -> dict[str, Any]:
        """Recompute every link + order (M15.3): tampering is detectable."""
        prev = GENESIS_PREV
        for position, event in enumerate(self._events, start=1):
            if event.seq != position or event.incident_id != self.incident_id:
                return {"valid": False, "checked": position - 1,
                        "first_bad_seq": event.seq, "reason": "order/owner"}
            if event.prev_hash != prev:
                return {"valid": False, "checked": position - 1,
                        "first_bad_seq": event.seq, "reason": "prev-link"}
            if event.curr_hash != link(event.prev_hash, event):
                return {"valid": False, "checked": position - 1,
                        "first_bad_seq": event.seq, "reason": "hash"}
            prev = event.curr_hash
        return {"valid": True, "checked": len(self._events),
                "first_bad_seq": None, "reason": ""}

    def export(self) -> dict[str, Any]:
        """Exportable proof with validity bool (M15.5, origin-labeled)."""
        verdict = self.verify()
        return {
            "origin": ORIGIN,
            "incident_id": self.incident_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "valid": verdict["valid"],
            "checked": verdict["checked"],
            "events": [e.model_dump(mode="json") for e in self._events],
        }

    def save(self, path: str | Path) -> Path:
        """Persist the chain to a JSONL file (P1: survive restarts).

        One ``model_dump(mode="json")`` object per line. The caller passes
        the path (this service never hardcodes locations); the incident id
        is sanitized to ``[A-Za-z0-9_-]{1,128}`` first. Writes atomically
        via tmp+rename (chains are small, full rewrite is simplest).
        """
        sanitize_incident_id(self.incident_id)
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(e.model_dump(mode="json"), sort_keys=True)
                 for e in self._events]
        tmp = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(out.parent),
            prefix=out.name + ".", suffix=".tmp", delete=False)
        try:
            tmp.write("".join(line + "\n" for line in lines))
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

    @classmethod
    def load(cls, incident_id: str, path: str | Path) -> AuditChain:
        """Reload a persisted chain (P1: tamper-evident reload).

        Re-validates every event via the contract, requires all events to
        belong to ``incident_id``, then recomputes ``verify()``. Raises
        AuditError on any invalid content (corrupt/tampered files never
        silently become empty chains). Missing file raises
        FileNotFoundError for the caller to distinguish.
        """
        sanitize_incident_id(incident_id)
        try:
            text = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise AuditError(f"audit file unreadable: {exc}") from exc
        chain = cls(incident_id=incident_id)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except ValueError as exc:
                raise AuditError(
                    f"audit file corrupt at line {lineno}: {exc}") from exc
            try:
                event = AuditEvent.model_validate(payload)
            except Exception as exc:
                raise AuditError(
                    f"audit file event invalid at line {lineno}: {exc}"
                ) from exc
            if event.incident_id != incident_id:
                raise AuditError(
                    f"audit file event owner mismatch at line {lineno}")
            chain._events.append(event)
        verdict = chain.verify()
        if not verdict["valid"]:
            raise AuditError(
                f"audit file failed verification: {verdict['reason']} "
                f"at seq {verdict['first_bad_seq']}")
        return chain

    def by_action(self, action_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.action_id == action_id]

    def by_approval(self, approval_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.approval_id == approval_id]

    def by_execution(self, execution_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.execution_id == execution_id]

    def by_evidence(self, evidence_id: str) -> list[AuditEvent]:
        return [e for e in self._events if evidence_id in e.evidence_ids]


def trace_link(incident_id: str, session_id: str) -> dict[str, Any]:
    """AIMS trace-link record (M15.4): incident->session, honestly labeled.

    The LINK is recorded locally; live AIMS trace content is verified in the
    Lyzr Studio UI, never claimed here (verified=False until then).
    """
    for name, value in (("incident_id", incident_id),
                        ("session_id", session_id)):
        if not isinstance(value, str) or not value.strip():
            raise AuditError(f"{name} must be a non-empty string")
    return {"kind": "aims-trace-link", "incident_id": incident_id,
            "session_id": session_id, "verified": False,
            "note": "live AIMS trace verified in Studio UI; "
                    "custom chain rows are never labeled AIMS"}


def record_fsm(chain: AuditChain, records: Sequence[Mapping[str, Any]],
               actor: str = "control-plane") -> int:
    """Ingest M14 audit_records() dicts into the chain (M15.1 adapter).

    Zero changes to fsm.py: the records it already banks (transitions with
    forced flags, handoffs, duplicate-suppressions) become typed events.
    """
    count = 0
    for record in records:
        kind = record.get("type")
        if kind == "transition":
            chain.emit("transition", actor=actor,
                       result=_clip(f"{record.get('frm')}->{record.get('to')} "
                                   f"reason={record.get('reason', '')} "
                                   f"forced={record.get('forced', False)} "
                                   f"refs={','.join(record.get('refs', []))}"))
        elif kind == "handoff":
            chain.emit("handoff", actor=actor, agent=str(record.get("from", "")),
                       result=_clip(f"{record.get('from')}->{record.get('to')} "
                                   f"refs={','.join(record.get('refs', []))}"))
        elif kind == "duplicate-suppressed":
            chain.emit("execution.duplicate-suppressed", actor=actor,
                       action_id=str(record.get("action_id", "")),
                       execution_id=str(record.get("execution_id", "")),
                       result="duplicate-suppressed")
        else:
            raise AuditError(f"unknown record type: {kind!r}")
        count += 1
    return count
