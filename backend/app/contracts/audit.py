"""M01.14 Audit schema - canonical AuditEvent contract.

Ownership: M01.14 owns THIS FILE ONLY (``backend/app/contracts/audit.py``).
No frozen enum is needed here (event-type vocabulary is an open operational
set; lifecycle enums stay M01.1-owned). Legacy ``app.schemas`` is a compat
layer owned by M01.1 - it is read in tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S32 -
``Event{event_id, seq, ts, incident_id, actor, agent, event_type,
input_hash, evidence_ids, policy{version,rule,result}, action_id,
approval_id, execution_id, result, prev_hash,
curr_hash=SHA256(prev+canonical)}``. Emitted on every
transition/tool/policy/approval/exec/verify/RCA/eval event. Custom chain =
exportable proof (``GET /incidents/{id}/audit`` returns chain + ``valid``
bool + verify routine). NEVER label custom rows "AIMS" (AIMS =
trace/transcripts/reports/audit-log views, linked incident->session).

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
audit event. It performs NO chain linking, NO hash verification, NO ordering
enforcement across events, and NO emission. Those are audit duties (future
M15). A constructed ``AuditEvent`` is well-formed DATA - chain validity is
proven only by the verify routine over the full ordered chain.
``compute_hash`` is the pure canonical hash primitive (same as legacy).

Legacy wire mapping (field names match legacy ``app.schemas.AuditEvent``
EXACTLY)::

    event_id / seq / ts / incident_id / actor / agent / event_type /
    input_hash / evidence_ids / policy / action_id / approval_id /
    execution_id / result / prev_hash / curr_hash.

    ``policy`` stores canonical ``FrozenDict``; legacy carries a plain dict.

Bounds table::

    event_id/incident_id           1..MAX_ID_LEN (128, identifiers)
    actor/agent                    "" or 1..MAX_ID_LEN (agent "" = system event)
    event_type                     1..MAX_TYPE_LEN (128, e.g. policy.decision)
    input_hash/prev_hash/curr_hash "" or 1..MAX_HASH_LEN (256; "" = genesis/link
                                     pending - chain assembly owns linkage)
    evidence_ids                   0..MAX_EVID_REFS (100 ID strings)
    policy                         0..MAX_POLICY_ENTRIES (32; bytes capped)
    action_id/approval_id/execution_id "" or 1..MAX_ID_LEN (refs, "" = n/a)
    result                         0..MAX_RESULT_LEN (1024, verbatim)
    seq                            int >= 0 (ordering owned by the chain store)

Bypass containment (Escape 1, M01.2-M01.13 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation.

NOT implemented here (owned elsewhere): event emission points (M15.1),
hash-chain linking + verify endpoint + tamper detection (M15.2/M15.3), AIMS
trace linkage (M15.4), export format (M15.5), evidence linkage queries
(M15.6).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.incident import FrozenDict
from app.contracts.values import canonical_json, new_id, sha256_hex, utcnow

MAX_ID_LEN = 128
MAX_TYPE_LEN = 128
MAX_HASH_LEN = 256
MAX_EVID_REFS = 100
MAX_POLICY_ENTRIES = 32
MAX_POLICY_JSON_BYTES = 8192
MAX_RESULT_LEN = 1024


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _check_blank_or_identifier(name: str, value: str, max_len: int) -> str:
    """Link rule: "" (n/a) or full identifier discipline."""
    if value == "":
        return value
    return _check_identifier(name, value, max_len)


class AuditEvent(BaseModel):
    """One append-only audit event: who did what, linked to prev hash."""

    model_config = {"frozen": True, "extra": "forbid"}

    event_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Opaque event id (uuid4 hex default).",
    )
    seq: int = Field(
        ge=0,
        description="Monotonic position in the chain (store assigns).",
    )
    ts: datetime = Field(
        default_factory=utcnow,
        description="tz-aware event time (naive rejected).",
    )
    incident_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    actor: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Actor identity (human/agent id or system role).",
    )
    agent: str = Field(
        default="",
        max_length=MAX_ID_LEN,
        description='Agent id, or "" for non-agent system events.',
    )
    event_type: str = Field(
        min_length=1,
        max_length=MAX_TYPE_LEN,
        description="Event type token (e.g. policy.decision).",
    )
    input_hash: str = Field(
        default="",
        max_length=MAX_HASH_LEN,
        description='Input digest, or "" when not applicable.',
    )
    evidence_ids: tuple[str, ...] = Field(
        default=(),
        description="Evidence cited by this event.",
    )
    policy: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Policy snapshot {version,rule,result}.",
    )
    action_id: str = Field(
        default="",
        max_length=MAX_ID_LEN,
        description='Action ref, or "" when n/a.',
    )
    approval_id: str = Field(
        default="",
        max_length=MAX_ID_LEN,
        description='Approval ref, or "" when n/a.',
    )
    execution_id: str = Field(
        default="",
        max_length=MAX_ID_LEN,
        description='Execution ref, or "" when n/a.',
    )
    result: str = Field(
        default="",
        max_length=MAX_RESULT_LEN,
        description="Outcome token/detail (verbatim, may be empty).",
    )
    prev_hash: str = Field(
        default="",
        max_length=MAX_HASH_LEN,
        description='Previous chain hash, or "" for genesis.',
    )
    curr_hash: str = Field(
        default="",
        max_length=MAX_HASH_LEN,
        description='This event hash, or "" before chain assembly.',
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "AuditEvent.model_construct is blocked: it skips validation. "
            "Use AuditEvent(...) or AuditEvent.model_validate for trusted "
            "instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None,
                   deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation."""
        if update:
            merged = self.model_dump()
            merged.update(dict(update))
            return self.model_validate(merged)
        return super().model_copy(update=None, deep=deep)

    @staticmethod
    def compute_hash(prev_hash: str, canonical_event: str) -> str:
        """Chain primitive: SHA256(prev_hash + canonical_event JSON)."""
        return sha256_hex(prev_hash + canonical_event)

    @field_validator("event_id", "incident_id", "actor", "event_type")
    @classmethod
    def _required_ids(cls, v: str, info: Any) -> str:
        caps = {"event_id": MAX_ID_LEN, "incident_id": MAX_ID_LEN,
                "actor": MAX_ID_LEN, "event_type": MAX_TYPE_LEN}
        return _check_identifier(str(info.field_name), v,
                                 caps[str(info.field_name)])

    @field_validator("agent", "action_id", "approval_id", "execution_id")
    @classmethod
    def _optional_refs(cls, v: str, info: Any) -> str:
        return _check_blank_or_identifier(str(info.field_name), v, MAX_ID_LEN)

    @field_validator("input_hash", "prev_hash", "curr_hash")
    @classmethod
    def _optional_hashes(cls, v: str, info: Any) -> str:
        return _check_blank_or_identifier(str(info.field_name), v, MAX_HASH_LEN)

    @field_validator("seq", mode="before")
    @classmethod
    def _seq_strict(cls, v: Any) -> Any:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("seq must be an integer (bool rejected)")
        return v

    @field_validator("ts")
    @classmethod
    def _ts(cls, v: Any) -> datetime:
        if not isinstance(v, datetime):
            raise ValueError("ts must be a datetime")
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("ts must be timezone-aware (reject naive)")
        return v

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def _evidence_ids(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("evidence_ids must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError("evidence_ids must be a list of ID strings")
        items = list(v)
        if len(items) > MAX_EVID_REFS:
            raise ValueError(
                f"evidence_ids must hold at most {MAX_EVID_REFS} entries")
        checked: list[str] = []
        for item in items:
            if not isinstance(item, str):
                raise ValueError("evidence_ids entries must be non-empty strings")
            checked.append(_check_identifier(
                "evidence_ids entries", item, MAX_ID_LEN))
        return checked

    @field_validator("policy")
    @classmethod
    def _policy(cls, v: FrozenDict) -> FrozenDict:
        if len(v) > MAX_POLICY_ENTRIES:
            raise ValueError(
                f"policy must hold at most {MAX_POLICY_ENTRIES} entries")
        size = len(canonical_json(v.to_plain()).encode("utf-8"))
        if size > MAX_POLICY_JSON_BYTES:
            raise ValueError(
                f"policy must serialize within {MAX_POLICY_JSON_BYTES} bytes")
        return v

    @field_validator("result")
    @classmethod
    def _result(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("result must be a string")
        if len(v) > MAX_RESULT_LEN:
            raise ValueError(f"result must be at most {MAX_RESULT_LEN} characters")
        return v

    @classmethod
    def from_legacy(cls, legacy: Any) -> AuditEvent:
        """Build a canonical AuditEvent from ``app.schemas`` (1:1 wire)."""
        return cls(
            event_id=str(legacy.event_id),
            seq=int(legacy.seq),
            ts=legacy.ts,
            incident_id=str(legacy.incident_id),
            actor=str(legacy.actor),
            agent=str(legacy.agent),
            event_type=str(legacy.event_type),
            input_hash=str(legacy.input_hash),
            evidence_ids=tuple(legacy.evidence_ids),
            policy=FrozenDict(dict(legacy.policy)),
            action_id=str(legacy.action_id),
            approval_id=str(legacy.approval_id),
            execution_id=str(legacy.execution_id),
            result=str(legacy.result),
            prev_hash=str(legacy.prev_hash),
            curr_hash=str(legacy.curr_hash),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.AuditEvent`` shape."""
        from app.schemas import AuditEvent as LegacyEvent  # noqa: E402

        return LegacyEvent(
            event_id=self.event_id,
            seq=self.seq,
            ts=self.ts,
            incident_id=self.incident_id,
            actor=self.actor,
            agent=self.agent,
            event_type=self.event_type,
            input_hash=self.input_hash,
            evidence_ids=list(self.evidence_ids),
            policy=self.policy.to_plain(),
            action_id=self.action_id,
            approval_id=self.approval_id,
            execution_id=self.execution_id,
            result=self.result,
            prev_hash=self.prev_hash,
            curr_hash=self.curr_hash,
        )
