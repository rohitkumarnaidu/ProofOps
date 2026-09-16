"""M01.10 Execution schema - canonical Execution contract.

Ownership: M01.10 owns THIS FILE ONLY (``backend/app/contracts/execution.py``).
Frozen vocabulary (``ExecutorTier``) is owned by M01.1 and is imported, never
redeclared. Legacy ``app.schemas`` is a compat layer owned by M01.1 - it is
read in tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S28 - execution accepted iff validator-pass +
(ALLOW-permit | valid token for exact params hash); incident locked;
dry-run; tier applied; ``execution{state_diff{before,after}, logs, tier}``
recorded; duplicate ``action_id`` -> cached result + audit. ``kind`` tier
stays RESERVED (absent by design) until its tier lands.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
execution record. It performs NO gate checks (validator/policy/token), NO
locking, NO dry-run, NO tier dispatch, and NO idempotency caching. Those are
executor duties (future M08/M14). A constructed ``Execution`` is a
well-formed record - never proof that execution was authorized.

Legacy wire mapping (field names match legacy ``app.schemas.Execution``
EXACTLY)::

    execution_id / action_id / incident_id / tier / state_diff / logs /
    idempotency_key.

    ``state_diff`` stores canonical ``FrozenDict`` (deep-immutable, detached
    on dump); legacy carries a plain dict and the bridges coerce both ways.
    ``logs`` stores an immutable tuple (dumped as a fresh list).

Bounds table::

    execution_id/action_id/incident_id  1..MAX_ID_LEN (128, identifiers)
    idempotency_key                     1..MAX_ID_LEN (128, REQUIRED: no
                                          default - every execution must name
                                          its key)
    state_diff                          0..MAX_DIFF_ENTRIES (64; depth/bytes
                                          capped like action parameters)
    logs                                0..MAX_LOGS (256 lines, each <=4096;
                                          verbatim lines, blanks allowed)

Bypass containment (Escape 1, M01.2-M01.9 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation.

NOT implemented here (owned elsewhere): mock/docker executors (M08),
idempotency caching + duplicate-suppressed audit (M14.5), execution logging
pipeline (M08.4), verification of recorded state (M09), rollback of recorded
executions (M10).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import ExecutorTier
from app.contracts.incident import FrozenDict
from app.contracts.values import canonical_json, new_id

MAX_ID_LEN = 128
MAX_DIFF_ENTRIES = 64
MAX_DIFF_DEPTH = 5
MAX_DIFF_JSON_BYTES = 16384
MAX_LOGS = 256
MAX_LOG_LEN = 4096


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _nested_depth(value: Any) -> int:
    """Deepest container nesting level (scalars 0). Iterative: no recursion limit."""
    best = 0
    stack: list[Any] = [value]
    levels: list[int] = [0]
    while stack:
        v = stack.pop()
        d = levels.pop()
        if isinstance(v, (Mapping, FrozenDict)):
            best = max(best, d + 1)
            for item in v.values():
                stack.append(item)
                levels.append(d + 1)
        elif isinstance(v, (list, tuple)):
            best = max(best, d + 1)
            for item in v:
                stack.append(item)
                levels.append(d + 1)
    return best


class Execution(BaseModel):
    """One execution record: what ran, where, and what changed."""

    model_config = {"frozen": True, "extra": "forbid"}

    execution_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Opaque execution id (uuid4 hex default).",
    )
    action_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    incident_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    tier: ExecutorTier = Field(
        default=ExecutorTier.MOCK,
        description="Strict ExecutorTier (mock|docker; kind reserved absent).",
    )
    state_diff: FrozenDict = Field(
        default_factory=FrozenDict,
        description="State diff {before,after} (mapping only).",
    )
    logs: tuple[str, ...] = Field(
        default=(),
        description="Executor log lines (verbatim, blanks allowed).",
    )
    idempotency_key: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="REQUIRED idempotency key (no default by design).",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "Execution.model_construct is blocked: it skips validation. "
            "Use Execution(...) or Execution.model_validate for trusted "
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

    @field_validator("execution_id", "action_id", "incident_id",
                       "idempotency_key")
    @classmethod
    def _ids(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, MAX_ID_LEN)

    @field_validator("state_diff")
    @classmethod
    def _state_diff(cls, v: FrozenDict) -> FrozenDict:
        if len(v) > MAX_DIFF_ENTRIES:
            raise ValueError(
                f"state_diff must hold at most {MAX_DIFF_ENTRIES} entries")
        for k in v:
            _check_identifier("state_diff keys", k, MAX_ID_LEN)
        if _nested_depth(v) > MAX_DIFF_DEPTH:
            raise ValueError(
                f"state_diff must nest at most {MAX_DIFF_DEPTH} levels deep")
        size = len(canonical_json(v.to_plain()).encode("utf-8"))
        if size > MAX_DIFF_JSON_BYTES:
            raise ValueError(
                f"state_diff must serialize within {MAX_DIFF_JSON_BYTES} bytes")
        return v

    @field_validator("logs", mode="before")
    @classmethod
    def _logs(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("logs must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError("logs must be a list of strings")
        items = list(v)
        if len(items) > MAX_LOGS:
            raise ValueError(f"logs must hold at most {MAX_LOGS} entries")
        for item in items:
            if not isinstance(item, str):
                raise ValueError("logs entries must be strings")
            if len(item) > MAX_LOG_LEN:
                raise ValueError(
                    f"logs entries must be at most {MAX_LOG_LEN} characters")
        return items

    @classmethod
    def from_legacy(cls, legacy: Any) -> Execution:
        """Build a canonical Execution from ``app.schemas`` (1:1 wire)."""
        if type(legacy) is cls:
            return legacy  # already canonical: exact, no coercion
        return cls(
            execution_id=str(legacy.execution_id),
            action_id=str(legacy.action_id),
            incident_id=str(legacy.incident_id),
            tier=legacy.tier,
            state_diff=FrozenDict(dict(legacy.state_diff)),
            logs=tuple(legacy.logs),
            idempotency_key=str(legacy.idempotency_key),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.Execution`` shape."""
        from app.schemas import Execution as LegacyExecution  # noqa: E402

        return LegacyExecution(
            execution_id=self.execution_id,
            action_id=self.action_id,
            incident_id=self.incident_id,
            tier=self.tier,
            state_diff=self.state_diff,
            logs=self.logs,
            idempotency_key=self.idempotency_key,
        )
