"""M01.12 Rollback schema - canonical Rollback contract.

Ownership: M01.12 owns THIS FILE ONLY (``backend/app/contracts/rollback.py``).
No frozen enum is needed here (verdict vocabulary stays M01.1-owned; trigger
conditions reference it by plain step names). Legacy ``app.schemas`` is a
compat layer owned by M01.1 - it is read in tests/bridges but never modified
here.

Spec: PS03_FINAL_SPEC_V2 S30 - every reversible YELLOW mutation carries
``rollback_action`` + conditions + re-verification criteria. Auto ONE attempt
on FAILED/WORSENED/ROLLBACK_REQUIRED; success -> re-verify -> RESOLVED else
ESCALATED. Irreversible (RED) actions have no rollback path by design (the
absence of a Rollback for them is enforced by policy, not by this shape).

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
rollback record. It performs NO reversibility adjudication, NO condition
evaluation, NO execution, and NO re-verification. Those are rollback-executor
duties (future M10). A constructed ``Rollback`` is well-formed DATA - never
permission to mutate.

Legacy wire mapping (field names match legacy ``app.schemas.Rollback``
EXACTLY)::

    execution_id / rollback_action / conditions / verification /
    attempted / succeeded.

    ``rollback_action`` stores canonical ``FrozenDict`` (REQUIRED, no
    default: a rollback without a template is malformed); legacy carries a
    plain dict and the bridges coerce both ways.

Bounds table::

    execution_id              1..MAX_ID_LEN (128, identifier)
    rollback_action           1..MAX_RB_ENTRIES (32; depth/bytes capped)
    conditions / verification 0..MAX_STEPS (32 non-blank strings <=1024)
    attempted                 bool (default False)
    succeeded                 None (unknown) or bool (default None)

Bypass containment (Escape 1, M01.2-M01.11 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation.

NOT implemented here (owned elsewhere): rollback template authoring (M10.1),
condition evaluation (M10.2), single-attempt executor (M10.3),
re-verification (M10.4), escalation on irreversible/failure (M10.5).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn, Optional, Self

from pydantic import BaseModel, Field, field_validator, model_validator

from app.contracts.incident import FrozenDict
from app.contracts.values import canonical_json

MAX_ID_LEN = 128
MAX_RB_ENTRIES = 32
MAX_RB_DEPTH = 5
MAX_RB_JSON_BYTES = 16384
MAX_STEPS = 32
MAX_STEP_LEN = 1024


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


class Rollback(BaseModel):
    """One rollback record: template + conditions + attempt outcome."""

    model_config = {"frozen": True, "extra": "forbid"}

    execution_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    rollback_action: FrozenDict = Field(
        description="REQUIRED rollback template (mapping only).",
    )
    conditions: tuple[str, ...] = Field(
        default=(),
        description="Trigger conditions (e.g. FAILED, WORSENED).",
    )
    verification: tuple[str, ...] = Field(
        default=(),
        description="Re-verification step names.",
    )
    attempted: bool = Field(
        default=False,
        description="Whether the single auto-attempt ran.",
    )
    succeeded: Optional[bool] = Field(
        default=None,
        description="None = unknown/not-yet-attempted; else outcome.",
    )    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "Rollback.model_construct is blocked: it skips validation. "
            "Use Rollback(...) or Rollback.model_validate for trusted "
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

    @field_validator("execution_id")
    @classmethod
    def _execution_id(cls, v: str) -> str:
        return _check_identifier("execution_id", v, MAX_ID_LEN)

    @field_validator("rollback_action", mode="before")
    @classmethod
    def _rollback_action(cls, v: Any) -> Any:
        if isinstance(v, FrozenDict):
            action = v
        elif isinstance(v, Mapping):
            try:
                action = FrozenDict(dict(v))
            except Exception as exc:
                raise ValueError(
                    "rollback_action must be a string-keyed object") from exc
        else:
            raise ValueError(
                "rollback_action is REQUIRED and must be an object "
                f"(got {type(v).__name__})"
            )
        if len(action) > MAX_RB_ENTRIES:
            raise ValueError(
                f"rollback_action must hold at most {MAX_RB_ENTRIES} entries")
        size = len(canonical_json(action.to_plain()).encode("utf-8"))
        if size > MAX_RB_JSON_BYTES:
            raise ValueError(
                f"rollback_action must serialize within {MAX_RB_JSON_BYTES} bytes")
        return action

    @field_validator("conditions", "verification", mode="before")
    @classmethod
    def _steps(cls, v: Any, info: Any) -> Any:
        name = str(info.field_name)
        if v is None:
            raise ValueError(f"{name} must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError(f"{name} must be a list of strings")
        items = list(v)
        if len(items) > MAX_STEPS:
            raise ValueError(f"{name} must hold at most {MAX_STEPS} entries")
        checked: list[str] = []
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"{name} entries must be non-empty strings")
            if item != item.strip():
                raise ValueError(
                    f"{name} entries must not have leading/trailing whitespace")
            if len(item) > MAX_STEP_LEN:
                raise ValueError(
                    f"{name} entries must be at most {MAX_STEP_LEN} characters")
            checked.append(item)
        return checked

    @field_validator("attempted", mode="before")
    @classmethod
    def _attempted_strict(cls, v: Any) -> Any:
        if type(v) is not bool:
            raise ValueError("attempted must be a boolean")
        return v

    @field_validator("succeeded", mode="before")
    @classmethod
    def _succeeded_strict(cls, v: Any) -> Any:
        if v is None or type(v) is bool:
            return v
        raise ValueError("succeeded must be null or a boolean")

    @model_validator(mode="after")
    def _outcome_consistency(self) -> "Rollback":
        # An outcome without an attempt is incoherent (succeeded=True/False
        # proves the single auto-attempt ran). attempted=True +
        # succeeded=None stays legal: the attempt ran, the outcome is not
        # yet recorded.
        if self.succeeded is not None and not self.attempted:
            raise ValueError("succeeded outcome requires attempted=True")
        return self

    @classmethod
    def from_legacy(cls, legacy: Any) -> Rollback:
        """Build a canonical Rollback from ``app.schemas`` (1:1 wire)."""
        return cls(
            execution_id=str(legacy.execution_id),
            rollback_action=FrozenDict(dict(legacy.rollback_action)),
            conditions=tuple(legacy.conditions),
            verification=tuple(legacy.verification),
            attempted=bool(legacy.attempted),
            succeeded=legacy.succeeded,
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.Rollback`` shape."""
        from app.schemas import Rollback as LegacyRollback  # noqa: E402

        return LegacyRollback(
            execution_id=self.execution_id,
            rollback_action=self.rollback_action,
            conditions=self.conditions,
            verification=self.verification,
            attempted=self.attempted,
            succeeded=self.succeeded,
        )
