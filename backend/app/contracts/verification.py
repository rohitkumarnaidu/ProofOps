"""M01.11 Verification schema - canonical VerificationResult contract.

Ownership: M01.11 owns THIS FILE ONLY
(``backend/app/contracts/verification.py``). Frozen vocabulary (``Verdict``)
is owned by M01.1 and is imported, never redeclared. Legacy ``app.schemas``
is a compat layer owned by M01.1 - it is read in tests/bridges but never
modified here.

Spec: PS03_FINAL_SPEC_V2 S29 - independent checks (pod ready, deploy
available, err_rate<thr, p95<SLO, zero new CrashLoop 60s, version==expected)
with verdict RESOLVED|PARTIAL|FAILED|WORSENED|ROLLBACK_REQUIRED|ESCALATE.
Planner output is inadmissible as evidence; exit-0-with-bad-SLO -> FAILED.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
verification result (strict verdict, bool-only checks map, bounded detail).
It performs NO health probing, NO SLO comparison, and NO verdict computation.
Those are verifier duties (future M09). A constructed result is well-formed
DATA - only the independent deterministic verifier may author one, and the
planner's own assertions are never valid input.

Legacy wire mapping (field names match legacy ``app.schemas``
``VerificationResult`` EXACTLY)::

    execution_id / verdict / checks / detail.

    ``checks`` stores canonical ``FrozenDict`` restricted to bool values
    (deep-immutable, detached on dump); legacy carries a plain dict and the
    bridges coerce both ways.

Bounds table::

    execution_id  1..MAX_ID_LEN   (128, identifier)
    checks        0..MAX_CHECKS   (32 named bool checks)
    detail        0..MAX_DETAIL   (4096, verbatim, may be "")

Bypass containment (Escape 1, M01.2-M01.10 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation.

NOT implemented here (owned elsewhere): health/deployment/SLO/error/latency/
CrashLoop checks (M09.1-M09.6), verdict matrix computation (M09.7), rollback
triggering on FAILED (M09.8/M10), SLO config versioning.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import Verdict
from app.contracts.incident import FrozenDict

MAX_ID_LEN = 128
MAX_CHECKS = 32
MAX_CHECK_NAME_LEN = 128
MAX_DETAIL = 4096


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


class VerificationResult(BaseModel):
    """One independent verification outcome for an execution."""

    model_config = {"frozen": True, "extra": "forbid"}

    execution_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    verdict: Verdict = Field(
        description="Strict Verdict (exit status is NOT a verdict).",
    )
    checks: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Named bool checks (e.g. {pod_ready: true}).",
    )
    detail: str = Field(
        default="",
        max_length=MAX_DETAIL,
        description="Human-readable detail (verbatim, may be empty).",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "VerificationResult.model_construct is blocked: it skips "
            "validation. Use VerificationResult(...) or "
            "VerificationResult.model_validate for trusted instances."
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

    @field_validator("checks", mode="before")
    @classmethod
    def _checks_bool_map(cls, v: Any) -> Any:
        if isinstance(v, FrozenDict):
            items = list(v.items())
        elif isinstance(v, Mapping):
            try:
                items = list(dict(v).items())
            except Exception as exc:
                raise ValueError("checks must be a string-keyed object") from exc
        else:
            raise ValueError(
                "checks must be an object mapping names to booleans "
                f"(got {type(v).__name__})"
            )
        if len(items) > MAX_CHECKS:
            raise ValueError(f"checks must hold at most {MAX_CHECKS} entries")
        for k, val in items:
            _check_identifier("checks names", k, MAX_CHECK_NAME_LEN)
            # isinstance(True, int) is True: exclude bool FIRST, then require
            # exact bool so 0/1/"true" can never launder as a check outcome.
            if type(val) is not bool:
                raise ValueError(
                    f"checks[{k!r}] must be a boolean, got {type(val).__name__}")
        return FrozenDict(dict(items))

    @field_validator("detail")
    @classmethod
    def _detail(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("detail must be a string")
        if len(v) > MAX_DETAIL:
            raise ValueError(f"detail must be at most {MAX_DETAIL} characters")
        return v

    @classmethod
    def from_legacy(cls, legacy: Any) -> VerificationResult:
        """Build a canonical result from ``app.schemas`` (1:1 wire)."""
        return cls(
            execution_id=str(legacy.execution_id),
            verdict=legacy.verdict,
            checks=FrozenDict(dict(legacy.checks)),
            detail=str(legacy.detail),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas`` shape."""
        from app.schemas import (  # noqa: E402
            VerificationResult as LegacyResult,
        )

        return LegacyResult(
            execution_id=self.execution_id,
            verdict=self.verdict,
            checks=self.checks.to_plain(),
            detail=self.detail,
        )
