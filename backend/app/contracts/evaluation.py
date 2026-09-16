"""M01.15 Evaluation schema - canonical EvaluationRun + BenchmarkResult.

Ownership: M01.15 owns THIS FILE ONLY
(``backend/app/contracts/evaluation.py``). No frozen enum is needed here
(suite/variant vocabularies are owned by M16/M17; transitions belong to the
eval runner). Legacy ``app.schemas`` is a compat layer owned by M01.1 - it is
read in tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S33 - custom runner (pipeline-level) stores
``runs/*.jsonl`` + metrics JSON + HTML scorecard; S34 golden benchmarks carry
expected RCA + allowed/forbidden + SLO per case; S36 six quality gates
(C1-C6) grade every run. Raw tokens metered; $ via editable pricing table
only (never hard-coded vendor prices).

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
eval-run record and one benchmark-result record (metric maps are finite
float-only; token counters are non-negative ints). It performs NO grading, NO
scoring, NO baseline comparison, and NO benchmark fabrication. Those are
evaluation duties (future M16/M17). A constructed record is well-formed DATA
- every number it carries must trace to a measured run (JSONL) or be labeled
a derived metric. Fabricated metrics are a STOP condition.

Legacy wire mapping (field names match legacy ``app.schemas`` EXACTLY)::

    EvaluationRun: run_id / suite / case_id / passed / scores /
                   tokens_in / tokens_out / llm_calls / latency_ms.
    BenchmarkResult: case_id / scenario / variant / expected_cause /
                     predicted_cause / unsafe_executions /
                     citation_coverage / passed.

    ``scores``/``latency_ms`` store canonical ``FrozenDict`` restricted to
    finite float values (int accepted, bool rejected); legacy carries plain
    dicts.

Bounds table::

    run_id/suite/case_id/scenario  1..MAX_ID_LEN (128, identifiers)
    variant                        1..MAX_VARIANT_LEN (64, e.g. ADVERSARIAL)
    expected_cause                 1..MAX_TEXT_LEN (4096, verbatim, non-blank)
    predicted_cause                0..MAX_TEXT_LEN (4096; "" = unpredicted)
    scores/latency_ms              0..MAX_METRICS (64 finite-float entries)
    tokens_in/out, llm_calls, unsafe_executions  int >= 0
    citation_coverage              0..1 inclusive (strict JSON number)
    passed                         bool

Bypass containment (Escape 1, M01.2-M01.14 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation on BOTH
models.

NOT implemented here (owned elsewhere): eval runner pipeline (M16.1),
dataset loading incl. deep-5x5 + stub-7 (M16.2/M17), graders (M16.3),
baseline/optimized capture (M16.4/M16.5), C1-C6 gate scoring (M16.6/M36),
JSONL persistence + HTML scorecard (M16.8/M16.9).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.incident import FrozenDict
from app.contracts.values import new_id

MAX_ID_LEN = 128
MAX_VARIANT_LEN = 64
MAX_TEXT_LEN = 4096
MAX_METRICS = 64


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _check_float_map(name: str, value: Any) -> FrozenDict:
    """Metric-map rule: string keys, finite float values (bool rejected)."""
    if isinstance(value, FrozenDict):
        items = list(value.items())
    elif isinstance(value, Mapping):
        try:
            items = list(dict(value).items())
        except Exception as exc:
            raise ValueError(f"{name} must be a string-keyed object") from exc
    else:
        raise ValueError(
            f"{name} must be an object mapping names to numbers "
            f"(got {type(value).__name__})"
        )
    if len(items) > MAX_METRICS:
        raise ValueError(f"{name} must hold at most {MAX_METRICS} entries")
    clean: dict[str, float] = {}
    for k, val in items:
        _check_identifier(f"{name} keys", k, MAX_ID_LEN)
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ValueError(
                f"{name}[{k!r}] must be a JSON number (bool/str rejected)")
        if not math.isfinite(float(val)):
            raise ValueError(f"{name}[{k!r}] must be finite (NaN/inf rejected)")
        clean[k] = float(val)
    return FrozenDict(clean)


def _check_counter(name: str, value: Any) -> int:
    """Counter rule: non-negative int (bool rejected)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer (bool rejected)")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _check_ratio(name: str, value: Any) -> float:
    """Ratio rule: 0..1 inclusive strict JSON number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a JSON number (bool/str rejected)")
    if not math.isfinite(float(value)):
        raise ValueError(f"{name} must be finite (NaN/inf rejected)")
    if not 0.0 <= float(value) <= 1.0:
        raise ValueError(f"{name} must be within 0..1")
    return float(value)


class EvaluationRun(BaseModel):
    """One measured evaluation-run record: scores + budgets, no judgment."""

    model_config = {"frozen": True, "extra": "forbid"}

    run_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Opaque run id (uuid4 hex default).",
    )
    suite: str = Field(min_length=1, max_length=MAX_ID_LEN)
    case_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    passed: bool = Field(default=False)
    scores: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Metric scores (finite floats).",
    )
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    llm_calls: int = Field(default=0, ge=0)
    latency_ms: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Per-stage latency in ms (finite floats).",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "EvaluationRun.model_construct is blocked: it skips validation. "
            "Use EvaluationRun(...) or EvaluationRun.model_validate for "
            "trusted instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None,
                   deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation."""
        if update:
            merged = self.model_dump()
            merged.update(dict(update))
            return self.model_validate(merged)
        return super().model_copy(update=None, deep=deep)

    @field_validator("run_id", "suite", "case_id")
    @classmethod
    def _ids(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, MAX_ID_LEN)

    @field_validator("scores", "latency_ms", mode="before")
    @classmethod
    def _metrics(cls, v: Any, info: Any) -> Any:
        return _check_float_map(str(info.field_name), v)

    @field_validator("tokens_in", "tokens_out", "llm_calls", mode="before")
    @classmethod
    def _counters(cls, v: Any, info: Any) -> Any:
        return _check_counter(str(info.field_name), v)

    @field_validator("passed", mode="before")
    @classmethod
    def _passed_strict(cls, v: Any) -> Any:
        if type(v) is not bool:
            raise ValueError("passed must be a boolean")
        return v

    @classmethod
    def from_legacy(cls, legacy: Any) -> EvaluationRun:
        """Build a canonical run from ``app.schemas`` (1:1 wire)."""
        if type(legacy) is cls:
            return legacy  # already canonical: exact, no coercion
        return cls(
            run_id=str(legacy.run_id),
            suite=str(legacy.suite),
            case_id=str(legacy.case_id),
            passed=bool(legacy.passed),
            scores=FrozenDict({k: float(x)
                               for k, x in dict(legacy.scores).items()}),
            tokens_in=int(legacy.tokens_in),
            tokens_out=int(legacy.tokens_out),
            llm_calls=int(legacy.llm_calls),
            latency_ms=FrozenDict({k: float(x)
                                   for k, x in dict(legacy.latency_ms).items()}),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.EvaluationRun`` shape."""
        from app.schemas import EvaluationRun as LegacyRun  # noqa: E402

        return LegacyRun(
            run_id=self.run_id,
            suite=self.suite,
            case_id=self.case_id,
            passed=self.passed,
            scores=self.scores,
            tokens_in=self.tokens_in,
            tokens_out=self.tokens_out,
            llm_calls=self.llm_calls,
            latency_ms=self.latency_ms,
        )


class BenchmarkResult(BaseModel):
    """One benchmark-case outcome: prediction vs expected + safety counts."""

    model_config = {"frozen": True, "extra": "forbid"}

    case_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    scenario: str = Field(min_length=1, max_length=MAX_ID_LEN)
    variant: str = Field(
        min_length=1,
        max_length=MAX_VARIANT_LEN,
        description="Variant token (e.g. NORMAL, ADVERSARIAL).",
    )
    expected_cause: str = Field(min_length=1, max_length=MAX_TEXT_LEN)
    predicted_cause: str = Field(
        default="",
        max_length=MAX_TEXT_LEN,
        description='Predicted cause, or "" when unpredicted.',
    )
    unsafe_executions: int = Field(
        default=0,
        ge=0,
        description="Must be 0 (gate: unsafe_exec==0).",
    )
    citation_coverage: float = Field(
        default=0,
        ge=0,
        le=1,
        description="MUST-CITE coverage 0..1 (gate: 1.0).",
    )
    passed: bool = Field(default=False)

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "BenchmarkResult.model_construct is blocked: it skips validation. "
            "Use BenchmarkResult(...) or BenchmarkResult.model_validate for "
            "trusted instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None,
                   deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation."""
        if update:
            merged = self.model_dump()
            merged.update(dict(update))
            return self.model_validate(merged)
        return super().model_copy(update=None, deep=deep)

    @field_validator("case_id", "scenario")
    @classmethod
    def _ids(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, MAX_ID_LEN)

    @field_validator("variant")
    @classmethod
    def _variant(cls, v: str) -> str:
        return _check_identifier("variant", v, MAX_VARIANT_LEN)

    @field_validator("expected_cause")
    @classmethod
    def _expected(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("expected_cause must be a non-empty string")
        if len(v) > MAX_TEXT_LEN:
            raise ValueError(
                f"expected_cause must be at most {MAX_TEXT_LEN} characters")
        return v

    @field_validator("predicted_cause")
    @classmethod
    def _predicted(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("predicted_cause must be a string")
        if len(v) > MAX_TEXT_LEN:
            raise ValueError(
                f"predicted_cause must be at most {MAX_TEXT_LEN} characters")
        return v

    @field_validator("unsafe_executions", mode="before")
    @classmethod
    def _unsafe(cls, v: Any) -> Any:
        return _check_counter("unsafe_executions", v)

    @field_validator("citation_coverage", mode="before")
    @classmethod
    def _coverage(cls, v: Any) -> Any:
        return _check_ratio("citation_coverage", v)

    @field_validator("passed", mode="before")
    @classmethod
    def _passed_strict(cls, v: Any) -> Any:
        if type(v) is not bool:
            raise ValueError("passed must be a boolean")
        return v

    @classmethod
    def from_legacy(cls, legacy: Any) -> BenchmarkResult:
        """Build a canonical result from ``app.schemas`` (1:1 wire)."""
        if type(legacy) is cls:
            return legacy  # already canonical: exact, no coercion
        return cls(
            case_id=str(legacy.case_id),
            scenario=str(legacy.scenario),
            variant=str(legacy.variant),
            expected_cause=str(legacy.expected_cause),
            predicted_cause=str(legacy.predicted_cause),
            unsafe_executions=int(legacy.unsafe_executions),
            citation_coverage=float(legacy.citation_coverage),
            passed=bool(legacy.passed),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.BenchmarkResult`` shape."""
        from app.schemas import BenchmarkResult as LegacyBench  # noqa: E402

        return LegacyBench(
            case_id=self.case_id,
            scenario=self.scenario,
            variant=self.variant,
            expected_cause=self.expected_cause,
            predicted_cause=self.predicted_cause,
            unsafe_executions=self.unsafe_executions,
            citation_coverage=self.citation_coverage,
            passed=self.passed,
        )
