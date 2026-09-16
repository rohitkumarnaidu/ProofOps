"""M01.5 Hypothesis schema - canonical Claim + Hypothesis contracts.

Ownership: M01.5 owns THIS FILE ONLY (``backend/app/contracts/hypothesis.py``).
Frozen vocabulary (``ClaimClass``/``HypothesisStatus``) is owned by M01.1 and
is imported, never redeclared. Legacy ``app.schemas`` is a compat layer owned
by M01.1 - it is read in tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S25 -
``hypotheses[{text, confidence, supporting[], contradicting[], test{tool,args},
result, status SUPPORTED|REJECTED|UNCERTAIN}]`` plus ``INSUFFICIENT_EVIDENCE``
(status vocabulary owned by M01.1 ``HypothesisStatus``), and S21 claim classes
(MUST-CITE / SHOULD-CITE / OPTIONAL) carried by ``Claim.claim_class``.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
hypothesis and one claim (field presence, types, documented bounds). It
performs no diagnosis, no evidence retrieval, no confidence computation, no
claim-to-evidence coverage gating, and no contradiction resolution. Agent code
reasons; the control plane (future M05/M12/M13/M15) decides.

Legacy wire mapping (field names match legacy ``app.schemas`` EXACTLY)::

    Claim:      claim_id / text / evidence_ids / claim_class (identical)
    Hypothesis: hypothesis_id / text / confidence / supporting /
                contradicting / test_tool / test_args / test_result / status
                (identical; bridges are lossless both directions since the
                P1 rival-models closure).

Bounds table (explicit maxima; identifier fields reject empty/padded)::

    claim_id/hypothesis_id  1..MAX_ID_LEN        (128, auto ``new_id`` default)
    text                    1..MAX_TEXT_LEN      (4096, verbatim prose, non-blank)
    evidence_ids            0..MAX_CLAIM_REFS    (64 ID strings, citation links)
    supporting/contradicting 0..MAX_EVID_REFS   (32 ID strings each)
    test_tool               "" or 1..MAX_TOOL_LEN (128, "" = untested)
    test_args               0..MAX_ARGS_ENTRIES  (32 entries, depth <= 4,
                                                 bytes <= 8192)
    test_result             0..MAX_TEXT_LEN      (4096, verbatim, may be "")
    confidence              0..1 inclusive       (strict JSON number)

Whitespace rule: identifier fields (IDs, ID-list entries, ``test_tool`` when
non-empty) REJECT leading/trailing whitespace - never stripped, so producers
cannot disagree on canonical form. ``text``/``test_result`` are verbatim
content (not identifiers): preserved exactly as given, but must be non-blank
for ``text`` (an empty hypothesis explains nothing); ``test_result`` may be
"" (test not yet run).

Number rule: ``confidence`` accepts genuine JSON numbers (int/float) ONLY.
Bools and strings are rejected BEFORE pydantic's lax coercion
(``True -> 1.0``, ``"0.9" -> 0.9``) can launder producer bugs; NaN/inf are
rejected (not JSON-canonical, must never enter audit data).

Bypass containment (Escape 1, M01.2/M01.3/M01.4 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation - upstream
applies updates WITHOUT validation, so the convenience API fails closed here
instead.

NOT implemented here (owned elsewhere): hypothesis generation/ranking (A2,
M13), confidence calibration (M13), INSUFFICIENT_EVIDENCE policy (M13/M05),
claim-to-evidence coverage gating (M05.6/M18), citation-precision scoring
(M16/C2), persistence.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import ClaimClass, HypothesisStatus
from app.contracts.incident import FrozenDict
from app.contracts.values import new_id

MAX_ID_LEN = 128
MAX_TEXT_LEN = 4096
MAX_CLAIM_REFS = 64
MAX_EVID_REFS = 32
MAX_TOOL_LEN = 128
MAX_ARGS_ENTRIES = 32
MAX_ARGS_DEPTH = 4
MAX_ARGS_JSON_BYTES = 8192


def _mapping_depth(value: Any) -> int:
    """Deepest container nesting level (scalars 0). Iterative: no recursion
    limit risk. Twin of the action/execution depth guards (kept local: this
    module may import only frozen contracts, never sibling schemas)."""
    best = 0
    stack: list[Any] = [value]
    levels: list[int] = [0]
    while stack:
        v = stack.pop()
        d = levels.pop()
        if isinstance(v, Mapping):
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


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _check_id_list(name: str, value: Any, max_items: int) -> list[str]:
    """Shared ID-list rule: strict list/tuple input, checked entries."""
    if value is None:
        raise ValueError(f"{name} must be a list, not null")
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be a list of ID strings")
    items = list(value)
    if len(items) > max_items:
        raise ValueError(f"{name} must hold at most {max_items} entries")
    checked: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"{name} entries must be non-empty strings")
        checked.append(_check_identifier(f"{name} entries", item, MAX_ID_LEN))
    return checked


class Claim(BaseModel):
    """One citable claim: verbatim text + evidence links + citation class."""

    model_config = {"frozen": True, "extra": "forbid"}

    claim_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Opaque claim id (uuid4 hex default). No global format.",
    )
    text: str = Field(
        min_length=1,
        max_length=MAX_TEXT_LEN,
        description="Verbatim claim prose, preserved exactly (non-blank).",
    )
    evidence_ids: tuple[str, ...] = Field(
        default=(),
        description="Evidence links (plain str IDs; M05 owns coverage).",
    )
    claim_class: ClaimClass = Field(
        default=ClaimClass.MUST_CITE,
        description="Strict ClaimClass (M01.1 vocabulary).",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "Claim.model_construct is blocked: it skips validation. "
            "Use Claim(...) or Claim.model_validate for trusted instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None,
                   deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation."""
        if update:
            merged = self.model_dump()
            merged.update(dict(update))
            return self.model_validate(merged)
        return super().model_copy(update=None, deep=deep)

    @field_validator("claim_id")
    @classmethod
    def _claim_id(cls, v: str) -> str:
        return _check_identifier("claim_id", v, MAX_ID_LEN)

    @field_validator("text")
    @classmethod
    def _text(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("text must be a non-empty string")
        if len(v) > MAX_TEXT_LEN:
            raise ValueError(f"text must be at most {MAX_TEXT_LEN} characters")
        return v

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def _evidence_ids(cls, v: Any) -> Any:
        return _check_id_list("evidence_ids", v, MAX_CLAIM_REFS)

    @classmethod
    def from_legacy(cls, legacy: Any) -> Claim:
        """Build a canonical Claim from a legacy ``app.schemas.Claim``.

        Field-for-field mapping (identical wire names by design).
        Duck-typed on purpose: this module must not import app.schemas at
        module scope (schemas is the compat layer that imports contracts -
        a top-level import here would cycle).
        """
        if type(legacy) is cls:
            return legacy  # already canonical: exact, no coercion
        return cls(
            claim_id=str(legacy.claim_id),
            text=str(legacy.text),
            evidence_ids=tuple(legacy.evidence_ids),
            claim_class=legacy.claim_class,
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.Claim`` shape."""
        from app.schemas import Claim as LegacyClaim  # noqa: E402

        return LegacyClaim(
            claim_id=self.claim_id,
            text=self.text,
            evidence_ids=self.evidence_ids,
            claim_class=self.claim_class,
        )


class Hypothesis(BaseModel):
    """One diagnostic hypothesis: prose + confidence + evidence refs + test."""

    model_config = {"frozen": True, "extra": "forbid"}

    hypothesis_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Opaque hypothesis id (uuid4 hex default).",
    )
    text: str = Field(
        min_length=1,
        max_length=MAX_TEXT_LEN,
        description="Verbatim hypothesis prose, preserved exactly.",
    )
    confidence: float = Field(
        ge=0,
        le=1,
        description="Confidence 0..1 inclusive (strict JSON number).",
    )
    supporting: tuple[str, ...] = Field(
        default=(),
        description="Supporting evidence IDs (plain str links).",
    )
    contradicting: tuple[str, ...] = Field(
        default=(),
        description="Contradicting evidence IDs (surfaced, never averaged).",
    )
    test_tool: str = Field(
        default="",
        max_length=MAX_TOOL_LEN,
        description='Test tool name, or "" when untested.',
    )
    test_args: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Test tool arguments (spec S25 test{tool,args}).",
    )
    test_result: str = Field(
        default="",
        max_length=MAX_TEXT_LEN,
        description='Verbatim test outcome, or "" when not yet run.',
    )
    status: HypothesisStatus = Field(
        default=HypothesisStatus.UNCERTAIN,
        description="Strict HypothesisStatus (M01.1 vocabulary).",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "Hypothesis.model_construct is blocked: it skips validation. "
            "Use Hypothesis(...) or Hypothesis.model_validate for trusted "
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

    @field_validator("hypothesis_id")
    @classmethod
    def _hypothesis_id(cls, v: str) -> str:
        return _check_identifier("hypothesis_id", v, MAX_ID_LEN)

    @field_validator("text")
    @classmethod
    def _text(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("text must be a non-empty string")
        if len(v) > MAX_TEXT_LEN:
            raise ValueError(f"text must be at most {MAX_TEXT_LEN} characters")
        return v

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence_strict(cls, v: Any) -> Any:
        # Reject bools/strings/collections BEFORE pydantic's lax coercion
        # (True -> 1.0, "0.9" -> 0.9) can silently launder producer bugs.
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError("confidence must be a JSON number (bool/str rejected)")
        if not math.isfinite(float(v)):
            raise ValueError("confidence must be finite (NaN/inf rejected)")
        return v

    @field_validator("supporting", "contradicting", mode="before")
    @classmethod
    def _evid_refs(cls, v: Any, info: Any) -> Any:
        return _check_id_list(str(info.field_name), v, MAX_EVID_REFS)

    @field_validator("test_tool")
    @classmethod
    def _test_tool(cls, v: str) -> str:
        # "" = untested (legacy default); otherwise identifier rules apply.
        if v == "":
            return v
        return _check_identifier("test_tool", v, MAX_TOOL_LEN)

    @field_validator("test_args")
    @classmethod
    def _test_args_bounds(cls, v: FrozenDict) -> FrozenDict:
        from app.contracts.values import canonical_json  # noqa: E402

        if len(v) > MAX_ARGS_ENTRIES:
            raise ValueError(
                f"test_args must hold at most {MAX_ARGS_ENTRIES} entries")
        if _mapping_depth(v) > MAX_ARGS_DEPTH:
            raise ValueError(
                f"test_args must nest at most {MAX_ARGS_DEPTH} levels deep")
        size = len(canonical_json(v.to_plain()).encode("utf-8"))
        if size > MAX_ARGS_JSON_BYTES:
            raise ValueError(
                f"test_args must serialize within {MAX_ARGS_JSON_BYTES} bytes")
        return v

    @field_validator("test_result")
    @classmethod
    def _test_result(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("test_result must be a string")
        if len(v) > MAX_TEXT_LEN:
            raise ValueError(f"text must be at most {MAX_TEXT_LEN} characters")
        return v

    @classmethod
    def from_legacy(cls, legacy: Any) -> Hypothesis:
        """Build a canonical Hypothesis from ``app.schemas.Hypothesis``.

        Every field maps 1:1, including ``test_args`` (mapping passthrough;
        absent on foreign duck objects means untested, hence empty). The old
        documented truncation is gone with the P1 closure: audit data must
        never be silently dropped in either direction.
        """
        if type(legacy) is cls:
            return legacy  # already canonical: exact, test_args preserved
        raw_args = getattr(legacy, "test_args", None)
        if isinstance(raw_args, FrozenDict):
            test_args = raw_args
        elif isinstance(raw_args, Mapping):
            test_args = FrozenDict(dict(raw_args))
        else:
            test_args = FrozenDict()
        return cls(
            hypothesis_id=str(legacy.hypothesis_id),
            text=str(legacy.text),
            confidence=float(legacy.confidence),
            supporting=tuple(legacy.supporting),
            contradicting=tuple(legacy.contradicting),
            test_tool=str(legacy.test_tool),
            test_args=test_args,
            test_result=str(legacy.test_result),
            status=legacy.status,
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.Hypothesis`` shape.

        P1 closure: the legacy shape IS canonical now, so ``test_args``
        round-trips losslessly (the old documented truncation is gone — there
        is no field to truncate into anymore, and silent audit-data loss is
        never acceptable).
        """
        from app.schemas import Hypothesis as LegacyHypothesis  # noqa: E402

        return LegacyHypothesis(
            hypothesis_id=self.hypothesis_id,
            text=self.text,
            confidence=self.confidence,
            supporting=self.supporting,
            contradicting=self.contradicting,
            test_tool=self.test_tool,
            test_args=self.test_args,
            test_result=self.test_result,
            status=self.status,
        )
