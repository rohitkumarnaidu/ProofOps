"""M01.4 Evidence schema (canonical contract, owned by M01.4 ONLY).

Ownership: M01.4 owns this file exclusively. No other module may edit it.
Frozen-vocabulary reuse: ``source_type`` is the M01.1-frozen
``app.contracts.enums.SourceType`` (log/metric/trace/deploy/topology/
runbook/history) and ``trust`` is the M01.1-frozen
``app.contracts.enums.TrustLevel`` (high/med/low), imported from
``app.contracts`` — never redeclared here. No other enum is defined in
this file. (``EvidenceType`` is the frozen M01.1 alias of ``SourceType``;
the kind-vs-source split is reserved for M05.)

Spec: PS03_FINAL_SPEC_V2 §21 —
``Evidence{evidence_id, incident_id, source_type, source_id, ts,
ref(span/line/row), hash, freshness_s, relevance 0..1, trust high|med|low}``.

Trust boundary: this contract performs validated construction ONLY. It
guarantees the SHAPE of an evidence record (field presence, types,
documented bounds); it does not authenticate the source, judge relevance,
or authorize anything. Consumers must treat a constructed ``Evidence`` as
well-formed DATA, never as a trusted instruction, and never as proof that
the referenced source actually says what a claim asserts.

Scalar-only model: every field is a ``str`` / ``datetime`` / ``float`` /
frozen enum, so there are no containers to alias — dump detachment and
round-trip determinism hold by construction (asserted by test).

Bounds table (all enforced at construction; rationale per constant):
- MAX_EVIDENCE_ID_LEN = 128 ... uuid4 hex is 32 chars; 128 leaves room for
  human/upstream prefixes while staying index/log safe.
- MAX_INCIDENT_ID_LEN = 128 ... incident IDs are identifier-shaped
  (same PK rationale as M01.2 MAX_ID_ITEM_LEN).
- MAX_SOURCE_ID_LEN = 128 .... source-row IDs are identifier-shaped spans,
  trace IDs, deploy IDs, runbook pins (same PK rationale).
- MAX_REF_LEN = 256 ........... ref is a human/navigable pointer
  ("logs/app.log:120-145", "trace 4f2a span 7", "row 9182"); 256 fits
  paths/URIs while bounding rows.
- MAX_HASH_LEN = 128 .......... sha256 hex is 64 chars; 128 leaves room for
  an algorithm prefix should M05 ever version its hashing scheme.
- MAX_FRESHNESS_S = 315360000.0  10 years in seconds; freshness is
  non-negative age — larger values are meaningless and unbounded floats
  risk DB/API absurdity.
- relevance is a closed 0..1 float; NaN/inf rejected (non-finite floats
  are not JSON-canonical and must never enter the audit chain).
- freshness_s likewise rejects NaN/inf.

Whitespace rule: leading/trailing whitespace is REJECTED (ValidationError)
on every identifier field (evidence_id, incident_id, source_id, ref,
hash) — never silently stripped, so two producers can never disagree on
an identifier's canonical form.

Timestamp rule: ``ts`` must be timezone-aware (naive datetimes rejected),
defaulting to ``utcnow()``. Cross-module timestamps (Alert/Incident) share
the same rule and helper — no second clock.

Status choice: there is deliberately NO lifecycle/status field here.
Evidence is an immutable observation record; workflow state lives on the
incident/action (M14), and claim-class gating (MUST-CITE coverage) lives
with the RCA publisher (spec §21 gate), not in this shape.

Explicitly NOT implemented (owned elsewhere, must not be added here):
claim↔evidence mapping and MUST-CITE coverage gating (M05/RCA publisher),
retrieval/ranking (M12), runbook/history KB linkage (M12/M13), freshness
policy (which ages are "stale" is a policy decision, M06), persistence,
and any telemetry-source SDK coupling.
"""
from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import datetime
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import SourceType, TrustLevel
from app.contracts.values import new_id, utcnow

MAX_EVIDENCE_ID_LEN = 128
MAX_INCIDENT_ID_LEN = 128
MAX_SOURCE_ID_LEN = 128
MAX_REF_LEN = 256
MAX_HASH_LEN = 128
MAX_FRESHNESS_S = 315360000.0  # 10 years in seconds; freshness is an age


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _check_finite(name: str, value: float) -> float:
    """Reject NaN/inf: non-finite floats are not JSON-canonical."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(float(value)):
        raise ValueError(f"{name} must be finite (NaN/inf rejected)")
    return float(value)


class Evidence(BaseModel):
    """Canonical evidence contract: validated construction only, no behavior."""

    model_config = {"frozen": True, "extra": "forbid"}

    evidence_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_EVIDENCE_ID_LEN,
    )
    incident_id: str = Field(min_length=1, max_length=MAX_INCIDENT_ID_LEN)
    source_type: SourceType
    source_id: str = Field(min_length=1, max_length=MAX_SOURCE_ID_LEN)
    ts: datetime = Field(default_factory=utcnow)
    ref: str = Field(min_length=1, max_length=MAX_REF_LEN)
    hash: str = Field(min_length=1, max_length=MAX_HASH_LEN)
    freshness_s: float = Field(default=0.0, ge=0.0, le=MAX_FRESHNESS_S)
    relevance: float = Field(default=0.0, ge=0.0, le=1.0)
    trust: TrustLevel = TrustLevel.MED

    # -- Escape 1: bypass containment ----------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor.

        Use ``Evidence(...)`` / ``model_validate`` / ``model_validate_json``
        so every instance carries validated state. Raising here (instead of
        merely documenting) makes the bypass fail loudly at the call site.
        """
        raise TypeError(
            "Evidence.model_construct is blocked: it skips validation. "
            "Use Evidence(...) or Evidence.model_validate for trusted instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation.

        Upstream ``model_copy(update=...)`` applies updates WITHOUT
        validation (verified sibling bypass of ``model_construct``). Merging
        then re-validating keeps the convenience API while failing closed on
        invalid updates; unknown keys are rejected (``extra=forbid``).
        """
        if update:
            merged = self.model_dump()
            merged.update(dict(update))
            return self.model_validate(merged)
        return super().model_copy(update=None, deep=deep)

    @field_validator(
        "evidence_id", "incident_id", "source_id", "ref", "hash"
    )
    @classmethod
    def _identifiers_canonical(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, {
            "evidence_id": MAX_EVIDENCE_ID_LEN,
            "incident_id": MAX_INCIDENT_ID_LEN,
            "source_id": MAX_SOURCE_ID_LEN,
            "ref": MAX_REF_LEN,
            "hash": MAX_HASH_LEN,
        }[str(info.field_name)])

    @field_validator("ts")
    @classmethod
    def _ts_tz_aware(cls, v: datetime) -> datetime:
        if not isinstance(v, datetime):
            raise ValueError("ts must be a datetime")
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("ts must be timezone-aware (reject naive)")
        return v

    @field_validator("freshness_s", "relevance", mode="before")
    @classmethod
    def _numbers_strict(cls, v: Any) -> Any:
        # Reject bools/strings/collections BEFORE pydantic's lax coercion
        # (True -> 1.0, "12" -> 12.0) can silently launder producer bugs.
        # Genuine JSON numbers (int/float) pass through to range checks.
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError("must be a JSON number (bool/str rejected)")
        return v

    @field_validator("freshness_s")
    @classmethod
    def _freshness_bounded(cls, v: float) -> float:
        v = _check_finite("freshness_s", v)
        if v < 0.0 or v > MAX_FRESHNESS_S:
            raise ValueError(
                f"freshness_s must be within 0..{MAX_FRESHNESS_S}"
            )
        return v

    @field_validator("relevance")
    @classmethod
    def _relevance_bounded(cls, v: float) -> float:
        v = _check_finite("relevance", v)
        if v < 0.0 or v > 1.0:
            raise ValueError("relevance must be within 0..1")
        return v

    @classmethod
    def from_legacy(cls, legacy: Any) -> Evidence:
        """Build a canonical Evidence from a legacy ``app.schemas.Evidence``.

        Mapping (documented, field-for-field; legacy shape already carries
        the spec §21 fields): evidence_id <- evidence_id;
        incident_id <- incident_id; source_type <- source_type;
        source_id <- source_id; ts <- ts; ref <- ref; hash <- hash;
        freshness_s <- freshness_s; relevance <- relevance; trust <- trust.
        Duck-typed on purpose: this module must not import app.schemas at
        module scope (schemas is the compat layer that imports contracts —
        a top-level import here would cycle).
        """
        return cls(
            evidence_id=str(legacy.evidence_id),
            incident_id=str(legacy.incident_id),
            source_type=legacy.source_type,
            source_id=str(legacy.source_id),
            ts=legacy.ts,
            ref=str(legacy.ref),
            hash=str(legacy.hash),
            freshness_s=float(legacy.freshness_s),
            relevance=float(legacy.relevance),
            trust=legacy.trust,
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.Evidence`` shape.

        Reverse of from_legacy. The import is method-local to avoid a
        contracts -> schemas import cycle; returns Any so this module never
        depends on the legacy type at import time.
        """
        from app.schemas import Evidence as LegacyEvidence  # noqa: E402

        return LegacyEvidence(
            evidence_id=self.evidence_id,
            incident_id=self.incident_id,
            source_type=self.source_type,
            source_id=self.source_id,
            ts=self.ts,
            ref=self.ref,
            hash=self.hash,
            freshness_s=self.freshness_s,
            relevance=self.relevance,
            trust=self.trust,
        )
