"""M01.4 Evidence schema - canonical Evidence contract.

Ownership: M01.4 owns THIS FILE ONLY (``backend/app/contracts/evidence.py``).
Frozen vocabulary (``SourceType``/``TrustLevel``) is owned by M01.1 and is
imported, never redeclared. Legacy ``app.schemas`` is a compat layer owned by
M01.1 - it is read in tests but never modified here.

Spec: PS03_FINAL_SPEC_V2 S21 -
``Evidence{evidence_id, incident_id, source_type, source_id, ts,
ref(span/line/row), hash, freshness_s, relevance 0..1, trust high|med|low}``.
Field names match the spec and the legacy wire EXACTLY (no renames): a
renamed wire is a broken wire.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
evidence item. It performs no retrieval, no ranking, no claim mapping, no hash
computation/verification, and no freshness/trust policy. Agent code reasons;
the control plane (future M05/M12/M15) decides.

Legacy wire mapping (canonical == legacy ``app.schemas.Evidence``)::

    evidence_id  == evidence_id   (opaque id, ``values.new_id`` default)
    incident_id  == incident_id   (plain str link; M01.2 owns Incident)
    source_type  == source_type   (strict ``SourceType``)
    source_id    == source_id     (which instrument / object)
    ts           == ts            (tz-aware in both)
    ref          == ref           (IDENTICAL pointer-to-source concept for
                                  wire continuity: line range, row id, ...)
    hash         == hash          (opaque digest string, see below)
    freshness_s  == freshness_s   (non-negative finite float seconds)
    relevance    == relevance     (0..1 inclusive)
    trust        == trust         (strict ``TrustLevel``)

Bounds table (explicit maxima; ``min_length=1`` fields reject empty)::

    evidence_id  1..MAX_ID_LEN        (128, auto ``new_id`` default)
    incident_id  1..MAX_ID_LEN        (128, REQUIRED, plain str link)
    source_id    1..MAX_ID_LEN        (128, REQUIRED)
    ref          1..MAX_REF_LEN       (512, REQUIRED, wire continuity)
    hash         1..MAX_HASH_LEN      (256, REQUIRED, opaque string)
    freshness_s  0..MAX_FRESHNESS_S   (10 years in seconds; age, finite)
    relevance    0..1 inclusive       (finite float, default 1.0)

Whitespace rule: identifier fields (``evidence_id``, ``incident_id``,
``source_id``, ``ref``, ``hash``) REJECT leading/trailing whitespace
(space/tab/newline) - never stripped, so producers cannot disagree on
canonical form.

Number rule: ``freshness_s``/``relevance`` accept genuine JSON numbers
(int/float) ONLY. Bools and strings are rejected BEFORE pydantic's lax
coercion (``True -> 1.0``, ``"30" -> 30.0``) can launder producer bugs;
NaN/inf are rejected (not JSON-canonical, must never enter audit data).

Trust-level semantics (advisory labels; computation lives in future M05.4)::

    high = cross-validated by >= 2 independent sources AND fresh, from an
           instrumented healthy pipeline.
    med  = single healthy source, plausible, not yet cross-validated
           (default for newly captured evidence).
    low  = stale, unhealthy/degraded pipeline, or third-party/unverifiable
           provenance - consume only with corroboration.

Hash-field contract: ``hash`` documents the EXPECTED shape (64-char lowercase
hex sha256 digest as produced by ``values.sha256_hex``) but accepts ANY
non-empty bounded string. No hash is computed or verified here; chain of
custody beyond carrying this field belongs to M15/M05.2.

Bypass containment (Escape 1, M01.2/M01.3 standard): ``model_construct`` is
overridden to raise ``TypeError`` and ``model_copy(update=...)`` is routed
through full re-validation - upstream applies updates WITHOUT validation,
so the convenience API fails closed here instead.

NOT implemented here (owned elsewhere): retrieval / reranking / predigestion
(M12), claim-to-evidence mapping logic beyond ``evidence_ids: list[str]``
style linkage readiness (M05), freshness gating / staleness escalation policy
(M05.3/M18.4), trust computation / multi-source agreement (M05.4),
chain-of-custody verification beyond the opaque ``hash`` field (M15).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import datetime
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import SourceType, TrustLevel
from app.contracts.values import new_id, utcnow

MAX_ID_LEN = 128
MAX_REF_LEN = 512
MAX_HASH_LEN = 256
MAX_FRESHNESS_S = 315360000.0  # 10 years in seconds; freshness is an age


class Evidence(BaseModel):
    """One canonical evidence item: a bounded source pointer + scores."""

    model_config = {"frozen": True, "extra": "forbid"}

    evidence_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Opaque evidence id (uuid4 hex default). No global format.",
    )
    incident_id: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Plain str link to the owning incident. M01.2 owns "
        "Incident; it is never imported here.",
    )
    source_type: SourceType = Field(
        description="Strict SourceType (M01.1 vocabulary; log/metric/trace/"
        "deploy/topology/runbook/history)."
    )
    source_id: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Which instrument/object produced this (service, host, "
        "runbook id, ...).",
    )
    ts: datetime = Field(
        default_factory=utcnow,
        description="tz-aware observation time. "
        "Naive datetimes are rejected.",
    )
    ref: str = Field(
        min_length=1,
        max_length=MAX_REF_LEN,
        description="Pointer to the full source blob. Same concept and name "
        "as legacy `ref` for wire continuity.",
    )
    hash: str = Field(
        min_length=1,
        max_length=MAX_HASH_LEN,
        description="Opaque integrity-digest string. Expected shape is a "
        "64-char lowercase hex sha256 digest (see values.sha256_hex), but "
        "any non-empty bounded string is accepted; nothing is computed or "
        "verified here.",
    )
    freshness_s: float = Field(
        default=0.0,
        ge=0,
        le=MAX_FRESHNESS_S,
        description="Age of the underlying observation in seconds at capture. "
        "Non-negative finite float, capped: larger values are meaningless.",
    )
    relevance: float = Field(
        default=1.0,
        ge=0,
        le=1,
        description="Relevance score 0..1 inclusive. Default 1.0: fully "
        "relevant until a scorer down-weights it.",
    )
    trust: TrustLevel = Field(
        default=TrustLevel.MED,
        description="Strict TrustLevel. high = cross-validated + fresh "
        "instrumented source; med = single healthy source; low = "
        "stale/unhealthy/third-party.",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor.

        Use ``Evidence(...)`` / ``model_validate`` / ``model_validate_json``
        so every instance carries validated state.
        """
        raise TypeError(
            "Evidence.model_construct is blocked: it skips validation. "
            "Use Evidence(...) or Evidence.model_validate for trusted instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation.

        Upstream ``model_copy(update=...)`` applies updates WITHOUT
        validation. Merging then re-validating keeps the convenience API
        while failing closed on invalid updates; unknown keys are rejected
        (``extra=forbid``).
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
    def _no_padded_identifiers(cls, v: str, info: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        if v != v.strip():
            raise ValueError(
                "identifier fields must not have leading/trailing whitespace"
            )
        if len(v) > {
            "evidence_id": MAX_ID_LEN,
            "incident_id": MAX_ID_LEN,
            "source_id": MAX_ID_LEN,
            "ref": MAX_REF_LEN,
            "hash": MAX_HASH_LEN,
        }[str(info.field_name)]:
            raise ValueError(f"{info.field_name} exceeds its documented maximum")
        return v

    @field_validator("ts")
    @classmethod
    def _require_tz_aware(cls, v: datetime) -> datetime:
        if not isinstance(v, datetime):
            raise ValueError("ts must be a datetime")
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("ts must be tz-aware (reject naive)")
        return v

    @field_validator("freshness_s", "relevance", mode="before")
    @classmethod
    def _numbers_strict(cls, v: Any) -> Any:
        # Reject bools/strings/collections BEFORE pydantic's lax coercion
        # (True -> 1.0, "30" -> 30.0) can silently launder producer bugs.
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError("must be a JSON number (bool/str rejected)")
        if not math.isfinite(float(v)):
            raise ValueError("must be finite (NaN/inf rejected)")
        return v

    @classmethod
    def from_legacy(cls, legacy: Any) -> Evidence:
        """Build a canonical Evidence from a legacy ``app.schemas.Evidence``.

        Field-for-field mapping (identical wire names by design):
        evidence_id, incident_id, source_type, source_id, ts, ref, hash,
        freshness_s, relevance, trust. Duck-typed on purpose: this module
        must not import app.schemas at module scope (schemas is the compat
        layer that imports contracts - a top-level import here would cycle).
        """
        if type(legacy) is cls:
            return legacy  # already canonical: exact, no coercion
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
