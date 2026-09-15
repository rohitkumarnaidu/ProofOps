"""M01.4 Evidence schema — canonical Evidence contract.

Ownership: M01.4 owns THIS FILE ONLY (``backend/app/contracts/evidence.py``).
Frozen vocabulary (``SourceType``/``TrustLevel``) is owned by M01.1 and is
imported, never redeclared. Legacy ``app.schemas`` is a compat layer owned by
M01.1 — it is read in tests but never modified here.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
evidence item. It performs no retrieval, no ranking, no claim mapping, no hash
computation/verification, and no freshness/trust policy. Agent code reasons;
the control plane (future M05/M12/M15) decides.

Legacy wire mapping (canonical -> legacy ``app.schemas.Evidence``)::

    evidence_id  == evidence_id   (opaque id, ``values.new_id`` default)
    incident_id  == incident_id   (plain str link; M01.2 owns Incident)
    source_type  == source_type   (strict ``SourceType``)
    source_id    == source_id     (which instrument / object)
    timestamp    == ts            (renamed; tz-aware in both)
    ref          == ref           (IDENTICAL pointer-to-source concept for
                                  wire continuity: line range, row id, ...)
    hash         == hash          (opaque digest string, see below)
    freshness    == freshness_s   (renamed; non-negative float seconds)
    relevance    == relevance     (0..1 inclusive)
    trust_level  == trust         (renamed; strict ``TrustLevel``)
    content      -- NEW, no legacy counterpart (bounded excerpt, DATA only)
    span         -- NEW, no legacy counterpart (bounded sub-pointer)

Bounds table (explicit maxima; ``min_length=1`` fields reject empty)::

    evidence_id  1..MAX_ID_LEN        (128, auto ``new_id`` default)
    incident_id  1..MAX_ID_LEN        (128, REQUIRED, plain str link)
    source_id    1..MAX_ID_LEN        (128, REQUIRED)
    ref          1..MAX_REF_LEN       (512, REQUIRED, wire continuity)
    span         0..MAX_SPAN_LEN      (256, optional sub-pointer)
    hash         1..MAX_HASH_LEN      (256, REQUIRED, opaque string)
    content      0..MAX_CONTENT_LEN   (4000, optional excerpt, DATA only)
    freshness    >= 0, finite         (float seconds, default 0.0)
    relevance    0..1 inclusive       (finite float, default 1.0)

Whitespace rule: identifier fields (``evidence_id``, ``incident_id``,
``source_id``, ``ref``, ``span``, ``hash``) REJECT leading/trailing
whitespace (space/tab/newline). ``content`` is exempt: it is free-text DATA
and may contain any characters, stored verbatim, never interpreted.

Trust-level semantics (advisory labels; computation lives in future M05.4)::

    high = cross-validated by >= 2 independent sources AND fresh, from an
           instrumented healthy pipeline.
    med  = single healthy source, plausible, not yet cross-validated
           (default for newly captured evidence).
    low  = stale, unhealthy/degraded pipeline, or third-party/unverifiable
           provenance — consume only with corroboration.

Hash-field contract: ``hash`` documents the EXPECTED shape (64-char lowercase
hex sha256 digest as produced by ``values.sha256_hex``) but accepts ANY
non-empty bounded string. No hash is computed or verified here; chain of
custody beyond carrying this field belongs to M15/M05.2.

NOT implemented here (owned elsewhere): retrieval / reranking / predigestion
(M12), claim-to-evidence mapping logic beyond ``evidence_ids: list[str]``
style linkage readiness (M05), freshness gating / staleness escalation policy
(M05.3/M18.4), trust computation / multi-source agreement (M05.4),
chain-of-custody verification beyond the opaque ``hash`` field (M15).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import SourceType, TrustLevel
from app.contracts.values import new_id, utcnow

MAX_ID_LEN = 128
MAX_REF_LEN = 512
MAX_SPAN_LEN = 256
MAX_HASH_LEN = 256
MAX_CONTENT_LEN = 4000


class Evidence(BaseModel):
    """One canonical evidence item: a bounded pointer + excerpt + scores."""

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
    timestamp: datetime = Field(
        default_factory=utcnow,
        description="tz-aware observation time (legacy name: ts). "
        "Naive datetimes are rejected.",
    )
    content: str = Field(
        default="",
        max_length=MAX_CONTENT_LEN,
        description="Bounded excerpt of the underlying observation. Inert "
        "DATA: stored verbatim, never interpreted or executed.",
    )
    span: str = Field(
        default="",
        max_length=MAX_SPAN_LEN,
        description="Bounded sub-pointer inside ref (line range, row id, "
        "byte window). Optional; empty means 'whole ref'.",
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
    freshness: float = Field(
        default=0.0,
        ge=0,
        allow_inf_nan=False,
        description="Age of the underlying observation in seconds at capture "
        "(legacy name: freshness_s). Non-negative finite float.",
    )
    relevance: float = Field(
        default=1.0,
        ge=0,
        le=1,
        allow_inf_nan=False,
        description="Relevance score 0..1 inclusive. Default 1.0: fully "
        "relevant until a scorer down-weights it.",
    )
    trust_level: TrustLevel = Field(
        default=TrustLevel.MED,
        description="Strict TrustLevel (legacy name: trust). high = "
        "cross-validated + fresh instrumented source; med = single healthy "
        "source; low = stale/unhealthy/third-party.",
    )

    @field_validator(
        "evidence_id", "incident_id", "source_id", "ref", "span", "hash"
    )
    @classmethod
    def _no_padded_identifiers(cls, v: str) -> str:
        if v and v != v.strip():
            raise ValueError(
                "identifier fields must not have leading/trailing whitespace"
            )
        return v

    @field_validator("timestamp")
    @classmethod
    def _require_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("timestamp must be tz-aware (reject naive)")
        return v
