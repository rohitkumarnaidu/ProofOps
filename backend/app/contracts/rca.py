"""M01.13 RCA schema - canonical RCA (postmortem) contract.

Ownership: M01.13 owns THIS FILE ONLY (``backend/app/contracts/rca.py``).
``Claim`` is M01.5-owned and imported, never redeclared. Legacy
``app.schemas`` is a compat layer owned by M01.1 - it is read in
tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S31 - sections: summary, timeline (ts+actor+hash per
row), root cause (claims+map), impact (MTTR, blast), remediation log,
prevention, audit ref. Blameless lint blocks personal-blame terms. Gate S21
enforced in ``publish_rca``: all MUST-CITE claims need >=1 valid-hash
evidence or publication is DENIED.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
postmortem document. It performs NO evidence-coverage gating, NO blameless
linting, NO causal validation, and NO publication authorization. Those are
RCA duties (future A4/M13.5 + publish gate). A constructed ``RCA`` is a
well-formed DRAFT - never a published finding.

Legacy wire mapping (field names match legacy ``app.schemas.RCA`` EXACTLY)::

    incident_id / summary / timeline / root_cause / impact /
    remediation_log / prevention / claims / audit_ref.

    ``timeline``/``remediation_log`` store tuples of ``FrozenDict`` rows;
    ``impact`` stores ``FrozenDict``; ``claims`` stores canonical ``Claim``
    (M01.5); legacy carries plain dicts/lists and S.Claim, coerced both ways.

Bounds table::

    incident_id        1..MAX_ID_LEN  (128, identifier)
    summary/root_cause 1..MAX_PROSE   (8192 each, verbatim, non-blank)
    timeline/remediation_log 0..MAX_ROWS (256 mapping rows each)
    impact             0..MAX_IMPACT_ENTRIES (64; depth/bytes capped)
    prevention         0..MAX_PREV    (64 non-blank strings <=1024)
    claims             0..MAX_CLAIMS  (64 canonical Claim)
    audit_ref          "" or 1..MAX_REF_LEN (256; "" = unpublished draft)

Bypass containment (Escape 1, M01.2-M01.12 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation.

NOT implemented here (owned elsewhere): MUST-CITE coverage gate (M05.6),
blameless lint (A4), gated publish (publish_rca), claim->evidence map
rendering (UI M19.6), prevention-PR draft ([OPTIONAL]).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.hypothesis import Claim
from app.contracts.incident import FrozenDict
from app.contracts.values import canonical_json

MAX_ID_LEN = 128
MAX_PROSE = 8192
MAX_ROWS = 256
MAX_IMPACT_ENTRIES = 64
MAX_IMPACT_DEPTH = 5
MAX_IMPACT_JSON_BYTES = 16384
MAX_PREV = 64
MAX_PREV_LEN = 1024
MAX_CLAIMS = 64
MAX_REF_LEN = 256


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _check_prose(name: str, value: str) -> str:
    """Verbatim prose rule: non-blank, preserved exactly, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > MAX_PROSE:
        raise ValueError(f"{name} must be at most {MAX_PROSE} characters")
    return value


def _check_rows(name: str, value: Any) -> list[FrozenDict]:
    """Row-list rule: strict list of string-keyed mappings."""
    if value is None:
        raise ValueError(f"{name} must be a list, not null")
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be a list of objects")
    items = list(value)
    if len(items) > MAX_ROWS:
        raise ValueError(f"{name} must hold at most {MAX_ROWS} rows")
    rows: list[FrozenDict] = []
    for row in items:
        if isinstance(row, FrozenDict):
            rows.append(row)
        elif isinstance(row, Mapping):
            rows.append(FrozenDict(dict(row)))
        else:
            raise ValueError(f"{name} rows must be objects")
    return rows


class RCA(BaseModel):
    """One blameless postmortem draft: timeline + cause + prevention."""

    model_config = {"frozen": True, "extra": "forbid"}

    incident_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    summary: str = Field(
        min_length=1,
        max_length=MAX_PROSE,
        description="Executive summary (verbatim, non-blank).",
    )
    timeline: tuple[FrozenDict, ...] = Field(
        default=(),
        description="Chronological rows (ts+actor+hash per row).",
    )

    root_cause: str = Field(
        min_length=1,
        max_length=MAX_PROSE,
        description="Verified root cause (verbatim, non-blank).",
    )
    impact: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Impact summary (MTTR, blast).",
    )
    remediation_log: tuple[FrozenDict, ...] = Field(
        default=(),
        description="Remediation/approval/verification record rows.",
    )
    prevention: tuple[str, ...] = Field(
        default=(),
        description="Blameless prevention notes.",
    )
    claims: tuple[Claim, ...] = Field(
        default=(),
        description="Claim->evidence map (canonical M01.5 Claim).",
    )
    audit_ref: str = Field(
        default="",
        max_length=MAX_REF_LEN,
        description='Audit chain reference, or "" for an unpublished draft.',
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "RCA.model_construct is blocked: it skips validation. "
            "Use RCA(...) or RCA.model_validate for trusted instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None,
                   deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation."""
        if update:
            merged = self.model_dump()
            merged.update(dict(update))
            return self.model_validate(merged)
        return super().model_copy(update=None, deep=deep)

    @field_validator("incident_id")
    @classmethod
    def _incident_id(cls, v: str) -> str:
        return _check_identifier("incident_id", v, MAX_ID_LEN)

    @field_validator("summary", "root_cause")
    @classmethod
    def _prose(cls, v: str, info: Any) -> str:
        return _check_prose(str(info.field_name), v)

    @field_validator("timeline", "remediation_log", mode="before")
    @classmethod
    def _rows(cls, v: Any, info: Any) -> Any:
        rows = _check_rows(str(info.field_name), v)
        # Timeline rows carry the documented ts+actor+hash contract (field
        # description); a row missing any of them is malformed, never
        # "sparse". Remediation rows stay untyped record rows by design.
        if str(info.field_name) == "timeline":
            for row in rows:
                missing = {"ts", "actor", "hash"} - set(row.keys())
                if missing:
                    raise ValueError(
                        "timeline rows must carry ts+actor+hash, "
                        f"missing: {sorted(missing)}")
        return rows

    @field_validator("impact")
    @classmethod
    def _impact(cls, v: FrozenDict) -> FrozenDict:
        if len(v) > MAX_IMPACT_ENTRIES:
            raise ValueError(
                f"impact must hold at most {MAX_IMPACT_ENTRIES} entries")
        size = len(canonical_json(v.to_plain()).encode("utf-8"))
        if size > MAX_IMPACT_JSON_BYTES:
            raise ValueError(
                f"impact must serialize within {MAX_IMPACT_JSON_BYTES} bytes")
        return v

    @field_validator("prevention", mode="before")
    @classmethod
    def _prevention(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("prevention must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError("prevention must be a list of strings")
        items = list(v)
        if len(items) > MAX_PREV:
            raise ValueError(f"prevention must hold at most {MAX_PREV} entries")
        checked: list[str] = []
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("prevention entries must be non-empty strings")
            if len(item) > MAX_PREV_LEN:
                raise ValueError(
                    f"prevention entries must be at most {MAX_PREV_LEN} characters")
            checked.append(item)
        return checked

    @field_validator("claims", mode="before")
    @classmethod
    def _claims(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("claims must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError("claims must be a list of Claim")
        items = list(v)
        if len(items) > MAX_CLAIMS:
            raise ValueError(f"claims must hold at most {MAX_CLAIMS} entries")
        return items  # membership enforced by Claim coercion

    @field_validator("audit_ref")
    @classmethod
    def _audit_ref(cls, v: str) -> str:
        if v == "":
            return v
        return _check_identifier("audit_ref", v, MAX_REF_LEN)

    @classmethod
    def from_legacy(cls, legacy: Any) -> RCA:
        """Build a canonical RCA from ``app.schemas``.

        Legacy claims (``S.Claim``) upgrade via ``Claim.from_legacy``;
        timeline/remediation rows coerce to ``FrozenDict``.
        """
        return cls(
            incident_id=str(legacy.incident_id),
            summary=str(legacy.summary),
            timeline=tuple(legacy.timeline),
            root_cause=str(legacy.root_cause),
            impact=FrozenDict(dict(legacy.impact)),
            remediation_log=tuple(legacy.remediation_log),
            prevention=tuple(legacy.prevention),
            claims=tuple(Claim.from_legacy(c) for c in legacy.claims),
            audit_ref=str(legacy.audit_ref),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.RCA`` shape."""
        from app.schemas import RCA as LegacyRCA  # noqa: E402

        return LegacyRCA(
            incident_id=self.incident_id,
            summary=self.summary,
            timeline=self.timeline,
            root_cause=self.root_cause,
            impact=self.impact,
            remediation_log=self.remediation_log,
            prevention=self.prevention,
            claims=tuple(c.to_legacy() for c in self.claims),
            audit_ref=self.audit_ref,
        )
