"""M01.2 canonical Incident contract (data only, no workflows).

Single definition point for the Incident domain object. M01.3+ and M02
import from here (via ``app.contracts``); never redeclare.

Frozen M01.1 vocabulary reused (no duplicates):
- ``Severity`` (P1-P4), ``Environment`` (dev/staging/prod/mock),
  ``IncidentStatus`` (18 canonical FSM states).

Legacy compatibility: ``Incident(fingerprint=..., severity=...)`` keeps
working — ``service`` defaults to ``"unknown"`` (normalizer convention),
``environment`` to ``mock``, ``status`` to ``NEW``, timestamps auto-set.
``app.schemas.Incident`` is a re-export of this class (no second definition).
Lists may be passed as ``list`` (stored as immutable ``tuple``); mappings as
``dict`` (stored as immutable ``FrozenDict``). JSON wire output is unchanged.

Ownership: M01.2 owns shape + field validation only. Lifecycle/FSM (M14),
correlation/grouping (M04), diagnosis linkage (M05+), persistence (DB
migrations) live elsewhere. In particular this model does NOT couple
``status`` to ``resolved_at`` and does NOT auto-touch ``updated_at``.

Trust boundary (Escape 1 — model_construct):
- Pydantic deliberately ships ``BaseModel.model_construct`` as a
  validation-bypassing construction API. ProofOps cannot remove that
  upstream API, so this contract CONTAINS it instead:
  ``Incident.model_construct`` is overridden to raise ``TypeError`` (the
  bypass is BLOCKED on this class, verified by test), ``model_copy`` with
  ``update=...`` is routed through full re-validation (a second bypass in
  the same family, verified unvalidated upstream), and AST scan tests forbid
  ``model_construct`` in application code and pin the only tolerated
  ``object.__setattr__`` sites (``FrozenDict`` construction + two
  pre-existing non-Incident sites, all documented in the scan test).
- Only ``Incident(...)``, ``model_validate`` and ``model_validate_json``
  enforce the contract. Any instance obtained through other means (upstream
  bypass APIs on other models, in-process ``object.__setattr__`` memory
  tampering) MUST be re-validated with
  ``Incident.model_validate(inst.model_dump())`` before crossing a trust
  boundary — re-validation is proven to reject bypassed data.
- Framework-level bypass APIs remain available upstream; they are NOT USED
  BY PROOFOps INTERNAL CODE (scan-enforced).

Deep immutability (Escape 2 — shallow frozen containers):
- ``frozen=True`` stops attribute reassignment but NOT item mutation of the
  stored ``impact`` / ``source_alert_ids`` / ``metadata`` containers.
- Design evaluation: (A) ``tuple`` for ID sequences — accepted: JSON-native,
  coerced from ``list`` input, zero per-read cost, fails loudly on append.
  (B) immutable stdlib mapping — rejected: none exists that Pydantic can
  validate/serialize (``MappingProxyType`` has no core-schema support).
  (C) defensive copy-on-read — rejected: silent no-op mutations mask bugs
  and every attribute read pays a deep copy. (D) immutable value-object
  wrapper — accepted for mappings (``FrozenDict`` below, stdlib-only).
- Chosen: A+D hybrid. ID lists are stored as ``tuple[str, ...]`` (dumped as
  fresh ``list``); ``impact``/``metadata`` are stored as ``FrozenDict``
  (dumped as fresh plain ``dict``). Nested ``dict``/``list``/``tuple``
  values are frozen recursively at construction AND the input is copied, so
  construction never aliases caller-owned JSON-native containers.
- ``inc.impact["x"] = ...`` / ``inc.source_alert_ids.append(...)`` /
  ``inc.metadata["x"] = ...`` all raise ``TypeError``/``AttributeError``;
  ``model_dump()``/``model_dump_json()`` return detached objects by
  construction (serializers emit fresh containers on every call).
- Limitation (documented, out of scope): exotic non-JSON values placed in
  ``impact``/``metadata`` (``set``, arbitrary objects) are passed through
  by reference — a caller holding the reference can mutate the referent.
  ``datetime`` values are immutable and safe. JSON-native values carry the
  full guarantee above.

Explicit bounds (Escape 3 — unbounded input):
- Every string/container field carries a documented ceiling (DoS + DB +
  API rationale). See the ``MAX_*`` constants: identifier-shaped strings
  max out at 128 chars (uuid-hex 32 for generated IDs, sha256-hex 64 for
  fingerprints, k8s 63-char service cap — all with headroom, all PK/B-tree
  friendly); ID lists cap at 100 entries (correlation groups are bounded by
  the dedup window; seeds produce handfuls); ``impact`` caps at 32 entries
  / 4 KiB canonical JSON (blast summaries are small); ``metadata`` caps at
  64 entries / 128-char keys / depth 5 / 16 KiB canonical JSON (generous
  ceiling — Evidence Packs live elsewhere, see M05). Checks run fail-fast:
  counts, then keys/depth, then serialized bytes.

Whitespace policy (Escape 4):
- REJECT, never strip. Identifier fields (``incident_id``,
  ``fingerprint``, ``service``, ``diagnosis_reference``, every ID-list
  entry, every ``impact``/``metadata`` key) with leading/trailing
  whitespace raise ``ValidationError`` — stripping could silently merge or
  alter identifiers and mask upstream bugs. Interior whitespace is allowed.
  Free-form payload data (``impact``/``metadata`` VALUES) is preserved
  as-is. One rule, whole contract.
"""
from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping
from datetime import datetime
from typing import Any, NoReturn, Optional, Self

from pydantic import BaseModel, Field, field_serializer, field_validator, model_validator
from pydantic_core import core_schema

from app.contracts.enums import Environment, IncidentStatus, Severity
from app.contracts.values import canonical_json, new_id, utcnow

# --------------------------------------------------------------------------
# Explicit bounds (Escape 3). Rationale per constant; enforced below.
# --------------------------------------------------------------------------
MAX_INCIDENT_ID_LEN = 128  # uuid4-hex is 32; custom human IDs welcome; PK-index friendly
MAX_FINGERPRINT_LEN = 128  # sha256-hex is 64 + algorithm margin; correlator emits 16
MAX_SERVICE_LEN = 128  # > k8s 63-char service cap, with namespaced/compound headroom
MAX_ID_ITEM_LEN = 128  # alert/evidence/action IDs are identifier-shaped (PK rationale)
MAX_ID_LIST_ITEMS = 100  # correlation groups bounded by dedup window; seeds yield handfuls
MAX_DIAGNOSIS_REF_LEN = 128  # ID-like reference (same PK rationale)
MAX_IMPACT_ENTRIES = 32  # impact is a small blast summary, not a telemetry dump
MAX_IMPACT_JSON_BYTES = 4096  # 4 KiB canonical JSON ceiling for impact
MAX_METADATA_ENTRIES = 64  # generous ceiling; Evidence Packs (M05) live elsewhere
MAX_METADATA_KEY_LEN = 128  # metadata keys are lookup identifiers
MAX_METADATA_DEPTH = 5  # nesting-explosion guard (containers-deep, see _nested_depth)
MAX_METADATA_JSON_BYTES = 16384  # 16 KiB canonical JSON ceiling for metadata


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule (Escape 4): non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _freeze_value(value: Any) -> Any:
    """Recursively freeze JSON-native containers (copying, never aliasing)."""
    if isinstance(value, FrozenDict):
        return value  # already frozen: immutable, sharing is safe
    if isinstance(value, Mapping):
        return FrozenDict(value)
    if isinstance(value, list):
        return tuple(_freeze_value(v) for v in value)
    if isinstance(value, tuple):
        return tuple(_freeze_value(v) for v in value)
    return value  # scalars + exotic pass-through (see module docstring)


def _normalize(value: Any) -> Any:
    """Recursively render frozen structures as plain JSON-native containers."""
    if isinstance(value, FrozenDict):
        return {k: _normalize(v) for k, v in value._data.items()}
    if isinstance(value, Mapping):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def _nested_depth(value: Any) -> int:
    """Deepest container nesting level (scalars 0). Iterative: no recursion limit."""
    best = 0
    stack = [value]
    levels = [0]
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


class FrozenDict(Mapping):
    """Immutable string-keyed mapping value object (Escape 2, design D).

    stdlib-only (``collections.abc.Mapping`` + ``__slots__``). Instances are
    deeply immutable: attribute setting/rebinding is blocked, there are no
    mutating methods, and nested ``dict``/``list``/``tuple`` values are
    frozen recursively at construction (inputs are copied, never aliased).
    Serializes as a plain JSON object; :meth:`to_plain` renders fresh
    detached ``dict``/``list`` structures (nested tuples become lists).
    """

    __slots__ = ("_data",)
    _data: dict[str, Any]

    def __new__(cls, data: Mapping[str, Any] | None = None) -> "FrozenDict":
        self = super().__new__(cls)
        src = {} if data is None else data
        # NOTE: sole sanctioned ``object.__setattr__`` site in backend/
        # (frozen-value-object construction; enforced by AST scan test).
        object.__setattr__(
            self, "_data", {k: _freeze_value(v) for k, v in dict(src).items()}
        )
        return self

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        raise TypeError("FrozenDict is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise TypeError("FrozenDict is immutable")

    # -- Mapping interface (reads only) ------------------------------------
    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:  # type: ignore[override]
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Mapping):
            # Content equality across frozen/plain shapes: sequences compare
            # by content whether list or tuple (JSON-array equivalence).
            return bool(_normalize(self._data) == _normalize(dict(other)))
        return NotImplemented

    def __repr__(self) -> str:
        return f"FrozenDict({self.to_plain()!r})"

    # -- detachment helpers --------------------------------------------------
    def to_plain(self) -> dict[str, Any]:
        """Fresh plain ``dict`` rendering (new containers on every call)."""
        result = _normalize(self._data)
        assert isinstance(result, dict)
        return result

    def __copy__(self) -> "FrozenDict":
        return self  # immutable: sharing is safe

    def __deepcopy__(self, memo: dict) -> "FrozenDict":
        return FrozenDict(copy.deepcopy(self._data, memo))

    def __reduce__(self) -> Any:
        # Version-proof pickle: rebuild from the plain rendering.
        return (FrozenDict, (self.to_plain(),))

    # -- Pydantic integration --------------------------------------------------
    @classmethod
    def _validate_full(cls, v: Any, info: Any) -> "FrozenDict":
        if isinstance(v, cls):
            return v
        if isinstance(v, Mapping):
            try:
                data = dict(v)
            except Exception as exc:
                raise ValueError(f"{info.field_name} must be a string-keyed object") from exc
            for k in data:
                if not isinstance(k, str):
                    raise ValueError(f"{info.field_name} keys must be strings")
            try:
                return cls(data)
            except RecursionError as exc:
                # Adversarial nesting (thousands deep) exhausts the C stack
                # inside recursive freezing. Fail closed as a validation
                # error — never propagate a crash past the trust boundary.
                # Per-field depth caps (all <=5) still apply after this net.
                raise ValueError(
                    f"{info.field_name} is nested too deeply to freeze "
                    f"safely") from exc
        raise ValueError(f"{info.field_name} must be an object, not {type(v).__name__}")

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any) -> Any:
        return core_schema.with_info_plain_validator_function(
            cls._validate_full,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: v.to_plain() if isinstance(v, cls) else dict(v),
                return_schema=core_schema.dict_schema(),
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema_obj: Any, handler: Any) -> dict[str, Any]:
        return {"type": "object", "additionalProperties": True}


class Incident(BaseModel):
    """Canonical incident (control-plane contract, frozen shape)."""

    model_config = {"frozen": True, "extra": "forbid"}

    incident_id: str = Field(default_factory=new_id, min_length=1, max_length=MAX_INCIDENT_ID_LEN)
    status: IncidentStatus = IncidentStatus.NEW
    severity: Severity
    service: str = Field(default="unknown", min_length=1, max_length=MAX_SERVICE_LEN)
    environment: Environment = Environment.MOCK
    impact: FrozenDict = Field(default_factory=FrozenDict)
    fingerprint: str = Field(min_length=1, max_length=MAX_FINGERPRINT_LEN)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    detected_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    source_alert_ids: tuple[str, ...] = Field(default=())
    evidence_ids: tuple[str, ...] = Field(default=())
    diagnosis_reference: Optional[str] = Field(default=None, max_length=MAX_DIAGNOSIS_REF_LEN)
    action_references: tuple[str, ...] = Field(default=())
    metadata: FrozenDict = Field(default_factory=FrozenDict)

    # -- Escape 1: bypass containment ----------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor.

        Use ``Incident(...)`` / ``model_validate`` / ``model_validate_json``
        so every instance carries validated state. Raising here (instead of
        merely documenting) makes the bypass fail loudly at the call site.
        """
        raise TypeError(
            "Incident.model_construct is blocked: it skips validation. "
            "Use Incident(...) or Incident.model_validate for trusted instances."
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

    # -- scalar identifiers: non-blank, unpadded, bounded (Escapes 3+4) ------
    @field_validator("incident_id")
    @classmethod
    def _incident_id(cls, v: str) -> str:
        return _check_identifier("incident_id", v, MAX_INCIDENT_ID_LEN)

    @field_validator("fingerprint")
    @classmethod
    def _fingerprint(cls, v: str) -> str:
        return _check_identifier("fingerprint", v, MAX_FINGERPRINT_LEN)

    @field_validator("service")
    @classmethod
    def _service(cls, v: str) -> str:
        return _check_identifier("service", v, MAX_SERVICE_LEN)

    @field_validator("diagnosis_reference")
    @classmethod
    def _diagnosis_ref(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return _check_identifier("diagnosis_reference", v, MAX_DIAGNOSIS_REF_LEN)

    # -- ID lists: strict sequence input, stored immutable (Escapes 2+3+4) ---
    @field_validator("source_alert_ids", "evidence_ids", "action_references",
                      mode="before")
    @classmethod
    def _id_lists(cls, v: Any, info: Any) -> Any:
        name = str(info.field_name)
        if v is None:
            raise ValueError(f"{name} must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError(f"{name} must be a list of ID strings")
        items = list(v)
        if len(items) > MAX_ID_LIST_ITEMS:
            raise ValueError(f"{name} must hold at most {MAX_ID_LIST_ITEMS} entries")
        checked: list[str] = []
        for item in items:
            if not isinstance(item, str):
                raise ValueError(f"{name} entries must be non-empty strings")
            checked.append(_check_identifier(f"{name} entries", item, MAX_ID_ITEM_LEN))
        return checked

    @field_serializer("source_alert_ids", "evidence_ids", "action_references")
    def _ser_id_lists(self, v: tuple[str, ...]) -> list[str]:
        # Fresh list on every dump: JSON wire shape + detachment by construction.
        return list(v)

    # -- mappings: bounded keys/depth/bytes (Escapes 3+4) ----------------------
    @field_validator("impact")
    @classmethod
    def _impact_bounds(cls, v: FrozenDict) -> FrozenDict:
        if len(v) > MAX_IMPACT_ENTRIES:
            raise ValueError(f"impact must hold at most {MAX_IMPACT_ENTRIES} entries")
        cls._check_mapping_keys("impact", v, MAX_METADATA_KEY_LEN)
        if _nested_depth(v) > MAX_METADATA_DEPTH:
            raise ValueError(f"impact must nest at most {MAX_METADATA_DEPTH} levels deep")
        size = len(canonical_json(v.to_plain()).encode("utf-8"))
        if size > MAX_IMPACT_JSON_BYTES:
            raise ValueError(f"impact must serialize within {MAX_IMPACT_JSON_BYTES} bytes")
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_bounds(cls, v: FrozenDict) -> FrozenDict:
        if len(v) > MAX_METADATA_ENTRIES:
            raise ValueError(f"metadata must hold at most {MAX_METADATA_ENTRIES} entries")
        cls._check_mapping_keys("metadata", v, MAX_METADATA_KEY_LEN)
        if _nested_depth(v) > MAX_METADATA_DEPTH:
            raise ValueError(f"metadata must nest at most {MAX_METADATA_DEPTH} levels deep")
        size = len(canonical_json(v.to_plain()).encode("utf-8"))
        if size > MAX_METADATA_JSON_BYTES:
            raise ValueError(f"metadata must serialize within {MAX_METADATA_JSON_BYTES} bytes")
        return v

    @staticmethod
    def _check_mapping_keys(name: str, v: FrozenDict, max_key_len: int) -> None:
        for k in v:
            _check_identifier(f"{name} keys", k, max_key_len)

    @field_validator("created_at", "updated_at", "detected_at", "resolved_at")
    @classmethod
    def _tz_aware(cls, v: Optional[datetime], info: Any) -> Optional[datetime]:
        if v is None:
            return None
        if not isinstance(v, datetime):
            raise ValueError(f"{info.field_name} must be a datetime")
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError(f"{info.field_name} must be timezone-aware")
        return v

    @model_validator(mode="after")
    def _ordering(self) -> "Incident":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must be >= created_at")
        if self.resolved_at is not None:
            if self.resolved_at < self.created_at:
                raise ValueError("resolved_at must be >= created_at")
            if (self.detected_at is not None
                    and self.resolved_at < self.detected_at):
                raise ValueError("resolved_at must be >= detected_at")
        return self
