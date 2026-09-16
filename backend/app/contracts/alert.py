"""M01.3 Alert schema (canonical contract, owned by M01.3 ONLY).

Ownership: M01.3 owns this file exclusively. No other module may edit it.
Frozen-vocabulary reuse: ``severity`` is the M01.1-frozen
``app.contracts.enums.Severity`` (P1..P4) and ``environment`` is the
M01.1-frozen ``app.contracts.enums.Environment`` (dev/staging/prod/mock),
imported from ``app.contracts`` — never redeclared here. No other enum is
defined in this file.

Trust boundary: this contract performs validated construction ONLY. It
guarantees the SHAPE of an alert (field presence, types, documented bounds);
it does not authenticate the sender, deduplicate, correlate, or authorize
anything. Consumers must treat a constructed ``Alert`` as well-formed DATA,
never as a trusted instruction.

Deep immutability (Escape 2 — shallow frozen containers):
- ``frozen=True`` stops attribute reassignment but NOT item mutation of the
  stored ``labels`` / ``metadata`` containers. Like M01.2, this contract
  stores them as ``FrozenDict`` (imported from ``app.contracts.incident`` —
  single canonical implementation, stdlib-only). Nested ``dict`` / ``list`` /
  ``tuple`` values are frozen recursively at construction AND the input is
  copied, so construction never aliases caller-owned JSON-native containers.
- ``alert.labels["x"] = ...`` / ``alert.metadata["x"] = ...`` /
  ``alert.metadata["nested"]["x"] = ...`` all raise ``TypeError``;
  ``model_dump()`` / ``model_dump_json()`` return detached objects by
  construction (serializers emit fresh containers on every call).
- Reuses ``FrozenDict`` from ``app.contracts.incident`` to avoid a duplicate
  competing implementation. If FrozenDict is later centralized (e.g. in
  ``app.contracts.values``), this import should be retargeted and
  ``backend/app/contracts/__init__.py`` should re-export it. EXPORT NEED
  recorded for lead integration session.

Bounds table (all enforced at construction; rationale per constant):
- MAX_ALERT_ID_LEN = 128 ... uuid4 hex is 32 chars; 128 leaves room for
  human/upstream prefixes (e.g. "prom-...") while staying index/log safe.
- MAX_SOURCE_LEN = 64 ..... origin tokens are short DNS-like names
  ("prometheus", "pagerduty"); 64 blocks payload smuggling in this field.
- MAX_SERVICE_LEN = 128 ... k8s service names cap at 63 chars; 128 also fits
  "namespace/service" qualified forms.
- MAX_RESOURCE_LEN = 256 .. affected-object refs can be paths/ARNs/URIs;
  256 fits those while bounding rows.
- MAX_MESSAGE_LEN = 4096 ... pager/annotation bodies are ~KBs; 4 KiB keeps
  log lines and audit rows safe.
- MAX_FINGERPRINT_LEN = 128  sha256 hex is 64 chars; 128 leaves room for an
  algorithm prefix should M04 fingerprinting ever version its scheme.
- MAX_STATUS_LEN = 32 ...... lifecycle tokens are single short words.
- MAX_LABELS_COUNT = 32 .... Prometheus cardinality discipline: alert label
  sets stay in the dozens, never hundreds.
- MAX_METADATA_COUNT = 32 .. same discipline for vendor-neutral context.
- MAX_LABEL_KEY_LEN = 128 . label keys become index/series keys; short.
- MAX_LABEL_VALUE_LEN = 1024  label values stay annotation-sized.
- MAX_METADATA_KEY_LEN = 128  same index-safety rule for metadata keys.
- MAX_METADATA_STR_LEN = 4096  any single string leaf inside metadata is
  capped like message bodies.
- MAX_LABELS_BYTES = 8192 ... serialized (canonical_json) byte ceiling for
  the whole labels mapping; stops many-small-entries blowups the per-field
  caps alone would miss.
- MAX_METADATA_BYTES = 16384  serialized byte ceiling for metadata (larger:
  metadata legitimately carries nested context labels cannot).
- MAX_NESTING_DEPTH = 4 ..... metadata may nest (dicts/lists) but never
  deeper than 4 levels; labels are flat by type (dict[str, str]).
- ``labels`` values are flat strings (Prometheus-style pairs); ``metadata``
  values are JSON-like (str/int/float/bool/None/list/dict) for nested
  vendor-neutral context.

Whitespace rule: leading/trailing whitespace is REJECTED (ValidationError)
on every identifier field (alert_id, source, service, resource, fingerprint,
status, and every labels/metadata key) — never silently stripped, so two
producers can never disagree on an identifier's canonical form. ``message``
is verbatim content (not an identifier): it is preserved exactly as given,
including any padding, so audit copies stay byte-faithful. ``message`` must
be non-blank (empty or whitespace-only rejected) but "  hi  " is preserved.

Status choice: ``status`` is a plain ``str`` (NOT an enum — lifecycle
vocabulary belongs to future correlation/incident modules, and this module
must not freeze their state machine). Membership is validated against the
documented closed set ALERT_STATUSES = ("firing", "acknowledged",
"silenced", "resolved"): "firing" (active, default), "acknowledged" (seen
by a human), "silenced" (temporarily muted upstream), "resolved" (cleared
upstream). Transitions between these states are NOT owned here.

Explicitly NOT implemented (owned elsewhere, must not be added here):
dedup / fingerprint computation / correlation / grouping (M04), severity
re-mapping policy (M04), routing / notification policy (M06), incident
linking beyond the plain-string cross-module reference pattern (there is
deliberately NO incident_id field: M01.2 is unmerged and cross-module links
stay plain str IDs when that module lands), persistence, and any vendor
SDK coupling (``source`` is a bare origin token; no vendor-specific
required fields exist).
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import Environment, Severity
from app.contracts.incident import FrozenDict
from app.contracts.values import canonical_json, new_id, utcnow

MAX_ALERT_ID_LEN = 128
MAX_SOURCE_LEN = 64
MAX_SERVICE_LEN = 128
MAX_RESOURCE_LEN = 256
MAX_MESSAGE_LEN = 4096
MAX_FINGERPRINT_LEN = 128
MAX_STATUS_LEN = 32
MAX_LABELS_COUNT = 32
MAX_METADATA_COUNT = 32
MAX_LABEL_KEY_LEN = 128
MAX_LABEL_VALUE_LEN = 1024
MAX_METADATA_KEY_LEN = 128
MAX_METADATA_STR_LEN = 4096
MAX_LABELS_BYTES = 8192
MAX_METADATA_BYTES = 16384
MAX_NESTING_DEPTH = 4

# Plain-str closed set (NOT an enum): lifecycle vocabulary is reserved for
# future correlation/incident modules; this contract only checks membership.
ALERT_STATUSES: tuple[str, ...] = (
    "firing",
    "acknowledged",
    "silenced",
    "resolved",
)
DEFAULT_STATUS = "firing"

# Legacy severity_raw -> Severity mapping used ONLY by from_legacy, so alerts
# recorded under the old free-form convention keep a defined meaning.
# Unknown values are rejected, never guessed.
_LEGACY_SEVERITY_MAP: dict[str, Severity] = {
    "P1": Severity.P1,
    "P2": Severity.P2,
    "P3": Severity.P3,
    "P4": Severity.P4,
    "CRITICAL": Severity.P1,
    "CRIT": Severity.P1,
    "FATAL": Severity.P1,
    "HIGH": Severity.P2,
    "ERROR": Severity.P2,
    "MEDIUM": Severity.P3,
    "WARNING": Severity.P3,
    "WARN": Severity.P3,
    "LOW": Severity.P4,
    "INFO": Severity.P4,
}


def _reject_padded(name: str, value: str) -> str:
    """Reject leading/trailing whitespace; never strip (canonical-form rule)."""
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    return value


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


def _check_metadata_value(value: Any, path: str) -> None:
    """Reject non-JSON scalar types and over-long string leaves."""
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, str) and len(value) > MAX_METADATA_STR_LEN:
            raise ValueError(
                f"metadata value at {path!r} exceeds "
                f"{MAX_METADATA_STR_LEN} chars"
            )
        return
    if isinstance(value, (Mapping, FrozenDict)):
        for key, sub in value.items():
            if not isinstance(key, str):
                raise ValueError(f"metadata key at {path!r} must be a string")
            if key != key.strip() or not key:
                raise ValueError(
                    f"metadata key at {path!r} must be non-blank "
                    "without leading/trailing whitespace"
                )
            if len(key) > MAX_METADATA_KEY_LEN:
                raise ValueError(
                    f"metadata key at {path!r} exceeds "
                    f"{MAX_METADATA_KEY_LEN} chars"
                )
            _check_metadata_value(sub, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for idx, sub in enumerate(value):
            _check_metadata_value(sub, f"{path}[{idx}]")
        return
    raise ValueError(
        f"metadata value at {path!r} must be JSON-like "
        f"(str/int/float/bool/None/list/dict), got {type(value).__name__}"
    )


class Alert(BaseModel):
    """Canonical alert contract: validated construction only, no behavior."""

    model_config = {"frozen": True, "extra": "forbid"}

    alert_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ALERT_ID_LEN,
    )
    source: str = Field(min_length=1, max_length=MAX_SOURCE_LEN)
    timestamp: datetime = Field(default_factory=utcnow)
    service: str = Field(min_length=1, max_length=MAX_SERVICE_LEN)
    resource: str = Field(default="", max_length=MAX_RESOURCE_LEN)
    severity: Severity
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LEN)
    labels: FrozenDict = Field(default_factory=FrozenDict)
    fingerprint: str = Field(min_length=1, max_length=MAX_FINGERPRINT_LEN)
    environment: Environment = Environment.MOCK
    status: str = Field(
        default=DEFAULT_STATUS, min_length=1, max_length=MAX_STATUS_LEN
    )
    metadata: FrozenDict = Field(default_factory=FrozenDict)

    # -- Escape 1: bypass containment ----------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor.

        Use ``Alert(...)`` / ``model_validate`` / ``model_validate_json``
        so every instance carries validated state. Raising here (instead of
        merely documenting) makes the bypass fail loudly at the call site.
        """
        raise TypeError(
            "Alert.model_construct is blocked: it skips validation. "
            "Use Alert(...) or Alert.model_validate for trusted instances."
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
        "alert_id", "source", "service", "fingerprint", "status"
    )
    @classmethod
    def _identifiers_canonical(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, {
            "alert_id": MAX_ALERT_ID_LEN,
            "source": MAX_SOURCE_LEN,
            "service": MAX_SERVICE_LEN,
            "fingerprint": MAX_FINGERPRINT_LEN,
            "status": MAX_STATUS_LEN,
        }[str(info.field_name)])

    @field_validator("resource")
    @classmethod
    def _resource_canonical(cls, v: str) -> str:
        # resource may be absent ("") but never padded/whitespace-only.
        if v == "":
            return v
        return _check_identifier("resource", v, MAX_RESOURCE_LEN)

    @field_validator("message")
    @classmethod
    def _message_nonblank(cls, v: str) -> str:
        # message is free-form content (verbatim, padding preserved) but
        # must be non-blank: empty or whitespace-only is rejected as
        # meaningless alert body. Interior and padded content preserved.
        if not isinstance(v, str):
            raise ValueError("message must be a string")
        if not v.strip():
            raise ValueError("message must be non-blank (empty or whitespace-only rejected)")
        if len(v) > MAX_MESSAGE_LEN:
            raise ValueError(f"message must be at most {MAX_MESSAGE_LEN} characters")
        return v

    @field_validator("status")
    @classmethod
    def _status_known(cls, v: str) -> str:
        if v not in ALERT_STATUSES:
            raise ValueError(
                f"status must be one of {list(ALERT_STATUSES)}, got: {v!r}"
            )
        return v

    @field_validator("timestamp")
    @classmethod
    def _timestamp_tz_aware(cls, v: datetime) -> datetime:
        if not isinstance(v, datetime):
            raise ValueError("timestamp must be a datetime")
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("timestamp must be timezone-aware (reject naive)")
        return v

    @field_validator("labels")
    @classmethod
    def _labels_bounded(cls, v: FrozenDict) -> FrozenDict:
        if not isinstance(v, (Mapping, FrozenDict)):
            raise ValueError("labels must be an object, never a scalar/list")
        if len(v) > MAX_LABELS_COUNT:
            raise ValueError(
                f"labels must hold at most {MAX_LABELS_COUNT} entries, "
                f"got {len(v)}"
            )
        for key, val in v.items():
            if not isinstance(key, str):
                raise ValueError("labels keys must be strings")
            if key != key.strip() or not key:
                raise ValueError(
                    "labels keys must be non-blank without "
                    "leading/trailing whitespace"
                )
            if len(key) > MAX_LABEL_KEY_LEN:
                raise ValueError(
                    f"labels key exceeds {MAX_LABEL_KEY_LEN} chars: {key!r}"
                )
            if not isinstance(val, str):
                raise ValueError(
                    f"labels values must be strings (flat pairs), "
                    f"key {key!r} got {type(val).__name__}"
                )
            if len(val) > MAX_LABEL_VALUE_LEN:
                raise ValueError(
                    f"labels value for {key!r} exceeds "
                    f"{MAX_LABEL_VALUE_LEN} chars"
                )
        size = len(canonical_json(v.to_plain()).encode("utf-8"))
        if size > MAX_LABELS_BYTES:
            raise ValueError(
                f"labels serialized size {size} exceeds "
                f"{MAX_LABELS_BYTES} bytes"
            )
        return v

    @field_validator("metadata", mode="before")
    @classmethod
    def _metadata_depth_precheck(cls, v: Any) -> Any:
        # Pre-FrozenDict depth gate: reject deeply nested raw payloads
        # before the recursive FrozenDict freeze (Escape 3 / RecursionError).
        # Iterative, no stack blowup. Only dict/list/tuple carry depth.
        if isinstance(v, (dict, list, tuple)) or isinstance(v, Mapping):
            if _nested_depth(v) > MAX_NESTING_DEPTH:
                raise ValueError(
                    f"metadata nesting exceeds {MAX_NESTING_DEPTH} levels"
                )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_bounded(cls, v: FrozenDict) -> FrozenDict:
        if not isinstance(v, (Mapping, FrozenDict)):
            raise ValueError("metadata must be an object, never a scalar/list")
        if len(v) > MAX_METADATA_COUNT:
            raise ValueError(
                f"metadata must hold at most {MAX_METADATA_COUNT} entries, "
                f"got {len(v)}"
            )
        for key in v:
            if not isinstance(key, str):
                raise ValueError("metadata keys must be strings")
            if key != key.strip() or not key:
                raise ValueError(
                    "metadata keys must be non-blank without "
                    "leading/trailing whitespace"
                )
            if len(key) > MAX_METADATA_KEY_LEN:
                raise ValueError(
                    f"metadata key exceeds {MAX_METADATA_KEY_LEN} chars"
                )
        # Depth check first (iterative, no recursion): fail fast on
        # adversary deeply nested payloads that would otherwise blow the
        # recursive _check_metadata_value stack (RecursionError).
        if _nested_depth(v) > MAX_NESTING_DEPTH:
            raise ValueError(
                f"metadata nesting exceeds {MAX_NESTING_DEPTH} levels"
            )
        for key, val in v.items():
            _check_metadata_value(val, key)
        size = len(canonical_json(v.to_plain()).encode("utf-8"))
        if size > MAX_METADATA_BYTES:
            raise ValueError(
                f"metadata serialized size {size} exceeds "
                f"{MAX_METADATA_BYTES} bytes"
            )
        return v

    @classmethod
    def from_legacy(cls, legacy: Any, *, source: str = "legacy") -> Alert:
        """Build a canonical Alert from a legacy ``app.schemas.Alert``.

        Mapping (documented, lossless where the legacy shape has data):
        alert_id <- alert_id; timestamp <- ts; service <- service;
        environment <- environment; severity <- severity_raw via
        _LEGACY_SEVERITY_MAP (unknown values raise, never guessed);
        fingerprint <- signature; resource <- labels["resource"] (or "");
        message <- labels["message"] (or signature, never empty);
        labels <- legacy labels coerced to flat str pairs minus the
        consumed "resource"/"message" keys; status <- "firing";
        metadata <- {"legacy_hash": hash} when the legacy hash is set.
        ``source`` has no legacy counterpart, so the caller supplies it
        (default "legacy" marks unmigrated producers). Duck-typed on purpose:
        this module must not import app.schemas at module scope (schemas is
        the compat layer that imports contracts — a top-level import here
        would cycle).

        Strict-typing (M01 90+ pass): the legacy shape is mutable and
        validation-bypassable, so every consumed field is type-checked here
        and non-str input is REJECTED (never ``str()``-coerced — coercion
        launders injected attribute values into trusted fields).
        """
        if type(legacy) is cls:
            return legacy  # already canonical: exact, no mapping
        legacy_alert_id = legacy.alert_id
        if not isinstance(legacy_alert_id, str):
            raise ValueError("legacy alert_id must be a string")
        legacy_service = legacy.service
        if not isinstance(legacy_service, str):
            raise ValueError("legacy service must be a string")
        legacy_signature = legacy.signature
        if not isinstance(legacy_signature, str):
            raise ValueError("legacy signature must be a string")
        if not isinstance(legacy.severity_raw, str):
            raise ValueError("legacy severity_raw must be a string")
        raw_sev = legacy.severity_raw.strip().upper()
        severity = _LEGACY_SEVERITY_MAP.get(raw_sev)
        if severity is None:
            raise ValueError(
                f"cannot map legacy severity_raw {legacy.severity_raw!r} "
                "to P1..P4"
            )
        raw_labels = legacy.labels or {}
        if not isinstance(raw_labels, Mapping):
            raise ValueError("legacy labels must be a mapping")
        raw_labels = dict(raw_labels)
        resource_raw = raw_labels.pop("resource", "")
        if not isinstance(resource_raw, str):
            raise ValueError("legacy labels['resource'] must be a string")
        resource = resource_raw
        message_raw = raw_labels.pop("message", "")
        if not isinstance(message_raw, str):
            raise ValueError("legacy labels['message'] must be a string")
        message = message_raw or legacy_signature
        flat_labels: dict[str, str] = {}
        for k, val in raw_labels.items():
            if not isinstance(k, str) or not isinstance(val, str):
                raise ValueError(
                    "legacy labels must be flat string pairs")
            flat_labels[k] = val
        metadata: dict[str, Any] = {}
        legacy_hash = getattr(legacy, "hash", "")
        if legacy_hash:
            if not isinstance(legacy_hash, str):
                raise ValueError("legacy hash must be a string")
            metadata["legacy_hash"] = legacy_hash
        return cls(
            alert_id=legacy_alert_id,
            source=source,
            timestamp=legacy.ts,
            service=legacy_service,
            resource=resource,
            severity=severity,
            message=message,
            labels=flat_labels,  # type: ignore[arg-type]
            fingerprint=legacy_signature,
            environment=legacy.environment,
            status=DEFAULT_STATUS,
            metadata=metadata,  # type: ignore[arg-type]
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.Alert`` shape.

        Reverse of from_legacy (message/resource round-trip inside labels;
        legacy_hash travels back into ``hash``). The import is method-local
        to avoid a contracts -> schemas import cycle; returns Any so this
        module never depends on the legacy type at import time.
        """
        from app.schemas import Alert as LegacyAlert  # noqa: E402

        labels: dict[str, Any] = dict(self.labels.to_plain())
        if self.resource:
            labels.setdefault("resource", self.resource)
        labels.setdefault("message", self.message)
        legacy_hash = self.metadata.get("legacy_hash", "")
        return LegacyAlert(
            alert_id=self.alert_id,
            ts=self.timestamp,
            service=self.service,
            environment=self.environment,
            severity_raw=self.severity.value,
            signature=self.fingerprint,
            labels=labels,
            hash=str(legacy_hash) if legacy_hash is not None else "",
        )
