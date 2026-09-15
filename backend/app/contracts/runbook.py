"""M01.6 Runbook schema - canonical Runbook contract.

Ownership: M01.6 owns THIS FILE ONLY (``backend/app/contracts/runbook.py``).
Frozen vocabulary (``ActionType``/``Environment``) is owned by M01.1 and is
imported, never redeclared. ``ACTION_TYPES`` is the M01.1 allowlist source:
``allowed_actions``/``forbidden_actions`` entries are strict ``ActionType``
members, so a runbook can never name an action the control plane does not
know. Legacy ``app.schemas`` is a compat layer owned by M01.1 - it is read in
tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S20 - ``{id, version semver, title, trigger, scope,
preconditions[], diagnostic_steps[], allowed_actions[typed+ranges],
forbidden_actions[], parameters JSON-schema, approval{for},
verification{slos[]}, rollback{template}, owner, reviewed_at, hash}``.
SELECT+PARAMETERIZE only: the LLM may choose a runbook and fill its
parameters; it may NOT invent runtime procedures.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
runbook (field presence, types, semver pin, allowlist membership, documented
bounds). It performs no file loading, no hash verification, no version-pin
enforcement against live state, and no parameter-schema execution. Those are
loader/policy duties (future M06/M11). A constructed ``Runbook`` is
well-formed DATA, never a trusted instruction.

Legacy wire mapping (field names match legacy ``app.schemas.Runbook``
EXACTLY)::

    runbook_id / version / title / trigger / scope / preconditions /
    diagnostic_steps / allowed_actions / forbidden_actions /
    parameters_schema / approval / verification / rollback / owner /
    reviewed_at / hash.

    ``scope`` stores canonical ``Environment`` members (validated membership:
    dev/staging/prod/mock); legacy carries plain strings and the bridges
    coerce both directions. ``allowed_actions``/``forbidden_actions`` store
    canonical ``ActionType`` members; same coercion rule.

Bounds table (explicit maxima; identifier fields reject empty/padded)::

    runbook_id   1..MAX_ID_LEN        (128)
    version      semver x.y.z         (pinned; "latest"/"1.2" rejected)
    title        1..MAX_TITLE_LEN     (256, verbatim, non-blank)
    trigger / parameters_schema / approval / rollback
                 0..MAX_MAP_ENTRIES  (32 entries each; depth/bytes capped)
    scope        0..MAX_SCOPE_ENVS    (4 = every Environment; validated)
    preconditions / diagnostic_steps / verification
                 0..MAX_STEPS        (64 non-blank strings, each <=1024)
    allowed/forbidden 0..18 each     (allowlist size; must be DISJOINT)
    owner        "" or 1..MAX_ID_LEN  ("" = unset, legacy default)
    reviewed_at  "" or 1..MAX_STAMP_LEN (64, "" = unset; date semantics loader-owned)
    hash         "" or 1..MAX_HASH_LEN  (256, "" = unhashed; opaque string)

Contradiction rule (fail-closed): ``allowed_actions`` and
``forbidden_actions`` must be DISJOINT. A runbook that both allows and
forbids the same action is malformed and rejected at construction. All five
shipped runbooks satisfy this (verified by test).

Bypass containment (Escape 1, M01.2-M01.5 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation.

NOT implemented here (owned elsewhere): YAML loading/parsing (M11.2), hash
verification against file bytes (M11.3), version-pin enforcement (M11.4),
parameter validation against ``parameters_schema`` (M11.5), policy evaluation
of allowed/forbidden scope (M06), poisoning detection beyond structural
contradiction (M11.6/M18.2).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator, model_validator

from app.contracts.enums import ActionType, Environment
from app.contracts.incident import FrozenDict
from app.contracts.values import SEMVER_RE, canonical_json

MAX_ID_LEN = 128
MAX_TITLE_LEN = 256
MAX_MAP_ENTRIES = 32
MAX_MAP_DEPTH = 4
MAX_MAP_JSON_BYTES = 8192
MAX_SCOPE_ENVS = 4
MAX_STEPS = 64
MAX_STEP_LEN = 1024
MAX_STAMP_LEN = 64
MAX_HASH_LEN = 256


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _check_blank_or_identifier(name: str, value: str, max_len: int) -> str:
    """Legacy-compat rule: "" (unset) or full identifier discipline."""
    if value == "":
        return value
    return _check_identifier(name, value, max_len)


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


def _check_mapping(name: str, value: FrozenDict) -> FrozenDict:
    """Shared mapping rule: bounded entries, depth, serialized bytes."""
    if len(value) > MAX_MAP_ENTRIES:
        raise ValueError(f"{name} must hold at most {MAX_MAP_ENTRIES} entries")
    for k in value:
        _check_identifier(f"{name} keys", k, MAX_ID_LEN)
    if _nested_depth(value) > MAX_MAP_DEPTH:
        raise ValueError(f"{name} must nest at most {MAX_MAP_DEPTH} levels deep")
    size = len(canonical_json(value.to_plain()).encode("utf-8"))
    if size > MAX_MAP_JSON_BYTES:
        raise ValueError(f"{name} must serialize within {MAX_MAP_JSON_BYTES} bytes")
    return value


def _check_steps(name: str, value: Any) -> list[str]:
    """Shared step-list rule: strict list of non-blank bounded strings."""
    if value is None:
        raise ValueError(f"{name} must be a list, not null")
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be a list of strings")
    items = list(value)
    if len(items) > MAX_STEPS:
        raise ValueError(f"{name} must hold at most {MAX_STEPS} entries")
    checked: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{name} entries must be non-empty strings")
        if item != item.strip():
            raise ValueError(f"{name} entries must not have leading/trailing whitespace")
        if len(item) > MAX_STEP_LEN:
            raise ValueError(f"{name} entries must be at most {MAX_STEP_LEN} characters")
        checked.append(item)
    return checked


class Runbook(BaseModel):
    """One governed runbook: pinned procedure + typed action scope."""

    model_config = {"frozen": True, "extra": "forbid"}

    runbook_id: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Runbook id (e.g. bad-deploy-rollback).",
    )
    version: str = Field(
        min_length=1,
        description="Pinned semver x.y.z (floating versions rejected).",
    )
    title: str = Field(
        min_length=1,
        max_length=MAX_TITLE_LEN,
        description="Human title, verbatim (non-blank).",
    )
    trigger: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Trigger matchers (alert regex, service, ...).",
    )
    scope: tuple[Environment, ...] = Field(
        default=(),
        description="Environments this runbook governs (validated members).",
    )
    preconditions: tuple[str, ...] = Field(
        default=(),
        description="Preconditions that must hold before use.",
    )
    diagnostic_steps: tuple[str, ...] = Field(
        default=(),
        description="Diagnostic procedure steps.",
    )
    allowed_actions: tuple[ActionType, ...] = Field(
        default=(),
        description="Typed allowlist (M01.1 ActionType; disjoint from forbidden).",
    )
    forbidden_actions: tuple[ActionType, ...] = Field(
        default=(),
        description="Typed denylist (M01.1 ActionType; disjoint from allowed).",
    )
    parameters_schema: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Parameter JSON-schema (shape owned by M11.5).",
    )
    approval: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Approval obligations (e.g. {for: [...]}).",
    )
    verification: tuple[str, ...] = Field(
        default=(),
        description="Verification SLO/check names.",
    )
    rollback: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Rollback template (may be empty: irreversible).",
    )
    owner: str = Field(
        default="",
        max_length=MAX_ID_LEN,
        description='Owning team, or "" when unset (legacy default).',
    )
    reviewed_at: str = Field(
        default="",
        max_length=MAX_STAMP_LEN,
        description='Review stamp, or "" when unset (date semantics loader-owned).',
    )
    hash: str = Field(
        default="",
        max_length=MAX_HASH_LEN,
        description='Integrity digest string, or "" when unhashed (opaque).',
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "Runbook.model_construct is blocked: it skips validation. "
            "Use Runbook(...) or Runbook.model_validate for trusted instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None,
                   deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation."""
        if update:
            merged = self.model_dump()
            merged.update(dict(update))
            return self.model_validate(merged)
        return super().model_copy(update=None, deep=deep)

    @field_validator("runbook_id")
    @classmethod
    def _runbook_id(cls, v: str) -> str:
        return _check_identifier("runbook_id", v, MAX_ID_LEN)

    @field_validator("version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not isinstance(v, str) or not SEMVER_RE.match(v):
            raise ValueError(f"runbook version must be pinned semver x.y.z, got: {v!r}")
        return v

    @field_validator("title")
    @classmethod
    def _title(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("title must be a non-empty string")
        if v != v.strip():
            raise ValueError("title must not have leading/trailing whitespace")
        if len(v) > MAX_TITLE_LEN:
            raise ValueError(f"title must be at most {MAX_TITLE_LEN} characters")
        return v

    @field_validator("trigger", "parameters_schema", "approval", "rollback")
    @classmethod
    def _mappings(cls, v: FrozenDict, info: Any) -> FrozenDict:
        return _check_mapping(str(info.field_name), v)

    @field_validator("scope", mode="before")
    @classmethod
    def _scope(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("scope must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError("scope must be a list of environment names")
        items = list(v)
        if len(items) > MAX_SCOPE_ENVS:
            raise ValueError(f"scope must hold at most {MAX_SCOPE_ENVS} entries")
        return items  # membership enforced by Environment coercion

    @field_validator("preconditions", "diagnostic_steps", "verification",
                       mode="before")
    @classmethod
    def _steps(cls, v: Any, info: Any) -> Any:
        return _check_steps(str(info.field_name), v)

    @field_validator("allowed_actions", "forbidden_actions", mode="before")
    @classmethod
    def _action_lists(cls, v: Any, info: Any) -> Any:
        name = str(info.field_name)
        if v is None:
            raise ValueError(f"{name} must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError(f"{name} must be a list of action names")
        items = list(v)
        if len(items) > 18:  # allowlist size: cannot name more than exist
            raise ValueError(f"{name} must hold at most 18 entries")
        return items  # membership enforced by ActionType coercion

    @field_validator("owner")
    @classmethod
    def _owner(cls, v: str) -> str:
        return _check_blank_or_identifier("owner", v, MAX_ID_LEN)

    @field_validator("reviewed_at")
    @classmethod
    def _reviewed_at(cls, v: str) -> str:
        return _check_blank_or_identifier("reviewed_at", v, MAX_STAMP_LEN)

    @field_validator("hash")
    @classmethod
    def _hash(cls, v: str) -> str:
        return _check_blank_or_identifier("hash", v, MAX_HASH_LEN)

    @model_validator(mode="after")
    def _disjoint_action_scope(self) -> Runbook:
        overlap = set(self.allowed_actions) & set(self.forbidden_actions)
        if overlap:
            names = sorted(str(a) for a in overlap)
            raise ValueError(f"allowed_actions and forbidden_actions must be disjoint, overlap: {names}")
        return self

    @classmethod
    def from_legacy(cls, legacy: Any) -> Runbook:
        """Build a canonical Runbook from ``app.schemas.Runbook``.

        ``scope`` plain strings coerce to ``Environment``; action-name strings
        coerce to ``ActionType`` (unknown names are rejected, never guessed).
        """
        return cls(
            runbook_id=str(legacy.runbook_id),
            version=str(legacy.version),
            title=str(legacy.title),
            trigger=FrozenDict(dict(legacy.trigger)),
            scope=tuple(legacy.scope),
            preconditions=tuple(legacy.preconditions),
            diagnostic_steps=tuple(legacy.diagnostic_steps),
            allowed_actions=tuple(legacy.allowed_actions),
            forbidden_actions=tuple(legacy.forbidden_actions),
            parameters_schema=FrozenDict(dict(legacy.parameters_schema)),
            approval=FrozenDict(dict(legacy.approval)),
            verification=tuple(legacy.verification),
            rollback=FrozenDict(dict(legacy.rollback)),
            owner=str(legacy.owner),
            reviewed_at=str(legacy.reviewed_at),
            hash=str(legacy.hash),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.Runbook`` shape."""
        from app.schemas import Runbook as LegacyRunbook  # noqa: E402

        return LegacyRunbook(
            runbook_id=self.runbook_id,
            version=self.version,
            title=self.title,
            trigger=self.trigger.to_plain(),
            scope=[str(e) for e in self.scope],
            preconditions=list(self.preconditions),
            diagnostic_steps=list(self.diagnostic_steps),
            allowed_actions=[str(a) for a in self.allowed_actions],
            forbidden_actions=[str(a) for a in self.forbidden_actions],
            parameters_schema=self.parameters_schema.to_plain(),
            approval=self.approval.to_plain(),
            verification=list(self.verification),
            rollback=self.rollback.to_plain(),
            owner=self.owner,
            reviewed_at=self.reviewed_at,
            hash=self.hash,
        )
