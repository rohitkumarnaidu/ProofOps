"""M01.8 PolicyDecision schema - canonical policy verdict contract.

Ownership: M01.8 owns THIS FILE ONLY (``backend/app/contracts/policy.py``).
Frozen vocabulary (``Decision``/``RiskLevel``) is owned by M01.1 and is
imported, never redeclared. Legacy ``app.schemas`` is a compat layer owned by
M01.1 - it is read in tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S18 - ``evaluate(...) ->
{ALLOW|ESCALATE|DENY, rule_id, obligations[], ttl}``. Every decision captures
policy version + matched rule + result + obligations; priority
DENY > ESCALATE > ALLOW; default DENY.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
policy verdict. It performs NO rule evaluation, NO conflict resolution, NO
default-deny logic, and NO risk computation. Those are engine duties (future
M06.5). A constructed ``PolicyDecision`` is well-formed DATA - only the
engine, reading the versioned bundle, may author one.

Legacy wire mapping (field names match legacy ``app.schemas.PolicyDecision``
EXACTLY)::

    decision / rule_id / policy_version / effective_risk / obligations /
    ttl_seconds / message.

Bounds table::

    rule_id         1..MAX_RULE_LEN   (128, e.g. DENY-shell)
    policy_version  1..MAX_VER_LEN    (64, bundle tag e.g. "v1"; NOT semver -
                                       bundles version as vX, see
                                       policies/bundle_v1.yaml)
    obligations     0..MAX_OBLIG     (32 entries, each <=1024, non-blank)
    ttl_seconds     0..MAX_TTL_S      (86400 = 24h ceiling; default 600)
    message         0..MAX_MSG_LEN    (4096, verbatim, may be "")

Bypass containment (Escape 1, M01.2-M01.7 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation.

NOT implemented here (owned elsewhere): bundle loading/parsing (M06.4),
rule matching and conflict resolution (M06.5/M06.7), default-deny on unknown
or exception (M06.6), blast-radius evaluation (M06.8), environment-aware
rules (M06.9), decision audit linkage (M06.10/M15).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import Decision, RiskLevel

MAX_RULE_LEN = 128
MAX_VER_LEN = 64
MAX_OBLIG = 32
MAX_OBLIG_LEN = 1024
MAX_TTL_S = 86400
MAX_MSG_LEN = 4096


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


class PolicyDecision(BaseModel):
    """One deterministic policy verdict: decision + rule ref + obligations."""

    model_config = {"frozen": True, "extra": "forbid"}

    decision: Decision = Field(
        description="Strict Decision: ALLOW | ESCALATE | DENY.",
    )
    rule_id: str = Field(
        min_length=1,
        max_length=MAX_RULE_LEN,
        description="Matched bundle rule id (e.g. DENY-shell).",
    )
    policy_version: str = Field(
        min_length=1,
        max_length=MAX_VER_LEN,
        description='Bundle tag (e.g. "v1"). Bundle versioning, not semver.',
    )
    effective_risk: RiskLevel = Field(
        description="Policy-computed risk (strict; replaces model advisory).",
    )
    obligations: tuple[str, ...] = Field(
        default=(),
        description="Obligations (e.g. hitl-approval, verify-slos).",
    )
    ttl_seconds: int = Field(
        default=600,
        ge=0,
        le=MAX_TTL_S,
        description="Permit freshness TTL in seconds (execute re-checks <=5m).",
    )
    message: str = Field(
        default="",
        max_length=MAX_MSG_LEN,
        description="Human-readable verdict message (verbatim, may be empty).",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "PolicyDecision.model_construct is blocked: it skips validation. "
            "Use PolicyDecision(...) or PolicyDecision.model_validate for "
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

    @field_validator("rule_id")
    @classmethod
    def _rule_id(cls, v: str) -> str:
        return _check_identifier("rule_id", v, MAX_RULE_LEN)

    @field_validator("policy_version")
    @classmethod
    def _policy_version(cls, v: str) -> str:
        return _check_identifier("policy_version", v, MAX_VER_LEN)

    @field_validator("ttl_seconds", mode="before")
    @classmethod
    def _ttl_strict(cls, v: Any) -> Any:
        # Reject bools BEFORE coercion (True -> 1 would launder a bug).
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("ttl_seconds must be an integer (bool rejected)")
        return v

    @field_validator("obligations", mode="before")
    @classmethod
    def _obligations(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("obligations must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError("obligations must be a list of strings")
        items = list(v)
        if len(items) > MAX_OBLIG:
            raise ValueError(f"obligations must hold at most {MAX_OBLIG} entries")
        checked: list[str] = []
        for item in items:
            if not isinstance(item, str):
                raise ValueError("obligations entries must be non-empty strings")
            checked.append(_check_identifier(
                "obligations entries", item, MAX_OBLIG_LEN))
        return checked

    @field_validator("message")
    @classmethod
    def _message(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("message must be a string")
        if len(v) > MAX_MSG_LEN:
            raise ValueError(f"message must be at most {MAX_MSG_LEN} characters")
        return v

    @classmethod
    def from_legacy(cls, legacy: Any) -> PolicyDecision:
        """Build a canonical PolicyDecision from ``app.schemas`` (1:1 wire)."""
        return cls(
            decision=legacy.decision,
            rule_id=str(legacy.rule_id),
            policy_version=str(legacy.policy_version),
            effective_risk=legacy.effective_risk,
            obligations=tuple(legacy.obligations),
            ttl_seconds=int(legacy.ttl_seconds),
            message=str(legacy.message),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.PolicyDecision`` shape."""
        from app.schemas import PolicyDecision as LegacyDecision  # noqa: E402

        return LegacyDecision(
            decision=self.decision,
            rule_id=self.rule_id,
            policy_version=self.policy_version,
            effective_risk=self.effective_risk,
            obligations=list(self.obligations),
            ttl_seconds=self.ttl_seconds,
            message=self.message,
        )
