"""M01.9 Approval schema - canonical ApprovalRequest + ApprovalToken contracts.

Ownership: M01.9 owns THIS FILE ONLY (``backend/app/contracts/approval.py``).
No frozen enum is needed here (lifecycle ``ApprovalStatus`` vocabulary stays
M01.1-owned; transitions belong to M07). Legacy ``app.schemas`` is a compat
layer owned by M01.1 - it is read in tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S27 -
``Request{incident, action+params-hash, risk, blast, evidence, reason, policy
ref, expected, rollback, agent, ts, expires}`` and
``Token=HMAC-SHA256(secret, action_id|actor|params_hash|scope|expiry|nonce)``.
Server verifies: signature, actor role, scope==exact params hash, expiry,
nonce unused (store+burn). Replay/tamper/expired/wrong-actor -> DENY + audit.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
approval request and one approval token carrier. It performs NO HMAC signing,
NO signature verification, NO nonce store+burn, NO expiry enforcement, and NO
actor-role checks. Those are HITL duties (future M07). A constructed token
carrier proves NOTHING by itself - only server-side verification against the
secret + nonce store authorizes. ``is_expired`` is a pure clock comparison
helper (same as legacy); it is not authorization.

Legacy wire mapping (field names match legacy ``app.schemas`` EXACTLY)::

    ApprovalRequest: approval_id / incident_id / action_id / actor /
                     params_hash / scope / expires_at / nonce.
    ApprovalToken:   token / approval_id / action_id / actor /
                     params_hash / expires_at (+ is_expired helper).

Bounds table::

    approval_id/action_id/incident_id/actor  1..MAX_ID_LEN (128, identifiers)
    params_hash/scope                        1..MAX_HASH_LEN (256, opaque)
    token                                    1..MAX_TOKEN_LEN (1024, opaque)
    nonce                                    8..MAX_NONCE_LEN (128; min 8 readable
                                                               entropy floor)
    expires_at                               tz-aware datetime (naive rejected)

Bypass containment (Escape 1, M01.2-M01.8 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation on BOTH
models.

NOT implemented here (owned elsewhere): HMAC issue/verify (M07.2), nonce
single-use burn (M07.3), TTL expiry escalation (M07.4), scope/actor binding
checks (M07.5/M07.6), replay protection (M07.7), approval audit events
(M07.8), approve/deny API + Safety Gate UI (M15-phase T15).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, NoReturn, Optional, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.values import new_id, utcnow

MAX_ID_LEN = 128
MAX_HASH_LEN = 256
MAX_TOKEN_LEN = 1024
MIN_NONCE_LEN = 8
MAX_NONCE_LEN = 128


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _check_expiry(v: Any, name: str) -> datetime:
    """Expiry rule: must be a timezone-aware datetime (naive rejected)."""
    if not isinstance(v, datetime):
        raise ValueError(f"{name} must be a datetime")
    if v.tzinfo is None or v.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware (reject naive)")
    return v


class ApprovalRequest(BaseModel):
    """One human-approval request: exact action scope awaiting a decision."""

    model_config = {"frozen": True, "extra": "forbid"}

    approval_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Opaque approval id (uuid4 hex default).",
    )
    incident_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    action_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    actor: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Expected approver identity (server checks role).",
    )
    params_hash: str = Field(
        min_length=1,
        max_length=MAX_HASH_LEN,
        description="Exact parameter commitment (values.params_hash).",
    )
    scope: str = Field(
        min_length=1,
        max_length=MAX_HASH_LEN,
        description="Approval scope string (must equal exact params hash).",
    )
    expires_at: datetime = Field(
        description="tz-aware expiry (TTL 10m, 15m demo mode).",
    )
    nonce: str = Field(
        min_length=MIN_NONCE_LEN,
        max_length=MAX_NONCE_LEN,
        description="Single-use nonce (min 8 chars readable entropy floor).",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "ApprovalRequest.model_construct is blocked: it skips validation. "
            "Use ApprovalRequest(...) or ApprovalRequest.model_validate for "
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

    @field_validator("approval_id", "incident_id", "action_id", "actor")
    @classmethod
    def _ids(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, MAX_ID_LEN)

    @field_validator("params_hash", "scope")
    @classmethod
    def _hashes(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, MAX_HASH_LEN)

    @field_validator("nonce")
    @classmethod
    def _nonce(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("nonce must be a non-empty string")
        if v != v.strip():
            raise ValueError("nonce must not have leading/trailing whitespace")
        if not MIN_NONCE_LEN <= len(v) <= MAX_NONCE_LEN:
            raise ValueError(
                f"nonce must be {MIN_NONCE_LEN}..{MAX_NONCE_LEN} characters")
        return v

    @field_validator("expires_at")
    @classmethod
    def _expires_at(cls, v: Any) -> datetime:
        return _check_expiry(v, "expires_at")

    @classmethod
    def from_legacy(cls, legacy: Any) -> ApprovalRequest:
        """Build a canonical ApprovalRequest from ``app.schemas`` (1:1 wire)."""
        return cls(
            approval_id=str(legacy.approval_id),
            incident_id=str(legacy.incident_id),
            action_id=str(legacy.action_id),
            actor=str(legacy.actor),
            params_hash=str(legacy.params_hash),
            scope=str(legacy.scope),
            expires_at=legacy.expires_at,
            nonce=str(legacy.nonce),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.ApprovalRequest`` shape."""
        from app.schemas import ApprovalRequest as LegacyRequest  # noqa: E402

        return LegacyRequest(
            approval_id=self.approval_id,
            incident_id=self.incident_id,
            action_id=self.action_id,
            actor=self.actor,
            params_hash=self.params_hash,
            scope=self.scope,
            expires_at=self.expires_at,
            nonce=self.nonce,
        )


class ApprovalToken(BaseModel):
    """One approval token carrier: opaque HMAC string + bound references."""

    model_config = {"frozen": True, "extra": "forbid"}

    token: str = Field(
        min_length=1,
        max_length=MAX_TOKEN_LEN,
        description="Opaque HMAC token string (verified server-side only).",
    )
    approval_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    action_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    actor: str = Field(min_length=1, max_length=MAX_ID_LEN)
    params_hash: str = Field(min_length=1, max_length=MAX_HASH_LEN)
    expires_at: datetime = Field(description="tz-aware expiry.")

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "ApprovalToken.model_construct is blocked: it skips validation. "
            "Use ApprovalToken(...) or ApprovalToken.model_validate for "
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

    @field_validator("token")
    @classmethod
    def _token(cls, v: str) -> str:
        return _check_identifier("token", v, MAX_TOKEN_LEN)

    @field_validator("approval_id", "action_id", "actor")
    @classmethod
    def _ids(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, MAX_ID_LEN)

    @field_validator("params_hash")
    @classmethod
    def _params_hash(cls, v: str) -> str:
        return _check_identifier("params_hash", v, MAX_HASH_LEN)

    @field_validator("expires_at")
    @classmethod
    def _expires_at(cls, v: Any) -> datetime:
        return _check_expiry(v, "expires_at")

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Pure clock comparison (NOT authorization - server decides)."""
        return (now or utcnow()) >= self.expires_at

    @classmethod
    def from_legacy(cls, legacy: Any) -> ApprovalToken:
        """Build a canonical ApprovalToken from ``app.schemas`` (1:1 wire)."""
        return cls(
            token=str(legacy.token),
            approval_id=str(legacy.approval_id),
            action_id=str(legacy.action_id),
            actor=str(legacy.actor),
            params_hash=str(legacy.params_hash),
            expires_at=legacy.expires_at,
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.ApprovalToken`` shape."""
        from app.schemas import ApprovalToken as LegacyToken  # noqa: E402

        return LegacyToken(
            token=self.token,
            approval_id=self.approval_id,
            action_id=self.action_id,
            actor=self.actor,
            params_hash=self.params_hash,
            expires_at=self.expires_at,
        )
