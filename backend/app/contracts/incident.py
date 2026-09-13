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

Ownership: M01.2 owns shape + field validation only. Lifecycle/FSM (M14),
correlation/grouping (M04), diagnosis linkage (M05+), persistence (DB
migrations) live elsewhere. In particular this model does NOT couple
``status`` to ``resolved_at`` and does NOT auto-touch ``updated_at``.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app.contracts.enums import Environment, IncidentStatus, Severity
from app.contracts.values import new_id, utcnow


def _require_nonblank(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


class Incident(BaseModel):
    """Canonical incident (control-plane contract, frozen shape)."""

    model_config = {"frozen": True, "extra": "forbid"}

    incident_id: str = Field(default_factory=new_id, min_length=1)
    status: IncidentStatus = IncidentStatus.NEW
    severity: Severity
    service: str = Field(default="unknown", min_length=1)
    environment: Environment = Environment.MOCK
    impact: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    detected_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    source_alert_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    diagnosis_reference: Optional[str] = None
    action_references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("incident_id", "fingerprint", "service")
    @classmethod
    def _nonblank(cls, v: str, info: Any) -> str:
        return _require_nonblank(str(info.field_name), v)

    @field_validator("diagnosis_reference")
    @classmethod
    def _diagnosis_ref(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return _require_nonblank("diagnosis_reference", v)

    @field_validator("source_alert_ids", "evidence_ids", "action_references",
                     mode="before")
    @classmethod
    def _id_lists(cls, v: Any, info: Any) -> Any:
        if v is None:
            raise ValueError(f"{info.field_name} must be a list, not null")
        if not isinstance(v, list):
            raise ValueError(f"{info.field_name} must be a list of ID strings")
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"{info.field_name} entries must be non-empty strings")
        return v

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
