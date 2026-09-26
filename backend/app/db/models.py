"""SQLAlchemy 2.0 Declarative Models for ProofOps Control Plane."""
from __future__ import annotations

import time
from typing import List, Optional

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base declarative class for all database models."""


class IncidentRecord(Base):
    """Persistent storage for FSM IncidentRun."""
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    state: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="P3")
    fingerprint: Mapped[str] = mapped_column(String(128), default="")
    service: Mapped[str] = mapped_column(String(64), default="unknown")
    environment: Mapped[str] = mapped_column(String(32), default="prod")
    replans: Mapped[int] = mapped_column(Integer, default=0)
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False)
    permit_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    consumed_refs_json: Mapped[str] = mapped_column(Text, default="[]")
    handoffs_json: Mapped[str] = mapped_column(Text, default="[]")
    suppressions_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time, onupdate=time.time)

    history: Mapped[List[TransitionRecordModel]] = relationship(
        "TransitionRecordModel",
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="TransitionRecordModel.seq",
    )


class TransitionRecordModel(Base):
    """Persistent history transition records for each incident."""
    __tablename__ = "incident_transitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        index=True,
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    frm: Mapped[str] = mapped_column(String(64), nullable=False)
    to: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, default="")
    refs_json: Mapped[str] = mapped_column(Text, default="[]")
    forced: Mapped[bool] = mapped_column(Boolean, default=False)
    at: Mapped[float] = mapped_column(Float, default=time.time)

    incident: Mapped[IncidentRecord] = relationship("IncidentRecord", back_populates="history")


class ApprovalRecordModel(Base):
    """Persistent approval requests, HMAC tokens, nonces, and statuses."""
    __tablename__ = "approvals"

    approval_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(128), index=True)
    action_id: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="")
    scope: Mapped[str] = mapped_column(String(128), default="")
    params_hash: Mapped[str] = mapped_column(String(128), default="")
    token_hash: Mapped[str] = mapped_column(String(128), default="")
    nonce: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    expires_at: Mapped[float] = mapped_column(Float, default=0.0)
    action_payload_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class ExecutionRecordModel(Base):
    """Persistent execution logs, state diffs, and verification results."""
    __tablename__ = "executions"

    execution_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(128), index=True)
    action_id: Mapped[str] = mapped_column(String(128), index=True)
    tier: Mapped[str] = mapped_column(String(32), default="mock")
    before_state_json: Mapped[str] = mapped_column(Text, default="{}")
    after_state_json: Mapped[str] = mapped_column(Text, default="{}")
    state_diff_json: Mapped[str] = mapped_column(Text, default="{}")
    logs_json: Mapped[str] = mapped_column(Text, default="[]")
    idempotency_key: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class AuditEventRecordModel(Base):
    """Persistent SHA-256 Merkle audit events."""
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(128), index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(128), default="")
    curr_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), default="")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
