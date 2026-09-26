"""Database Repository for IncidentRuns, Approvals, Executions, and Audit Chains."""
from __future__ import annotations

import dataclasses
import json
from typing import Any

from sqlalchemy import desc, select

from app.db.models import (
    ApprovalRecordModel,
    AuditEventRecordModel,
    ExecutionRecordModel,
    IncidentRecord,
    TransitionRecordModel,
)
from app.db.session import get_db_session
from app.services.fsm import IncidentRun, Permit, TransitionRecord


def _serialize_permit(permit: Permit | None) -> str | None:
    if permit is None:
        return None
    return json.dumps(dataclasses.asdict(permit))


def _deserialize_permit(raw: str | None) -> Permit | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return Permit(
            action_id=data["action_id"],
            params_hash=data["params_hash"],
            expires_at=data["expires_at"],
            token_ref=data["token_ref"],
            auto=data.get("auto", False),
        )
    except Exception:
        return None


async def save_incident_run(run: IncidentRun) -> None:
    """Persist an IncidentRun to database with atomic history cascade."""
    async with get_db_session() as session:
        stmt = select(IncidentRecord).where(IncidentRecord.incident_id == run.incident_id)
        res = await session.execute(stmt)
        record = res.scalar_one_or_none()

        if record is None:
            record = IncidentRecord(
                incident_id=run.incident_id,
                state=run.state,
                replans=run.replans,
                rolled_back=run.rolled_back,
                permit_json=_serialize_permit(run.permit),
                consumed_refs_json=json.dumps(sorted(run.consumed_refs)),
                handoffs_json=json.dumps([dict(h) for h in run.handoffs]),
                suppressions_json=json.dumps([dict(s) for s in run.suppressions]),
            )
            session.add(record)
        else:
            record.state = run.state
            record.replans = run.replans
            record.rolled_back = run.rolled_back
            record.permit_json = _serialize_permit(run.permit)
            record.consumed_refs_json = json.dumps(sorted(run.consumed_refs))
            record.handoffs_json = json.dumps([dict(h) for h in run.handoffs])
            record.suppressions_json = json.dumps([dict(s) for s in run.suppressions])

        # Delete existing transition models to avoid duplicates and re-insert current history
        existing_seqs = {r.seq for r in record.history}
        for rec in run.history:
            if rec.seq not in existing_seqs:
                t_model = TransitionRecordModel(
                    incident_id=run.incident_id,
                    seq=rec.seq,
                    frm=rec.frm,
                    to=rec.to,
                    reason=rec.reason,
                    refs_json=json.dumps(rec.refs),
                    forced=rec.forced,
                    at=rec.at,
                )
                session.add(t_model)


async def load_incident_run(incident_id: str) -> IncidentRun | None:
    """Load an IncidentRun by incident_id from the database."""
    async with get_db_session() as session:
        stmt = (
            select(IncidentRecord)
            .where(IncidentRecord.incident_id == incident_id)
        )
        res = await session.execute(stmt)
        record = res.scalar_one_or_none()
        if record is None:
            return None

        history = [
            TransitionRecord(
                seq=t.seq,
                frm=t.frm,
                to=t.to,
                reason=t.reason,
                refs=json.loads(t.refs_json) if t.refs_json else [],
                forced=t.forced,
                at=t.at,
            )
            for t in sorted(record.history, key=lambda x: x.seq)
        ]

        permit = _deserialize_permit(record.permit_json)
        consumed = json.loads(record.consumed_refs_json) if record.consumed_refs_json else []
        handoffs = json.loads(record.handoffs_json) if record.handoffs_json else []
        suppressions = json.loads(record.suppressions_json) if record.suppressions_json else []

        run = IncidentRun(
            incident_id=record.incident_id,
            state=record.state,
            history=history,
            handoffs=handoffs,
            suppressions=suppressions,
            replans=record.replans,
            rolled_back=record.rolled_back,
            permit=permit,
            consumed_refs=set(consumed),
        )
        return run


async def list_incident_runs() -> list[IncidentRun]:
    """List all persisted IncidentRuns sorted by created_at."""
    async with get_db_session() as session:
        stmt = select(IncidentRecord).order_by(desc(IncidentRecord.created_at))
        res = await session.execute(stmt)
        records = res.scalars().all()

        runs: list[IncidentRun] = []
        for record in records:
            history = [
                TransitionRecord(
                    seq=t.seq,
                    frm=t.frm,
                    to=t.to,
                    reason=t.reason,
                    refs=json.loads(t.refs_json) if t.refs_json else [],
                    forced=t.forced,
                    at=t.at,
                )
                for t in sorted(record.history, key=lambda x: x.seq)
            ]
            run = IncidentRun(
                incident_id=record.incident_id,
                state=record.state,
                history=history,
                handoffs=json.loads(record.handoffs_json) if record.handoffs_json else [],
                suppressions=json.loads(record.suppressions_json) if record.suppressions_json else [],
                replans=record.replans,
                rolled_back=record.rolled_back,
                permit=_deserialize_permit(record.permit_json),
                consumed_refs=set(json.loads(record.consumed_refs_json) if record.consumed_refs_json else []),
            )
            runs.append(run)
        return runs


async def save_approval_record(data: dict[str, Any]) -> None:
    """Save or update an approval record."""
    async with get_db_session() as session:
        stmt = select(ApprovalRecordModel).where(ApprovalRecordModel.approval_id == data["approval_id"])
        res = await session.execute(stmt)
        rec = res.scalar_one_or_none()
        if rec is None:
            rec = ApprovalRecordModel(
                approval_id=data["approval_id"],
                incident_id=data.get("incident_id", ""),
                action_id=data.get("action_id", ""),
                actor=data.get("actor", ""),
                scope=data.get("scope", ""),
                params_hash=data.get("params_hash", ""),
                token_hash=data.get("token_hash", ""),
                nonce=data.get("nonce", ""),
                status=data.get("status", "pending"),
                expires_at=data.get("expires_at", 0.0),
                action_payload_json=json.dumps(data.get("action", {})),
            )
            session.add(rec)
        else:
            rec.status = data.get("status", rec.status)


async def save_execution_record(data: dict[str, Any]) -> None:
    """Save or update an execution record."""
    async with get_db_session() as session:
        stmt = select(ExecutionRecordModel).where(ExecutionRecordModel.execution_id == data["execution_id"])
        res = await session.execute(stmt)
        rec = res.scalar_one_or_none()
        if rec is None:
            rec = ExecutionRecordModel(
                execution_id=data["execution_id"],
                incident_id=data.get("incident_id", ""),
                action_id=data.get("action_id", ""),
                tier=data.get("tier", "mock"),
                before_state_json=json.dumps(data.get("before_state", {})),
                after_state_json=json.dumps(data.get("after_state", {})),
                state_diff_json=json.dumps(data.get("state_diff", {})),
                logs_json=json.dumps(list(data.get("logs", []))),
                idempotency_key=data.get("idempotency_key", ""),
            )
            session.add(rec)
        else:
            rec.tier = data.get("tier", rec.tier)
            rec.after_state_json = json.dumps(data.get("after_state", {}))
            rec.state_diff_json = json.dumps(data.get("state_diff", {}))
            rec.logs_json = json.dumps(list(data.get("logs", [])))


async def save_audit_event(incident_id: str, seq: int, event_type: str, prev_hash: str, curr_hash: str, actor: str, payload: dict[str, Any]) -> None:
    """Save an audit event into the append-only table (idempotent on incident_id + seq)."""
    async with get_db_session() as session:
        stmt = select(AuditEventRecordModel).where(
            AuditEventRecordModel.incident_id == incident_id,
            AuditEventRecordModel.seq == seq
        )
        res = await session.execute(stmt)
        rec = res.scalar_one_or_none()
        if rec is None:
            rec = AuditEventRecordModel(
                incident_id=incident_id,
                seq=seq,
                event_type=event_type,
                prev_hash=prev_hash,
                curr_hash=curr_hash,
                actor=actor,
                payload_json=json.dumps(payload),
            )
            session.add(rec)
