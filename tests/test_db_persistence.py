"""Tests for enterprise database persistence (SQLAlchemy 2.0 async engine + repository)."""
import asyncio
import os
import sys
import uuid
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.db.session import init_db, db_health, get_db_session
from app.db.models import IncidentRecord, ApprovalRecordModel, ExecutionRecordModel, AuditEventRecordModel
from app.db.repository import (
    save_incident_run,
    load_incident_run,
    list_incident_runs,
    save_approval_record,
    save_execution_record,
    save_audit_event,
)
from app.services.fsm import IncidentRun, TransitionRecord, Permit
from sqlalchemy import select


@pytest.mark.asyncio
async def test_init_db_and_health():
    await init_db()
    health = await db_health()
    assert health["healthy"] is True
    assert health["dialect"] in ("sqlite", "postgresql")
    assert health["database"] == "proofops"
    assert health["error"] is None


@pytest.mark.asyncio
async def test_save_and_load_incident_run():
    await init_db()
    uid = uuid.uuid4().hex[:6]
    inc_id = f"inc-db-test-{uid}"
    run = IncidentRun(
        incident_id=inc_id,
        state="DIAGNOSING",
        replans=1,
        rolled_back=False,
        consumed_refs={"alert-1", "alert-2"},
        handoffs=[{"agent": "A1", "summary": "Triage done"}, {"agent": "A2", "summary": "Diagnosed"}],
        suppressions=[{"fingerprint": "fp-123"}],
        permit=Permit(action_id="act-1", params_hash="abc12345", expires_at=999999.0, token_ref="tok-ref-1", auto=True),
    )
    run.history.append(TransitionRecord(seq=1, frm="NEW", to="TRIAGING", reason="start", refs=["alert-1"], forced=False, at=100.0))
    run.history.append(TransitionRecord(seq=2, frm="TRIAGING", to="DIAGNOSING", reason="triaged", refs=["alert-2"], forced=False, at=105.0))

    await save_incident_run(run)

    loaded = await load_incident_run(inc_id)
    assert loaded is not None
    assert loaded.incident_id == inc_id
    assert loaded.state == "DIAGNOSING"
    assert loaded.replans == 1
    assert loaded.rolled_back is False
    assert loaded.consumed_refs == {"alert-1", "alert-2"}
    assert len(loaded.history) == 2
    assert loaded.history[0].frm == "NEW"
    assert loaded.history[0].to == "TRIAGING"
    assert loaded.history[1].frm == "TRIAGING"
    assert loaded.history[1].to == "DIAGNOSING"
    assert loaded.permit is not None
    assert loaded.permit.action_id == "act-1"
    assert loaded.permit.token_ref == "tok-ref-1"
    assert len(loaded.handoffs) == 2
    assert loaded.handoffs[0]["agent"] == "A1"


@pytest.mark.asyncio
async def test_update_and_cascade_incident_run():
    await init_db()
    uid = uuid.uuid4().hex[:6]
    inc_id = f"inc-db-cascade-{uid}"
    run = IncidentRun(incident_id=inc_id, state="NEW")
    await save_incident_run(run)

    # Advance state and append transition
    run.state = "TRIAGING"
    run.history.append(TransitionRecord(seq=1, frm="NEW", to="TRIAGING", reason="started", refs=[], forced=False, at=200.0))
    await save_incident_run(run)

    loaded = await load_incident_run(inc_id)
    assert loaded is not None
    assert loaded.state == "TRIAGING"
    assert len(loaded.history) == 1
    assert loaded.history[0].seq == 1


@pytest.mark.asyncio
async def test_list_incident_runs():
    await init_db()
    runs = await list_incident_runs()
    assert isinstance(runs, list)
    assert len(runs) > 0


@pytest.mark.asyncio
async def test_approval_record_persistence():
    await init_db()
    uid = uuid.uuid4().hex[:6]
    appr_id = f"appr-db-{uid}"
    appr_data = {
        "approval_id": appr_id,
        "incident_id": f"inc-{uid}",
        "action_id": f"act-{uid}",
        "actor": "commander-1",
        "scope": "restart_pod:payment-service",
        "params_hash": "paramhash123",
        "token_hash": "tokenhash456",
        "nonce": f"nonce-{uid}",
        "status": "pending",
        "expires_at": 1800000.0,
        "action": {"type": "restart_pod", "target": "payment-service"},
    }
    await save_approval_record(appr_data)

    async with get_db_session() as session:
        stmt = select(ApprovalRecordModel).where(ApprovalRecordModel.approval_id == appr_id)
        res = await session.execute(stmt)
        record = res.scalar_one_or_none()
        assert record is not None
        assert record.actor == "commander-1"
        assert record.status == "pending"

    # Update approval status
    appr_data["status"] = "approved"
    await save_approval_record(appr_data)

    async with get_db_session() as session:
        stmt = select(ApprovalRecordModel).where(ApprovalRecordModel.approval_id == appr_id)
        res = await session.execute(stmt)
        record = res.scalar_one_or_none()
        assert record is not None
        assert record.status == "approved"


@pytest.mark.asyncio
async def test_execution_record_persistence():
    await init_db()
    uid = uuid.uuid4().hex[:6]
    exec_id = f"exec-db-{uid}"
    exec_data = {
        "execution_id": exec_id,
        "incident_id": f"inc-{uid}",
        "action_id": f"act-{uid}",
        "tier": "k8s",
        "before_state": {"replicas": 1, "image": "v2"},
        "after_state": {"replicas": 3, "image": "v2"},
        "state_diff": {"changed": {"replicas": {"before": 1, "after": 3}}},
        "logs": ["Scale requested", "Scaled to 3 replicas successfully"],
        "idempotency_key": f"idem-key-{uid}",
    }
    await save_execution_record(exec_data)

    async with get_db_session() as session:
        stmt = select(ExecutionRecordModel).where(ExecutionRecordModel.execution_id == exec_id)
        res = await session.execute(stmt)
        record = res.scalar_one_or_none()
        assert record is not None
        assert record.tier == "k8s"
        assert record.idempotency_key == f"idem-key-{uid}"


@pytest.mark.asyncio
async def test_audit_event_persistence():
    await init_db()
    uid = uuid.uuid4().hex[:6]
    inc_id = f"inc-audit-{uid}"
    await save_audit_event(
        incident_id=inc_id,
        seq=1,
        event_type="incident.created",
        prev_hash="GENESIS_0000",
        curr_hash="hash_block_1",
        actor="system",
        payload={"severity": "P1"},
    )

    async with get_db_session() as session:
        stmt = select(AuditEventRecordModel).where(
            AuditEventRecordModel.incident_id == inc_id,
            AuditEventRecordModel.seq == 1
        )
        res = await session.execute(stmt)
        record = res.scalar_one_or_none()
        assert record is not None
        assert record.event_type == "incident.created"
        assert record.curr_hash == "hash_block_1"
