"""ProofOps shared contracts entrypoint (V2 §16, §21, §25, §27, §32).

COMPATIBILITY LAYER (M01.1, rivalry closed in the M01 90+ pass): every name
here IS the canonical ``app.contracts`` object — ``S.X is C.X`` for 15 of 16
models plus all enums and helpers (proven by
tests/test_contracts_m01_rivalry.py). The single exception is ``Alert``,
which keeps its historical RAW-telemetry input shape (``severity_raw`` /
``signature`` / flat ``labels``) as the documented input to the
``Alert.from_legacy`` migration bridge — a different pipeline STAGE (raw
ingest), not a rival validator of the normalized shape. It is contained, not
trusted: zero production importers (proven by grep AND pinned by
``test_no_production_schemas_import`` — any future backend/scripts/telemetry
import of ``app.schemas`` fails CI), and the live path normalizes raw dicts
directly (``services/normalizer.py``, zero ``schemas`` references). New code
must import from ``app.contracts`` directly; this module stays so old import
lines keep working.

Single source of truth for every component (agents, backend, policy,
executor, frontend, evaluation). No component invents its own shape.
Runtime authorization (GREEN/YELLOW/RED, HITL, sandbox) lives in services,
NOT here — schemas only guarantee structure. The LLM-proposed `risk_level`
on Action is ADVISORY; the policy engine recomputes it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.contracts import (  # noqa: F401 (pure re-export surface: every name below IS the canonical object, except Alert)
    ACTION_TYPES,
    FSM_STATES,
    NAMESPACE_RE,
    SEMVER_RE,
    Action,
    ActionType,
    ActorType,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalToken,
    AuditEvent,
    BenchmarkResult,
    Claim,
    ClaimClass,
    ConfidenceLevel,
    Decision,
    Environment,
    EvaluationRun,
    Evidence,
    EvidenceType,
    Execution,
    ExecutionStatus,
    ExecutorTier,
    FailureCode,
    Hypothesis,
    HypothesisStatus,
    Incident,
    IncidentStatus,
    PolicyDecision,
    RCA,
    RiskLevel,
    Rollback,
    Runbook,
    Severity,
    SourceType,
    TrustLevel,
    Verdict,
    VerificationResult,
    canonical_json,
    confidence_bucket,
    new_id,
    params_hash,
    sha256_hex,
    utcnow,
)


# ------------------------------------------------------------------ Alert --
# RETAINED raw-telemetry input shape (see module docstring): the ONLY model
# still defined here. Consumed exclusively by ``Alert.from_legacy`` (severity
# mapping + message/resource extraction + hash preservation) and its tests.
# NEVER a trust validator: no production module may import app.schemas
# (pinned by test_no_production_schemas_import). Weaker than canonical BY
# DESIGN (raw ingest precedes validation); the strict-typed from_legacy
# bridge (M01 90+ pass) rejects non-str injections instead of coercing them.
class Alert(BaseModel):
    alert_id: str = Field(default_factory=new_id)
    ts: datetime = Field(default_factory=utcnow)
    service: str = Field(min_length=1)
    environment: Environment = Environment.MOCK
    severity_raw: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    labels: dict[str, Any] = {}
    hash: str = ""
