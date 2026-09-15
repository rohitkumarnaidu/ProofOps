"""M01.1 contract freeze surface (canonical package).

M01.2+ and M02 import from ``app.contracts`` ONLY. ``app.schemas`` remains as
a compatibility re-export layer; it defines no domain vocabulary of its own.

Freeze version: 1.0. Any breaking change needs a change request + impact
analysis + human review + version bump + migration plan.
"""
from __future__ import annotations

from app.contracts.enums import (
    ACTION_TYPES,
    FSM_STATES,
    ActionType,
    ActorType,
    ApprovalStatus,
    ClaimClass,
    ConfidenceLevel,
    Decision,
    Environment,
    EvidenceType,
    ExecutionStatus,
    ExecutorTier,
    FailureCode,
    HypothesisStatus,
    IncidentStatus,
    RiskLevel,
    Severity,
    SourceType,
    TrustLevel,
    Verdict,
)
from app.contracts.values import (
    MAX_PAGE_SIZE,
    NAMESPACE_RE,
    SEMVER_RE,
    PageParams,
    canonical_json,
    confidence_bucket,
    new_id,
    params_hash,
    sha256_hex,
    utcnow,
)
from app.contracts.alert import Alert
from app.contracts.evidence import Evidence
from app.contracts.hypothesis import Claim, Hypothesis
from app.contracts.runbook import Runbook
from app.contracts.action import Action
from app.contracts.policy import PolicyDecision
from app.contracts.approval import ApprovalRequest, ApprovalToken
from app.contracts.execution import Execution
from app.contracts.verification import VerificationResult
from app.contracts.rollback import Rollback
from app.contracts.rca import RCA
from app.contracts.audit import AuditEvent
from app.contracts.evaluation import BenchmarkResult, EvaluationRun
from app.contracts.incident import Incident

CONTRACT_VERSION = "1.0"

__all__ = [
    "CONTRACT_VERSION",
    "ACTION_TYPES",
    "FSM_STATES",
    "MAX_PAGE_SIZE",
    "NAMESPACE_RE",
    "SEMVER_RE",
    "ActionType",
    "Action",
    "ActorType",
    "ApprovalStatus",
    "ApprovalRequest",
    "ApprovalToken",
    "AuditEvent",
    "BenchmarkResult",
    "Claim",
    "EvaluationRun",
    "Execution",
    "Hypothesis",
    "PolicyDecision",
    "RCA",
    "Rollback",
    "Runbook",
    "ClaimClass",
    "ConfidenceLevel",
    "Decision",
    "Environment",
    "EvidenceType",
    "ExecutionStatus",
    "ExecutorTier",
    "FailureCode",
    "HypothesisStatus",
    "Incident",
    "IncidentStatus",
    "Alert",
    "Evidence",
    "VerificationResult",
    "PageParams",
    "RiskLevel",
    "Severity",
    "SourceType",
    "TrustLevel",
    "Verdict",
    "canonical_json",
    "confidence_bucket",
    "new_id",
    "params_hash",
    "sha256_hex",
    "utcnow",
]
