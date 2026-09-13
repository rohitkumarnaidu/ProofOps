"""ProofOps shared contracts (V2 §16, §21, §25, §27, §32).

COMPATIBILITY LAYER (M01.1): this module defines no domain vocabulary of its
own. Canonical definitions live in ``app.contracts``; everything here is a
re-export or a model re-typed onto the canonical Enums. M01.2+ must import
from ``app.contracts`` directly.

Single source of truth for every component (agents, backend, policy,
executor, frontend, evaluation). No component invents its own shape.
Runtime authorization (GREEN/YELLOW/RED, HITL, sandbox) lives in services,
NOT here — schemas only guarantee structure. The LLM-proposed `risk_level`
on Action is ADVISORY; the policy engine recomputes it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from app.contracts import (  # noqa: F401 (re-export surface)
    ACTION_TYPES,
    FSM_STATES,
    NAMESPACE_RE,
    SEMVER_RE,
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
    Incident,
    IncidentStatus,
    RiskLevel,
    Severity,
    SourceType,
    TrustLevel,
    Verdict,
    canonical_json,
    confidence_bucket,
    new_id,
    params_hash,
    sha256_hex,
    utcnow,
)

# ---------------------------------------------------------------- telemetry
class Alert(BaseModel):
    alert_id: str = Field(default_factory=new_id)
    ts: datetime = Field(default_factory=utcnow)
    service: str = Field(min_length=1)
    environment: Environment = Environment.MOCK
    severity_raw: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    labels: dict[str, Any] = {}
    hash: str = ""


# ---------------------------------------------------------------- incident
# M01.2: canonical Incident lives in app.contracts.incident; re-exported here
# for backward compatibility (single definition, no drift).


# ---------------------------------------------------------------- evidence
class Evidence(BaseModel):
    evidence_id: str = Field(default_factory=new_id)
    incident_id: str = Field(min_length=1)
    source_type: SourceType
    source_id: str = Field(min_length=1)
    ts: datetime = Field(default_factory=utcnow)
    ref: str = Field(min_length=1)  # pointer to full blob (line range, row id, ...)
    hash: str = Field(min_length=1)
    freshness_s: float = Field(ge=0)
    relevance: float = Field(ge=0, le=1)
    trust: TrustLevel = TrustLevel.MED


class Claim(BaseModel):
    claim_id: str = Field(default_factory=new_id)
    text: str = Field(min_length=1)
    evidence_ids: list[str] = []
    claim_class: ClaimClass = ClaimClass.MUST_CITE


class Hypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=new_id)
    text: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    supporting: list[str] = []
    contradicting: list[str] = []
    test_tool: str = ""
    test_result: str = ""
    status: HypothesisStatus = HypothesisStatus.UNCERTAIN


# ---------------------------------------------------------------- runbook
class Runbook(BaseModel):
    runbook_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    title: str = Field(min_length=1)
    trigger: dict[str, Any] = {}
    scope: list[str] = []
    preconditions: list[str] = []
    diagnostic_steps: list[str] = []
    allowed_actions: list[str] = []
    forbidden_actions: list[str] = []
    parameters_schema: dict[str, Any] = {}
    approval: dict[str, Any] = {}
    verification: list[str] = []
    rollback: dict[str, Any] = {}
    owner: str = ""
    reviewed_at: str = ""
    hash: str = ""

    @field_validator("version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not SEMVER_RE.match(v):
            raise ValueError(f"runbook version must be semver x.y.z, got: {v}")
        return v


# ---------------------------------------------------------------- action
class Action(BaseModel):
    action_id: str = Field(default_factory=new_id)
    incident_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    action_type: ActionType
    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    environment: Environment = Environment.MOCK
    namespace: str = "default"
    parameters: dict[str, Any] = {}
    risk_level: RiskLevel = RiskLevel.GREEN  # ADVISORY ONLY — policy recomputes
    reason: str = Field(min_length=1)
    evidence_ids: list[str] = []
    runbook_id: str = Field(min_length=1)
    runbook_version: str = Field(min_length=1)
    expected_outcome: str = Field(min_length=1)
    rollback_action: Optional[dict[str, Any]] = None
    verification_plan: list[str] = []

    @field_validator("namespace")
    @classmethod
    def _namespace(cls, v: str) -> str:
        if not NAMESPACE_RE.match(v):
            raise ValueError(f"invalid k8s namespace: {v}")
        return v

    @field_validator("runbook_version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not SEMVER_RE.match(v):
            raise ValueError(f"runbook version must be pinned semver x.y.z, got: {v}")
        return v

    @field_validator("parameters")
    @classmethod
    def _params_object(cls, v: Any) -> dict:
        if not isinstance(v, dict):
            raise ValueError("parameters must be an object, never a string/command")
        return v


class PolicyDecision(BaseModel):
    decision: Decision
    rule_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    effective_risk: RiskLevel
    obligations: list[str] = []
    ttl_seconds: int = Field(default=600, ge=0)
    message: str = ""


# ---------------------------------------------------------------- HITL
class ApprovalRequest(BaseModel):
    approval_id: str = Field(default_factory=new_id)
    incident_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    params_hash: str = Field(min_length=1)  # noqa: F811 (contract field name shadows helper import by necessity)
    scope: str = Field(min_length=1)
    expires_at: datetime
    nonce: str = Field(min_length=8)


class ApprovalToken(BaseModel):
    token: str = Field(min_length=1)
    approval_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    params_hash: str = Field(min_length=1)  # noqa: F811 (contract field name shadows helper import by necessity)
    expires_at: datetime

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        return (now or utcnow()) >= self.expires_at


# ---------------------------------------------------------------- execution
class Execution(BaseModel):
    execution_id: str = Field(default_factory=new_id)
    action_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    tier: ExecutorTier = ExecutorTier.MOCK  # kind reserved until its tier lands
    state_diff: dict[str, Any] = {}
    logs: list[str] = []
    idempotency_key: str = Field(min_length=1)


class VerificationResult(BaseModel):
    execution_id: str = Field(min_length=1)
    verdict: Verdict
    checks: dict[str, bool] = {}
    detail: str = ""


class Rollback(BaseModel):
    execution_id: str = Field(min_length=1)
    rollback_action: dict[str, Any]
    conditions: list[str] = []
    verification: list[str] = []
    attempted: bool = False
    succeeded: Optional[bool] = None


# ---------------------------------------------------------------- RCA / audit
class RCA(BaseModel):
    incident_id: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    timeline: list[dict[str, Any]] = []
    root_cause: str = Field(min_length=1)
    impact: dict[str, Any] = {}
    remediation_log: list[dict[str, Any]] = []
    prevention: list[str] = []
    claims: list[Claim] = []
    audit_ref: str = ""


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=new_id)
    seq: int = Field(ge=0)
    ts: datetime = Field(default_factory=utcnow)
    incident_id: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    agent: str = ""
    event_type: str = Field(min_length=1)
    input_hash: str = ""
    evidence_ids: list[str] = []
    policy: dict[str, Any] = {}
    action_id: str = ""
    approval_id: str = ""
    execution_id: str = ""
    result: str = ""
    prev_hash: str = ""
    curr_hash: str = ""

    @staticmethod
    def compute_hash(prev_hash: str, canonical_event: str) -> str:
        return sha256_hex(prev_hash + canonical_event)


# ---------------------------------------------------------------- evaluation
class EvaluationRun(BaseModel):
    run_id: str = Field(default_factory=new_id)
    suite: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    passed: bool = False
    scores: dict[str, float] = {}
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    llm_calls: int = Field(default=0, ge=0)
    latency_ms: dict[str, float] = {}


class BenchmarkResult(BaseModel):
    case_id: str = Field(min_length=1)
    scenario: str = Field(min_length=1)
    variant: str = Field(min_length=1)
    expected_cause: str = Field(min_length=1)
    predicted_cause: str = ""
    unsafe_executions: int = Field(default=0, ge=0)
    citation_coverage: float = Field(default=0, ge=0, le=1)
    passed: bool = False
