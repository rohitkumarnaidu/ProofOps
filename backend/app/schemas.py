"""ProofOps shared contracts (V2 §16, §21, §25, §27, §32).

Single source of truth for every component (agents, backend, policy,
executor, frontend, evaluation). No component invents its own shape.
Runtime authorization (GREEN/YELLOW/RED, HITL, sandbox) lives in services,
NOT here — schemas only guarantee structure. The LLM-proposed `risk_level`
on Action is ADVISORY; the policy engine recomputes it.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

Severity = Literal["P1", "P2", "P3", "P4"]
Environment = Literal["dev", "staging", "prod", "mock"]
RiskLevel = Literal["GREEN", "YELLOW", "RED"]
Decision = Literal["ALLOW", "ESCALATE", "DENY"]
Verdict = Literal["RESOLVED", "PARTIAL", "FAILED", "WORSENED", "ROLLBACK_REQUIRED", "ESCALATE"]
HypothesisStatus = Literal["SUPPORTED", "REJECTED", "UNCERTAIN", "INSUFFICIENT_EVIDENCE"]
TrustLevel = Literal["high", "med", "low"]
ClaimClass = Literal["MUST-CITE", "SHOULD-CITE", "OPTIONAL"]

ACTION_TYPES = (
    "read", "describe", "logs", "metrics", "list",
    "restart_pod", "scale_deployment", "rolling_restart", "rollback_deployment",
    "patch_config", "delete_pod", "delete_deployment", "delete_namespace",
    "rbac_change", "secret_access", "db_write", "reboot_node", "shell",
)
ActionType = Literal[  # type: ignore[valid-type]
    "read", "describe", "logs", "metrics", "list",
    "restart_pod", "scale_deployment", "rolling_restart", "rollback_deployment",
    "patch_config", "delete_pod", "delete_deployment", "delete_namespace",
    "rbac_change", "secret_access", "db_write", "reboot_node", "shell",
]

FSM_STATES = (
    "NEW", "TRIAGING", "CORRELATED", "INVESTIGATING", "DIAGNOSING", "PLANNED",
    "POLICY_CHECK", "BLOCKED", "AWAITING_APPROVAL", "APPROVED", "EXECUTING",
    "VERIFYING", "RESOLVED", "ROLLBACK", "ESCALATED", "RCA_PENDING",
    "RCA_PUBLISHED", "AUDITED",
)

NAMESPACE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def params_hash(params: dict) -> str:
    """Scope binding: approval tokens commit to the EXACT parameter set."""
    return sha256_hex(canonical_json(params))


# ---------------------------------------------------------------- telemetry
class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: datetime = Field(default_factory=utcnow)
    service: str = Field(min_length=1)
    environment: Environment = "mock"
    severity_raw: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    labels: dict[str, Any] = {}
    hash: str = ""


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str = Field(min_length=1)
    severity: Severity
    status: str = "NEW"

    @field_validator("status")
    @classmethod
    def _known_state(cls, v: str) -> str:
        if v not in FSM_STATES:
            raise ValueError(f"unknown FSM state: {v}")
        return v


# ---------------------------------------------------------------- evidence
class Evidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = Field(min_length=1)
    source_type: Literal["log", "metric", "trace", "deploy", "topology", "runbook", "history"]
    source_id: str = Field(min_length=1)
    ts: datetime = Field(default_factory=utcnow)
    ref: str = Field(min_length=1)  # pointer to full blob (line range, row id, ...)
    hash: str = Field(min_length=1)
    freshness_s: float = Field(ge=0)
    relevance: float = Field(ge=0, le=1)
    trust: TrustLevel = "med"


class Claim(BaseModel):
    claim_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    text: str = Field(min_length=1)
    evidence_ids: list[str] = []
    claim_class: ClaimClass = "MUST-CITE"


class Hypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    text: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    supporting: list[str] = []
    contradicting: list[str] = []
    test_tool: str = ""
    test_result: str = ""
    status: HypothesisStatus = "UNCERTAIN"


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
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    action_type: ActionType
    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    environment: Environment = "mock"
    namespace: str = "default"
    parameters: dict[str, Any] = {}
    risk_level: RiskLevel = "GREEN"  # ADVISORY ONLY — policy recomputes
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
    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    params_hash: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    expires_at: datetime
    nonce: str = Field(min_length=8)


class ApprovalToken(BaseModel):
    token: str = Field(min_length=1)
    approval_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    params_hash: str = Field(min_length=1)
    expires_at: datetime

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        return (now or utcnow()) >= self.expires_at


# ---------------------------------------------------------------- execution
class Execution(BaseModel):
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    tier: Literal["mock", "docker", "kind"] = "mock"
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
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
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
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
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
