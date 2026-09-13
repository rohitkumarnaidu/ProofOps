"""M01.1 shared domain primitives (canonical str-Enums).

Single definition point for every domain vocabulary in ProofOps. M01.2+ and
M02 import from here (via ``app.contracts``) — never redeclare.

Boundaries (locked M01.1 decisions):
- M00 operational enums (``config.AppEnv/Executor/LogLevel/SeedVariant``)
  stay in M00.2-frozen ``app.config``: they describe HOW the process runs.
  These describe WHAT the domain talks about. Do not merge them.
- Domain ``Environment`` (dev/staging/prod/mock: WHERE the workload lives)
  is a different axis from ``AppEnv`` (development/test/demo/production:
  HOW this process runs). Documented, not merged.
- ``ExecutorTier`` is mock|docker only. ``kind`` is RESERVED (absent by
  design) until its tier lands — mirrors the M00.2 production rule.
- ``EvidenceType`` is an alias of ``SourceType``: the kind-vs-source
  distinction is reserved for M05; one definition, two names, zero drift.
"""
from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """str-valued Enum: serializes as its value, compares equal to it."""

    def __str__(self) -> str:
        return self.value


class Severity(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Environment(StrEnum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"
    MOCK = "mock"


class RiskLevel(StrEnum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    ESCALATE = "ESCALATE"
    DENY = "DENY"


class Verdict(StrEnum):
    RESOLVED = "RESOLVED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    WORSENED = "WORSENED"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    ESCALATE = "ESCALATE"


class HypothesisStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    REJECTED = "REJECTED"
    UNCERTAIN = "UNCERTAIN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class TrustLevel(StrEnum):
    HIGH = "high"
    MED = "med"
    LOW = "low"


class ClaimClass(StrEnum):
    MUST_CITE = "MUST-CITE"
    SHOULD_CITE = "SHOULD-CITE"
    OPTIONAL = "OPTIONAL"


# Allowlist source for ActionType. The class below must match this tuple
# exactly (asserted both directions in tests/test_contracts_m01_1.py), so the
# allowlist and the Enum can never drift.
ACTION_TYPES: tuple[str, ...] = (
    "read", "describe", "logs", "metrics", "list",
    "restart_pod", "scale_deployment", "rolling_restart", "rollback_deployment",
    "patch_config", "delete_pod", "delete_deployment", "delete_namespace",
    "rbac_change", "secret_access", "db_write", "reboot_node", "shell",
)


class ActionType(StrEnum):
    READ = "read"
    DESCRIBE = "describe"
    LOGS = "logs"
    METRICS = "metrics"
    LIST = "list"
    RESTART_POD = "restart_pod"
    SCALE_DEPLOYMENT = "scale_deployment"
    ROLLING_RESTART = "rolling_restart"
    ROLLBACK_DEPLOYMENT = "rollback_deployment"
    PATCH_CONFIG = "patch_config"
    DELETE_POD = "delete_pod"
    DELETE_DEPLOYMENT = "delete_deployment"
    DELETE_NAMESPACE = "delete_namespace"
    RBAC_CHANGE = "rbac_change"
    SECRET_ACCESS = "secret_access"
    DB_WRITE = "db_write"
    REBOOT_NODE = "reboot_node"
    SHELL = "shell"


# Canonical FSM states (spec §93 lineage). IncidentStatus must match this
# tuple exactly (asserted both directions in tests); same no-drift rule.
FSM_STATES: tuple[str, ...] = (
    "NEW", "TRIAGING", "CORRELATED", "INVESTIGATING", "DIAGNOSING", "PLANNED",
    "POLICY_CHECK", "BLOCKED", "AWAITING_APPROVAL", "APPROVED", "EXECUTING",
    "VERIFYING", "RESOLVED", "ROLLBACK", "ESCALATED", "RCA_PENDING",
    "RCA_PUBLISHED", "AUDITED",
)


class IncidentStatus(StrEnum):
    NEW = "NEW"
    TRIAGING = "TRIAGING"
    CORRELATED = "CORRELATED"
    INVESTIGATING = "INVESTIGATING"
    DIAGNOSING = "DIAGNOSING"
    PLANNED = "PLANNED"
    POLICY_CHECK = "POLICY_CHECK"
    BLOCKED = "BLOCKED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    ROLLBACK = "ROLLBACK"
    ESCALATED = "ESCALATED"
    RCA_PENDING = "RCA_PENDING"
    RCA_PUBLISHED = "RCA_PUBLISHED"
    AUDITED = "AUDITED"


class SourceType(StrEnum):
    """Where a piece of evidence/telemetry came from (spec §135 lineage)."""

    LOG = "log"
    METRIC = "metric"
    TRACE = "trace"
    DEPLOY = "deploy"
    TOPOLOGY = "topology"
    RUNBOOK = "runbook"
    HISTORY = "history"


# Alias, not a second definition: kind-vs-source split reserved for M05.
EvidenceType = SourceType


class ActorType(StrEnum):
    """Who performed an audited act. Minimal M01.1 vocabulary."""

    HUMAN = "human"
    AGENT = "agent"
    SYSTEM = "system"
    POLICY = "policy"


class ApprovalStatus(StrEnum):
    """Approval lifecycle (M07 owns transitions; this owns vocabulary)."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class ExecutionStatus(StrEnum):
    """Execution lifecycle (M08/M10 own transitions).

    CACHED marks an idempotent replay served without re-executing
    (spec: duplicates return cached + ``duplicate-suppressed`` audit).
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CACHED = "CACHED"


class ConfidenceLevel(StrEnum):
    """Bucket for 0..1 confidences. Mapping is an M01.1 decision (see
    values.confidence_bucket); change only via contract change request."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FailureCode(StrEnum):
    """Machine-readable failure reason for executions/verifications."""

    NONE = "none"
    TIMEOUT = "timeout"
    POLICY_DENIED = "policy_denied"
    APPROVAL_EXPIRED = "approval_expired"
    PRECONDITION_FAILED = "precondition_failed"
    EXECUTOR_ERROR = "executor_error"
    VERIFICATION_FAILED = "verification_failed"
    UNKNOWN = "unknown"


class ExecutorTier(StrEnum):
    """Execution tier. ``kind`` deliberately absent (reserved)."""

    MOCK = "mock"
    DOCKER = "docker"
