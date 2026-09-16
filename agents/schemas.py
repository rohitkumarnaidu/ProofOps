"""M13.6 structured I/O: agent-local Pydantic envelopes + strict parsing.

Canonical domain shapes (Alert/Incident/Evidence/Hypothesis/Claim/Action/
Runbook) are M01-owned and imported, never redeclared. This module owns the
thin RESULT envelopes each agent returns, the loop/possession budgets, and
parse_or_reject: every model response (live or mocked) is re-validated here
-- server-side code never trusts client JSON alone.

Bounds (AGENTS.md SS1.1/SS14.2, enforced): hypotheses <= 3, tools <= 5/agent
(tools.py), LLM calls <= 12/incident (session.py), re-plans <= 2.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Literal, Mapping

from pydantic import BaseModel, Field, field_validator, model_validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.contracts.action import Action  # noqa: E402 (M01.7 canonical)
from app.contracts.hypothesis import Hypothesis  # noqa: E402 (M01.5 canonical)

MAX_HYPOTHESES = 3
MAX_TOOLS_PER_AGENT = 5
MAX_LLM_CALLS_PER_INCIDENT = 12
MAX_REPLANS = 2
SESSION_WINDOW = 10
MEMORY_FACTS_CAP = 50
MAX_OUTPUT_BYTES = 65536

SEVERITIES = ("P1", "P2", "P3", "P4")


class AgentError(Exception):
    """Base for agent-platform failures (fail-closed, auditable)."""


class OutputRejected(AgentError, ValueError):
    """Model output failed schema re-validation: rejected, never trusted."""


class BudgetExceeded(AgentError):
    """Loop/call budget exhausted: stop, escalate, never loop unbounded."""


class ToolDenied(AgentError):
    """Tool call outside the agent's ACL or server-side-only: denied + audit."""


class ToolUnavailable(AgentError):
    """ACL-permitted tool with no registered provider: error, never invented."""


def _identifier(name: str, value: str, max_len: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def parse_or_reject(model_cls: type[BaseModel], payload: Any) -> BaseModel:
    """Re-validate one model response (M13.6): mapping + size + schema."""
    if not isinstance(payload, Mapping):
        raise OutputRejected(
            f"model output must be a mapping, got {type(payload).__name__}")
    try:
        size = len(json.dumps(payload, default=str).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise OutputRejected(f"model output not JSON-serializable: {exc}") from exc
    if size > MAX_OUTPUT_BYTES:
        raise OutputRejected(
            f"model output {size} bytes exceeds {MAX_OUTPUT_BYTES} cap")
    try:
        return model_cls.model_validate(dict(payload))
    except Exception as exc:
        raise OutputRejected(f"schema validation failed: {exc}") from exc


class TriageResult(BaseModel):
    """A1 output: severity proposal + fingerprint + owner hint (all advisory).

    Deterministic correlation (M04) owns grouping/severity truth; the control
    plane (M14) decides. The agent proposes, cites signals, never mutates.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    incident_id: str = Field(min_length=1, max_length=128)
    severity: Literal["P1", "P2", "P3", "P4"]
    fingerprint: str = Field(min_length=16, max_length=16)
    owner: str = Field(min_length=1, max_length=128)
    signals: list[str] = Field(default_factory=list, max_length=16)
    evidence_ids: list[str] = Field(default_factory=list, max_length=64)
    fallback: bool = False
    agent: Literal["triage"] = "triage"
    model_tier: Literal["small"] = "small"

    @field_validator("incident_id", "owner")
    @classmethod
    def _ids(cls, v: str, info: Any) -> str:
        return _identifier(str(info.field_name), v)

    @field_validator("fingerprint")
    @classmethod
    def _fp(cls, v: str) -> str:
        # Parity with M04 correlator.fingerprint (sha256 truncated to 16).
        # Spec S24 implies full sha256; the 64-vs-16 delta is flagged for
        # the M04 hardening owner -- agents must match pipeline truth.
        import re as _re
        if not _re.fullmatch(r"[0-9a-f]{16}", v):
            raise ValueError("fingerprint must be 16-char lowercase hex (M04)")
        return v


class DiagnosticResult(BaseModel):
    """A2 output: <=3 competing hypotheses + runbook pin, or INSUFFICIENT."""

    model_config = {"frozen": True, "extra": "forbid"}

    incident_id: str = Field(min_length=1, max_length=128)
    hypotheses: list[Hypothesis] = Field(max_length=MAX_HYPOTHESES)
    runbook_id: str = Field(default="", max_length=128)
    runbook_version: str = Field(default="", max_length=32)
    verdict: Literal["PINNED", "INSUFFICIENT_EVIDENCE"]
    single_cause_why: str = Field(default="", max_length=1024)
    fallback: bool = False
    agent: Literal["diagnostic"] = "diagnostic"
    model_tier: Literal["large"] = "large"

    @field_validator("incident_id")
    @classmethod
    def _iid(cls, v: str) -> str:
        return _identifier("incident_id", v)

    @model_validator(mode="after")
    def _pin_rules(self) -> DiagnosticResult:
        if self.verdict == "PINNED":
            if not self.runbook_id.strip():
                raise ValueError("PINNED requires a runbook_id")
            if len(self.hypotheses) < 2 and not self.single_cause_why.strip():
                raise ValueError(
                    "single-hypothesis pins must document why "
                    "(single_cause_why)")
        return self


class PlanResult(BaseModel):
    """A3 output: exactly one structured Action (data only, never executed)."""

    model_config = {"frozen": True, "extra": "forbid"}

    action: Action
    replans_used: int = Field(default=0, ge=0, le=MAX_REPLANS)
    agent: Literal["planner"] = "planner"
    model_tier: Literal["medium"] = "medium"


class RCAReport(BaseModel):
    """A4 output: factual RCA draft + publish-gate flag (M15 publishes)."""

    model_config = {"frozen": True, "extra": "forbid"}

    incident_id: str = Field(min_length=1, max_length=128)
    summary: str = Field(min_length=1, max_length=4096)
    timeline: list[str] = Field(max_length=64)
    root_cause: str = Field(min_length=1, max_length=4096)
    claim_ids: list[str] = Field(default_factory=list, max_length=64)
    remediation_log: list[str] = Field(default_factory=list, max_length=32)
    prevention: list[str] = Field(default_factory=list, max_length=32)
    gated: bool = False
    gate_reason: str = Field(default="", max_length=1024)
    agent: Literal["reporter"] = "reporter"
    model_tier: Literal["economical"] = "economical"

    @field_validator("incident_id")
    @classmethod
    def _iid(cls, v: str) -> str:
        return _identifier("incident_id", v)

    @model_validator(mode="after")
    def _gate_reason(self) -> RCAReport:
        if self.gated and not self.gate_reason.strip():
            raise ValueError("gated reports must state gate_reason")
        return self
