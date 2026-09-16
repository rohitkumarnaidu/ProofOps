"""M13.8 RAI: per-agent guard attachment + local input/output checks.

Defense in depth ONLY (spec S04-G02): these scans run on every agent
interaction, but they never replace validator, policy, authorization,
sandbox, or verification. Input telemetry containing secrets is REDACTED
before it reaches any prompt (secrets never enter model context). Output
carrying secrets is BLOCKED. Instruction-like text in DATA is flagged, never
followed -- following is prevented structurally (agents have no exec tools).

Studio-side RAI (policy PS03-Governed) verdicts travel on ClientResult;
attach() records the local half of the attachment honestly as mode "local".
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents import AGENTS  # noqa: E402 (M13 workforce map)

RAI_POLICY = "PS03-Governed"

_SECRET_RES = (
    # Named credential assignments ("token" needs a separator so ordinary
    # prose like "tokens per incident" never matches).
    re.compile(r"(?i)\b(api[_-]?key|passwd|password|secret|token)\b"
               r"\s*[:=]\s*['\"]?\S+"),
    # Bearer tokens are unambiguous even space-separated.
    re.compile(r"\bbearer\s+\S+", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
)

_INSTRUCTION_RES = (
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"approve\s+and\s+execute", re.IGNORECASE),
    re.compile(r"delete\s+namespace\s+\S*\s*--force", re.IGNORECASE),
)

REDACTED = "[REDACTED]"
MAX_FINDING_CHARS = 200


# Guard verdicts as Literals (same no-enum-outside-contracts rationale as
# lyzr_client.Mode): constrained strings, no new Enum vocabulary.
Verdict = Literal["ALLOW", "REDACT", "BLOCK"]


@dataclass(frozen=True)
class Finding:
    kind: str  # "secret" | "instruction"
    detail: str


def _check_agent(agent: str) -> str:
    if agent not in AGENTS:
        raise ValueError(f"unknown agent: {agent!r}")
    return agent


def attach(agent: str, connected: bool = False) -> dict[str, Any]:
    """Per-agent RAI attachment record (M13.8): policy + honest mode."""
    _check_agent(agent)
    return {"agent": agent, "rai_policy": RAI_POLICY,
            "mode": "lyzr-studio" if connected else "local",
            "input_checks": ["secret-redact", "instruction-flag"],
            "output_checks": ["secret-block", "instruction-flag"]}


def _scan(text: str) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    redacted = text
    for pattern in _SECRET_RES:
        match = pattern.search(redacted)
        if match:
            findings.append(Finding(
                kind="secret",
                detail=f"secret-like span at {match.start()} (redacted)"))
            redacted = pattern.sub(REDACTED, redacted)
    for pattern in _INSTRUCTION_RES:
        match = pattern.search(redacted)
        if match:
            snippet = match.group(0)[:MAX_FINDING_CHARS]
            findings.append(Finding(
                kind="instruction",
                detail=f"instruction-in-data (quoted, not followed): {snippet}"))
    return findings, redacted


def check_input(agent: str, text: str) -> tuple[Verdict, str, list[Finding]]:
    """Guard model INPUT: secrets redacted, instructions flagged-as-data."""
    _check_agent(agent)
    if not isinstance(text, str):
        raise ValueError("text must be str")
    findings, redacted = _scan(text)
    if any(f.kind == "secret" for f in findings):
        return "REDACT", redacted, findings
    return "ALLOW", redacted, findings


def check_output(agent: str, text: str) -> tuple[Verdict, str, list[Finding]]:
    """Guard model OUTPUT: secret leaks blocked, instructions flagged."""
    _check_agent(agent)
    if not isinstance(text, str):
        raise ValueError("text must be str")
    findings, redacted = _scan(text)
    if any(f.kind == "secret" for f in findings):
        return "BLOCK", redacted, findings
    return "ALLOW", redacted, findings
