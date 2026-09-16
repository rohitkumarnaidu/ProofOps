"""A4 RCA Reporter: verified record -> blameless RCA draft + gate flag (M13.5).

Runs after verification. Assembles timeline, verified root cause,
remediation/approval/verification record, claim->evidence map, and blameless
prevention notes. Publishes NOTHING: the MUST-CITE gate is evaluated here
(via M05.6) and a below-coverage draft returns gated=True with a reason --
the publisher (M14/M15) enforces. Personal-blame terms fail the lint and
reject the draft (fail-closed, never softened).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents import rai  # noqa: E402 (M13.8 guards)
from agents import session as session_mod  # noqa: E402 (M13.7 sessions)
from agents.memory import GLOBAL_CONTEXT  # noqa: E402 (M13.10 context)
from agents.schemas import (  # noqa: E402 (M13.6 envelopes)
    OutputRejected,
    RCAReport,
)
from app.contracts.hypothesis import Claim  # noqa: E402 (M01.5 claims)
from app.services.evidence import must_cite_coverage  # noqa: E402 (M05.6 gate)

PROMPT_NAME = "reporter.md"
MAX_TIMELINE_ROW = 1024

#: Personal-blame vocabulary: any hit rejects the draft (blameless lint).
BLAME_TOKENS = ("blame", " at fault", "fault of", "incompetent", "negligent",
                "careless", "stupid", "idiot", "scapegoat")


def prompt_text() -> str:
    path = Path(__file__).resolve().parent / "prompts" / PROMPT_NAME
    return path.read_text(encoding="utf-8")


def lint_blameless(text: str) -> list[str]:
    """Case-insensitive blame-term scan over one prose field."""
    lowered = text.lower()
    return [token for token in BLAME_TOKENS if token in lowered]


def lint_report_fields(fields: Mapping[str, Any]) -> list[str]:
    """Scan every prose field; return 'field:token' hits."""
    hits: list[str] = []

    def _walk(name: str, value: Any) -> None:
        if isinstance(value, str):
            hits.extend(f"{name}:{token}" for token in lint_blameless(value))
        elif isinstance(value, (list, tuple)):
            for pos, item in enumerate(value):
                _walk(f"{name}[{pos}]", item)

    for field_name, field_value in fields.items():
        _walk(field_name, field_value)
    return hits


def _check_timeline(timeline: Sequence[Any]) -> list[str]:
    if not isinstance(timeline, (list, tuple)) or not timeline:
        raise OutputRejected("timeline must be a non-empty list")
    rows: list[str] = []
    for row in timeline:
        if not isinstance(row, str) or not row.strip():
            raise OutputRejected("timeline rows must be non-empty strings")
        if len(row) > MAX_TIMELINE_ROW:
            raise OutputRejected("timeline row exceeds 1024 chars")
        rows.append(row)
    if len(rows) > 64:
        raise OutputRejected("timeline exceeds 64 rows")
    return rows


def _coverage(claims: Sequence[Claim],
              valid_evidence_ids: set[str] | frozenset[str]) -> float:
    for claim in claims:
        if not isinstance(claim, Claim):
            raise OutputRejected("claims must be Claim contracts")
    return must_cite_coverage(list(claims), valid_evidence_ids)


def run_report(incident_id: str, timeline: Sequence[Any], root_cause: str,
               claims: Sequence[Claim], valid_evidence_ids: set[str],
               remediation_log: Sequence[str], prevention: Sequence[str],
               client: Any, store: session_mod.SessionStore) -> RCAReport:
    """A4 entry point: record -> linted, gated RCA draft (M13.5)."""
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise ValueError("incident_id must be a non-empty string")
    if not isinstance(root_cause, str) or not root_cause.strip():
        raise OutputRejected("root_cause must be a non-empty string")
    rows = _check_timeline(timeline)
    prose = {"root_cause": root_cause,
             "timeline": rows,
             "remediation_log": list(remediation_log),
             "prevention": list(prevention)}
    blame = lint_report_fields(prose)
    if blame:
        raise OutputRejected(f"blameless-lint violations: {blame}")
    coverage = _coverage(claims, valid_evidence_ids)
    claim_ids = [c.claim_id for c in claims]
    session = store.get_or_create(incident_id, "reporter")
    if coverage < 1.0:
        return RCAReport(
            incident_id=incident_id,
            summary=(f"GATED draft for {incident_id}: MUST-CITE coverage "
                     f"{coverage:.2f} below 1.0; publication denied."),
            timeline=rows, root_cause=root_cause, claim_ids=claim_ids,
            remediation_log=list(remediation_log),
            prevention=list(prevention), gated=True,
            gate_reason=(f"must-cite coverage {coverage:.2f} < 1.0 "
                         f"(rca-gate-failed)"))
    summary = f"RCA for {incident_id}: {root_cause[:120]}"
    if client.mode_for("reporter") == "CONNECTED":
        rendered = (prompt_text() + "\n\n## CURRENT INPUT (UNTRUSTED DATA)\n"
                    "```DATA\n" + json.dumps(
                        {"incident_id": incident_id, "timeline": rows,
                         "root_cause": root_cause,
                         "remediation_log": list(remediation_log),
                         "prevention": list(prevention)}, default=str) +
                    "\n```\nGlobal context: " + GLOBAL_CONTEXT)
        verdict, redacted, _ = rai.check_input("reporter", rendered)
        if verdict == "BLOCK":
            raise OutputRejected("reporter input blocked by RAI check")
        session.record_call()
        result = client.chat("reporter", incident_id, redacted)
        if result.mode == "CONNECTED" and result.payload is not None:
            candidate = result.payload.get("summary")
            if not isinstance(candidate, str) or not candidate.strip():
                raise OutputRejected("reporter summary must be non-empty")
            if len(candidate) > 4096:
                raise OutputRejected("reporter summary exceeds 4096 chars")
            blame = lint_blameless(candidate)
            if blame:
                raise OutputRejected(
                    f"blameless-lint violations in summary: {blame}")
            summary = candidate
    return RCAReport(incident_id=incident_id, summary=summary, timeline=rows,
                     root_cause=root_cause, claim_ids=claim_ids,
                     remediation_log=list(remediation_log),
                     prevention=list(prevention), gated=False, gate_reason="")
