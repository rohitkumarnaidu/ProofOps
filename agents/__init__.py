"""ProofOps Lyzr agent workforce (M13): reasoning agents on deterministic rails.

Exactly four agents (AGENTS.md SS3, frozen): A1 Triage, A2 Diagnostic,
A3 Remediation Planner, A4 RCA Reporter. LLMs reason; they never authorize,
execute, verify, or audit -- those stay CUSTOM-DETERMINISTIC (validator,
policy, HITL, sandbox, verifier, hash audit) owned by other modules.

Label honesty: the Lyzr client speaks the real Agent API wire shape
(scripts/verify_lyzr.py precedent). Without keys it reports DISABLED and
agents take marked deterministic fallbacks -- never faked as live Lyzr.
No module here reads environment secrets; keys arrive as explicit config.
"""
from __future__ import annotations

AGENTS = ("triage", "diagnostic", "planner", "reporter")

#: Model routing tiers (M20 owns optimization; tiers only route size class).
MODEL_TIERS = {
    "triage": "small",
    "diagnostic": "large",
    "planner": "medium",
    "reporter": "economical",
}
