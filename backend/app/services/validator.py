"""Canonical Action validator (V2 §16, Rules 02/03/11).

Structural gate BEFORE policy: shapes, ranges, runbook pinning, evidence
presence, rollback presence, shell/metacharacter rejection. Returns a list
of error strings; empty == valid. Never raises on bad input (fail-closed
callers treat any exception as rejection too).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts.action import Action  # noqa: E402 (M01.7 canonical)
from app.contracts.runbook import Runbook  # noqa: E402 (M01.6 canonical)

SHELL_META = re.compile(r"[;&|`$()\\n]")
IMAGE_TAG = re.compile(r"^[a-z0-9._-]{1,128}$")
DESTRUCTIVE_SQL = re.compile(r"\b(DROP|DELETE\s+FROM|TRUNCATE)\b", re.IGNORECASE)

READ_TYPES = {"read", "describe", "logs", "metrics", "list"}


def validate_action(action: Action, runbook: Runbook | None = None) -> list[str]:
    errs: list[str] = []
    mutation = action.action_type not in READ_TYPES

    # 1. shell is never a valid LLM output (RULE 03)
    if action.action_type == "shell":
        errs.append("shell actions are never authorized")
        return errs  # nothing else matters

    # 2. runbook allowlist / pinning
    if runbook is not None:
        if action.action_type not in runbook.allowed_actions:
            errs.append(f"{action.action_type} not in runbook {runbook.runbook_id} allowed list")
        if action.action_type in runbook.forbidden_actions:
            errs.append(f"{action.action_type} forbidden by runbook {runbook.runbook_id}")
        if action.runbook_id != runbook.runbook_id or \
                action.runbook_version != runbook.version:
            errs.append("runbook id/version must pin the loaded runbook exactly")

    # 3. evidence + verification for mutations (RULE 11 groundwork)
    if mutation:
        if not action.evidence_ids:
            errs.append("mutations require at least one evidence_id")
        if not action.verification_plan:
            errs.append("mutations require a verification_plan")

    # 4. parameter shape guards
    p = action.parameters
    if "replicas" in p:
        r = p["replicas"]
        if not isinstance(r, int) or isinstance(r, bool) or not 1 <= r <= 10:
            errs.append("replicas must be an integer 1..10")
    if "image_tag" in p and not IMAGE_TAG.match(str(p["image_tag"])):
        errs.append("image_tag failed allowlist")
    for k, v in p.items():
        if isinstance(v, str):
            if SHELL_META.search(v):
                errs.append(f"parameter {k!r} contains shell metacharacters")
            if DESTRUCTIVE_SQL.search(v):
                errs.append(f"parameter {k!r} contains destructive SQL")

    # 5. reversible YELLOW must carry rollback
    reversible = {"restart_pod", "scale_deployment", "rolling_restart",
                  "rollback_deployment", "patch_config"}
    if action.action_type in reversible and not action.rollback_action:
        errs.append(f"{action.action_type} requires rollback_action")
    return errs
