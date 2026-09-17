"""Canonical Action validator (V2 §16, Rules 02/03/11).

Structural gate BEFORE policy: shapes, ranges, runbook pinning, evidence
presence, rollback presence, shell/metacharacter rejection. Returns a list
of error strings; empty == valid. Never raises on bad input (fail-closed
callers treat any exception as rejection too).
"""
from __future__ import annotations

import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts.action import Action  # noqa: E402 (M01.7 canonical)
from app.contracts.runbook import Runbook  # noqa: E402 (M01.6 canonical)

SHELL_META = re.compile(r"[;&|`$()\\<>\r\n\t]")
IMAGE_TAG = re.compile(r"^[a-z0-9._-]{1,128}$")
# Destructive statement openers only (M06 90+ pass): bare UPDATE/INSERT are
# ordinary words in parameter text ("update config", "insert key") and must
# NOT match — only the destructive shapes (with SET/INTO) are rejected.
DESTRUCTIVE_SQL = re.compile(
    r"\b(DROP|DELETE\s+FROM|TRUNCATE|UPDATE\s+\S+\s+SET|INSERT\s+INTO)\b",
    re.IGNORECASE)

READ_TYPES = {"read", "describe", "logs", "metrics", "list"}


def _scan_param_values(node: Any, errs: list[str], path: str = "") -> None:
    """Recursive metachar/SQL scan over parameter VALUES (M06 90+ pass).

    The old top-level-only loop missed nested payloads ({"cfg": {"cmd":
    "a;evil"}}). Iterative (no recursion-limit risk): mappings recurse into
    values, lists/tuples into items, strings get both pattern checks with
    dotted paths ("cfg.cmd") for auditability. Non-string scalars (int,
    float, bool, None) cannot carry shell/SQL and are skipped.
    """
    stack: list[tuple[Any, str]] = [(node, path)]
    while stack:
        value, at = stack.pop()
        if isinstance(value, str):
            where = f"parameter {at!r}" if at else "parameter value"
            if SHELL_META.search(value):
                errs.append(f"{where} contains shell metacharacters")
            if DESTRUCTIVE_SQL.search(value):
                errs.append(f"{where} contains destructive SQL")
        elif isinstance(value, Mapping):
            for k, v in value.items():
                stack.append((v, f"{at}.{k}" if at else str(k)))
        elif isinstance(value, (list, tuple)):
            for i, v in enumerate(value):
                stack.append((v, f"{at}[{i}]"))


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
    _scan_param_values(p, errs)

    # 5. reversible YELLOW must carry rollback
    reversible = {"restart_pod", "scale_deployment", "rolling_restart",
                  "rollback_deployment", "patch_config"}
    if action.action_type in reversible and not action.rollback_action:
        errs.append(f"{action.action_type} requires rollback_action")
    return errs
