"""Rollback controller (V2 §30). At most ONE automatic attempt.

rollback_for() builds the inverse Action from the before-snapshot.
should_rollback() maps verdicts to the single-attempt rule.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.schemas import Action, VerificationResult  # noqa: E402

MAX_AUTO_ROLLBACKS = 1
ROLLBACK_ON = {"FAILED", "WORSENED", "ROLLBACK_REQUIRED"}


def should_rollback(verdict: str, attempts: int) -> bool:
    return verdict in ROLLBACK_ON and attempts < MAX_AUTO_ROLLBACKS


def rollback_for(action: Action, before: dict[str, Any]) -> Action:
    """Inverse action restoring the before-snapshot for reversible types."""
    inverse: dict[str, Any] = {}
    if action.action_type == "scale_deployment":
        inverse = {"replicas": int(before.get("replicas", 3))}
        rtype = "scale_deployment"
    elif action.action_type == "rollback_deployment":
        inverse = {"to_version": str(before.get("deployment_version", "v22"))}
        rtype = "rollback_deployment"
    elif action.action_type == "patch_config":
        inverse = {"config_rev": str(before.get("config_rev", "c1"))}
        rtype = "patch_config"
    else:
        rtype = action.action_type  # restart/rolling_restart: re-issue is safe-ish
        inverse = dict(action.parameters)
    return Action(
        incident_id=action.incident_id, agent_id="rollback-controller",
        action_type=rtype, resource_type=action.resource_type,  # type: ignore[arg-type]
        resource_id=action.resource_id, environment=action.environment,
        namespace=action.namespace, parameters=inverse,
        reason=f"auto-rollback of {action.action_id}",
        evidence_ids=list(action.evidence_ids),
        runbook_id=action.runbook_id, runbook_version=action.runbook_version,
        expected_outcome="restore pre-action state",
        verification_plan=list(action.verification_plan))
