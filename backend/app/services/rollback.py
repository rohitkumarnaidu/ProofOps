"""Rollback controller (M10). At most ONE automatic attempt.

rollback_for() builds the inverse Action from the before-snapshot.
should_rollback() maps verdicts to the single-attempt rule.
RED destructive actions have NO autonomous rollback path by design:
rollback_for() refuses them (fail closed) instead of inventing one.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts.action import Action  # noqa: E402 (M01.7 canonical)
from app.contracts.enums import ActionType, Verdict  # noqa: E402 (M01.1 vocab)
from app.contracts.incident import FrozenDict  # noqa: E402 (frozen mapping)

MAX_AUTO_ROLLBACKS = 1
ROLLBACK_ON = frozenset({Verdict.FAILED, Verdict.WORSENED,
                         Verdict.ROLLBACK_REQUIRED})

# Reversible YELLOW types with defined inverses (mirrors risk_matrix.yaml).
REVERSIBLE = frozenset({ActionType.RESTART_POD, ActionType.SCALE_DEPLOYMENT,
                        ActionType.ROLLING_RESTART,
                        ActionType.ROLLBACK_DEPLOYMENT, ActionType.PATCH_CONFIG})


def should_rollback(verdict: str | Verdict, attempts: int) -> bool:
    return verdict in ROLLBACK_ON and attempts < MAX_AUTO_ROLLBACKS


def rollback_for(action: Action, before: dict[str, Any]) -> Action:
    """Inverse action restoring the before-snapshot for reversible types."""
    if action.action_type not in REVERSIBLE:
        raise ValueError(
            f"no autonomous rollback path for {action.action_type}: "
            "irreversible actions escalate, never auto-invert")
    inverse: dict[str, Any] = {}
    if action.action_type == ActionType.SCALE_DEPLOYMENT:
        inverse = {"replicas": int(before.get("replicas", 3))}
        rtype = ActionType.SCALE_DEPLOYMENT
    elif action.action_type == ActionType.ROLLBACK_DEPLOYMENT:
        inverse = {"to_version": str(before.get("deployment_version", "v22"))}
        rtype = ActionType.ROLLBACK_DEPLOYMENT
    elif action.action_type == ActionType.PATCH_CONFIG:
        inverse = {"config_rev": str(before.get("config_rev", "c1"))}
        rtype = ActionType.PATCH_CONFIG
    else:
        rtype = action.action_type  # restart/rolling_restart: re-issue is safe
        inverse = dict(action.parameters.to_plain())
    return Action(
        incident_id=action.incident_id, agent_id="rollback-controller",
        action_type=rtype, resource_type=action.resource_type,
        resource_id=action.resource_id, environment=action.environment,
        namespace=action.namespace, parameters=FrozenDict(inverse),
        reason=f"auto-rollback of {action.action_id}",
        evidence_ids=tuple(action.evidence_ids),
        runbook_id=action.runbook_id, runbook_version=action.runbook_version,
        expected_outcome="restore pre-action state",
        verification_plan=tuple(action.verification_plan))
