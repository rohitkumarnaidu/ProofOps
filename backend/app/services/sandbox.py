"""Stateful mock sandbox executor (M08). Tier: mock (default).

Realistic state transitions per action; reads produce zero diff. RED/denied
actions NEVER reach apply() - the FSM/executor gate enforces
validator+policy+HITL first; apply() asserts the action is allowlisted.
Docker/Kind tiers later reuse the same Action schema.

Docker tier honesty (M08.5/M08.6): without a reachable daemon this module
REFUSES docker execution (RuntimeError) instead of faking success. The
allowlist (DOCKERABLE) and the required daemon constraints
(DOCKER_CONSTRAINTS) are defined and tested, but no success is ever
simulated: a fake docker success would be a falsified capability (STOP).
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts import ExecutorTier  # noqa: E402 (M01.1 frozen enums)
from app.contracts.action import Action  # noqa: E402 (M01.7 canonical)
from app.contracts.execution import Execution  # noqa: E402 (M01.10 canonical)
from app.contracts.incident import FrozenDict  # noqa: E402 (frozen mapping)

READ_TYPES = {"read", "describe", "logs", "metrics", "list"}
MOCKABLE = READ_TYPES | {"restart_pod", "scale_deployment", "rolling_restart",
                         "rollback_deployment", "patch_config"}
# Docker tier reuses the same typed transitions (no shell path on any tier).
DOCKERABLE = set(MOCKABLE)

# Required daemon constraints for the docker tier (M08.6). Declared here so
# the future docker executor and its tests share one source; NOT enforced
# here because this module never touches a daemon.
DOCKER_CONSTRAINTS = {
    "unprivileged": True,
    "no_secret_mounts": True,
    "network_isolated": True,
    "timeout_s": 60,
}


def initial_state(service: str = "web", version: str = "v23",
                  error_rate: float = 0.18) -> dict[str, Any]:
    return {"service": service, "deployment_version": version,
            "replicas": 3, "error_rate": error_rate, "pods_ready": True,
            "restarts": 0, "config_rev": "c1"}


def apply(action: Action, state: dict[str, Any]) -> tuple[Execution, dict]:
    """Apply an AUTHORIZED action. Returns (execution, new_state)."""
    if action.action_type not in MOCKABLE:
        raise ValueError(f"not executable in mock tier: {action.action_type}")
    before = copy.deepcopy(state)
    after = copy.deepcopy(state)
    logs = [f"mock-exec {action.action_type} {action.resource_id}"]
    p = action.parameters

    if action.action_type == "rollback_deployment":
        after["deployment_version"] = str(p.get("to_version", "v22"))
        after["error_rate"] = 0.008
        logs.append(f"rolled back to {after['deployment_version']}")
    elif action.action_type == "restart_pod":
        after["restarts"] = int(state.get("restarts", 0)) + 1
        after["pods_ready"] = True
    elif action.action_type == "scale_deployment":
        after["replicas"] = int(p.get("replicas", state.get("replicas", 3)))
    elif action.action_type == "rolling_restart":
        after["restarts"] = int(state.get("restarts", 0)) + 1
        after["error_rate"] = round(float(state.get("error_rate", 0)) * 0.5, 4)
    elif action.action_type == "patch_config":
        after["config_rev"] = "c2"
    # reads: no mutation

    diff = {k: {"before": before.get(k), "after": after.get(k)}
            for k in after if before.get(k) != after.get(k)}
    exe = Execution(action_id=action.action_id, incident_id=action.incident_id,
                    tier=ExecutorTier.MOCK, state_diff=FrozenDict({"before": before,
                                              "after": after,
                                              "changed": diff}),
                    logs=tuple(logs), idempotency_key=action.action_id)
    return exe, after


def apply_docker(action: Action, state: dict[str, Any]) -> tuple[Execution, dict]:
    """Docker tier (M08.5): REFUSES without a reachable, constrained daemon.

    This build has no daemon client: pretending success would falsify
    execution evidence. Callers must catch RuntimeError and fall back to
    the mock tier explicitly (tier-labelled, never silent).
    """
    raise RuntimeError(
        "docker tier unavailable: no reachable daemon in this build; "
        "re-run on the mock tier (DOCKER_CONSTRAINTS documents the "
        "required daemon shape)")
