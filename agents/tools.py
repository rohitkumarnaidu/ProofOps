"""Tool specs + per-agent ACLs + provider registry (M13 ACL half).

Spec S19: READ tools are Lyzr-callable (FastAPI GET, shared demo auth,
timeout 5-15s, retry 1 when idempotent); MUTATION tools are server-side only
-- specified here for auditability but invoke() ALWAYS denies them, for every
agent, with no exception path. A3 "propose only" means returning a structured
Action in its output schema, never a tool call; A4's publish_rca is gated
server-side (M14/M15).

Read tools dispatch to registered providers; an ACL-permitted tool with no
provider raises ToolUnavailable (typed error, never hallucinated values).
Built-in provider: fetch_runbook via the M11 loader (real, pinned, hashed).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents import AGENTS  # noqa: E402 (M13 workforce map)
from agents.schemas import ToolDenied, ToolUnavailable  # noqa: E402
from app.services.runbooks import load_runbook  # noqa: E402 (M11 loader)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    scope: str
    risk: str
    timeout_s: int
    retry: int
    mutating: bool
    args: tuple[str, ...] = ()


def _read(name: str, scope: str, args: tuple[str, ...],
          timeout_s: int = 10) -> ToolSpec:
    return ToolSpec(name=name, scope=scope, risk="green",
                    timeout_s=timeout_s, retry=1, mutating=False, args=args)


READ_SPECS: dict[str, ToolSpec] = {
    spec.name: spec for spec in (
        _read("fetch_alerts", "alerts by incident", ("incident_id",)),
        _read("get_logs", "service logs window", ("service", "window", "limit")),
        _read("query_metrics", "service metric deltas", ("service", "window")),
        _read("get_traces", "trace exemplars", ("trace_id",)),
        _read("get_deployments", "deploy history", ("service",)),
        _read("fetch_runbook", "pinned runbook", ("runbook_id",)),
        _read("get_topology", "service neighbors", ("service",)),
    )
}

MUTATING_SPECS: dict[str, ToolSpec] = {
    spec.name: spec for spec in (
        ToolSpec("propose_action", "structured Action proposal", "yellow",
                 5, 0, True, ("action",)),
        ToolSpec("execute_action", "sandboxed execution", "yellow/red",
                 60, 0, True, ("action_id", "approval_token")),
        ToolSpec("verify_slo", "independent verification", "green",
                 25, 0, True, ("execution_id",)),
        ToolSpec("rollback", "governed rollback", "yellow",
                 60, 0, True, ("execution_id",)),
        ToolSpec("publish_rca", "gated RCA publish", "green",
                 5, 0, True, ("incident_id",)),
    )
}

_ALL_READS = frozenset(READ_SPECS)

#: Distinct tool ACLs per agent (asserted by contract tests, spec S19).
ACL: dict[str, frozenset[str]] = {
    # A1: reads minus topology (no diagnosis ownership, no mutation).
    "triage": _ALL_READS - {"get_topology"},
    # A2: full reads (topology needed for dependency hypotheses).
    "diagnostic": _ALL_READS,
    # A3: output-only (structured Action); tools would be shell-adjacent.
    "planner": frozenset(),
    # A4: reads for timeline/remediation assembly; publish is server-side.
    "reporter": _ALL_READS,
}

Provider = Callable[[dict[str, Any]], Any]
_PROVIDERS: dict[str, Provider] = {}


def _check_agent(agent: str) -> str:
    if agent not in AGENTS:
        raise ToolDenied(f"unknown agent: {agent!r}")
    return agent


def spec_of(tool: str) -> ToolSpec:
    """Spec lookup (reads + mutating); unknown names denied, never guessed."""
    if tool in READ_SPECS:
        return READ_SPECS[tool]
    if tool in MUTATING_SPECS:
        return MUTATING_SPECS[tool]
    raise ToolDenied(f"unknown tool: {tool!r}")


def check_acl(agent: str, tool: str) -> ToolSpec:
    """Fail-closed authorization for one tool call (M13 ACL)."""
    _check_agent(agent)
    spec = spec_of(tool)
    if spec.mutating:
        raise ToolDenied(f"tool {tool!r} is server-side-only")
    if tool not in ACL[agent]:
        raise ToolDenied(f"agent {agent!r} may not call {tool!r}")
    return spec


def register_provider(tool: str, fn: Provider) -> None:
    """Control-plane hook: bind a read-tool implementation (M14 owns calls)."""
    spec = spec_of(tool)
    if spec.mutating:
        raise ToolDenied(f"cannot register server-side tool {tool!r}")
    _PROVIDERS[tool] = fn


def clear_providers() -> None:
    _PROVIDERS.clear()
    _PROVIDERS["fetch_runbook"] = _fetch_runbook_provider


def _check_args(spec: ToolSpec, args: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(args, Mapping):
        raise ToolDenied("tool args must be a mapping")
    args = dict(args)
    unknown = set(args) - set(spec.args)
    if unknown:
        raise ToolDenied(f"unknown args for {spec.name}: {sorted(unknown)}")
    missing = set(spec.args) - set(args)
    if missing:
        raise ToolDenied(f"missing args for {spec.name}: {sorted(missing)}")
    if spec.name == "get_logs":
        limit = args.get("limit", 100)
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ToolDenied("get_logs limit must be an int")
        if not 1 <= limit <= 500:
            raise ToolDenied("get_logs limit must be within 1..500")
    return args


def invoke(agent: str, tool: str, args: Mapping[str, Any]) -> Any:
    """ACL-checked, provider-backed tool call (reads only, M13)."""
    spec = check_acl(agent, tool)
    checked = _check_args(spec, args)
    provider = _PROVIDERS.get(tool)
    if provider is None:
        raise ToolUnavailable(
            f"no provider registered for {tool!r} (not hallucinated)")
    return provider(checked)


def _fetch_runbook_provider(args: dict[str, Any]) -> dict[str, Any]:
    """Built-in read provider: pinned, hash-verified runbook (M11)."""
    runbook_id = args["runbook_id"]
    if not isinstance(runbook_id, str) or not runbook_id.strip():
        raise ToolDenied("runbook_id must be a non-empty string")
    return load_runbook(runbook_id).model_dump()


clear_providers()
