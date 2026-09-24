"""Lane 2 observability (M20 metrics): counters, SLOs, SloAlert evaluation.

Ownership: THIS FILE (``backend/app/services/metrics.py``) plus
``policies/slo.yaml`` (versioned SLOs) plus the additive ``/metrics`` +
``/alerts`` routes and the ASGI middleware in ``backend/app/main.py``.

Stdlib only (no Prometheus client): exposition is hand-rendered text via
render_prometheus(). The registry is in-memory and thread-safe (one Lock);
reset() exists for tests.

Wiring note: HTTP route/code/latency is recorded by the tiny ASGI middleware
in main.py (the narrowest choke point that touches no other lane's files).
Every router-fed counter below (approvals / policy / LLM / tool / budget /
approval-latency) is FUTURE WORK owned by its lane: the increment functions
exist and are unit-tested, but no router calls them yet, so snapshot()
reports zeros and the affected SLO objectives evaluate ``ok`` with a
``no data`` note until wired. Documented, never faked.

Paging: evaluate_alerts() returns firing/ok states only. There is NO paging
infrastructure here -- routing a firing SloAlert to a human needs an external
webhook (PagerDuty/Opsgenie/etc.), which is future work. Do NOT build fake
paging in this module.
"""
from __future__ import annotations

import math
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

SLO_VERSION = "v1"
LATENCY_SAMPLES = 1024

_WINDOW_RE = re.compile(r"^[0-9]+[smhd]$")
_POLICY_DECISIONS = ("ALLOW", "ESCALATE", "DENY")
_COMPARE_OPS = ("gte", "lte", "is_true")
_OBJECTIVE_KINDS = ("availability", "latency", "readiness")


class MetricsError(Exception):
    """Malformed metrics/SLO input (fail-closed)."""


@dataclass
class SloAlert:
    """One SLO objective evaluated against a snapshot (firing/ok only)."""

    name: str
    state: str
    metric: str
    observed: float | bool | None
    target: float | None
    op: str
    window: str
    owner: str
    severity: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable view (served by GET /alerts)."""
        return {"name": self.name, "state": self.state,
                "metric": self.metric, "observed": self.observed,
                "target": self.target, "op": self.op,
                "window": self.window, "owner": self.owner,
                "severity": self.severity, "note": self.note}


@dataclass
class _Latency:
    n: int = 0
    total: float = 0.0
    samples: deque[float] = field(
        default_factory=lambda: deque(maxlen=LATENCY_SAMPLES))


_lock = threading.Lock()
_http: dict[tuple[str, str], int] = {}
_latency: dict[str, _Latency] = {}
_approval_latency = _Latency()
_approvals = {"issued": 0, "approved": 0, "denied": 0}
_policy = {"ALLOW": 0, "ESCALATE": 0, "DENY": 0}
_budget_exceeded = 0
_llm: dict[str, int] = {}
_tool: dict[str, int] = {}


def _check_latency(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(float(value)) or float(value) < 0:
        raise MetricsError(f"{name} must be a finite non-negative number")
    return float(value)


def _check_agent(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MetricsError(f"{name} must be a non-empty string")
    return value


def _percentile(samples: list[float], pct: float = 95.0) -> float | None:
    """Nearest-rank percentile over recent samples (None when empty)."""
    if not samples:
        return None
    ordered = sorted(samples)
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[rank - 1]


def observe_http(route: str, code: int, latency_s: float) -> None:
    """Record one served HTTP request (called by the main.py middleware)."""
    if not isinstance(route, str) or not route.strip():
        raise MetricsError("route must be a non-empty string")
    if isinstance(code, bool) or not isinstance(code, int) \
            or not 100 <= code <= 599:
        raise MetricsError("code must be an HTTP status int (100-599)")
    latency = _check_latency(latency_s, "latency_s")
    key = (route, str(code))
    with _lock:
        _http[key] = _http.get(key, 0) + 1
        bucket = _latency.get(route)
        if bucket is None:
            bucket = _Latency()
            _latency[route] = bucket
        bucket.n += 1
        bucket.total += latency
        bucket.samples.append(latency)


def approval_issued() -> None:
    """Count one approval request (FUTURE: wired by the approvals lane)."""
    with _lock:
        _approvals["issued"] += 1


def approval_approved() -> None:
    """Count one approval grant (FUTURE: wired by the approvals lane)."""
    with _lock:
        _approvals["approved"] += 1


def approval_denied() -> None:
    """Count one approval denial (FUTURE: wired by the approvals lane)."""
    with _lock:
        _approvals["denied"] += 1


def policy_decision(decision: str) -> None:
    """Count one policy verdict (FUTURE: wired by the policy lane)."""
    if decision not in _POLICY_DECISIONS:
        raise MetricsError(
            f"decision must be one of {list(_POLICY_DECISIONS)}")
    with _lock:
        _policy[decision] += 1


def budget_exceeded() -> None:
    """Count one budget breach (FUTURE: wired by the budgets lane)."""
    global _budget_exceeded
    with _lock:
        _budget_exceeded += 1


def llm_call(agent: str) -> None:
    """Count one LLM call for an agent (FUTURE: wired by the agents lane)."""
    name = _check_agent(agent, "agent")
    with _lock:
        _llm[name] = _llm.get(name, 0) + 1


def tool_call(agent: str) -> None:
    """Count one tool call for an agent (FUTURE: wired by the agents lane)."""
    name = _check_agent(agent, "agent")
    with _lock:
        _tool[name] = _tool.get(name, 0) + 1


def observe_approval_latency(latency_s: float) -> None:
    """Record one approval-decision latency (FUTURE: wired by approvals)."""
    latency = _check_latency(latency_s, "latency_s")
    with _lock:
        _approval_latency.n += 1
        _approval_latency.total += latency
        _approval_latency.samples.append(latency)


def reset() -> None:
    """Clear every counter (tests only; isolates cases)."""
    global _approval_latency, _budget_exceeded
    with _lock:
        _http.clear()
        _latency.clear()
        _approval_latency = _Latency()
        for key in _approvals:
            _approvals[key] = 0
        for key in _policy:
            _policy[key] = 0
        _budget_exceeded = 0
        _llm.clear()
        _tool.clear()


def snapshot() -> dict[str, Any]:
    """Point-in-time registry view (feeds evaluate_alerts + tests)."""
    with _lock:
        total = sum(_http.values())
        errors = sum(n for (_, code), n in _http.items()
                     if int(code) >= 500)
        merged: list[float] = []
        for bucket in _latency.values():
            merged.extend(bucket.samples)
        return {
            "http_requests_total": total,
            "http_errors_total": errors,
            "availability": (1.0 - errors / total) if total else None,
            "latency_count": sum(b.n for b in _latency.values()),
            "latency_sum": sum(b.total for b in _latency.values()),
            "latency_p95": _percentile(merged),
            "approval_latency_p95": _percentile(
                list(_approval_latency.samples)),
            "approvals_issued": _approvals["issued"],
            "approvals_approved": _approvals["approved"],
            "approvals_denied": _approvals["denied"],
            "policy": dict(_policy),
            "budget_exceeded": _budget_exceeded,
            "llm_calls": dict(_llm),
            "tool_calls": dict(_tool),
        }


def _esc(value: str) -> str:
    """Prometheus label escaping (backslash, newline, double-quote)."""
    return value.replace("\\", "\\\\").replace("\n", "\\n") \
        .replace('"', '\\"')


def render_prometheus() -> str:
    """Valid Prometheus exposition text over the current registry."""
    with _lock:
        http_items = sorted(_http.items())
        lat_items = sorted(_latency.items(),
                           key=lambda kv: kv[0])
        approvals = dict(_approvals)
        policy = dict(_policy)
        budget = _budget_exceeded
        llm = sorted(_llm.items())
        tool = sorted(_tool.items())
    lines = ["# HELP http_requests_total Total HTTP requests served.",
             "# TYPE http_requests_total counter"]
    for (route, code), count in http_items:
        lines.append(f'http_requests_total{{route="{_esc(route)}",'
                     f'code="{_esc(code)}"}} {count}')
    lines.append("# HELP http_request_latency_seconds "
                 "HTTP request latency in seconds.")
    lines.append("# TYPE http_request_latency_seconds summary")
    for route, bucket in lat_items:
        lines.append(f'http_request_latency_seconds_count{{route="'
                     f'{_esc(route)}"}} {bucket.n}')
        lines.append(f'http_request_latency_seconds_sum{{route="'
                     f'{_esc(route)}"}} {bucket.total!r}')
    lines.append("# HELP approvals_issued_total Approval requests issued.")
    lines.append("# TYPE approvals_issued_total counter")
    lines.append(f"approvals_issued_total {approvals['issued']}")
    lines.append("# HELP approvals_approved_total Approvals granted.")
    lines.append("# TYPE approvals_approved_total counter")
    lines.append(f"approvals_approved_total {approvals['approved']}")
    lines.append("# HELP approvals_denied_total Approvals denied.")
    lines.append("# TYPE approvals_denied_total counter")
    lines.append(f"approvals_denied_total {approvals['denied']}")
    lines.append("# HELP policy_decisions_total Policy verdicts by decision.")
    lines.append("# TYPE policy_decisions_total counter")
    for decision in _POLICY_DECISIONS:
        lines.append(f'policy_decisions_total{{decision="{decision}"}} '
                     f"{policy[decision]}")
    lines.append("# HELP budget_exceeded_total Budget breaches observed.")
    lines.append("# TYPE budget_exceeded_total counter")
    lines.append(f"budget_exceeded_total {budget}")
    lines.append("# HELP llm_calls_total LLM calls by agent.")
    lines.append("# TYPE llm_calls_total counter")
    for agent, count in llm:
        lines.append(f'llm_calls_total{{agent="{_esc(agent)}"}} {count}')
    lines.append("# HELP tool_calls_total Tool calls by agent.")
    lines.append("# TYPE tool_calls_total counter")
    for agent, count in tool:
        lines.append(f'tool_calls_total{{agent="{_esc(agent)}"}} {count}')
    return "\n".join(lines) + "\n"


def _check_window(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _WINDOW_RE.match(value):
        raise MetricsError(
            f"{name} must match <int>[smhd] (e.g. 30d, 1h, 5m)")
    return value


def _check_burn(entry: Any, objective: str) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise MetricsError(
            f"objective {objective!r}: burn entries must be mappings")
    severity = entry.get("severity")
    if not isinstance(severity, str) or not severity.strip():
        raise MetricsError(
            f"objective {objective!r}: burn severity must be non-empty")
    rate = entry.get("burn_rate")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) \
            or not math.isfinite(float(rate)) or float(rate) <= 0:
        raise MetricsError(
            f"objective {objective!r}: burn_rate must be a positive number")
    return {"severity": severity,
            "burn_rate": float(rate),
            "long_window": _check_window(entry.get("long_window"),
                                         f"{objective}.long_window"),
            "short_window": _check_window(entry.get("short_window"),
                                          f"{objective}.short_window")}


def _check_objective(entry: Any, seen: set[str]) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise MetricsError("slo objectives must be mappings")
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        raise MetricsError("slo objective name must be a non-empty string")
    if name in seen:
        raise MetricsError(f"duplicate slo objective {name!r}")
    seen.add(name)
    kind = entry.get("kind")
    if kind not in _OBJECTIVE_KINDS:
        raise MetricsError(
            f"objective {name!r}: kind must be one of "
            f"{list(_OBJECTIVE_KINDS)}")
    metric = entry.get("metric")
    if not isinstance(metric, str) or not metric.strip():
        raise MetricsError(
            f"objective {name!r}: metric must be a non-empty string")
    op = entry.get("op")
    if op not in _COMPARE_OPS:
        raise MetricsError(
            f"objective {name!r}: op must be one of {list(_COMPARE_OPS)}")
    target = entry.get("target")
    if op == "is_true":
        if target is not None:
            raise MetricsError(
                f"objective {name!r}: is_true takes no numeric target")
    else:
        if isinstance(target, bool) or not isinstance(target, (int, float)) \
                or not math.isfinite(float(target)):
            raise MetricsError(
                f"objective {name!r}: target must be a finite number")
        target = float(target)
    window = _check_window(entry.get("window"), f"{name}.window")
    owner = entry.get("owner")
    if not isinstance(owner, str) or not owner.strip():
        raise MetricsError(
            f"objective {name!r}: owner must be a non-empty string")
    burns = entry.get("burn_rate_alerts")
    if not isinstance(burns, list) or not burns:
        raise MetricsError(
            f"objective {name!r}: burn_rate_alerts must be a non-empty list")
    return {"name": name, "kind": kind, "metric": metric, "op": op,
            "target": target, "window": window, "owner": owner,
            "burn_rate_alerts": [_check_burn(b, name) for b in burns]}


def load_slo(path: str | Path | None = None) -> dict[str, Any]:
    """Load + validate the versioned SLO file (fail-closed)."""
    import yaml  # type: ignore[import-untyped]  # same missing-stubs cause
    # as budgets/runbooks/policy (types-PyYAML absent); narrow, justified:
    # the SLOs MUST stay editable YAML per scope, single reader is here.
    if path is None:
        path = Path(__file__).resolve().parents[3] / "policies" \
            / "slo.yaml"
    try:
        with open(path, encoding="utf-8") as handle:
            doc = yaml.safe_load(handle)
    except OSError as exc:
        raise MetricsError(f"slo file unreadable: {exc}") from exc
    except Exception as exc:
        raise MetricsError(f"slo file is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise MetricsError("slo file must be a mapping")
    if str(doc.get("version")) != SLO_VERSION:
        raise MetricsError(f"slo version must be {SLO_VERSION!r}")
    objectives = doc.get("objectives")
    if not isinstance(objectives, list) or not objectives:
        raise MetricsError("slo objectives must be a non-empty list")
    seen: set[str] = set()
    return {"version": str(doc.get("version")),
            "effective_from": doc.get("effective_from"),
            "objectives": [_check_objective(o, seen) for o in objectives]}


def _as_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(float(value)):
        raise MetricsError(
            f"snapshot[{name!r}] must be a finite number for comparison")
    return float(value)


def _as_optional_number(value: Any, name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(float(value)):
        raise MetricsError(
            f"slo objective {name!r}: target must be a finite number "
            f"or omitted")
    return float(value)


def _required_target(value: float | None, name: str) -> float:
    if value is None:
        raise MetricsError(
            f"slo objective {name!r}: target is required for comparison")
    return value


def _evaluate_one(snapshot: Mapping[str, Any], obj: Any) -> SloAlert:
    if not isinstance(obj, dict):
        raise MetricsError("slo objectives must be mappings")
    name = obj.get("name")
    metric = obj.get("metric")
    op = obj.get("op")
    if not isinstance(name, str) or not name \
            or not isinstance(metric, str) or not metric \
            or op not in _COMPARE_OPS:
        raise MetricsError("slo objective missing name/metric/valid op")
    window_raw = obj.get("window")
    window = window_raw if isinstance(window_raw, str) else ""
    owner_raw = obj.get("owner")
    owner = owner_raw if isinstance(owner_raw, str) else ""
    burns = obj.get("burn_rate_alerts")
    severity_top = "unknown"
    if isinstance(burns, list) and burns and isinstance(burns[0], dict) \
            and isinstance(burns[0].get("severity"), str):
        severity_top = str(burns[0].get("severity"))
    target = _as_optional_number(obj.get("target"), name)
    if op == "is_true" and target is not None:
        raise MetricsError(
            f"slo objective {name!r}: is_true takes no numeric target")
    if op != "is_true" and target is None:
        raise MetricsError(
            f"slo objective {name!r}: target is required for op {op!r}")
    observed = snapshot.get(metric)
    if observed is None:
        return SloAlert(name=name, state="ok", metric=metric, observed=None,
                     target=target, op=op, window=window, owner=owner,
                     severity="none",
                     note="no data (counter not yet wired)")
    if op == "is_true":
        firing = observed is not True
        watched: float | bool | None = bool(observed)
    elif op == "gte":
        watched = _as_number(observed, metric)
        firing = watched < _required_target(target, name)
    else:
        watched = _as_number(observed, metric)
        firing = watched > _required_target(target, name)
    if firing:
        return SloAlert(
            name=name, state="firing", metric=metric, observed=watched,
            target=target, op=op, window=window, owner=owner,
            severity=severity_top,
            note=f"target {op} {target}, observed {watched}")
    return SloAlert(name=name, state="ok", metric=metric, observed=watched,
                 target=target, op=op, window=window, owner=owner,
                 severity="none",
                 note=f"target {op} {target}, observed {watched}")


def evaluate_alerts(snapshot: Mapping[str, Any],
                    slo: Mapping[str, Any]) -> list[SloAlert]:
    """Pure SloAlert evaluation: each SLO objective -> firing or ok.

    No paging, no side effects, no I/O. A missing snapshot key means "no
    data yet" (ok + note), never firing: an unwired counter must not page.
    A malformed SLO fails closed with MetricsError.
    """
    if not isinstance(snapshot, Mapping):
        raise MetricsError("snapshot must be a mapping")
    if not isinstance(slo, Mapping):
        raise MetricsError("slo must be a mapping")
    objectives = slo.get("objectives")
    if not isinstance(objectives, list) or not objectives:
        raise MetricsError("slo objectives must be a non-empty list")
    return [_evaluate_one(snapshot, obj) for obj in objectives]
