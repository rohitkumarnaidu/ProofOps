"""Deterministic correlator (M04): alerts -> incidents.

Grouping, deduplication, and severity are CODE, never LLM. Fingerprint binds
service, error signature, environment, and deploy window so re-runs are
identical. The LLM may propose an owner; it is never the authority for
grouping or severity.

Severity is TWO levels (see ADR-014): this module owns TRIAGE severity
(env + error + signature class); signal severity lives on the Alert
(normalizer mapping). They answer different questions and may differ.

Cross-service merge is PAIRWISE (M04 90+ pass): topology is one service
context ``{"service": S, "depends_on": [...]}`` and a merge needs the exact
unordered pair {S, dep} — flat membership ("either side named anywhere")
merged unrelated groups and is gone. Time (<=10m) and signature similarity
(>0.7) still gate on top.

Metric gate reads the error_rate family ONLY (M04 90+ pass): the old max
over every metric value let an unrelated cpu_percent=95 page P1. Non-finite
and boolean readings are skipped (garbage in, no signal out — M03 rejects
them at ingest for the normalized path).

Storms never crash: groups beyond 100 alerts keep the first 100 ids with a
capped flag and the full count (an incident with 200 alerts must still
exist, not ValidationError the whole correlation).

Accepts canonical ``Alert`` records or raw dicts (raw dicts are normalized
strictly first - malformed records fail closed instead of forming phantom
groups). Emits canonical ``Incident`` records with populated linkage
(``source_alert_ids``, service, environment, detected_at, grouping metadata).
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts.alert import Alert  # noqa: E402
from app.contracts.enums import Severity  # noqa: E402
from app.contracts.incident import Incident  # noqa: E402
from app.contracts.values import sha256_hex  # noqa: E402
from app.services.normalizer import normalize_alert  # noqa: E402

FP_SIGNATURES = {"flapping_probe", "cpu_blip"}
DEPLOY_WINDOW_S = 900  # ±15m deploy window bound into the fingerprint
MERGE_WINDOW_S = 600  # cross-service merge horizon (dependency edge)
DEDUP_WINDOW_S = 5  # duplicate suppression horizon (spec: dedup <=5s)
MAX_STORED_IDS = 100  # Incident.source_alert_ids bound (M01.2); storms cap here
ERROR_RATE_METRIC = "error_rate"  # the canonical SLO metric family name


def fingerprint(service: str, signature: str, env: str, deploy_id: str) -> str:
    """Grouping fingerprint: sha256(service|sig|env|deploy) truncated to 16.

    16 lowercase hex chars = 64 bits: collision-negligible at alert volumes
    (birthday bound ~4 billion alerts per (service, sig, env, deploy) space),
    and the width is PINNED — agent fingerprints (A1 TriageResult) require
    exactly 16 hex chars. The deploy leg encodes the ±15m WINDOW (in-window
    deploy id, else "none"): alerts on opposite sides of a deploy land in
    different groups without any timestamp in the hash itself.
    """
    return sha256_hex(f"{service}|{signature}|{env}|{deploy_id}")[:16]


def _alert_signature(alert: Alert) -> str:
    """Grouping signature carried in metadata (normalizer guarantees it)."""
    sig = alert.metadata.get("signature", "")
    if not isinstance(sig, str) or not sig:
        raise ValueError(
            "alert carries no signature metadata; normalize first")
    return sig


def _alert_ts(alert: Alert) -> float:
    return alert.timestamp.timestamp()


def _deploy_in_window(deploys: list[dict], service: str, ts: float) -> str:
    for d in deploys:
        if not isinstance(d, Mapping):
            continue
        if isinstance(d.get("ts"), bool):
            continue
        try:
            dts = float(d.get("ts", 0) or 0)
        except (TypeError, ValueError):
            continue
        if d.get("service") == service and abs(dts - ts) <= DEPLOY_WINDOW_S:
            return str(d.get("deploy_id", "none"))
    return "none"


def _sig_sim(a: str, b: str) -> float:
    if not a or not b:
        return 0.0  # empty signatures never match (no spurious merges)
    ta, tb = set(a.split("_")), set(b.split("_"))
    return len(ta & tb) / max(len(ta | tb), 1)


def _topology_edges(topology: dict) -> set[frozenset]:
    """Pairwise dependency edges from one service context (M04 90+ pass).

    ``{"service": S, "depends_on": [...]}`` -> {{S, dep}, ...}. Malformed
    topology fails closed (the old flat-membership check silently applied
    substring semantics to strings and TypeError'd on non-lists).
    """
    if not isinstance(topology, Mapping):
        raise ValueError(
            f"topology must be an object, got {type(topology).__name__}")
    service = topology.get("service", "")
    deps = topology.get("depends_on", [])
    if service is None:
        service = ""
    if deps is None:
        deps = []
    if not isinstance(service, str):
        raise ValueError("topology service must be a string")
    if isinstance(deps, (str, bytes)) or not isinstance(deps, (list, tuple)):
        raise ValueError("topology depends_on must be a list of services")
    edges: set[frozenset] = set()
    if deps and not service:
        raise ValueError(
            "topology depends_on without a service is uninterpretable")
    for dep in deps:
        if not isinstance(dep, str) or not dep:
            raise ValueError(
                "topology depends_on entries must be non-empty strings")
        if service:
            edges.add(frozenset((service, dep)))
    return edges


def deduplicate(alerts: list[Alert]) -> tuple[list[Alert], int, dict]:
    """Suppress duplicates: exact alert_id reruns + near-dups within <=5s.

    A near-dup shares (service, signature, environment) with an earlier alert
    no more than DEDUP_WINDOW_S apart. Order-preserving (keeps first).
    Returns (unique_alerts, suppressed_count, suppressed_by_key): the per-key
    map attributes suppression to (service, signature, env) so incidents
    report their OWN suppressed count, never a global total (M04 90+ pass).
    """
    seen_ids: set[str] = set()
    last_seen: dict[tuple[str, str, str], float] = {}
    unique: list[Alert] = []
    suppressed = 0
    by_key: dict[tuple[str, str, str], int] = {}
    for alert in alerts:
        key = (alert.service, _alert_signature(alert),
               str(alert.environment))
        if alert.alert_id in seen_ids:
            suppressed += 1
            by_key[key] = by_key.get(key, 0) + 1
            continue
        ts = _alert_ts(alert)
        prev = last_seen.get(key)
        if prev is not None and abs(ts - prev) <= DEDUP_WINDOW_S:
            suppressed += 1
            by_key[key] = by_key.get(key, 0) + 1
            continue
        seen_ids.add(alert.alert_id)
        last_seen[key] = ts
        unique.append(alert)
    return unique, suppressed, by_key


def _coerce_alerts(alerts: Any) -> list[Alert]:
    """Accept canonical Alerts or raw dicts (raw normalized strictly)."""
    if isinstance(alerts, (str, bytes)) or not isinstance(alerts, (list, tuple)):
        raise ValueError("alerts must be a list of Alert records or raw dicts")
    coerced: list[Alert] = []
    for item in alerts:
        if isinstance(item, Alert):
            coerced.append(item)
        elif isinstance(item, Mapping):
            coerced.append(normalize_alert(item))
        else:
            raise ValueError(
                "alerts entries must be Alert records or raw objects, got "
                f"{type(item).__name__}")
    return coerced


def correlate(alerts: list[dict] | list[Alert],
              deploys: list[dict] | None = None,
              metrics: list[dict] | None = None,
              topology: dict | None = None) -> list[Incident]:
    """Group alerts into incidents with P1-P4 severity (deterministic)."""
    canon = _coerce_alerts(alerts)
    if deploys is None:
        deploys = []
    if metrics is None:
        metrics = []
    if topology is None:
        topology = {}
    if not isinstance(deploys, (list, tuple)):
        raise ValueError(
            f"deploys must be a list, got {type(deploys).__name__}")
    if not isinstance(metrics, (list, tuple)):
        raise ValueError(
            f"metrics must be a list, got {type(metrics).__name__}")
    deploys = list(deploys)
    metrics = list(metrics)
    edges = _topology_edges(topology)
    # Error gate reads the error_rate family ONLY: max() over every value
    # let an unrelated cpu_percent=95 page P1. Non-finite and boolean
    # readings are skipped (garbage in, no signal out).
    max_err = 0.0
    for m in metrics:
        if not isinstance(m, Mapping):
            continue
        if m.get("name") != ERROR_RATE_METRIC:
            continue
        value = m.get("value", 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if value != value or abs(value) == float("inf"):
            continue
        max_err = max(max_err, float(value))

    ordered = sorted(canon, key=_alert_ts)
    unique, _suppressed_total, suppressed_by_key = deduplicate(ordered)

    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for alert in unique:
        svc, sig = alert.service, _alert_signature(alert)
        env = str(alert.environment)
        dep = _deploy_in_window(deploys, svc, _alert_ts(alert))
        key = fingerprint(svc, sig, env, dep)
        # cross-service merge: the pair must BE a dependency edge (either
        # direction) — flat "named anywhere" membership is gone (P1 #21).
        merged = None
        for k in order:
            g = groups[k]
            if g["service"] == svc:
                continue  # same service merges by fingerprint, not edges
            if frozenset((svc, g["service"])) not in edges:
                continue
            if (abs(_alert_ts(alert) - g["last_ts"]) <= MERGE_WINDOW_S
                    and _sig_sim(sig, g["signature"]) > 0.7):
                merged = k
                break
        key = merged or key
        if key not in groups:
            groups[key] = {"service": svc, "signature": sig, "env": env,
                           "fp": key, "alerts": [], "last_ts": 0.0,
                           "keys": set()}
            order.append(key)
        groups[key]["alerts"].append(alert)
        groups[key]["last_ts"] = _alert_ts(alert)
        groups[key]["keys"].add((svc, sig, env))

    incidents = []
    for k in order:
        g = groups[k]
        first_ts = min(_alert_ts(a) for a in g["alerts"])
        own_suppressed = sum(suppressed_by_key.get(key, 0)
                             for key in g["keys"])
        ids = [a.alert_id for a in g["alerts"]]
        capped = len(ids) > MAX_STORED_IDS
        incidents.append(Incident(
            fingerprint=g["fp"],
            severity=_severity(g, max_err),
            status="CORRELATED",
            service=g["service"],
            environment=g["env"],
            source_alert_ids=ids[:MAX_STORED_IDS],
            detected_at=datetime.fromtimestamp(first_ts, tz=timezone.utc),
            metadata={"signature": g["signature"],
                      "alert_count": len(g["alerts"]),
                      "suppressed_duplicates": own_suppressed,
                      "source_alert_ids_capped": capped},
        ))
    return incidents


def _severity(g: dict, max_err: float) -> Severity:
    # TRIAGE severity (signal severity lives on the Alert; see module
    # docstring + ADR-014 joint test). Keyword arms below are a documented
    # fail-closed heuristic, NOT precision retrieval: a prod error-spike
    # with NO metrics is a data gap, and data gaps escalate (P1), never
    # downgrade — downgrading on missing evidence would hide real spikes.
    if g["signature"] in FP_SIGNATURES and max_err < 0.01:
        return Severity.P4
    if g["signature"] == "suspicious_log_instruction":
        return Severity.P1  # security-like always P1
    if g["env"] == "prod" and (max_err > 0.05 or "spike" in g["signature"]
                               or "exhausted" in g["signature"]):
        return Severity.P1
    if g["env"] == "prod":
        return Severity.P2
    return Severity.P3
