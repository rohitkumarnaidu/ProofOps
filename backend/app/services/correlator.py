"""Deterministic correlator (M04): alerts -> incidents.

Grouping, deduplication, and severity are CODE, never LLM. Fingerprint binds
service, error signature, environment, and deploy window so re-runs are
identical. The LLM may propose an owner; it is never the authority for
grouping or severity.

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


def fingerprint(service: str, signature: str, env: str, deploy_id: str) -> str:
    """Grouping fingerprint: sha256(service|sig|env|deploy) truncated to 16."""
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
        try:
            dts = float(d.get("ts", 0) or 0)
        except (TypeError, ValueError):
            continue
        if d.get("service") == service and abs(dts - ts) <= DEPLOY_WINDOW_S:
            return str(d.get("deploy_id", "none"))
    return "none"


def _sig_sim(a: str, b: str) -> float:
    ta, tb = set(a.split("_")), set(b.split("_"))
    return len(ta & tb) / max(len(ta | tb), 1)


def deduplicate(alerts: list[Alert]) -> tuple[list[Alert], int]:
    """Suppress duplicates: exact alert_id reruns + near-dups within <=5s.

    A near-dup shares (service, signature, environment) with an earlier alert
    no more than DEDUP_WINDOW_S apart. Order-preserving (keeps first).
    Returns (unique_alerts, suppressed_count).
    """
    seen_ids: set[str] = set()
    last_seen: dict[tuple[str, str, str], float] = {}
    unique: list[Alert] = []
    suppressed = 0
    for alert in alerts:
        if alert.alert_id in seen_ids:
            suppressed += 1
            continue
        key = (alert.service, _alert_signature(alert),
               str(alert.environment))
        ts = _alert_ts(alert)
        prev = last_seen.get(key)
        if prev is not None and abs(ts - prev) <= DEDUP_WINDOW_S:
            suppressed += 1
            continue
        seen_ids.add(alert.alert_id)
        last_seen[key] = ts
        unique.append(alert)
    return unique, suppressed


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
    deploys = list(deploys or [])
    metrics = list(metrics or [])
    topology = dict(topology or {})
    max_err = 0.0
    for m in metrics:
        try:
            max_err = max(max_err, float(m.get("value", 0)))
        except (TypeError, ValueError, AttributeError):
            continue

    ordered = sorted(canon, key=_alert_ts)
    unique, suppressed = deduplicate(ordered)

    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for alert in unique:
        svc, sig = alert.service, _alert_signature(alert)
        env = str(alert.environment)
        dep = _deploy_in_window(deploys, svc, _alert_ts(alert))
        key = fingerprint(svc, sig, env, dep)
        # cross-service merge: dependency edge + time + similar signature
        merged = None
        for k in order:
            g = groups[k]
            if (svc in topology.get("depends_on", []) or
                    g["service"] in topology.get("depends_on", [])):
                if (abs(_alert_ts(alert) - g["last_ts"]) <= MERGE_WINDOW_S
                        and _sig_sim(sig, g["signature"]) > 0.7):
                    merged = k
                    break
        key = merged or key
        if key not in groups:
            groups[key] = {"service": svc, "signature": sig, "env": env,
                           "fp": key, "alerts": [], "last_ts": 0.0}
            order.append(key)
        groups[key]["alerts"].append(alert)
        groups[key]["last_ts"] = _alert_ts(alert)

    incidents = []
    for k in order:
        g = groups[k]
        first_ts = min(_alert_ts(a) for a in g["alerts"])
        incidents.append(Incident(
            fingerprint=g["fp"],
            severity=_severity(g, max_err),
            status="CORRELATED",
            service=g["service"],
            environment=g["env"],
            source_alert_ids=[a.alert_id for a in g["alerts"]],
            detected_at=datetime.fromtimestamp(first_ts, tz=timezone.utc),
            metadata={"signature": g["signature"],
                      "alert_count": len(g["alerts"]),
                      "suppressed_duplicates": suppressed},
        ))
    return incidents


def _severity(g: dict, max_err: float) -> Severity:
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
