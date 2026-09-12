"""Deterministic correlator: alerts -> incidents (V2 §24).

Grouping and severity are CODE, never LLM. Fingerprint binds service,
error signature, environment and deploy window so re-runs are identical.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.schemas import Incident, sha256_hex  # noqa: E402

FP_SIGNATURES = {"flapping_probe", "cpu_blip"}
DEPLOY_WINDOW_S = 900
MERGE_WINDOW_S = 600


def fingerprint(service: str, signature: str, env: str, deploy_id: str) -> str:
    return sha256_hex(f"{service}|{signature}|{env}|{deploy_id}")[:16]


def _deploy_in_window(deploys: list[dict], service: str, ts: float) -> str:
    for d in deploys:
        if d.get("service") == service and abs(float(d.get("ts", 0)) - ts) <= DEPLOY_WINDOW_S:
            return str(d.get("deploy_id", "none"))
    return "none"


def _sig_sim(a: str, b: str) -> float:
    ta, tb = set(a.split("_")), set(b.split("_"))
    return len(ta & tb) / max(len(ta | tb), 1)


def correlate(alerts: list[dict], deploys: list[dict] | None = None,
              metrics: list[dict] | None = None,
              topology: dict | None = None) -> list[Incident]:
    """Group normalized alert dicts into incidents with P1-P4 severity."""
    deploys = deploys or []
    metrics = metrics or []
    topology = topology or {}
    max_err = max([float(m.get("value", 0)) for m in metrics] or [0.0])

    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for al in sorted(alerts, key=lambda a: float(a.get("ts", 0) or 0)):
        svc, sig = al["service"], al["signature"]
        env = al.get("environment", "mock")
        dep = _deploy_in_window(deploys, svc, float(al.get("ts", 0) or 0))
        key = fingerprint(svc, sig, env, dep)
        # cross-service merge: dependency edge + time + similar signature
        merged = None
        for k in order:
            g = groups[k]
            if (svc in topology.get("depends_on", []) or
                    g["service"] in topology.get("depends_on", [])):
                if (abs(float(al.get("ts", 0) or 0) - g["last_ts"]) <= MERGE_WINDOW_S
                        and _sig_sim(sig, g["signature"]) > 0.7):
                    merged = k
                    break
        key = merged or key
        if key not in groups:
            groups[key] = {"service": svc, "signature": sig, "env": env,
                           "fp": key, "alerts": [], "last_ts": 0.0}
            order.append(key)
        groups[key]["alerts"].append(al)
        groups[key]["last_ts"] = float(al.get("ts", 0) or 0)

    incidents = []
    for k in order:
        g = groups[k]
        sev = _severity(g, max_err)
        incidents.append(Incident(fingerprint=g["fp"], severity=sev, status="CORRELATED"))
    return incidents


def _severity(g: dict, max_err: float) -> str:
    if g["signature"] in FP_SIGNATURES and max_err < 0.01:
        return "P4"
    if g["signature"] == "suspicious_log_instruction":
        return "P1"  # security-like always P1
    if g["env"] == "prod" and (max_err > 0.05 or "spike" in g["signature"]
                               or "exhausted" in g["signature"]):
        return "P1"
    if g["env"] == "prod":
        return "P2"
    return "P3"
