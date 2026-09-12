"""Deterministic normalizer: raw telemetry -> canonical records + hashes."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.schemas import Alert, canonical_json, sha256_hex  # noqa: E402


def hash_record(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


def normalize_alert(raw: dict) -> Alert:
    """Map a raw alert dict onto the canonical Alert contract."""
    a = Alert(
        alert_id=str(raw.get("alert_id", "")) or "unknown",
        service=str(raw.get("service", "unknown")),
        environment=raw.get("environment", "mock"),
        severity_raw=str(raw.get("severity_raw", "unknown")),
        signature=str(raw.get("signature", "unknown")),
        labels=dict(raw.get("labels", {})),
    )
    if raw.get("ts") is not None:
        object.__setattr__(a, "ts", raw["ts"]) if isinstance(raw["ts"], str) else None
    payload = {"service": a.service, "signature": a.signature,
               "ts": str(raw.get("ts")), "labels": a.labels}
    a.hash = hash_record(payload)
    return a


def normalize_log(raw: dict) -> dict:
    """Canonical log record (dict; full blob stays in DB, ref by hash)."""
    rec = {
        "ts": raw.get("ts"), "service": raw.get("service", "unknown"),
        "pod": raw.get("pod", "?"), "level": raw.get("level", "INFO"),
        "msg": str(raw.get("msg", ""))[:2000],
        "trace_id": raw.get("trace_id", ""),
    }
    rec["hash"] = hash_record(rec)
    return rec
