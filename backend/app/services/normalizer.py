"""Deterministic normalizer (M03): raw telemetry -> canonical contracts + hashes.

Raw telemetry is untrusted DATA: every record is validated, bounded, and
rebuilt onto a canonical contract; nothing passes through by reference and
nothing is guessed. Unknown severity, bad timestamps, or non-object payloads
fail closed (ValidationError/ValueError), never defaulted silently - except
the documented benign defaults below (source/service fallbacks that cannot
alter grouping or authorization).

Telemetry NEVER becomes instructions: injection payloads inside ``msg`` text
are preserved verbatim as inert content (asserted by test); the normalizer
has no instruction channel, only shape mapping.

Legacy wire carried (not dropped): ``severity_raw`` and ``signature`` live on
in ``Alert.metadata`` (verbatim DATA for correlation/debugging); the legacy
in-model ``hash`` hack (object.__setattr__ bypass, M01-era pin) is GONE -
hashes are computed OUT of model via :func:`alert_hash` over the canonical
JSON dump. Chain of custody beyond carrying/computation belongs to M05/M15.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts.alert import Alert, _LEGACY_SEVERITY_MAP  # noqa: E402
from app.contracts.enums import Environment  # noqa: E402
from app.contracts.incident import FrozenDict  # noqa: E402
from app.contracts.values import (  # noqa: E402
    canonical_json,
    new_id,
    sha256_hex,
    utcnow,
)

# Benign origin fallback: marks records whose sender did not identify itself.
# Cannot alter grouping (grouping keys on service/signature/env) or policy.
UNKNOWN_SOURCE = "unknown"
UNKNOWN_SERVICE = "unknown"

MAX_LOG_MSG = 2000  # log bodies truncated here; full blobs live in DB by ref


def hash_record(obj: Any) -> str:
    """Stable sha256 over canonical JSON (dicts/records/dumps)."""
    return sha256_hex(canonical_json(obj))


def alert_hash(alert: Alert) -> str:
    """Content hash of a canonical Alert (out-of-model custody helper)."""
    return hash_record(alert.model_dump(mode="json"))


def _coerce_ts(value: Any) -> datetime:
    """Coerce a raw timestamp to tz-aware UTC datetime (fail closed)."""
    if value is None:
        return utcnow()
    if isinstance(value, bool):
        raise ValueError("ts must be a timestamp, not a boolean")
    if isinstance(value, (int, float)):
        if not (value == value and abs(value) != float("inf")):
            raise ValueError("ts must be finite")
        if value < 0:
            raise ValueError("ts must be >= 0 (unix epoch)")
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"ts is not a parseable timestamp: {value!r}") from exc
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise ValueError("ts must be timezone-aware (reject naive)")
        return dt
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("ts must be timezone-aware (reject naive)")
        return value
    raise ValueError(f"ts has unsupported type: {type(value).__name__}")


def _raw_str(raw: Mapping[str, Any], key: str, default: str = "") -> str:
    """Scalar-to-str coercion for identifier-ish raw fields (fail closed)."""
    if key not in raw or raw[key] is None:
        return default
    value = raw[key]
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    raise ValueError(f"{key} must be a scalar string, got {type(value).__name__}")


def normalize_alert(raw: Any) -> Alert:
    """Map one raw alert record onto the canonical Alert contract."""
    if not isinstance(raw, Mapping):
        raise ValueError(
            f"alert must be an object, got {type(raw).__name__}")
    data = dict(raw)

    alert_id = _raw_str(data, "alert_id", "").strip() or new_id()
    severity_raw = _raw_str(data, "severity_raw", "").strip().upper()
    if severity_raw not in _LEGACY_SEVERITY_MAP:
        raise ValueError(
            f"unknown severity_raw (never guessed): {data.get('severity_raw')!r}")
    signature = _raw_str(data, "signature", "").strip()
    if not signature:
        raise ValueError("signature is required (correlation groups on it)")
    service = _raw_str(data, "service", UNKNOWN_SERVICE)
    message = _raw_str(data, "message", "")
    if not message.strip():
        message = f"{signature} on {service}"
    labels = data.get("labels", {})
    if labels is None:
        labels = {}
    if not isinstance(labels, Mapping):
        raise ValueError("labels must be an object, never a scalar/list")
    metadata: dict[str, Any] = {
        "severity_raw": _raw_str(data, "severity_raw", ""),
        "signature": signature,
    }
    for extra in ("trace_id", "pod"):
        if data.get(extra) is not None:
            metadata[extra] = str(data[extra])
    # NOTE: present-but-blank service/source/status/environment fall through
    # to the model and are REJECTED there (fail closed); only a MISSING key
    # takes the benign default above. Silent blank->default masking would let
    # unrelated alerts merge into one group.
    payload = {
        "alert_id": alert_id,
        "service": service,
        "environment": _raw_str(data, "environment", "mock"),
        "severity_raw": severity_raw,
        "signature": signature,
        "message": message,
    }
    fingerprint = sha256_hex(canonical_json(payload))[:64]
    try:
        environment = Environment(payload["environment"])
    except ValueError as exc:
        raise ValueError(
            f"unknown environment (never guessed): "
            f"{payload['environment']!r}") from exc
    return Alert(
        alert_id=alert_id,
        source=_raw_str(data, "source", UNKNOWN_SOURCE),
        timestamp=_coerce_ts(data.get("ts")),
        service=service,
        resource=_raw_str(data, "resource", _raw_str(data, "pod", "")),
        severity=_LEGACY_SEVERITY_MAP[severity_raw],
        message=message,
        labels=FrozenDict(dict(labels)),
        fingerprint=fingerprint,
        environment=environment,
        status=_raw_str(data, "status", "firing"),
        metadata=FrozenDict(metadata),
    )


def normalize_log(raw: Any) -> dict:
    """Canonical log record (dict; full blob stays in DB, ref by hash).

    ``msg`` is verbatim DATA (truncated to MAX_LOG_MSG), never interpreted:
    instruction-like content inside logs stays inert by construction - there
    is no code path here that reads ``msg`` as anything but characters.
    """
    if not isinstance(raw, Mapping):
        raise ValueError(
            f"log must be an object, got {type(raw).__name__}")
    rec = {
        "ts": raw.get("ts"),
        "service": str(raw.get("service", UNKNOWN_SERVICE)),
        "pod": str(raw.get("pod", "?")),
        "level": str(raw.get("level", "INFO")),
        "msg": str(raw.get("msg", ""))[:MAX_LOG_MSG],
        "trace_id": str(raw.get("trace_id", "")),
    }
    rec["hash"] = hash_record(rec)
    return rec


def normalize_metric(raw: Any) -> dict:
    """Canonical metric point: ts + service + name + finite float value."""
    if not isinstance(raw, Mapping):
        raise ValueError(
            f"metric must be an object, got {type(raw).__name__}")
    if raw.get("ts") is None:
        raise ValueError("metric ts is required")
    try:
        ts = float(raw["ts"])  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"metric ts must be numeric: {raw.get('ts')!r}") from exc
    if ts != ts or abs(ts) == float("inf"):
        raise ValueError("metric ts must be finite")
    name = _raw_str(raw, "name", "").strip()
    if not name:
        raise ValueError("metric name is required")
    value = raw.get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("metric value must be a JSON number (bool rejected)")
    if float(value) != float(value) or abs(float(value)) == float("inf"):
        raise ValueError("metric value must be finite (NaN/inf rejected)")
    rec = {
        "ts": ts,
        "service": str(raw.get("service", UNKNOWN_SERVICE)),
        "name": name,
        "value": float(value),
    }
    rec["hash"] = hash_record(rec)
    return rec


def normalize_trace(raw: Any) -> dict:
    """Canonical trace exemplar: trace_id ref integrity + context.

    Ref integrity: ``trace_id`` is preserved verbatim (the join key to the
    full trace blob); it is never rewritten, only validated present.
    """
    if not isinstance(raw, Mapping):
        raise ValueError(
            f"trace must be an object, got {type(raw).__name__}")
    trace_id = _raw_str(raw, "trace_id", "").strip()
    if not trace_id:
        raise ValueError("trace trace_id is required (ref integrity)")
    rec = {
        "trace_id": trace_id,
        "ts": raw.get("ts"),
        "service": str(raw.get("service", UNKNOWN_SERVICE)),
    }
    rec["hash"] = hash_record(rec)
    return rec


def normalize_deployment(raw: Any) -> dict:
    """Canonical deployment event: service + ts + from->to diff shape."""
    if not isinstance(raw, Mapping):
        raise ValueError(
            f"deployment must be an object, got {type(raw).__name__}")
    service = _raw_str(raw, "service", "").strip()
    if not service:
        raise ValueError("deployment service is required")
    if raw.get("ts") is None:
        raise ValueError("deployment ts is required")
    try:
        ts = float(raw["ts"])  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"deployment ts must be numeric: {raw.get('ts')!r}") from exc
    rec = {
        "deploy_id": _raw_str(raw, "deploy_id", "") or "unknown",
        "ts": ts,
        "service": service,
        "from_v": str(raw.get("from_v", "")),
        "to_v": str(raw.get("to_v", "")),
        "author": str(raw.get("author", UNKNOWN_SOURCE)),
    }
    rec["hash"] = hash_record(rec)
    return rec


def normalize_k8s_event(raw: Any) -> dict:
    """Canonical Kubernetes event: ts + service + kind + reason."""
    if not isinstance(raw, Mapping):
        raise ValueError(
            f"k8s event must be an object, got {type(raw).__name__}")
    if raw.get("ts") is None:
        raise ValueError("k8s event ts is required")
    try:
        ts = float(raw["ts"])  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"k8s event ts must be numeric: {raw.get('ts')!r}") from exc
    count = raw.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("k8s event count must be an integer >= 1")
    rec = {
        "ts": ts,
        "service": str(raw.get("service", UNKNOWN_SERVICE)),
        "kind": str(raw.get("kind", "Pod")),
        "reason": str(raw.get("reason", "Unknown")),
        "pod": str(raw.get("pod", "")),
        "count": count,
    }
    rec["hash"] = hash_record(rec)
    return rec


def normalize_telemetry(bundle: Any) -> dict:
    """Join all telemetry sources into one canonical model (M03.6).

    Cross-source join: every list is normalized record-by-record and indexed
    by service; a malformed bundle (or any malformed record) fails closed -
    partial models with silently dropped sources are forbidden, because a
    missing source could hide the root cause.
    """
    if not isinstance(bundle, Mapping):
        raise ValueError(
            f"telemetry bundle must be an object, got {type(bundle).__name__}")
    alerts = [normalize_alert(a) for a in bundle.get("alerts", [])]
    logs = [normalize_log(entry) for entry in bundle.get("logs", [])]
    metrics = [normalize_metric(m) for m in bundle.get("metrics", [])]
    traces = [normalize_trace(t) for t in bundle.get("traces", [])]
    deployments = [normalize_deployment(d)
                   for d in bundle.get("deploys", [])]
    k8s_events = [normalize_k8s_event(e)
                  for e in bundle.get("k8s_events", [])]
    topology = bundle.get("topology", {})
    if not isinstance(topology, Mapping):
        raise ValueError("topology must be an object")
    depends_on = topology.get("depends_on", [])
    if not isinstance(depends_on, list) or any(
            not isinstance(d, str) for d in depends_on):
        raise ValueError("topology depends_on must be a list of strings")
    by_service: dict[str, dict[str, int]] = {}
    for name, records in (("alerts", alerts), ("logs", logs),
                          ("metrics", metrics), ("traces", traces),
                          ("deployments", deployments),
                          ("k8s_events", k8s_events)):
        for rec in records:
            svc = rec.service if isinstance(rec, Alert) else rec["service"]
            by_service.setdefault(svc, {}).setdefault(name, 0)
            by_service[svc][name] += 1
    return {
        "alerts": alerts,
        "logs": logs,
        "metrics": metrics,
        "traces": traces,
        "deployments": deployments,
        "k8s_events": k8s_events,
        "topology": {"service": str(topology.get("service", "")),
                     "depends_on": list(depends_on)},
        "by_service": by_service,
    }
