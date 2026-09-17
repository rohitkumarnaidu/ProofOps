"""Evidence pre-digestion: telemetry -> bounded Evidence Pack (V2 §22-23).

Never send raw log dumps to an LLM. The pack carries digests + refs;
full blobs stay addressable by evidence hash. Budgets: top-5 error lines,
<=50 counted lines, 3 trace exemplars, pack target <=6k tokens.

Determinism: same (incident_id, bundle) -> byte-identical pack. Evidence
ids are content-derived (never uuid4), timestamps derive from bundle ts
(wall-clock only when the bundle carries no ts at all), trust comes from
the M05.4 rule (fresh + corroborated), never hardcoded.
"""
from __future__ import annotations

import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts import SourceType  # noqa: E402 (M01.1 frozen enums)
from app.contracts.evidence import Evidence  # noqa: E402 (M01.4 canonical)
from app.contracts.values import sha256_hex, utcnow  # noqa: E402
from app.services.evidence import STALE_AFTER_S, trust_for  # noqa: E402 (M05 rules)

MAX_COUNTED_LINES = 50
TOP_ERRORS = 5
TRACE_EXEMPLARS = 3


def _as_epoch(ts: Any) -> float | None:
    """Observation time as unix epoch, or None when unknown/malformed.

    Accepts ints/floats (finite, >= 0) and tz-aware datetimes (the normalized
    model shape). Everything else (missing, None, bools, NaN/inf, strings,
    naive datetimes, out-of-range magnitudes) is UNKNOWN — never guessed,
    never crashed on.
    """
    if isinstance(ts, bool):
        return None
    if isinstance(ts, (int, float)):
        if ts != ts or abs(ts) == float("inf") or ts < 0:
            return None
        return float(ts)
    if isinstance(ts, datetime):
        if ts.tzinfo is None or ts.utcoffset() is None:
            return None
        try:
            return ts.timestamp()
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _as_dt(epoch: float | None) -> datetime:
    """Epoch -> tz-aware datetime. Unknown time means arrival time (utcnow),
    matching the M03 observation doctrine: untimed observations are treated
    as fresh-at-pack, visibly (freshness_s 0.0), never backdated."""
    if epoch is None:
        return utcnow()
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return utcnow()


def build_evidence_pack(incident_id: str, tele: dict) -> dict[str, Any]:
    """Build the bounded Evidence Pack (deterministic, fail-tolerant).

    Container shapes (non-list logs/metrics/deploys, non-object bundle)
    raise ValueError — a misshapen bundle must not silently shed sources.
    Malformed ROWS inside a well-shaped list are skipped but still counted
    in window tallies (availability: one bad line must not deny the whole
    pack; M03 rejects them at ingest for the normalized path).
    """
    if not isinstance(tele, Mapping):
        raise ValueError(
            f"telemetry bundle must be an object, got {type(tele).__name__}")
    logs = tele.get("logs", [])
    metrics = tele.get("metrics", [])
    deploys = tele.get("deploys", [])
    if not isinstance(logs, (list, tuple)):
        raise ValueError("telemetry logs must be a list")
    if not isinstance(metrics, (list, tuple)):
        raise ValueError("telemetry metrics must be a list")
    if not isinstance(deploys, (list, tuple)):
        raise ValueError("telemetry deploys must be a list")
    errs = [lg for lg in logs
            if isinstance(lg, Mapping) and lg.get("level") == "ERROR"
            ][:MAX_COUNTED_LINES]
    sig_count = Counter(lg.get("msg", "").split("trace=")[0].strip()[:80]
                        for lg in errs
                        if isinstance(lg.get("msg", ""), str))
    err_vals = [float(m["value"]) for m in metrics
                if isinstance(m, Mapping) and m.get("name") == "error_rate"
                and isinstance(m.get("value"), (int, float))
                and not isinstance(m.get("value"), bool)
                and m.get("value") == m.get("value")
                and abs(m.get("value")) != float("inf")]
    delta = round(max(err_vals) - min(err_vals), 4) if len(err_vals) > 1 else 0.0

    # Detection anchor: the earliest alert ts (the moment the incident was
    # noticed). Freshness = detection - observation: how stale was this data
    # WHEN WE NOTICED, not when the bundle ended. (Anchoring at bundle end
    # punished the prime suspect: a deploy 5m before alerts reads 16m stale
    # once the metric series runs 11m past detection.) No alert ts anywhere
    # -> fall back to the latest observation ts -> arrival time (0.0).
    alert_epochs = [_as_epoch(a.get("ts")) for a in tele.get("alerts", [])
                    if isinstance(a, Mapping)]
    alert_epochs = [e for e in alert_epochs if e is not None]
    ends = [_as_epoch(lg.get("ts")) for lg in errs]
    ends += [_as_epoch(m.get("ts")) for m in metrics
             if isinstance(m, Mapping)]
    ends += [_as_epoch(d.get("ts")) for d in deploys
             if isinstance(d, Mapping)]
    ends = [e for e in ends if e is not None]
    detection = min(alert_epochs) if alert_epochs else None
    if detection is None:
        detection = max(ends) if ends else None

    def _fresh(item_epoch: float | None) -> float:
        if detection is None or item_epoch is None:
            return 0.0
        return max(0.0, round(detection - item_epoch, 1))

    ev: list[Evidence] = []
    for i, (msg, cnt) in enumerate(sig_count.most_common(TOP_ERRORS)):
        pods = {lg.get("pod") for lg in errs
                if isinstance(lg.get("msg", ""), str)
                and lg.get("msg", "").split("trace=")[0].strip()[:80] == msg
                and lg.get("pod")}
        h = sha256_hex(f"{incident_id}|log|{msg}|{cnt}")
        first_ts = next((_as_epoch(lg.get("ts")) for lg in errs
                         if isinstance(lg.get("msg", ""), str)
                         and lg.get("msg", "").split("trace=")[0].strip()[:80]
                         == msg and _as_epoch(lg.get("ts")) is not None),
                        detection)
        freshness = _fresh(first_ts)
        ev.append(Evidence(
            evidence_id=f"ev-{h[:16]}",
            incident_id=incident_id, source_type=SourceType.LOG,
            source_id=f"logs[{i}]", ref=f"count={cnt} :: {msg}",
            hash=h, ts=_as_dt(first_ts if first_ts is not None
                              else detection),
            freshness_s=freshness,
            relevance=round(1.0 - i * 0.1, 2),
            trust=trust_for(freshness <= STALE_AFTER_S, len(pods) >= 2)))
    if err_vals:
        # Metric aggregate: currency is detection time by construction (the
        # aggregate summarizes the incident window AS OF detection), hence
        # freshness 0.0 with ts=detection. Single source -> MED by the rule.
        h = sha256_hex(f"{incident_id}|metric|error_rate|{max(err_vals)}")
        ev.append(Evidence(
            evidence_id=f"ev-{h[:16]}",
            incident_id=incident_id, source_type=SourceType.METRIC,
            source_id="error_rate", ref=f"max={max(err_vals)} delta={delta}",
            hash=h, ts=_as_dt(detection), freshness_s=0.0, relevance=0.9,
            trust=trust_for(True, False)))
    for d in deploys:
        if not isinstance(d, Mapping):
            continue
        h = sha256_hex(f"{incident_id}|deploy|{d.get('deploy_id')}")
        dts = _as_epoch(d.get("ts"))
        freshness = _fresh(dts)
        ev.append(Evidence(
            evidence_id=f"ev-{h[:16]}",
            incident_id=incident_id, source_type=SourceType.DEPLOY,
            source_id=str(d.get("deploy_id") or "unknown"),
            ts=_as_dt(dts),
            ref=f"{d.get('from_v') or ''}->{d.get('to_v') or ''} "
                f"by {d.get('author') or 'unknown'}",
            hash=h, freshness_s=freshness, relevance=0.95,
            trust=trust_for(freshness <= STALE_AFTER_S, False)))
    traces = [t.get("trace_id", "") for t in tele.get("traces", [])
              if isinstance(t, Mapping)][:TRACE_EXEMPLARS]

    return {
        "incident_id": incident_id,
        "window": {"alerts": len(tele.get("alerts", [])),
                   "logs_seen": len(logs)},
        "error_signature": (sig_count.most_common(1) or [("none", 0)])[0][0],
        "top_errors": [{"msg": m, "count": c}
                       for m, c in sig_count.most_common(TOP_ERRORS)],
        "metric_delta": delta,
        "deploy_diff": [f"{d.get('from_v')}->{d.get('to_v')}" for d in deploys
                        if isinstance(d, Mapping)],
        "trace_exemplars": traces,
        "topology_neighbors": tele.get("topology", {}).get("depends_on", [])
        if isinstance(tele.get("topology", {}), Mapping) else [],
        "evidence": [e.model_dump() for e in ev],
    }
