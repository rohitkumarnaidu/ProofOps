"""Evidence pre-digestion: telemetry -> bounded Evidence Pack (V2 §22-23).

Never send raw log dumps to an LLM. The pack carries digests + refs;
full blobs stay addressable by evidence hash. Budgets: top-5 error lines,
<=50 counted lines, 3 trace exemplars, pack target <=6k tokens.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts import SourceType, TrustLevel  # noqa: E402 (M01.1 frozen enums)
from app.contracts.evidence import Evidence  # noqa: E402 (M01.4 canonical)
from app.contracts.values import sha256_hex, utcnow  # noqa: E402

MAX_COUNTED_LINES = 50
TOP_ERRORS = 5
TRACE_EXEMPLARS = 3


def build_evidence_pack(incident_id: str, tele: dict) -> dict[str, Any]:
    logs = tele.get("logs", [])
    metrics = tele.get("metrics", [])
    deploys = tele.get("deploys", [])
    errs = [lg for lg in logs if lg.get("level") == "ERROR"][:MAX_COUNTED_LINES]
    sig_count = Counter(lg.get("msg", "").split("trace=")[0].strip()[:80] for lg in errs)
    err_vals = [float(m["value"]) for m in metrics if m.get("name") == "error_rate"]
    delta = round(max(err_vals) - min(err_vals), 4) if len(err_vals) > 1 else 0.0

    ev: list[Evidence] = []
    for i, (msg, cnt) in enumerate(sig_count.most_common(TOP_ERRORS)):
        h = sha256_hex(f"{incident_id}|log|{msg}|{cnt}")
        ev.append(Evidence(incident_id=incident_id, source_type=SourceType.LOG,
                           source_id=f"logs[{i}]", ref=f"count={cnt} :: {msg}",
                           hash=h, freshness_s=60.0,
                           relevance=round(1.0 - i * 0.1, 2), trust=TrustLevel.HIGH))
    if err_vals:
        h = sha256_hex(f"{incident_id}|metric|error_rate|{max(err_vals)}")
        ev.append(Evidence(incident_id=incident_id, source_type=SourceType.METRIC,
                           source_id="error_rate", ref=f"max={max(err_vals)} delta={delta}",
                           hash=h, freshness_s=60.0, relevance=0.9, trust=TrustLevel.HIGH))
    for d in deploys:
        h = sha256_hex(f"{incident_id}|deploy|{d.get('deploy_id')}")
        ev.append(Evidence(
            incident_id=incident_id, source_type=SourceType.DEPLOY,
            source_id=str(d.get("deploy_id")), ts=utcnow(),
            ref=f"{d.get('from_v')}->{d.get('to_v')} by {d.get('author')}",
            hash=h, freshness_s=300.0, relevance=0.95, trust=TrustLevel.HIGH))
    traces = [t.get("trace_id", "") for t in tele.get("traces", [])][:TRACE_EXEMPLARS]

    return {
        "incident_id": incident_id,
        "window": {"alerts": len(tele.get("alerts", [])), "logs_seen": len(logs)},
        "error_signature": (sig_count.most_common(1) or [("none", 0)])[0][0],
        "top_errors": [{"msg": m, "count": c} for m, c in sig_count.most_common(TOP_ERRORS)],
        "metric_delta": delta,
        "deploy_diff": [f"{d.get('from_v')}->{d.get('to_v')}" for d in deploys],
        "trace_exemplars": traces,
        "topology_neighbors": tele.get("topology", {}).get("depends_on", []),
        "evidence": [e.model_dump() for e in ev],
    }
