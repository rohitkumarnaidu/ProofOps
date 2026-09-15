"""Independent deterministic verifier (M09). Planner output INADMISSIBLE.

Only observed state + SLO config decide the verdict. `command_succeeded`
(exit status) is accepted as a logged fact and recorded in the detail line,
but it NEVER influences the verdict: exit-0-with-bad-SLO is FAILED. A test
proves the same state yields the same verdict for exit True and False.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts import Verdict  # noqa: E402 (M01.1 frozen enums)
from app.contracts.incident import FrozenDict  # noqa: E402 (frozen mapping)
from app.contracts.verification import VerificationResult  # noqa: E402 (M01.11)


def verify(execution_id: str, before: dict, after: dict,
           slo: dict, expected: dict | None = None,
           command_succeeded: bool = True) -> VerificationResult:
    """before/after: sandbox state snapshots.

    slo: {"error_rate_below": x, "latency_p95_below_ms": y (optional)}.
    command_succeeded: exit status as logged fact - verdict-independent.
    """
    expected = expected or {}
    checks: dict[str, bool] = {}
    err = float(after.get("error_rate", 1.0))
    err_before = float(before.get("error_rate", 1.0))
    checks["error_rate_below_slo"] = err < float(slo.get("error_rate_below", 0.01))
    checks["pods_ready"] = bool(after.get("pods_ready", False))
    checks["replicas_positive"] = int(after.get("replicas", 0)) > 0
    if "version" in expected:
        checks["version_as_expected"] = after.get("deployment_version") == expected["version"]
    checks["no_crashloop"] = not after.get("crashloop", False)
    # Latency (M09.5): evaluated only when the SLO sets a threshold AND the
    # state reports p95. Absent data skips the check - it must never fail a
    # verdict for lack of instrumentation.
    lat_thr = slo.get("latency_p95_below_ms")
    lat_obs = after.get("latency_p95_ms")
    if lat_thr is not None and lat_obs is not None:
        checks["latency_p95_below_slo"] = float(lat_obs) < float(lat_thr)

    detail = (f"err {err_before}->{err} "
              f"exit={'0' if command_succeeded else 'nonzero'}")
    if err > err_before * 1.2 and err_before > 0:
        return VerificationResult(execution_id=execution_id, verdict=Verdict.WORSENED,
                                  checks=FrozenDict(checks), detail=detail)
    if all(checks.values()):
        return VerificationResult(execution_id=execution_id, verdict=Verdict.RESOLVED,
                                  checks=FrozenDict(checks), detail=detail)
    if checks["error_rate_below_slo"] and not all(checks.values()):
        return VerificationResult(execution_id=execution_id, verdict=Verdict.PARTIAL,
                                  checks=FrozenDict(checks), detail=detail)
    reversible = True  # caller (FSM) knows reversibility; default asks rollback
    if not checks["error_rate_below_slo"] and reversible:
        return VerificationResult(execution_id=execution_id,
                                  verdict=Verdict.ROLLBACK_REQUIRED,
                                  checks=FrozenDict(checks), detail=detail)
    return VerificationResult(execution_id=execution_id, verdict=Verdict.FAILED,
                              checks=FrozenDict(checks), detail=detail)
