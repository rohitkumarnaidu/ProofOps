"""Independent deterministic verifier (V2 §29). RULE 06/07.

Planner output is INADMISSIBLE: only live (simulated) state + SLO config
decide the verdict. `command_succeeded` is accepted as a logged fact but
never implies resolution.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts import Verdict  # noqa: E402 (M01.1 frozen enums)
from app.schemas import VerificationResult  # noqa: E402


def verify(execution_id: str, before: dict, after: dict,
           slo: dict, expected: dict | None = None) -> VerificationResult:
    """before/after: sandbox state snapshots. slo: {"error_rate_below": x}."""
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

    detail = f"err {err_before}->{err}"
    if err > err_before * 1.2 and err_before > 0:
        return VerificationResult(execution_id=execution_id, verdict=Verdict.WORSENED,
                                  checks=checks, detail=detail)
    if all(checks.values()):
        return VerificationResult(execution_id=execution_id, verdict=Verdict.RESOLVED,
                                  checks=checks, detail=detail)
    if checks["error_rate_below_slo"] and not all(checks.values()):
        return VerificationResult(execution_id=execution_id, verdict=Verdict.PARTIAL,
                                  checks=checks, detail=detail)
    reversible = True  # caller (FSM) knows reversibility; default asks rollback
    if not checks["error_rate_below_slo"] and reversible:
        return VerificationResult(execution_id=execution_id,
                                  verdict=Verdict.ROLLBACK_REQUIRED,
                                  checks=checks, detail=detail)
    return VerificationResult(execution_id=execution_id, verdict=Verdict.FAILED,
                              checks=checks, detail=detail)
