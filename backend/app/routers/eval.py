"""M19b eval smoke endpoint: measured harness numbers on demand (thin).

Ownership: M19 owns THIS ROUTER (RCA view needs live six-gate data; no
eval HTTP existed). The ENGINE stays M16 (imported, untouched). Systems
here are deterministic mocks, labeled on every response: these numbers
prove the EVAL MACHINERY runs end-to-end (loader -> runner -> graders ->
gates -> compare -> rubric), not product quality. Pipeline-system numbers
arrive with M20/M21; this endpoint's shape stays stable for them.

Nothing estimated: every figure derives from executed run_case() calls in
this request. GT isolation holds (public bundles to systems, sealed to
graders only).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from app.services import eval as eval_svc  # noqa: E402 (M16 engine)

try:  # pragma: no cover - container path (pinned deps)
    from fastapi import APIRouter as _APIRouter
    from fastapi import Header as _Header
    from fastapi import HTTPException as _HTTPException
    _APIRouter(prefix="/__probe__")
    router = _APIRouter(tags=["eval"])
    HTTPException = _HTTPException
    Header = _Header
except Exception:  # host-only drift (AGENTS.md S13.2)
    router = None  # type: ignore[assignment]

    def Header(default: object = None, **kwargs: object) -> object:  # type: ignore[no-redef]
        return default

    class HTTPException(Exception):  # type: ignore[no-redef]
        def __init__(self, status_code: int = 500, detail: str = "") -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

SYSTEM_LABEL = "mock-deterministic"


def _baseline(public: dict[str, Any]) -> dict[str, Any]:
    return eval_svc.mock_trace()


def _degraded(public: dict[str, Any]) -> dict[str, Any]:
    return eval_svc.mock_trace(
        retrieval={"p5": 0.4, "r5": 0.3, "mrr": 0.4, "ndcg": 0.4,
                   "irr": 0.6},
        budgets={"tokens_in": 60000, "tokens_out": 30000, "calls": 9,
                 "ctx_per_call": 6000, "cache_hit": 0.7},
        attacks=[{"name": "log-injection", "contained": False}])


def smoke_eval() -> dict[str, Any]:
    """Run deep-5/NORMAL/42 through both mock systems and score (M19b)."""
    cases = eval_svc.load_suite()
    base_cfg = eval_svc.RunConfig(name="baseline")
    opt_cfg = eval_svc.RunConfig(name="degraded", retrieval_mode="noisy",
                                 model_tier="small", predigest="raw")
    base_records = [eval_svc.run_case(c, _baseline, dict(base_cfg.__dict__))
                    for c in cases]
    opt_records = [eval_svc.run_case(c, _degraded, dict(opt_cfg.__dict__))
                   for c in cases]
    base = eval_svc.capture(base_cfg, base_records)
    opt = eval_svc.capture(opt_cfg, opt_records)
    delta = eval_svc.compare_summaries(base, opt)
    rubric = eval_svc.rubric(base_records + opt_records)
    return {"system": SYSTEM_LABEL,
            "note": "harness smoke: mock systems prove the machinery, "
                    "not product quality",
            "cases": len(cases), "baseline": base, "optimized": opt,
            "delta": delta, "rubric": rubric}


class SmokeBody(BaseModel):
    model_config = {"extra": "forbid"}
    confirm: bool = Field(default=False,
                          description="Set true: smoke runs compute, not free")


def http_smoke(body: SmokeBody,
               x_api_key: str | None = Header(default=None)
               ) -> dict[str, Any]:
    """Smoke runs compute: confirm gate + demo key (no open compute)."""
    from app.config import get_settings  # noqa: E402 (request-time only)
    from app.routers import auth as auth_mod
    auth_mod.guard_http(
        x_api_key, lambda: get_settings().PROOFOPS_API_KEY, HTTPException)
    if body.confirm is not True:
        raise HTTPException(status_code=400,
                            detail="confirm must be true to run smoke")
    try:
        return smoke_eval()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="smoke run failed (see server logs)") from exc


if router is not None:  # container path; host asserts wiring via AST
    router.post("/eval/smoke")(http_smoke)
