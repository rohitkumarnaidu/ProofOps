"""Alert ingestion + orchestrator control (M19b real-time ingress).

The product had no way for an incident to *arrive*. You typed an id into the
Command Center, which is not ingestion, it is manual data entry wearing a UI.

This router is the front door:

  POST /alerts/ingest   submit a telemetry bundle; the orchestrator picks it up
                        and drives the real pipeline
  GET  /orchestrator    what the worker is doing right now (read-only, honest)
  POST /orchestrator/stop  the kill-switch

Ingest is WRITE-GATED on the same roles as every other mutation, and it
validates the bundle against the pre-digester's expectations rather than
trusting it. A malformed bundle fails closed with a 422 and never reaches the
worker, because a half-valid incident that reaches the pipeline produces
confident nonsense instead of an honest escalation.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

try:  # pragma: no cover - container path (pinned deps)
    from fastapi import APIRouter as _APIRouter
    from fastapi import Header as _Header
    from fastapi import HTTPException as _HTTPException
    _APIRouter(prefix="/__probe__")
    router = _APIRouter(tags=["ingest"])
    HTTPException = _HTTPException
    Header = _Header
except Exception:  # host-only drift (AGENTS.md S13.2)
    router = None  # type: ignore[assignment]

    def Header(default: object = None, **kwargs: object) -> object:  # type: ignore[no-redef]
        return default

    class HTTPException(Exception):  # type: ignore[no-redef]
        def __init__(self, status_code: int = 500, detail: str = "") -> None:
            super().__init__(detail)

TELEMETRY_FIELDS = ("service", "env", "metrics", "error_signature")


class IngestBody(BaseModel):
    """One incident's telemetry bundle.

    `extra="forbid"` so a typo'd field is a 422 rather than a silently ignored
    key that makes the incident look emptier than it is.
    """

    model_config = {"extra": "forbid"}

    incident_id: str = Field(min_length=1, max_length=128)
    scenario: str = Field(default="bad-deploy", min_length=1, max_length=64)
    telemetry: dict[str, Any] = Field(default_factory=dict)
    #: Set false to accept the incident WITHOUT auto-driving it (inspection,
    #: or a demo that wants to step the FSM by hand).
    process: bool = True


def _require_telemetry_shape(telemetry: Mapping[str, Any]) -> str:
    """Reject a bundle that cannot support a real evidence pack."""
    if not isinstance(telemetry, Mapping) or not telemetry:
        raise HTTPException(
            status_code=422,
            detail="telemetry bundle is required and must be a non-empty object")
    missing = [name for name in TELEMETRY_FIELDS if name not in telemetry]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"telemetry is missing required field(s): {', '.join(missing)}")
    return ""


def ingest_incident(body: IngestBody,
                    x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Submit a telemetry bundle for the orchestrator to process."""
    from app.config import get_settings  # noqa: E402 (request-time only)
    from app.routers import auth as auth_mod
    from app.services import orchestrator as orchestrator_mod

    identity = auth_mod.guard_http(
        x_api_key, lambda: get_settings().PROOFOPS_API_KEY, HTTPException)
    try:
        auth_mod.require_role(identity, "operator", "approver", "admin")
    except auth_mod.KeyRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    _require_telemetry_shape(body.telemetry)

    if body.scenario not in orchestrator_mod.ORACLE:
        raise HTTPException(
            status_code=422,
            detail=(f"unknown scenario {body.scenario!r}; known: "
                    + ", ".join(sorted(orchestrator_mod.ORACLE))))

    worker = orchestrator_mod.ORCHESTRATOR
    if not body.process:
        # Accepted but deliberately not processed. Say so plainly rather than
        # returning a success that implies work happened.
        return {"accepted": True, "processed": False,
                "incident_id": body.incident_id,
                "detail": "process=false: accepted for inspection, not driven"}
    if not worker.stats.enabled:
        raise HTTPException(status_code=503,
                            detail="orchestrator is disabled (kill-switch engaged)")
    accepted = worker.submit(body.incident_id, body.scenario, body.telemetry,
                             source="ingest")
    if not accepted:
        return {"accepted": False, "processed": False,
                "incident_id": body.incident_id,
                "detail": ("duplicate incident id (suppressed to keep the audit "
                           "chain free of repeated transitions)")}
    return {"accepted": True, "processed": True,
            "incident_id": body.incident_id,
            "mode": worker.stats.mode,
            "detail": "queued; the orchestrator will drive the real pipeline"}


def http_ingest(body: IngestBody,
                x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    # No Body(...) default: FastAPI binds a Pydantic model parameter from its
    # annotation, and using Body() here would need an import that only exists
    # on the container path.
    return ingest_incident(body, x_api_key)


def orchestrator_state() -> dict[str, Any]:
    """What the worker is doing right now.

    Read-only and unauthenticated on purpose: this is the same class of
    operational telemetry as /meta and /healthz, it exposes no incident data
    beyond an id the caller already supplies, and the UI needs it to tell an
    operator whether the system is live or stalled.
    """
    from app.services import orchestrator as orchestrator_mod
    worker = orchestrator_mod.ORCHESTRATOR
    stats = worker.stats
    return {
        "running": worker.running,
        "enabled": stats.enabled,
        "mode": stats.mode,
        "auto_generate": worker.auto_generate,
        "submitted": stats.submitted,
        "processed": stats.processed,
        "blocked": stats.blocked,
        "stalled": stats.stalled,
        "failed": stats.failed,
        "duplicates_suppressed": stats.duplicates_suppressed,
        "last_incident": stats.last_incident,
        "last_outcome": stats.last_outcome,
        "queue_depth": worker._queue.qsize(),  # noqa: SLF001 - read-only probe
        "note": ("agent reasoning is SCRIPTED-ORACLE unless mode=live-lyzr; "
                 "the validator, policy engine, FSM, sandbox, verifier and "
                 "audit chain are real in both modes, and the worker never "
                 "approves anything"),
    }


def http_state() -> dict[str, Any]:
    return orchestrator_state()


def stop_orchestrator(x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Kill-switch: stop accepting and driving incidents.

    Write-gated, because stopping the control plane is a privileged action. The
    worker is marked disabled first, so an in-flight job cannot re-enable it.
    """
    from app.config import get_settings  # noqa: E402
    from app.routers import auth as auth_mod
    from app.services import orchestrator as orchestrator_mod

    identity = auth_mod.guard_http(
        x_api_key, lambda: get_settings().PROOFOPS_API_KEY, HTTPException)
    try:
        auth_mod.require_role(identity, "operator", "approver", "admin")
    except auth_mod.KeyRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    worker = orchestrator_mod.ORCHESTRATOR
    worker.stats.enabled = False
    return {"stopped": True, "running": worker.running, "enabled": False}


if router is not None:  # container path; host asserts wiring via AST
    router.post("/alerts/ingest")(http_ingest)
    router.get("/orchestrator")(http_state)
    router.post("/orchestrator/stop")(stop_orchestrator)
