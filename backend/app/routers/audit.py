"""M15b audit router: chain view + verify + export (thin translation).

Same pattern as routers/runs.py: pure functions carry the logic (host-safe
unit tests); @router registration is guarded for the host starlette drift
and asserted via AST. No chain logic here.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from app.services import audit as audit_svc  # noqa: E402 (M15 chain)

try:  # pragma: no cover - container path (pinned deps)
    from fastapi import APIRouter as _APIRouter
    from fastapi import Header as _Header
    from fastapi import HTTPException as _HTTPException
    _APIRouter(prefix="/__probe__")
    router = _APIRouter(tags=["audit"])
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

CHAINS: dict[str, audit_svc.AuditChain] = {}

#: Persisted-chain directory (repo ``var/``, gitignored). Filenames are
#: ``audit-<incident_id>.jsonl`` with the id sanitized by the service;
#: unsanitizable ids stay memory-only (no traversal, fail-closed files).
_VAR_DIR = Path(__file__).resolve().parents[3] / "var"


def _chain_path(incident_id: str) -> Path | None:
    """File for one incident's chain, or None when unpersistable."""
    try:
        safe = audit_svc.sanitize_incident_id(incident_id)
    except (audit_svc.AuditError, TypeError, ValueError):
        return None
    return _VAR_DIR / f"audit-{safe}.jsonl"


def persist_chain(chain: audit_svc.AuditChain) -> None:
    """Rewrite one router-managed chain to disk (atomic tmp+rename)."""
    path = _chain_path(chain.incident_id)
    if path is None:
        return
    chain.save(path)


class AuditMissing(Exception):
    """Unknown incident chain (HTTP 404)."""


def get_chain(incident_id: str) -> audit_svc.AuditChain:
    try:
        return CHAINS[incident_id]
    except KeyError as exc:
        raise AuditMissing(f"no audit chain: {incident_id}") from exc


def chain_view(incident_id: str) -> dict[str, Any]:
    """Chain + validity bool (spec S32 GET /incidents/{id}/audit)."""
    chain = get_chain(incident_id)
    verdict = chain.verify()
    return {"origin": audit_svc.ORIGIN, "incident_id": incident_id,
            "valid": verdict["valid"], "checked": verdict["checked"],
            "events": [e.model_dump(mode="json") for e in chain.events]}


def verify_view(incident_id: str) -> dict[str, Any]:
    chain = get_chain(incident_id)
    return {"incident_id": incident_id, **chain.verify()}


def export_view(incident_id: str) -> dict[str, Any]:
    return get_chain(incident_id).export()


def reset_demo_state() -> None:
    """Clear memory AND persisted chain files (demo/test-only).

    Test isolation depends on both layers clearing together: without file
    deletion, one test's ``var/audit-*.jsonl`` would leak into the next
    test's ``get_or_create_chain`` load. Never call in production.
    """
    CHAINS.clear()
    try:
        for path in _VAR_DIR.glob("audit-*.jsonl*"):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
    except OSError:
        pass


class EmitBody(BaseModel):
    model_config = {"extra": "forbid"}
    event_type: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)
    agent: str = Field(default="", max_length=128)
    input_hash: str = Field(default="", max_length=256)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    policy: dict[str, Any] | None = None
    action_id: str = Field(default="", max_length=128)
    approval_id: str = Field(default="", max_length=128)
    execution_id: str = Field(default="", max_length=128)
    result: str = Field(default="", max_length=1024)


def _guarded(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except AuditMissing as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except audit_svc.AuditError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _chain_of(incident_id: str) -> audit_svc.AuditChain:
    return get_or_create_chain(incident_id)


def get_or_create_chain(incident_id: str) -> audit_svc.AuditChain:
    """Serving-path chain accessor (P0-2: HTTP layers chain, never None).

    Loads from ``var/audit-<incident_id>.jsonl`` when memory misses (P1:
    chains survive restarts). A corrupt/tampered file raises AuditError --
    never silently starts empty. Missing file (or unpersistable id) starts
    a fresh in-memory chain.
    """
    if incident_id not in CHAINS:
        path = _chain_path(incident_id)
        if path is not None and path.is_file():
            # AuditError (corrupt/tampered) propagates: fail-closed reload.
            CHAINS[incident_id] = audit_svc.AuditChain.load(
                incident_id, path)
        else:
            CHAINS[incident_id] = audit_svc.AuditChain(incident_id=incident_id)
    return CHAINS[incident_id]


def http_emit(incident_id: str, body: EmitBody,
              x_api_key: str | None = Header(default=None)
              ) -> dict[str, Any]:
    """External appends require the demo key (P1: no open chain pollution)."""
    from app.config import get_settings  # noqa: E402 (request-time only)
    from app.routers import auth as auth_mod
    auth_mod.guard_http(
        x_api_key, lambda: get_settings().PROOFOPS_API_KEY, HTTPException)
    event = _guarded(_chain_of(incident_id).emit, body.event_type,
                     actor=body.actor, agent=body.agent,
                     input_hash=body.input_hash,
                     evidence_ids=body.evidence_ids, policy=body.policy,
                     action_id=body.action_id, approval_id=body.approval_id,
                     execution_id=body.execution_id, result=body.result)
    _guarded(persist_chain, _chain_of(incident_id))
    return event.model_dump(mode="json")


def http_view(incident_id: str) -> dict[str, Any]:
    return _guarded(chain_view, incident_id)


def http_verify(incident_id: str) -> dict[str, Any]:
    return _guarded(verify_view, incident_id)


def http_export(incident_id: str) -> dict[str, Any]:
    return _guarded(export_view, incident_id)


if router is not None:  # container path; host asserts wiring via AST
    router.get("/incidents/{incident_id}/audit")(http_view)
    router.post("/incidents/{incident_id}/audit/verify")(http_verify)
    router.get("/incidents/{incident_id}/audit/export")(http_export)
    router.post("/incidents/{incident_id}/audit/events")(http_emit)
