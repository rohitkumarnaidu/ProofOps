"""M19a approvals router: thin HITL request/approve/reject over M07 (thin).

Ownership: M19 owns THIS ROUTER (Safety Gate vertical slice). Approving
authority stays M07 (HMAC issue/verify, nonce burn); action SHAPE stays
M01.7; structural pre-check stays M06.1 validator. This router owns ONLY:
request queue (in-memory, M21 persists), demo-role gate (X-Role approver/
admin approves; M21 owns the real guard matrix), TTL countdown data,
Idempotency-Key on approve/reject, and audit event emission into a passed
M15 chain (HTTP layer passes none; M21 wires it).

Fail-closed: client-submitted actions are re-validated as contracts
(schema + validator); unknown ids 404; wrong role 403; bad signature/
scope/actor 403; replay 409; expired 410; empty secret refused at config.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from app.services import approval as approval_svc  # noqa: E402 (M07 tokens)
from app.services.validator import validate_action  # noqa: E402 (M06.1)

try:  # pragma: no cover - container path (pinned deps)
    from fastapi import APIRouter as _APIRouter
    from fastapi import Header as _Header
    from fastapi import HTTPException as _HTTPException
    _APIRouter(prefix="/__probe__")
    router = _APIRouter(tags=["approvals"])
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

APPROVER_ROLES = frozenset({"approver", "admin"})

REQUESTS: dict[str, dict[str, Any]] = {}
NONCES = approval_svc.NonceStore()
IDEM_RESPONSES: dict[tuple[str, str], dict[str, Any]] = {}


class ApprovalMissing(Exception):
    """Unknown approval id (HTTP 404)."""


class ApprovalDenied(Exception):
    """HITL denial: bad role/signature/scope/actor (HTTP 403)."""


class ApprovalReplayed(Exception):
    """Token reuse (HTTP 409)."""


class ApprovalExpired(Exception):
    """Past TTL (HTTP 410)."""


def http_status(exc: Exception) -> int:
    if isinstance(exc, ApprovalMissing):
        return 404
    if isinstance(exc, ApprovalReplayed):
        return 409
    if isinstance(exc, ApprovalExpired):
        return 410
    if isinstance(exc, ApprovalDenied):
        return 403
    if isinstance(exc, ValueError):
        return 422
    return 400


def _entry(approval_id: str) -> dict[str, Any]:
    try:
        return REQUESTS[approval_id]
    except KeyError as exc:
        raise ApprovalMissing(f"unknown approval: {approval_id}") from exc


def _emit(chain: Any, event_type: str, entry: dict[str, Any],
          actor: str, result: str) -> None:
    if chain is None:
        return
    chain.emit(event_type, actor=actor,
               approval_id=entry["request"].approval_id,
               action_id=entry["request"].action_id,
               evidence_ids=list(entry.get("evidence_ids", [])),
               result=result)


def request_approval(action: Mapping[str, Any], actor: str, secret: str,
                     ttl_seconds: int = 600,
                     chain: Any = None) -> dict[str, Any]:
    """Queue one approval request + mint its token (M19a request)."""
    from app.contracts.action import Action  # noqa: E402 (lazy: weight)

    if not isinstance(action, Mapping):
        raise ValueError("action must be a mapping")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor must be a non-empty string")
    try:
        candidate = Action(**dict(action))
    except Exception as exc:
        raise ValueError(f"action rejected by contract: {exc}") from exc
    issues = validate_action(candidate)
    if issues:
        raise ValueError(f"action rejected by validator: {issues}")
    req, token = approval_svc.issue(candidate, actor, secret,
                                    ttl_seconds=ttl_seconds)
    REQUESTS[req.approval_id] = {"request": req, "action": candidate,
                                 "status": "pending",
                                 "evidence_ids": list(
                                     candidate.evidence_ids)}
    _emit(chain, "approval.request", REQUESTS[req.approval_id], actor,
          f"requested {req.action_id}")
    return {"approval_id": req.approval_id, "token": token,
            "status": "pending",
            "expires_at": req.expires_at.isoformat(),
            "scope": req.scope}


def approval_view(approval_id: str, now: float | None = None) -> dict[str, Any]:
    """Status + TTL countdown data for the Safety Gate (M19a view)."""
    entry = _entry(approval_id)
    req = entry["request"]
    ts = time.time() if now is None else float(now)
    remaining = (req.expires_at - datetime.fromtimestamp(
        ts, tz=timezone.utc)).total_seconds()
    return {"approval_id": req.approval_id,
            "incident_id": req.incident_id,
            "action_id": req.action_id, "actor": req.actor,
            "scope": req.scope, "params_hash": req.params_hash,
            "status": entry["status"],
            "expires_at": req.expires_at.isoformat(),
            "seconds_remaining": max(0.0, remaining)}


def _idem(approval_id: str, key: str | None,
          produce: Any) -> dict[str, Any]:
    if key is not None:
        if not isinstance(key, str) or not key.strip():
            raise ValueError("idempotency_key must be a non-empty string")
        cache_key = (approval_id, key)
        if cache_key in IDEM_RESPONSES:
            cached = dict(IDEM_RESPONSES[cache_key])
            cached["duplicate"] = True
            return cached
    view = produce()
    view = dict(view)
    view["duplicate"] = False
    if key is not None:
        IDEM_RESPONSES[(approval_id, key)] = dict(view)
    return view


def approve_approval(approval_id: str, actor: str, token: str, role: str,
                     secret: str, idempotency_key: str | None = None,
                     chain: Any = None) -> dict[str, Any]:
    """Approve (role-gated, token-verified, single-use) (M19a approve)."""
    def _produce() -> dict[str, Any]:
        entry = _entry(approval_id)
        if entry["status"] == "expired":
            raise ApprovalExpired("approval expired")
        if entry["status"] != "pending":
            raise ApprovalDenied(
                f"approval is {entry['status']}, not pending")
        if role not in APPROVER_ROLES:
            raise ApprovalDenied(f"role {role!r} may not approve "
                                 f"(M21 owns the guard matrix)")
        req, action = entry["request"], entry["action"]
        try:
            approval_svc.verify(token, req, action, actor, secret, NONCES)
        except approval_svc.ApprovalError as exc:
            message = str(exc).lower()
            if "expired" in message:
                entry["status"] = "expired"
                _emit(chain, "approval.expire", entry, actor, message)
                raise ApprovalExpired(message) from exc
            if "replay" in message:
                raise ApprovalReplayed(message) from exc
            raise ApprovalDenied(message) from exc
        entry["status"] = "approved"
        _emit(chain, "approval.approve", entry, actor,
              f"approved {req.action_id}")
        return approval_view(approval_id)

    return _idem(approval_id, idempotency_key, _produce)


def reject_approval(approval_id: str, actor: str, role: str,
                    reason: str = "",
                    idempotency_key: str | None = None,
                    chain: Any = None) -> dict[str, Any]:
    """Deny with actor + reason recorded (M19a reject)."""
    def _produce() -> dict[str, Any]:
        entry = _entry(approval_id)
        if entry["status"] != "pending":
            raise ApprovalDenied(
                f"approval is {entry['status']}, not pending")
        if role not in APPROVER_ROLES:
            raise ApprovalDenied(f"role {role!r} may not reject")
        entry["status"] = "denied"
        _emit(chain, "approval.deny", entry, actor,
              reason or "denied by approver")
        return approval_view(approval_id)

    return _idem(approval_id, idempotency_key, _produce)


def sweep_approvals(now: float, chain: Any = None) -> list[str]:
    """Mark past-TTL pendings expired (M19a TTL; escalation is M14)."""
    expired: list[str] = []
    moment = datetime.fromtimestamp(float(now), tz=timezone.utc)
    for approval_id, entry in REQUESTS.items():
        if entry["status"] == "pending" \
                and entry["request"].expires_at <= moment:
            entry["status"] = "expired"
            _emit(chain, "approval.expire", entry,
                  entry["request"].actor, "ttl elapsed")
            expired.append(approval_id)
    return expired


def reset_demo_state() -> None:
    REQUESTS.clear()
    IDEM_RESPONSES.clear()
    NONCES._used.clear()


class ApprovalBody(BaseModel):
    model_config = {"extra": "forbid"}
    action: dict[str, Any]
    actor: str = Field(min_length=1, max_length=128)
    ttl_seconds: int = Field(default=600, ge=1, le=900)


class DecideBody(BaseModel):
    model_config = {"extra": "forbid"}
    actor: str = Field(min_length=1, max_length=128)
    token: str = Field(default="", max_length=512)
    role: str = Field(default="viewer", max_length=32)
    reason: str = Field(default="", max_length=1024)
    idempotency_key: str | None = Field(default=None, max_length=128)


def _guarded(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        raise HTTPException(status_code=http_status(exc),
                            detail=str(exc)) from exc


def _settings_secret() -> str:
    from app.config import get_settings  # noqa: E402 (request-time only)
    return get_settings().APPROVAL_SECRET


def http_request(body: ApprovalBody) -> dict[str, Any]:
    return _guarded(request_approval, body.action, body.actor,
                    _settings_secret(), body.ttl_seconds)


def http_view(approval_id: str) -> dict[str, Any]:
    return _guarded(approval_view, approval_id)


def _require_key(x_api_key: str | None) -> None:
    from app.config import get_settings  # noqa: E402 (request-time only)
    from app.routers import auth as auth_mod
    auth_mod.guard_http(
        x_api_key, lambda: get_settings().PROOFOPS_API_KEY, HTTPException)


def http_approve(approval_id: str, body: DecideBody,
                 x_api_key: str | None = Header(default=None)
                 ) -> dict[str, Any]:
    _require_key(x_api_key)
    return _guarded(approve_approval, approval_id, body.actor, body.token,
                    body.role, _settings_secret(), body.idempotency_key)


def http_reject(approval_id: str, body: DecideBody,
                x_api_key: str | None = Header(default=None)
                ) -> dict[str, Any]:
    _require_key(x_api_key)
    return _guarded(reject_approval, approval_id, body.actor, body.role,
                    body.reason, body.idempotency_key)


if router is not None:  # container path; host asserts wiring via AST
    router.post("/approvals")(http_request)
    router.get("/approvals/{approval_id}")(http_view)
    router.post("/approvals/{approval_id}/approve")(http_approve)
    router.post("/approvals/{approval_id}/reject")(http_reject)
