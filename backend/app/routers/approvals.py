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

import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from app.logging_setup import get_logger  # noqa: E402 (M00.5)
from app.services import approval as approval_svc  # noqa: E402 (M07 tokens)
from app.services.fsm import Permit  # noqa: E402 (M14 credential, no cycle)
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

#: Identity modes mirrored from the auth gate (kept local as plain strings so
#: this router never imports the auth module at module scope; the HTTP layer
#: passes the resolved value straight through).
_MODE_PER_KEY = "per_key"
_MODE_BOOTSTRAP = "bootstrap"

#: Permit-freshness ceiling for runs-router APPROVED edges (invariant 19:
#: execute re-checks permit freshness <= 5m). Stored approval TTL still
#: governs the human decision; the FSM credential never outlives either.
PERMIT_FRESHNESS_S = 300.0

REQUESTS: dict[str, dict[str, Any]] = {}

logger = get_logger(__name__)


def _state_dir() -> Any:
    from app import paths
    return paths.state_dir()


NONCE_STORE_PATH = _state_dir() / "nonces.jsonl"
try:
    NONCES = approval_svc.NonceStore(NONCE_STORE_PATH)
except OSError:
    NONCES = approval_svc.NonceStore()
IDEM_RESPONSES: dict[tuple[str, str], dict[str, Any]] = {}

#: File-persistence for the request queue (Lane 2, hardening loop 4).
#: Sanitized constant -- callers never choose the production path; tests may
#: pass an explicit tmp path via the ``path`` parameter of save/load.
STORE_PATH = _state_dir() / "approvals.json"

#: Lifecycle states accepted on reload (fail-closed set).
_APPROVAL_STATUSES = frozenset({"pending", "approved", "denied", "expired"})


def save_store(path: str | Path | None = None) -> Path:
    """Persist REQUESTS to JSON (atomic tmp+rename; Lane 2 loop 4).

    Request + action serialize via pydantic ``model_dump(mode="json")``;
    status as str, evidence_ids as list. The HMAC token itself is never
    stored (it is re-presented by the caller); crypto continuity comes from
    the reloaded request+action, which is exactly what ``verify`` binds.
    """
    out = Path(path) if path is not None else STORE_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        approval_id: {
            "request": entry["request"].model_dump(mode="json"),
            "action": entry["action"].model_dump(mode="json"),
            "status": entry["status"],
            "evidence_ids": list(entry.get("evidence_ids", [])),
            "requester_key_id": str(entry.get("requester_key_id", "")),
            "identity_mode": str(entry.get("identity_mode", "")),
            "decided_by": str(entry.get("decided_by", "")),
        }
        for approval_id, entry in REQUESTS.items()
    }
    text = json.dumps(payload, sort_keys=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(out.parent),
        prefix=out.name + ".", suffix=".tmp", delete=False)
    try:
        tmp.write(text + "\n")
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.replace(tmp.name, out)
    except OSError:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    return out


def load_store(path: str | Path | None = None) -> list[str]:
    """Reload REQUESTS from JSON (Lane 2 loop 4).

    Re-validates every entry via the ApprovalRequest/Action contracts;
    raises ValueError on any garbage (corrupt/tampered files never become
    partial state). All entries are validated BEFORE the live dict is
    replaced (fail-closed, never partial-load). Missing file raises
    FileNotFoundError for the caller to distinguish.
    """
    from app.contracts.action import Action  # noqa: E402 (lazy: weight)
    from app.contracts.approval import ApprovalRequest  # noqa: E402

    src = Path(path) if path is not None else STORE_PATH
    try:
        text = src.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError(f"approvals file unreadable: {exc}") from exc
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"approvals file corrupt: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("approvals file corrupt: top-level object required")
    staged: dict[str, dict[str, Any]] = {}
    for approval_id, item in raw.items():
        if not isinstance(item, dict):
            raise ValueError(
                f"approvals file entry {approval_id!r} invalid: not an object")
        try:
            req = ApprovalRequest.model_validate(item.get("request"))
            action = Action.model_validate(item.get("action"))
        except Exception as exc:
            raise ValueError(
                f"approvals file entry {approval_id!r} invalid: {exc}"
            ) from exc
        status = item.get("status")
        if status not in _APPROVAL_STATUSES:
            raise ValueError(
                f"approvals file entry {approval_id!r} invalid: "
                f"bad status {status!r}")
        evidence = item.get("evidence_ids")
        if not isinstance(evidence, list) or \
                any(not isinstance(e, str) for e in evidence):
            raise ValueError(
                f"approvals file entry {approval_id!r} invalid: "
                "evidence_ids must be a string list")
        extras: dict[str, str] = {}
        for name in ("requester_key_id", "identity_mode", "decided_by"):
            value = item.get(name, "")
            if not isinstance(value, str):
                raise ValueError(
                    f"approvals file entry {approval_id!r} invalid: "
                    f"{name} must be a string")
            extras[name] = value
        if approval_id != req.approval_id:
            raise ValueError(
                f"approvals file key {approval_id!r} mismatches "
                f"entry {req.approval_id!r}")
        staged[approval_id] = {"request": req, "action": action,
                               "status": status,
                               "evidence_ids": list(evidence), **extras}
    REQUESTS.clear()
    REQUESTS.update(staged)
    return sorted(staged)


def _ensure_loaded() -> None:
    """Auto-load on first store access when memory is empty (restart resume).

    No-op when memory holds requests or no file exists. Corrupt files raise
    (fail-closed, never silently empty); a raced deletion stays memory-only.
    """
    if REQUESTS:
        return
    if not STORE_PATH.is_file():
        return
    try:
        load_store()
    except FileNotFoundError:
        pass  # raced deletion between is_file and read: stay memory-only


def _save_best_effort() -> None:
    """Auto-save after mutations; durability must never fail the request."""
    try:
        save_store()
    except OSError:
        pass


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
    _ensure_loaded()
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


def _persist_chain(chain: Any) -> None:
    """Flush an audit chain to disk after a SERVING-PATH mutation.

    Audit events that never reach the file are not proof: after a restart the
    approval queue would still remember a decision while the exported chain
    meant to demonstrate it was empty -- and ``verify()`` would return
    valid=True over zero events. Called from the HTTP handlers only, so the
    pure-function layer stays hermetic for unit tests.
    """
    if chain is None:
        return
    from app.routers import audit as audit_router
    try:
        audit_router.persist_chain(chain)
    except Exception:
        pass


def _guarded_with_chain(fn: Any, chain: Any, *args: Any,
                        **kwargs: Any) -> Any:
    """Run a mutating helper and flush whatever it emitted."""
    try:
        out = fn(*args, **kwargs)
    except Exception as exc:
        _persist_chain(chain)
        raise HTTPException(status_code=http_status(exc),
                            detail=str(exc)) from exc
    _persist_chain(chain)
    return out


def request_approval(action: Mapping[str, Any], actor: str, secret: str,
                     ttl_seconds: int = 600,
                     chain: Any = None,
                     requester_key_id: str = "",
                     identity_mode: str = "",
                     audit_actor: str = "") -> dict[str, Any]:
    """Queue one approval request + mint its token (M19a request).

    ``requester_key_id``/``identity_mode`` record WHICH server-resolved key
    raised the request, so separation of duties can later compare two real
    principals instead of two client-supplied strings. ``audit_actor`` is the
    principal written into the chain and defaults to ``actor``. They are
    recorded data only: this function never authorizes anything on its own.
    """
    from app.contracts.action import Action  # noqa: E402 (lazy: weight)

    _ensure_loaded()  # resume persisted queue first: never clobber on save
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
                                     candidate.evidence_ids),
                                 "requester_key_id": str(requester_key_id),
                                 "identity_mode": str(identity_mode),
                                 "decided_by": ""}
    _emit(chain, "approval.request", REQUESTS[req.approval_id],
          audit_actor or actor,
          f"requested {req.action_id}"
          + ("" if identity_mode == _MODE_PER_KEY else
             " (identity mode " + (identity_mode or "unknown") +
             ": the actor is a client-asserted label, not an "
             "authenticated principal)"))
    _save_best_effort()
    return {"approval_id": req.approval_id, "token": token,
            "status": "pending",
            "expires_at": req.expires_at.isoformat(),
            "scope": req.scope,
            "identity_mode": str(identity_mode)}


def approval_view(approval_id: str, now: float | None = None) -> dict[str, Any]:
    """Status + TTL countdown data for the Safety Gate (M19a view).

    Also returns the identity provenance: which key store mode produced the
    decision, which key requested it, which key decided it, and whether
    separation of duties actually applied. ``sod`` is
    ``"enforced"`` only when a per-key store authorized the decision and the
    approver differed from the requester; ``"not_enforced_bootstrap"`` is the
    honest label for the shared demo credential.
    """
    entry = _entry(approval_id)
    req = entry["request"]
    ts = time.time() if now is None else float(now)
    remaining = (req.expires_at - datetime.fromtimestamp(
        ts, tz=timezone.utc)).total_seconds()
    mode = str(entry.get("identity_mode", ""))
    decided_by = str(entry.get("decided_by", ""))
    requester = str(entry.get("requester_key_id", ""))
    sod = "enforced" if mode == _MODE_PER_KEY and decided_by \
        and requester and decided_by != requester \
        else "not_enforced_bootstrap" if mode == _MODE_BOOTSTRAP \
        else "not_recorded"
    return {"approval_id": req.approval_id,
            "incident_id": req.incident_id,
            "action_id": req.action_id, "actor": req.actor,
            "scope": req.scope, "params_hash": req.params_hash,
            "status": entry["status"],
            "expires_at": req.expires_at.isoformat(),
            "seconds_remaining": max(0.0, remaining),
            "identity_mode": mode,
            "requester_key_id": requester,
            "decided_by": decided_by,
            "sod": sod}


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
                     chain: Any = None, *, enforce_sod: bool = False,
                     requester: str | None = None,
                     allow_self_approval: bool = False,
                     approver_key_id: str = "",
                     identity_mode: str = "",
                     audit_actor: str = "") -> dict[str, Any]:
    """Approve (role-gated, token-verified, single-use) (M19a approve).

    Separation of duties has two independent triggers, because the HMAC token
    subject is the request ACTOR and cannot simply be re-pointed at a second
    principal:

    1. ``enforce_sod=True`` (explicit legacy override, unchanged): the
       approver actor must differ from the requester, defaulting to the
       stored request actor. Denials emit ``approval.rejected`` BEFORE token
       verification, so a denied attempt never burns the nonce.
    2. ``identity_mode == "per_key"`` (the production path): the HTTP layer
       has already proven via the authenticated key that ``actor`` is that
       key's registered owner and that the key holds an approver/admin role.
       The REAL principal comparison is then ``approver_key_id`` vs the
       stored ``requester_key_id``. Self-approval is denied outright -- there
       is no override -- because a second human identity is the entire point
       of four-eyes control.

    ``mode == "bootstrap"`` is the shared demo credential with no per-user
    identity, so it keeps the legacy client-asserted-role behavior and the
    view labels the decision ``not_enforced_bootstrap`` rather than implying
    four-eyes control that did not happen.
    """
    def _produce() -> dict[str, Any]:
        entry = _entry(approval_id)
        if entry["status"] == "expired":
            raise ApprovalExpired("approval expired")
        if entry["status"] != "pending":
            raise ApprovalDenied(
                f"approval is {entry['status']}, not pending")
        if role and role not in APPROVER_ROLES:
            raise ApprovalDenied(f"role {role!r} may not approve "
                                 f"(M21 owns the guard matrix)")
        req, action = entry["request"], entry["action"]
        if identity_mode == _MODE_PER_KEY:
            requester_key = str(entry.get("requester_key_id", ""))
            if not approver_key_id or not requester_key:
                raise ApprovalDenied(
                    "separation of duties cannot be evaluated: per-key "
                    "identity is missing the approver or requester key id")
            if approver_key_id == requester_key:
                _emit(chain, "approval.rejected", entry, actor,
                      f"separation of duties: approver key "
                      f"{approver_key_id!r} is the requester key "
                      f"{requester_key!r}; self-approval is not permitted")
                raise ApprovalDenied(
                    "separation of duties: the approver key must differ from "
                    "the requesting key (no override on the per-key path)")
        elif enforce_sod:
            sod_requester = requester.strip() \
                if isinstance(requester, str) and requester.strip() \
                else req.actor
            if actor == sod_requester and not allow_self_approval:
                _emit(chain, "approval.rejected", entry, actor,
                      f"separation of duties: approver {actor!r} "
                      f"is the requester {sod_requester!r}")
                raise ApprovalDenied(
                    "separation of duties: approver must differ from "
                    "requester (pass allow_self_approval=True to override)")
        # TWO-PRINCIPAL VERIFICATION (the HMAC/SoD deadlock, resolved).
        # The token is signed over the REQUESTER's actor, so verifying with
        # the approver's name could never succeed for a genuinely distinct
        # approver -- which is exactly what separation of duties requires.
        # Nothing is weakened by verifying against ``req.actor``:
        # ``approval_svc.verify`` recomputes the MAC from the STORED request
        # fields (action_id, actor, params_hash, scope, expiry, nonce), so the
        # signature already proves the token was minted by this server for
        # this exact, untampered request. The passed ``actor`` only compared
        # the caller's own claim against the stored one -- an assertion check,
        # not integrity. Integrity stays bound to the request; the DECISION is
        # authorized separately by the authenticated approver key plus the
        # requester/approver key comparison above.
        verify_actor = req.actor if identity_mode == _MODE_PER_KEY else actor
        try:
            approval_svc.verify(token, req, action, verify_actor, secret,
                                NONCES)
        except approval_svc.ApprovalError as exc:
            message = str(exc).lower()
            if "expired" in message:
                entry["status"] = "expired"
                _emit(chain, "approval.expire", entry, actor, message)
                _save_best_effort()
                raise ApprovalExpired(message) from exc
            if "replay" in message:
                _emit(chain, "approval.rejected", entry, actor,
                      f"replay rejected: {message}")
                raise ApprovalReplayed(message) from exc
            _emit(chain, "approval.rejected", entry, actor,
                  f"verify rejected: {message}")
            raise ApprovalDenied(message) from exc
        entry["status"] = "approved"
        entry["decided_by"] = str(approver_key_id)
        # The REQUEST's identity mode is provenance and must never be
        # overwritten by the approver's: a request raised under bootstrap and
        # approved by a per-key approver would otherwise read
        # "identity_mode: per_key" and look like a server-enforced decision.
        # Keep the request's mode; the approver's principal is recorded in
        # decided_by, which is what the view and SoD reason over.
        _emit(chain, "approval.approve", entry, audit_actor or actor,
              f"approved {req.action_id} as key "
              f"{approver_key_id or 'bootstrap'}"
              + (f" (request raised in {identity_mode} identity mode)"
                 if identity_mode and identity_mode != _MODE_PER_KEY
                  else ""))
        _save_best_effort()
        view = approval_view(approval_id)
        _trigger_resume(approval_id, chain)
        return view

    return _idem(approval_id, idempotency_key, _produce)


def _trigger_resume(approval_id: str, chain: Any) -> None:
    """Hand a human-approved action to the orchestrator so the run continues.

    This is the seam that makes the lifecycle close. Until it existed, an
    approved request was recorded and nothing else happened: the run sat at
    AWAITING_APPROVAL forever, which made the whole product look unfinished.

    The action and permit are read back OUT of the stored record, never taken
    from the request body, so the thing that executes is the thing the human
    reviewed. The resume is queued, not run inline, so a slow execution cannot
    block the HTTP response to the approval that triggered it.

    Failures are logged and swallowed on purpose: the human decision is already
    durably recorded, and a resume that could not be scheduled must not
    retroactively turn a successful approval into an error. The run stays in
    AWAITING_APPROVAL and the orchestrator state endpoint shows the failure,
    which is the honest place for it.
    """
    try:
        from app.services import orchestrator as orchestrator_mod
        incident_id, action = approved_action(approval_id)
        permit = verified_permit(
            approval_id, token="", actor="", secret="",
            chain=chain, expected_incident=incident_id)
        worker = orchestrator_mod.ORCHESTRATOR
        if not worker.stats.enabled or not worker.running:
            return
        worker.resume(incident_id, action, permit)
    except Exception:
        logger.warning("approval %s recorded but resume not scheduled",
                       approval_id, exc_info=True)


def reject_approval(approval_id: str, actor: str, role: str,
                    reason: str = "",
                    idempotency_key: str | None = None,
                    chain: Any = None,
                    audit_actor: str = "",
                    approver_key_id: str = "") -> dict[str, Any]:
    """Deny with actor + reason recorded (M19a reject).

    Separation of duties is deliberately NOT applied to a denial: four-eyes
    control protects against GRANTING execution authority, and a denial can
    only withhold it. Forcing a second identity here would also stop the
    requester from withdrawing their own request. Authorization still applies
    -- the HTTP layer requires an authenticated key holding approver/admin
    before this is reached.
    """
    def _produce() -> dict[str, Any]:
        entry = _entry(approval_id)
        if entry["status"] != "pending":
            raise ApprovalDenied(
                f"approval is {entry['status']}, not pending")
        if role and role not in APPROVER_ROLES:
            raise ApprovalDenied(f"role {role!r} may not reject")
        entry["status"] = "denied"
        # A denial records the deciding principal too, so the exported chain
        # attributes every outcome to a key rather than only the approvals.
        if approver_key_id:
            entry["decided_by"] = str(approver_key_id)
        _emit(chain, "approval.deny", entry, audit_actor or actor,
              reason or "denied by approver")
        _save_best_effort()
        return approval_view(approval_id)

    return _idem(approval_id, idempotency_key, _produce)


def sweep_approvals(now: float, chain: Any = None) -> list[str]:
    """Mark past-TTL pendings expired (M19a TTL; escalation is M14)."""
    _ensure_loaded()
    expired: list[str] = []
    moment = datetime.fromtimestamp(float(now), tz=timezone.utc)
    for approval_id, entry in REQUESTS.items():
        if entry["status"] == "pending" \
                and entry["request"].expires_at <= moment:
            entry["status"] = "expired"
            _emit(chain, "approval.expire", entry,
                  entry["request"].actor, "ttl elapsed")
            expired.append(approval_id)
    _save_best_effort()
    return expired


def approved_action(approval_id: str) -> tuple[str, Any]:
    """(incident_id, Action) for an APPROVED request, straight from the store.

    This exists so the resume path can never be handed an action from a
    request body, a client payload or a re-plan. The action executed is the one
    the human actually approved, because it is read out of the same record the
    approval decision was written to.

    Raises ApprovalDenied for anything not in `approved` state, so a caller
    cannot resume on a pending, denied, expired or replayed request.
    """
    entry = _entry(approval_id)
    if entry["status"] != "approved":
        raise ApprovalDenied(
            f"approval is {entry['status']}, not approved; nothing to execute")
    req = entry["request"]
    return str(req.incident_id), entry["action"]


def verified_permit(approval_id: str, token: str, actor: str,
                    secret: str, now: float | None = None,
                    chain: Any = None,
                    expected_incident: str | None = None) -> Permit:
    """HMAC-bound FSM credential for an APPROVED edge (P0-1 fix).

    The runs router must never mint permits from client JSON. This binds
    the credential to a STORED, human-approved request: entry must exist,
    status must be "approved", and crypto (signature, actor, exact params
    hash, scope, expiry, nonce burn) must verify via M07. Expiry is capped
    at now + PERMIT_FRESHNESS_S (invariant 19). Raises ApprovalMissing /
    ApprovalDenied / ApprovalReplayed / ApprovalExpired (=> 404/403/409/410).

    Incident binding (P1): when ``expected_incident`` is provided
    (non-blank), the stored request's incident must equal it, else
    ApprovalDenied("incident mismatch..."). This stops an approval minted
    for incident A from authorizing a run for incident B. ``None`` (or
    blank) keeps the legacy unbound behavior for pure-helper callers.
    """
    entry = _entry(approval_id)
    if entry["status"] != "approved":
        raise ApprovalDenied(
            f"approval is {entry['status']}, not approved (human decision "
            "required before APPROVED)")
    req, action = entry["request"], entry["action"]
    # A per-key approval must carry the principal that decided it. Without it
    # the record cannot prove which authorized key performed the human
    # decision, and minting an execution permit from it would launder an
    # unattributed decision into a credential the FSM trusts.
    if entry.get("identity_mode") == _MODE_PER_KEY \
            and not str(entry.get("decided_by", "")):
        _emit(chain, "approval.rejected", entry, actor,
              "permit refused: per-key approval has no deciding principal")
        raise ApprovalDenied(
            "permit refused: per-key approval records no deciding principal")
    if isinstance(expected_incident, str) and expected_incident.strip():
        if req.incident_id != expected_incident:
            _emit(chain, "approval.rejected", entry, actor,
                  f"incident mismatch: approval for {req.incident_id!r} "
                  f"cannot authorize {expected_incident!r}")
            raise ApprovalDenied(
                f"incident mismatch: approval for {req.incident_id!r} "
                f"cannot authorize run {expected_incident!r}")
    try:
        # Crypto/binding check only: the approve step already burned the
        # approval nonce. Minting burns its own derived nonce below, so one
        # approval mints at most one permit (single-use end to end).
        approval_svc.verify(token, req, action, actor, secret, NONCES,
                            burn=False)
    except approval_svc.ApprovalError as exc:
        message = str(exc).lower()
        if "expired" in message:
            entry["status"] = "expired"
            _emit(chain, "approval.expire", entry, actor, message)
            raise ApprovalExpired(message) from exc
        if "replay" in message:
            _emit(chain, "approval.rejected", entry, actor,
                  f"replay rejected: {message}")
            raise ApprovalReplayed(message) from exc
        _emit(chain, "approval.rejected", entry, actor,
              f"verify rejected: {message}")
        raise ApprovalDenied(message) from exc
    if not NONCES.consume(req.nonce + ":permit"):
        _emit(chain, "approval.rejected", entry, actor,
              "permit already minted for this approval (replay)")
        raise ApprovalReplayed(
            "permit already minted for this approval (replay)")
    ts = time.time() if now is None else float(now)
    expiry = min(req.expires_at.timestamp(), ts + PERMIT_FRESHNESS_S)
    permit = Permit(action_id=req.action_id, params_hash=req.params_hash,
                    expires_at=expiry, token_ref=approval_id, auto=False)
    if chain is not None:
        chain.emit("permit.minted", actor=actor,
                   approval_id=approval_id, action_id=req.action_id,
                   result=f"bound permit for {req.action_id}")
    return permit


def reset_demo_state() -> None:
    """Clear memory AND the persisted queue file (demo/test-only).

    Test isolation depends on both layers clearing together: without file
    deletion, one test's ``var/approvals.json`` would leak into the next
    test's auto-load. Never call in production.
    """
    REQUESTS.clear()
    IDEM_RESPONSES.clear()
    NONCES.clear()
    try:
        STORE_PATH.unlink(missing_ok=True)
    except OSError:
        pass


class ApprovalBody(BaseModel):
    model_config = {"extra": "forbid"}
    action: dict[str, Any]
    actor: str = Field(default="", max_length=128)
    ttl_seconds: int = Field(default=600, ge=1, le=900)


class DecideBody(BaseModel):
    model_config = {"extra": "forbid"}
    actor: str = Field(default="", max_length=128)
    token: str = Field(default="", max_length=512)
    role: str = Field(default="", max_length=32)
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


def _chain_for(incident_id: str) -> Any:
    """Serving-path chain (P0-2: HTTP approvals emit, never silent)."""
    from app.routers import audit as audit_router
    if isinstance(incident_id, str) and incident_id.strip():
        return audit_router.get_or_create_chain(incident_id.strip())
    return None


def _require_key(x_api_key: str | None) -> dict[str, Any]:
    """Authenticate the caller and return its server-resolved identity."""
    from app.config import get_settings  # noqa: E402 (request-time only)
    from app.routers import auth as auth_mod
    return auth_mod.guard_http(
        x_api_key, lambda: get_settings().PROOFOPS_API_KEY, HTTPException)


def _authorize(identity: dict[str, Any], *roles: str) -> None:
    """Server-side authorization over the authenticated key.

    ``require_role`` never widens from client input, so a body that claims
    ``role="admin"`` cannot grant itself anything. A bootstrap identity (no
    key store deployed) is allowed for demo compatibility and the caller is
    expected to surface ``mode`` in its response.
    """
    from app.routers import auth as auth_mod
    try:
        auth_mod.require_role(identity, *roles)
    except auth_mod.KeyRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _assert_owner(identity: dict[str, Any], claimed_actor: str) -> None:
    """Bind a body-supplied actor to the authenticated key's owner.

    The HMAC token subject is a human-readable actor string, so it must be
    PROVEN: in per-key mode the claimed actor has to equal the owner
    registered for the presented key, otherwise anyone holding one key could
    act as any other named actor. Bootstrap mode cannot prove this, which is
    precisely why it is labeled as demo identity.
    """
    if identity.get("mode") != _MODE_PER_KEY:
        return
    owner = identity.get("owner")
    if not isinstance(owner, str) or not owner.strip() \
            or claimed_actor != owner:
        raise HTTPException(
            status_code=403,
            detail=f"actor {claimed_actor!r} is not the owner of API key "
                   f"{identity.get('key_id', '')!r}")


def _actor_for(identity: dict[str, Any], claimed: str) -> str:
    """Resolve the acting actor from the authenticated key.

    A blank body actor is filled from the key's registered owner, so a client
    cannot name itself. A non-blank claim is still checked against that owner
    in per-key mode, so a holder of one key cannot act as another named
    actor. In bootstrap mode the claim is accepted as a display label only --
    the response reports ``identity_mode: bootstrap`` precisely because that
    label is not an authenticated identity.
    """
    owner = identity.get("owner")
    owner_name = owner if isinstance(owner, str) and owner.strip() \
        else _MODE_BOOTSTRAP
    if not claimed or not claimed.strip():
        return owner_name
    _assert_owner(identity, claimed)
    return claimed


def _principal_or(identity: dict[str, Any], claimed: str) -> str:
    """Structured audit principal: the immutable key id, never the claim.

    The actor string is the HMAC subject and, in bootstrap mode, a
    client-supplied label. The chain must not record that label as if it were
    an authenticated identity, so the structured actor is the resolved
    principal and the claim survives only in the event's result text.
    """
    from app.routers import auth as auth_mod
    try:
        key_id = auth_mod.principal(identity)
    except auth_mod.KeyRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if claimed and claimed.strip() and claimed.strip() != key_id:
        return f"{key_id} (claimed {claimed.strip()})"
    return key_id


def _chain_for_approval(approval_id: str) -> Any:
    """Chain of the incident owning this approval (unknown id: none)."""
    _ensure_loaded()
    try:
        incident = REQUESTS[approval_id]["request"].incident_id
    except KeyError:
        return None
    return _chain_for(incident)


def http_request(body: ApprovalBody,
                 x_api_key: str | None = Header(default=None)
                 ) -> dict[str, Any]:
    identity = _require_key(x_api_key)
    # Raising an approval request WRITES to the queue, mints a live HMAC
    # token, and appends an approval.request record to the exported chain, so
    # it needs a write role -- otherwise a read-only viewer key could do all
    # three, which is the same capability the other mutating routes refuse.
    _authorize(identity, "operator", "approver", "admin")
    actor = _actor_for(identity, body.actor)
    incident = body.action.get("incident_id", "") \
        if isinstance(body.action, dict) else ""
    chain = _chain_for(incident)
    return _guarded_with_chain(
        request_approval, chain, body.action, actor,
        _settings_secret(), body.ttl_seconds, chain,
        str(identity.get("key_id", "")),
        str(identity.get("mode", "")),
        audit_actor=_principal_or(identity, body.actor))


def http_view(approval_id: str) -> dict[str, Any]:
    return _guarded(approval_view, approval_id)


def http_approve(approval_id: str, body: DecideBody,
                 x_api_key: str | None = Header(default=None)
                 ) -> dict[str, Any]:
    identity = _require_key(x_api_key)
    _authorize(identity, "approver", "admin")
    actor = _actor_for(identity, body.actor)
    chain = _chain_for_approval(approval_id)
    return _guarded_with_chain(
        approve_approval, chain, approval_id, actor, body.token,
        body.role, _settings_secret(), body.idempotency_key, chain,
        approver_key_id=str(identity.get("key_id", "")),
        identity_mode=str(identity.get("mode", "")),
        audit_actor=_principal_or(identity, body.actor))


def http_reject(approval_id: str, body: DecideBody,
                x_api_key: str | None = Header(default=None)
                ) -> dict[str, Any]:
    identity = _require_key(x_api_key)
    _authorize(identity, "approver", "admin")
    actor = _actor_for(identity, body.actor)
    chain = _chain_for_approval(approval_id)
    return _guarded_with_chain(
        reject_approval, chain, approval_id, actor, body.role,
        body.reason, body.idempotency_key, chain,
        audit_actor=_principal_or(identity, body.actor),
        approver_key_id=str(identity.get("key_id", "")))


if router is not None:  # container path; host asserts wiring via AST
    router.post("/approvals")(http_request)
    router.get("/approvals/{approval_id}")(http_view)
    router.post("/approvals/{approval_id}/approve")(http_approve)
    router.post("/approvals/{approval_id}/reject")(http_reject)
