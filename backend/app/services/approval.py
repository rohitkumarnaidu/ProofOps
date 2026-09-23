"""HMAC approval tokens (M07): identity+scope+param+time bound, single-use.

Token = HMAC-SHA256(secret, action_id|actor|params_hash|scope|expiry|nonce).
verify() enforces: signature, actor match, EXACT params hash, scope match,
expiry, and nonce freshness (replay -> DENY). Never trust the browser:
all checks are server-side. Approval is explicit, action-specific,
identity-bound, scope-bound, time-bound, single-use, auditable.

Nonce durability: NonceStore persists consumed nonces to an append-only
log (path optional; in-memory when None) so a restart cannot resurrect a
burned token. Writes are lock-guarded + fsync'd; the log compacts past
MAX_NONCES via atomic rename.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sys
import tempfile
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any
from collections.abc import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts.action import Action  # noqa: E402 (M01.7 canonical)
from app.contracts.approval import ApprovalRequest  # noqa: E402 (M01.9 canonical)
from app.contracts.incident import FrozenDict  # noqa: E402 (frozen mapping)
from app.contracts.values import params_hash, utcnow  # noqa: E402


class ApprovalError(Exception):
    pass


class NonceStore:
    """Single-use nonces, durable across restarts when a path is given.

    Append-only ``<nonce>\\n`` log (fsync per burn, lock-guarded). Compacts
    atomically past MAX_NONCES. path=None keeps the original in-memory
    behavior (tests, ephemeral use).
    """

    MAX_NONCES = 100000

    def __init__(self, path: str | Path | None = None) -> None:
        self._used: set[str] = set()
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._degraded = False
        self._path = Path(path) if path is not None else None
        if self._path is not None:
            try:
                if self._path.is_file():
                    for line in self._path.read_text(
                            encoding="utf-8").splitlines():
                        nonce = line.strip()
                        if nonce and nonce not in self._used:
                            self._used.add(nonce)
                            self._order.append(nonce)
            except OSError:
                self._path = None  # unwritable disk: memory-only, flagged
                self._degraded = True

    @property
    def persistent(self) -> bool:
        """True when burns survive a restart (file-backed)."""
        return self._path is not None

    @property
    def degraded(self) -> bool:
        """True when durability was lost (R1: fail-LOUD, never silent)."""
        return self._degraded

    def consume(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._used:
                return False
            self._used.add(nonce)
            self._order.append(nonce)
            if self._path is not None:
                try:
                    self._path.parent.mkdir(parents=True, exist_ok=True)
                    with open(self._path, "a", encoding="utf-8") as fh:
                        fh.write(nonce + "\n")
                        fh.flush()
                        os.fsync(fh.fileno())
                    if len(self._used) > self.MAX_NONCES:
                        self._compact_locked()
                except OSError:
                    # Durability best-effort; crypto still denies replays
                    # in-process, but the loss is FLAGGED, never silent.
                    self._degraded = True
            return True

    def _compact_locked(self) -> None:
        """Evict oldest-first, atomically (caller holds the lock)."""
        assert self._path is not None
        keep = self._order[-self.MAX_NONCES:]
        self._used = set(keep)
        self._order = list(keep)
        tmp = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(self._path.parent),
            delete=False)
        try:
            tmp.write("".join(n + "\n" for n in keep))
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp.close()
            os.replace(tmp.name, self._path)
        except OSError:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def clear(self) -> None:
        """Forget all burns (demo/test reset only, never production)."""
        with self._lock:
            self._used.clear()
            self._order.clear()
            if self._path is not None:
                try:
                    self._path.unlink(missing_ok=True)
                except OSError:
                    pass


def scope_of(action: Action) -> str:
    return (f"{action.action_type}:{action.resource_type}:{action.resource_id}:"
            f"{action.environment}:{action.namespace}")


def _params_dict(action: Action) -> dict[str, Any]:
    """Exact parameter set for scope binding (frozen -> plain, detached)."""
    params = action.parameters
    if isinstance(params, FrozenDict):
        return params.to_plain()
    if isinstance(params, Mapping):
        return dict(params)
    raise ApprovalError("parameters must be an object")


def _mac(secret: str, parts: list[str]) -> str:
    return hmac.new(secret.encode(), "|".join(parts).encode(),
                    hashlib.sha256).hexdigest()


def issue(action: Action, actor: str, secret: str,
          ttl_seconds: int = 600) -> tuple[ApprovalRequest, str]:
    """Issue a request + HMAC token. Empty secrets fail closed (fail-closed
    secrets are worse than useless: they mint self-verifying tokens)."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("approval secret must be a non-empty string")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor must be a non-empty string")
    nonce = secrets.token_hex(16)
    expires = utcnow() + timedelta(seconds=ttl_seconds)
    ph = params_hash(_params_dict(action))
    scope = scope_of(action)
    token = _mac(secret, [action.action_id, actor, ph, scope,
                          expires.isoformat(), nonce])
    req = ApprovalRequest(incident_id=action.incident_id,
                          action_id=action.action_id, actor=actor,
                          params_hash=ph, scope=scope,
                          expires_at=expires, nonce=nonce)
    return req, token


def verify(token: str, req: ApprovalRequest, action: Action, actor: str,
           secret: str, store: NonceStore, burn: bool = True
           ) -> ApprovalRequest:
    """Return req on success; raise ApprovalError (=> DENY) otherwise.

    burn=False checks crypto/binding only (permit-minting path, which burns
    its own derived nonce); the approve path always burns.
    """
    if not isinstance(token, str) or not token:
        raise ApprovalError("missing token")
    if utcnow() >= req.expires_at:
        raise ApprovalError("approval expired")
    if actor != req.actor:
        raise ApprovalError("wrong actor")
    if params_hash(_params_dict(action)) != req.params_hash:
        raise ApprovalError("parameters differ from approved scope")
    if scope_of(action) != req.scope or action.action_id != req.action_id:
        raise ApprovalError("scope mismatch")
    expect = _mac(secret, [req.action_id, req.actor, req.params_hash,
                           req.scope, req.expires_at.isoformat(), req.nonce])
    if not hmac.compare_digest(expect, token):
        raise ApprovalError("bad signature")
    if burn and not store.consume(req.nonce):
        raise ApprovalError("token replayed")
    return req
