"""HMAC approval tokens: identity+scope+param+time bound, single-use (V2 §27).

Token = HMAC-SHA256(secret, action_id|actor|params_hash|scope|expiry|nonce).
verify() enforces: signature, actor match, EXACT params hash, scope match,
expiry, and nonce freshness (replay -> DENY). Never trust the browser:
all checks are server-side. RULE 08/09.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.schemas import Action, ApprovalRequest, params_hash, utcnow  # noqa: E402


class ApprovalError(Exception):
    pass


class NonceStore:
    """Single-use nonces. In-memory for hackathon; Postgres table in V1."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def consume(self, nonce: str) -> bool:
        if nonce in self._used:
            return False
        self._used.add(nonce)
        return True


def scope_of(action: Action) -> str:
    return (f"{action.action_type}:{action.resource_type}:{action.resource_id}:"
            f"{action.environment}:{action.namespace}")


def _mac(secret: str, parts: list[str]) -> str:
    return hmac.new(secret.encode(), "|".join(parts).encode(),
                    hashlib.sha256).hexdigest()


def issue(action: Action, actor: str, secret: str,
          ttl_seconds: int = 600) -> tuple[ApprovalRequest, str]:
    nonce = secrets.token_hex(16)
    expires = utcnow() + timedelta(seconds=ttl_seconds)
    ph = params_hash(action.parameters)
    scope = scope_of(action)
    token = _mac(secret, [action.action_id, actor, ph, scope,
                          expires.isoformat(), nonce])
    req = ApprovalRequest(incident_id=action.incident_id,
                          action_id=action.action_id, actor=actor,
                          params_hash=ph, scope=scope,
                          expires_at=expires, nonce=nonce)
    return req, token


def verify(token: str, req: ApprovalRequest, action: Action, actor: str,
           secret: str, store: NonceStore) -> ApprovalRequest:
    """Return req on success; raise ApprovalError (=> DENY) otherwise."""
    if utcnow() >= req.expires_at:
        raise ApprovalError("approval expired")
    if actor != req.actor:
        raise ApprovalError("wrong actor")
    if params_hash(action.parameters) != req.params_hash:
        raise ApprovalError("parameters differ from approved scope")
    if scope_of(action) != req.scope or action.action_id != req.action_id:
        raise ApprovalError("scope mismatch")
    expect = _mac(secret, [req.action_id, req.actor, req.params_hash,
                           req.scope, req.expires_at.isoformat(), req.nonce])
    if not hmac.compare_digest(expect, token):
        raise ApprovalError("bad signature")
    if not store.consume(req.nonce):
        raise ApprovalError("token replayed")
    return req
