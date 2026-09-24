"""M21b demo-key guard: mutating HTTP handlers require X-API-Key (thin).

Ownership: M21. The full guard matrix (roles, scopes, rotation, persistence)
grows here in later hardening; this module owns the key check itself:
missing key -> 401, mismatch -> 403, match -> proceed (role gates stay
per-endpoint, owned by their routers). Expected key always comes from
server config at request time -- never from the caller, never defaulted.

Lane 1 (identity hardening): per-key identity with server-side roles.

- Key store: repo-relative ``var/api_keys.json`` -- a JSON list of
  ``{key_id, key_sha256, owner, roles[]}``. Only SHA256 hex digests are
  stored; raw keys are NEVER persisted. Presented keys are hashed and
  compared with ``hmac.compare_digest`` (constant-time per entry).
- ``resolve_identity()`` returns the resolved ``{key_id, owner, roles}``
  dict on success; ``guard_http()`` keeps its raise-on-fail contract and
  now ALSO returns that dict (callers that ignore the return value are
  unaffected).
- ``check_key_role()`` enforces the server-side role subset gate: when the
  resolved identity carries roles, the client-asserted role must be one of
  them; bootstrap identities (no roles) keep the legacy behavior.
- Separation of duties is enforced in approvals ``approve_approval``
  (opt-in ``enforce_sod``); this module only supplies the identity it
  reasons over.

FALLBACK (loud, deliberate): when ``var/api_keys.json`` is ABSENT or
UNREADABLE (missing file, permission error), the server falls back to the
pre-Lane-1 single-key behavior: the presented key is compared against the
configured ``PROOFOPS_API_KEY`` and the resolved identity is
``{key_id: "bootstrap", owner: "bootstrap", roles: []}`` (empty roles =
no server-side role gate, exactly as today). This keeps existing tests,
demos, and single-key deployments working with zero migration. A PRESENT
but corrupt store (bad JSON / bad entry shape / duplicates) does NOT fall
back -- it fails closed (ValueError -> HTTP 500) so a tampered store can
never silently downgrade the deployment to the shared bootstrap key.

Demo-grade (NOT production identity): no SSO/OIDC, no per-user passwords,
no key rotation/expiry, no remote revocation list. The store is a local
JSON file; rotation means replacing the file. Real deployments must put
SSO/OIDC in front of this gate (PLANNED, owning module TBD).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any


class KeyMissing(Exception):
    """No API key supplied (HTTP 401)."""


class KeyRejected(Exception):
    """Wrong API key (HTTP 403)."""


def http_status(exc: Exception) -> int:
    if isinstance(exc, KeyMissing):
        return 401
    if isinstance(exc, KeyRejected):
        return 403
    return 500


def check_api_key(provided: str | None, expected: str) -> None:
    """Fail-closed demo-key gate (M21b matrix, step one)."""
    if not isinstance(expected, str) or not expected:
        raise KeyRejected("server API key not configured")
    if provided is None or (isinstance(provided, str)
                            and not provided.strip()):
        raise KeyMissing("X-API-Key header required")
    if not isinstance(provided, str):
        raise KeyRejected("malformed API key")
    import hmac as _hmac
    if not _hmac.compare_digest(provided, expected):
        raise KeyRejected("invalid API key")


#: Per-key identity store (Lane 1): JSON list of
#: ``{key_id, key_sha256, owner, roles[]}``. Raw keys never touch disk.
KEY_STORE_PATH = Path(__file__).resolve().parents[3] / "var" / "api_keys.json"

#: Bootstrap identity used when the store is absent/unreadable (fallback).
BOOTSTRAP_KEY_ID = "bootstrap"
BOOTSTRAP_OWNER = "bootstrap"


def _entry_shape(entry: Any) -> dict[str, Any]:
    """Validate one store entry; fail closed on any shape violation."""
    if not isinstance(entry, dict):
        raise ValueError("key store entry must be an object")
    key_id = entry.get("key_id")
    digest = entry.get("key_sha256")
    owner = entry.get("owner")
    roles = entry.get("roles")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("key store entry needs a non-empty key_id")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError(
            f"key store entry {key_id!r} needs a 64-char hex key_sha256")
    try:
        int(digest, 16)
    except ValueError as exc:
        raise ValueError(
            f"key store entry {key_id!r} needs a 64-char hex key_sha256"
        ) from exc
    if not isinstance(owner, str) or not owner.strip():
        raise ValueError(
            f"key store entry {key_id!r} needs a non-empty owner")
    if not isinstance(roles, list) or any(
            not isinstance(item, str) or not item.strip() for item in roles):
        raise ValueError(
            f"key store entry {key_id!r} needs roles as a string list")
    return {"key_id": key_id, "owner": owner,
            "key_sha256": digest.lower(), "roles": list(roles)}


def load_key_store(path: str | Path | None = None
                   ) -> list[dict[str, Any]] | None:
    """Load the per-key store; None means "absent/unreadable -> fallback".

    Returns None when the file is missing or unreadable (OSError) -- the
    caller falls back to single-key behavior (documented above). Raises
    ValueError when the file is PRESENT but corrupt (bad JSON, non-list
    top level, bad entry shape, duplicate key_id/digest): a tampered store
    must fail closed, never silently downgrade to the shared key. Extra
    entry fields (e.g. "note" in the .example template) are ignored.
    """
    src = Path(path) if path is not None else KEY_STORE_PATH
    try:
        text = src.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError:
        return None
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"key store corrupt: {exc}") from exc
    if not isinstance(raw, list):
        raise ValueError("key store corrupt: top-level list required")
    entries = [_entry_shape(item) for item in raw]
    seen_ids: set[str] = set()
    seen_digests: set[str] = set()
    for item in entries:
        if item["key_id"] in seen_ids:
            raise ValueError(
                f"key store corrupt: duplicate key_id {item['key_id']!r}")
        if item["key_sha256"] in seen_digests:
            raise ValueError("key store corrupt: duplicate key_sha256")
        seen_ids.add(item["key_id"])
        seen_digests.add(item["key_sha256"])
    return entries


def resolve_identity(provided: str | None, expected: str,
                     *, store_path: str | Path | None = None
                     ) -> dict[str, Any]:
    """Resolve the presented key to {key_id, owner, roles} (Lane 1).

    Store present -> the SHA256 hex of the presented key is constant-time
    compared against each stored digest; a match returns the entry
    identity, a miss raises KeyRejected (HTTP 403). The ``expected``
    bootstrap secret is NOT consulted while a store is authoritative.
    Store absent/unreadable -> bootstrap fallback: ``check_api_key``
    against ``expected`` (same 401/403 behavior as before) with identity
    ``{key_id: "bootstrap", owner: "bootstrap", roles: []}``.
    Blank/non-string keys raise KeyMissing/KeyRejected exactly as before.
    """
    if provided is None or (isinstance(provided, str)
                            and not provided.strip()):
        raise KeyMissing("X-API-Key header required")
    if not isinstance(provided, str):
        raise KeyRejected("malformed API key")
    entries = load_key_store(store_path)
    if entries is None:
        check_api_key(provided, expected)
        return {"key_id": BOOTSTRAP_KEY_ID, "owner": BOOTSTRAP_OWNER,
                "roles": []}
    digest = hashlib.sha256(provided.encode("utf-8")).hexdigest()
    for item in entries:
        if hmac.compare_digest(digest, item["key_sha256"]):
            return {"key_id": item["key_id"], "owner": item["owner"],
                    "roles": list(item["roles"])}
    raise KeyRejected("invalid API key")


def check_key_role(identity_roles: Sequence[str] | None,
                   claimed_role: str) -> None:
    """Server-side role subset gate (Lane 1, opt-in).

    ``identity_roles`` empty/None (bootstrap fallback) -> allow anything:
    today's per-endpoint role gates apply unchanged. Otherwise the
    client-asserted ``claimed_role`` (e.g. DecideBody.role) must be an
    element of the key's roles, else KeyRejected (HTTP 403). Exact,
    case-sensitive match; fail closed on non-string claims.
    """
    if not identity_roles:
        return
    if not isinstance(claimed_role, str) \
            or claimed_role not in list(identity_roles):
        raise KeyRejected(
            f"role {claimed_role!r} not granted to this API key")


def guard_http(provided: str | None, expected_fn: object,
               http_exc_cls: type) -> dict[str, Any]:
    """Enforce the key gate inside mutating handlers (M21b matrix).

    Blank keys fail BEFORE touching config (host-safe unit tests never
    need env); mismatches resolve the expected key then compare.

    Lane 1: on success returns the resolved identity
    ``{key_id, owner, roles}`` (bootstrap fallback when no store). The
    raise-on-fail contract is unchanged -- existing callers that ignore
    the return value behave exactly as before.
    """
    if provided is None or (isinstance(provided, str)
                            and not provided.strip()):
        raise http_exc_cls(status_code=401, detail="X-API-Key required")
    try:
        expected = expected_fn()  # type: ignore[operator]
    except Exception as exc:
        raise http_exc_cls(status_code=500,
                           detail=f"key config unreadable: {exc}") from exc
    try:
        return resolve_identity(provided, expected)
    except (KeyMissing, KeyRejected) as exc:
        raise http_exc_cls(status_code=http_status(exc),
                           detail=str(exc)) from exc
    except ValueError as exc:
        raise http_exc_cls(status_code=500,
                           detail=f"key store unreadable: {exc}") from exc
    except Exception as exc:
        raise http_exc_cls(status_code=500,
                           detail=f"key identity unreadable: {exc}") from exc
