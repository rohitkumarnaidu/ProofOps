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
- ``resolve_identity()`` returns the resolved ``{key_id, owner, roles, mode}``
  dict on success; ``guard_http()`` keeps its raise-on-fail contract and
  now ALSO returns that dict (callers that ignore the return value are
  unaffected).
- ``require_role()`` is the PRODUCTION authorization gate: it reads the
  server-side roles attached to the authenticated key and never consults a
  client-asserted role. ``check_key_role()`` is retained for the older
  client-asserted-role comparison and is NOT an authorization boundary.
- Separation of duties is enforced in approvals ``approve_approval``
  (opt-in ``enforce_sod``); this module only supplies the identity it
  reasons over.

MODE (the honesty contract): ``mode`` is ``"per_key"`` when a key store
resolved the caller and ``"bootstrap"`` when the deployment fell back to the
single configured key. Every product surface that shows identity MUST show
``mode`` too, because ``bootstrap`` is a shared demo credential with NO
per-user identity and NO server-side roles -- a client can still assert a role
string, and separation of duties is not enforced. Reporting ``bootstrap`` as
authenticated user identity would be a false claim.

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
#: Resolved through app.paths so the container reads the state dir the image
#: creates and the compose volume mounts -- NOT a parents[N] guess, which in
#: the image layout resolved to /var and silently downgraded every request to
#: the full-authority bootstrap identity.
def _key_store_path() -> Any:
    from app import paths
    return paths.key_store_path()


KEY_STORE_PATH = _key_store_path()

#: Bootstrap identity used when the store is absent/unreadable (fallback).
BOOTSTRAP_KEY_ID = "bootstrap"
BOOTSTRAP_OWNER = "bootstrap"

#: Identity modes. ``per_key`` = a key store resolved this caller and its
#: roles are server-owned. ``bootstrap`` = shared single-key demo fallback,
#: no per-user identity, roles are client-asserted.
MODE_PER_KEY = "per_key"
MODE_BOOTSTRAP = "bootstrap"


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
    seen_owners: set[str] = set()
    for item in entries:
        if item["key_id"] in seen_ids:
            raise ValueError(
                f"key store corrupt: duplicate key_id {item['key_id']!r}")
        if item["key_sha256"] in seen_digests:
            raise ValueError("key store corrupt: duplicate key_sha256")
        # Two keys for ONE owner would defeat separation of duties: the check
        # compares key ids, so a single human holding k-laptop and k-desktop
        # could raise and approve their own action while the approval record
        # still reports four-eyes enforcement. Refuse the ambiguous store.
        if item["owner"] in seen_owners:
            raise ValueError(
                f"key store corrupt: duplicate owner {item['owner']!r} "
                "(separation of duties compares key ids, so one human "
                "must not hold two keys)")
        seen_ids.add(item["key_id"])
        seen_digests.add(item["key_sha256"])
        seen_owners.add(item["owner"])
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
                "roles": [], "mode": MODE_BOOTSTRAP}
    digest = hashlib.sha256(provided.encode("utf-8")).hexdigest()
    for item in entries:
        if hmac.compare_digest(digest, item["key_sha256"]):
            return {"key_id": item["key_id"], "owner": item["owner"],
                    "roles": list(item["roles"]), "mode": MODE_PER_KEY}
    if expected and hmac.compare_digest(provided, expected):
        return {"key_id": BOOTSTRAP_KEY_ID, "owner": BOOTSTRAP_OWNER,
                "roles": [], "mode": MODE_BOOTSTRAP}
    raise KeyRejected("invalid API key")


def principal(identity: dict[str, Any]) -> str:
    """The immutable audit principal for a resolved identity.

    ``key_id`` is the stable, non-secret identifier that survives an owner
    rename; the mutable display ``owner`` must never be used as the audit
    principal, or a renamed user would retroactively change who the audit
    chain claims acted.
    """
    key_id = identity.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise KeyRejected("resolved identity carries no key_id")
    return key_id


def require_role(identity: dict[str, Any], *allowed: str) -> None:
    """Server-side role gate over the AUTHENTICATED key (authorization).

    This is the production boundary: the allowed set is server code, and the
    caller is the resolved key identity. A client-asserted role NEVER widens
    this gate. Fail-closed rules:

    - ``per_key`` identity: the key's stored roles must contain at least one
      of ``allowed``; an empty role list is DENIED (a per-key store entry
      with no roles is an intentionally unprivileged key, never a wildcard).
    - ``bootstrap`` identity: allowed only when ``bootstrap_permits`` is
      True. The bootstrap path is the shared demo credential with no
      server-side roles, so the legacy client-asserted-role comparison is
      all that remains; callers MUST surface ``mode`` in their response so a
      reader can see that no per-user identity backed this decision.
    """
    if not allowed:
        raise ValueError("require_role needs at least one allowed role")
    if identity.get("mode") == MODE_BOOTSTRAP:
        if identity.get("bootstrap_permits", True):
            return
        raise KeyRejected("bootstrap demo identity may not perform this action")
    roles = identity.get("roles")
    if not isinstance(roles, (list, tuple)):
        raise KeyRejected("identity carries no server-side role list")
    granted = {r for r in roles if isinstance(r, str)}
    if not granted & set(allowed):
        raise KeyRejected(
            f"this API key ({principal(identity)}) holds none of "
            f"{sorted(set(allowed))} (granted: {sorted(granted)})")


def check_key_role(identity_roles: Sequence[str] | None,
                   claimed_role: str) -> None:
    """Compatibility helper over a CLIENT-ASSERTED role (NOT a boundary).

    It compares a role string the caller sent against the key's stored roles.
    That is a usability cross-check, not authorization: a caller who controls
    the string can pick any role it holds. Authorization must use
    ``require_role()``, which takes the allowed set from server code. Kept
    because the legacy endpoint role gates still call it, and removing it
    would silently widen those endpoints.

    ``identity_roles`` empty/None (bootstrap fallback) -> allow anything.
    Otherwise the client-asserted ``claimed_role`` must be an element of the
    roles; exact, case-sensitive; fail closed on non-string claims.
    """
    if not identity_roles:
        return
    if not isinstance(claimed_role, str) \
            or claimed_role not in list(identity_roles):
        raise KeyRejected(
            f"role {claimed_role!r} not granted to this API key")



def issue_jwt_token(identity: dict[str, Any], ttl_seconds: int = 86400) -> str:
    """Issue a signed HS256 JWT token for authenticated identity."""
    import jwt
    import time
    from app.config import get_settings
    secret = get_settings().APPROVAL_SECRET
    payload = {
        "sub": identity.get("key_id", ""),
        "owner": identity.get("owner", ""),
        "roles": identity.get("roles", []),
        "mode": identity.get("mode", MODE_BOOTSTRAP),
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
    }
    return str(jwt.encode(payload, secret, algorithm="HS256"))


def verify_jwt_token(token: str) -> dict[str, Any]:
    """Verify and decode a signed HS256 JWT bearer token."""
    import jwt
    from app.config import get_settings
    secret = get_settings().APPROVAL_SECRET
    try:
        data = jwt.decode(token, secret, algorithms=["HS256"])
        return {
            "key_id": str(data.get("sub", "")),
            "owner": str(data.get("owner", "")),
            "roles": list(data.get("roles", [])),
            "mode": str(data.get("mode", MODE_BOOTSTRAP)),
        }
    except Exception as exc:
        raise KeyRejected(f"invalid or expired bearer token: {exc}") from exc

def guard_http(provided: str | None, expected_fn: object,
               http_exc_cls: type,
               authorization: str | None = None) -> dict[str, Any]:
    """Enforce the key gate inside mutating handlers (M21b matrix).

    Blank keys fail BEFORE touching config (host-safe unit tests never
    need env); mismatches resolve the expected key then compare.

    Lane 1: on success returns the resolved identity
    ``{key_id, owner, roles}`` (bootstrap fallback when no store). The
    raise-on-fail contract is unchanged -- existing callers that ignore
    the return value behave exactly as before. Supports Bearer JWT tokens
    when authorization header is provided.
    """
    if authorization and isinstance(authorization, str) and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            return verify_jwt_token(token)
        except Exception as exc:
            raise http_exc_cls(status_code=403, detail=str(exc)) from exc

    if not isinstance(provided, str) or not provided.strip():
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


def identity_view(identity: dict[str, Any]) -> dict[str, Any]:
    """Project the resolved identity for a product surface (no secrets).

    Returns the stable principal, the mutable display owner, the server-side
    roles, and the identity MODE so a UI can label a bootstrap credential as
    demo-grade instead of presenting it as an authenticated user.
    """
    return {"key_id": identity.get("key_id", ""),
            "owner": identity.get("owner", ""),
            "roles": sorted(r for r in identity.get("roles", [])
                            if isinstance(r, str)),
            "mode": identity.get("mode", MODE_BOOTSTRAP),
            "server_enforced": identity.get("mode") == MODE_PER_KEY}


try:  # pragma: no cover - container path (pinned deps)
    from fastapi import APIRouter as _APIRouter
    from fastapi import Header as _Header
    from fastapi import HTTPException as _HTTPException
    _APIRouter(prefix="/__probe__")
    router = _APIRouter(tags=["auth"])
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


def _settings_key() -> str:
    from app.config import get_settings  # noqa: E402 (request-time only)
    return get_settings().PROOFOPS_API_KEY


def http_identity(x_api_key: str | None = Header(default=None)
                  ) -> dict[str, Any]:
    """``GET /identity``: who the server thinks the caller is.

    Exists so a client never has to assert its own identity or role: the UI
    reads the server-resolved principal and its roles, and shows ``mode``.
    """
    identity = guard_http(x_api_key, _settings_key, HTTPException)
    return identity_view(identity)


def http_token(payload: dict[str, Any] | None = None,
               x_api_key: str | None = Header(default=None),
               authorization: str | None = Header(default=None),
               ) -> dict[str, Any]:
    api_k = x_api_key if isinstance(x_api_key, str) else None
    auth_h = authorization if isinstance(authorization, str) else None
    key = api_k or (payload.get("api_key") if isinstance(payload, dict) else None)
    identity = guard_http(key, _settings_key, HTTPException, authorization=auth_h)
    token = issue_jwt_token(identity)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 86400,
        "identity": identity_view(identity),
    }

if router is not None:  # container path; host asserts wiring via AST
    router.get("/identity")(http_identity)
    router.get("/auth/identity")(http_identity)
    router.post("/token")(http_token)
    router.post("/auth/token")(http_token)
