"""M21b demo-key guard: mutating HTTP handlers require X-API-Key (thin).

Ownership: M21. The full guard matrix (roles, scopes, rotation, persistence)
grows here in later hardening; this module owns the key check itself:
missing key -> 401, mismatch -> 403, match -> proceed (role gates stay
per-endpoint, owned by their routers). Expected key always comes from
server config at request time -- never from the caller, never defaulted.
"""
from __future__ import annotations


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


def guard_http(provided: str | None, expected_fn: object,
               http_exc_cls: type) -> None:
    """Enforce the key gate inside mutating handlers (M21b matrix).

    Blank keys fail BEFORE touching config (host-safe unit tests never
    need env); mismatches resolve the expected key then compare.
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
        check_api_key(provided, expected)
    except Exception as exc:
        raise http_exc_cls(status_code=http_status(exc),
                           detail=str(exc)) from exc
