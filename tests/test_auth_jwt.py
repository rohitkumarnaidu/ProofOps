"""Tests for Enterprise JWT Authentication and Role-Based Access Control (RBAC)."""
import os
import sys
import time
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.routers import auth as auth_mod


class DummyHTTPException(Exception):
    def __init__(self, status_code: int = 500, detail: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def test_issue_and_verify_jwt_token():
    identity = {
        "key_id": "key-admin-001",
        "owner": "alice-commander",
        "roles": ["admin", "approver", "operator"],
        "mode": "per_key",
    }
    token = auth_mod.issue_jwt_token(identity, ttl_seconds=3600)
    assert isinstance(token, str)
    assert len(token) > 20

    decoded = auth_mod.verify_jwt_token(token)
    assert decoded["key_id"] == "key-admin-001"
    assert decoded["owner"] == "alice-commander"
    assert set(decoded["roles"]) == {"admin", "approver", "operator"}
    assert decoded["mode"] == "per_key"


def test_expired_jwt_token():
    identity = {
        "key_id": "key-expired-001",
        "owner": "bob",
        "roles": ["operator"],
        "mode": "per_key",
    }
    # Issue already expired token
    token = auth_mod.issue_jwt_token(identity, ttl_seconds=-10)
    with pytest.raises(auth_mod.KeyRejected) as exc_info:
        auth_mod.verify_jwt_token(token)
    assert "expired" in str(exc_info.value).lower()


def test_tampered_jwt_token():
    identity = {"key_id": "key-1", "owner": "carol", "roles": ["admin"]}
    token = auth_mod.issue_jwt_token(identity, ttl_seconds=3600)
    tampered = token[:-4] + "wxyz"
    with pytest.raises(auth_mod.KeyRejected):
        auth_mod.verify_jwt_token(tampered)


def test_guard_http_with_bearer_token():
    identity = {
        "key_id": "key-jwt-01",
        "owner": "dave",
        "roles": ["admin"],
        "mode": "per_key",
    }
    token = auth_mod.issue_jwt_token(identity, ttl_seconds=3600)

    # Calling guard_http with no API key, but valid Bearer token in authorization header
    resolved = auth_mod.guard_http(
        provided=None,
        expected_fn=lambda: "secret-key",
        http_exc_cls=DummyHTTPException,
        authorization=f"Bearer {token}",
    )
    assert resolved["key_id"] == "key-jwt-01"
    assert resolved["owner"] == "dave"
    assert "admin" in resolved["roles"]


def test_guard_http_with_invalid_bearer_token():
    with pytest.raises(DummyHTTPException) as exc_info:
        auth_mod.guard_http(
            provided=None,
            expected_fn=lambda: "secret-key",
            http_exc_cls=DummyHTTPException,
            authorization="Bearer completely-invalid-jwt-token",
        )
    assert exc_info.value.status_code == 403


def test_require_role_with_jwt_identity():
    identity = {
        "key_id": "key-role-01",
        "owner": "eve",
        "roles": ["approver", "operator"],
        "mode": "per_key",
    }
    # Permitted roles
    auth_mod.require_role(identity, "approver")
    auth_mod.require_role(identity, "operator")
    auth_mod.require_role(identity, "admin", "approver")

    # Forbidden role
    with pytest.raises(auth_mod.KeyRejected) as exc_info:
        auth_mod.require_role(identity, "admin")
    assert "holds none of" in str(exc_info.value).lower()


def test_http_token_endpoint():
    # Calling http_token with valid bootstrap or per_key key
    key = "test-bootstrap-key"
    from unittest.mock import patch
    with patch("app.routers.auth._settings_key", return_value=key):
        resp = auth_mod.http_token(payload={"api_key": key})
        assert "access_token" in resp
        assert resp["token_type"] == "bearer"
        assert resp["expires_in"] == 86400
        assert "identity" in resp
        assert resp["identity"]["mode"] in ("bootstrap", "per_key")
