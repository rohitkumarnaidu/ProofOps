"""M00.2 config hardening (90+ pass, host-safe UNIT + INTEGRATION).

New-file companion to tests/test_config.py (untouched): proves inventory↔docs
parity plus extra fail-closed edges without editing the frozen contract.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import get_settings, load_settings  # noqa: E402

BASE_ENV = {
    "APP_ENV": "development",
    "LOG_LEVEL": "INFO",
    "DEBUG": "false",
    "EXECUTOR": "mock",
    "APPROVAL_SECRET": "test-secret-16-chars-ok",
    "APPROVAL_TTL_SECONDS": "600",
    "POLICY_VERSION": "v1",
    "PROOFOPS_API_KEY": "test-api-key",
    "POSTGRES_USER": "proofops",
    "POSTGRES_PASSWORD": "test-db-pass",
    "POSTGRES_DB": "proofops",
}
KNOWN_KEYS = list(BASE_ENV) + [
    "LYZR_API_KEY", "LYZR_AGENT_ID", "LYZR_AGENT_TRIAGE_ID",
    "LYZR_AGENT_DIAGNOSTIC_ID", "LYZR_AGENT_PLANNER_ID",
    "LYZR_AGENT_REPORTER_ID", "LYZR_RAI_POLICY", "DATABASE_URL",
    "SEED_SCENARIO", "SEED_VARIANT", "SEED_SEED",
]


def make(monkeypatch, tmp_path, **env):
    for k in KNOWN_KEYS:
        monkeypatch.delenv(k, raising=False)
    empty = tmp_path / ".env.empty"
    empty.write_text("", encoding="utf-8")
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    get_settings.cache_clear()
    try:
        return load_settings(_env_file=str(empty))
    finally:
        get_settings.cache_clear()


class TestExtraFailClosed:
    def test_seed_seed_non_int_fails(self, monkeypatch, tmp_path):  # UNIT
        from app.config import ConfigurationError
        with pytest.raises(ConfigurationError) as ei:
            make(monkeypatch, tmp_path, **{**BASE_ENV, "SEED_SEED": "abc"})
        assert "SEED_SEED" in str(ei.value)

    def test_ttl_non_int_fails(self, monkeypatch, tmp_path):  # UNIT
        from app.config import ConfigurationError
        with pytest.raises(ConfigurationError):
            make(monkeypatch, tmp_path, **{**BASE_ENV, "APPROVAL_TTL_SECONDS": "abc"})

    def test_log_level_lowercase_fails_closed(self, monkeypatch, tmp_path):  # UNIT
        # Literal is uppercase-only; lowercase fails instead of silently mapping.
        from app.config import ConfigurationError
        with pytest.raises(ConfigurationError) as ei:
            make(monkeypatch, tmp_path, **{**BASE_ENV, "LOG_LEVEL": "info"})
        assert "LOG_LEVEL" in str(ei.value)

    def test_future_agent_ids_accepted(self, monkeypatch, tmp_path):  # UNIT
        s = make(monkeypatch, tmp_path, **{
            **BASE_ENV, "LYZR_AGENT_TRIAGE_ID": "ag-123"})
        assert s.LYZR_AGENT_TRIAGE_ID == "ag-123"

    def test_empty_seed_scenario_pinned_with_owner(self, monkeypatch, tmp_path):  # UNIT
        # LACK-7 boundary, pinned not fixed: frozen `config.py` accepts empty
        # SEED_SCENARIO today; validation is owned by a future contracts pass
        # (see ADR-008). This test documents the boundary so a silent change
        # fails loudly instead of drifting.
        s = make(monkeypatch, tmp_path, **{**BASE_ENV, "SEED_SCENARIO": ""})
        assert s.SEED_SCENARIO == ""


class TestInventoryDocsParity:
    def test_every_inventory_key_documented(self):  # INTEGRATION
        from app.config import Settings
        body = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
        for entry in Settings.inventory():
            assert entry["key"] in body, \
                f"inventory key {entry['key']} missing from CONFIGURATION.md"

    def test_no_direct_environ_outside_allowlist(self):  # INTEGRATION
        # Only scripts/verify_lyzr.py (standalone stdlib tool) may read
        # os.environ directly; everything else goes through Settings.
        offenders = []
        for path in list((ROOT / "backend").rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "environ":
                    offenders.append(str(path.relative_to(ROOT)))
                    break
        assert not offenders, f"direct os.environ in backend: {offenders}"
        assert "LYZR_API_KEY" in (ROOT / ".env.example").read_text(
            encoding="utf-8")
        assert re.search(r"os\.environ", (ROOT / "scripts" / "verify_lyzr.py").read_text(
            encoding="utf-8"))
