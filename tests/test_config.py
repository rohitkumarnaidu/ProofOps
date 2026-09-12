"""M00.2 configuration trust boundary tests.

Every test is tagged with its evidence class:
  UNIT         real Settings loading with isolated env (hermetic fixture)
  SECURITY     redaction / fail-closed / immutability attacks
  INTEGRATION  code/template/compose parity across the repo
  RUNTIME      process-level behavior (singleton, precedence incl. .env file)

Skipped runtime is never counted as passed (no skips in this file by design).
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import (  # noqa: E402
    ConfigurationError,
    REDACTED,
    SECRET_FIELDS,
    get_settings,
    load_settings,
)

# Every variable the contract owns. The fixture wipes these from the process
# env so tests are hermetic even when a real .env sits in the repo root.
KNOWN_KEYS = [
    "APP_ENV", "LOG_LEVEL", "DEBUG", "EXECUTOR",
    "APPROVAL_SECRET", "APPROVAL_TTL_SECONDS", "POLICY_VERSION",
    "PROOFOPS_API_KEY", "LYZR_API_KEY", "LYZR_AGENT_ID",
    "LYZR_AGENT_TRIAGE_ID", "LYZR_AGENT_DIAGNOSTIC_ID",
    "LYZR_AGENT_PLANNER_ID", "LYZR_AGENT_REPORTER_ID", "LYZR_RAI_POLICY",
    "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "DATABASE_URL",
    "SEED_SCENARIO", "SEED_VARIANT", "SEED_SEED",
]

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

PROD_ENV = {
    **BASE_ENV,
    "APP_ENV": "production",
    "EXECUTOR": "docker",
    "APPROVAL_SECRET": "prod-real-secret-32-chars-abcdef",
    "PROOFOPS_API_KEY": "prod-real-api-key",
    "POSTGRES_PASSWORD": "prod-real-db-pass",
    "DATABASE_URL": "postgresql+psycopg://proofops:prod-real-db-pass@db:5432/proofops",
}

# Template extras allowed only as documented FUTURE reservations (M13).
DOCUMENTED_FUTURE = {
    "LYZR_AGENT_TRIAGE_ID", "LYZR_AGENT_DIAGNOSTIC_ID",
    "LYZR_AGENT_PLANNER_ID", "LYZR_AGENT_REPORTER_ID",
}


def make(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **env: str):
    """Build Settings from exactly `env` — nothing leaks in from process/.env."""
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


# --- positive (UNIT) ----------------------------------------------------------

class TestValidConfigs:
    def test_development_defaults(self, monkeypatch, tmp_path):  # UNIT
        s = make(monkeypatch, tmp_path, **BASE_ENV)
        assert s.APP_ENV == "development"
        assert s.EXECUTOR == "mock"
        assert s.POLICY_VERSION == "v1"
        assert s.APPROVAL_TTL_SECONDS == 600
        assert s.LOG_LEVEL == "INFO" and s.DEBUG is False
        assert s.LYZR_ENABLED is False

    def test_test_env(self, monkeypatch, tmp_path):  # UNIT
        s = make(monkeypatch, tmp_path, **{**BASE_ENV, "APP_ENV": "test"})
        assert s.APP_ENV == "test"
        assert (s.SEED_SCENARIO, s.SEED_VARIANT, s.SEED_SEED) == \
            ("bad-deploy", "NORMAL", 42)

    def test_demo_env_seeded(self, monkeypatch, tmp_path):  # UNIT
        s = make(monkeypatch, tmp_path, **{
            **BASE_ENV, "APP_ENV": "demo",
            "SEED_SCENARIO": "bad-deploy", "SEED_VARIANT": "NOISY", "SEED_SEED": 7,
        })
        assert (s.SEED_VARIANT, s.SEED_SEED) == ("NOISY", 7)

    def test_production_valid(self, monkeypatch, tmp_path):  # UNIT
        s = make(monkeypatch, tmp_path, **PROD_ENV)
        assert s.APP_ENV == "production" and s.EXECUTOR == "docker"

    def test_lyzr_enabled_derived(self, monkeypatch, tmp_path):  # UNIT
        off = make(monkeypatch, tmp_path, **BASE_ENV)
        assert off.LYZR_ENABLED is False
        on = make(monkeypatch, tmp_path, **{**BASE_ENV, "LYZR_API_KEY": "lzr-x"})
        assert on.LYZR_ENABLED is True

    def test_database_url_derived_when_unset(self, monkeypatch, tmp_path):  # UNIT
        s = make(monkeypatch, tmp_path, **BASE_ENV)
        assert s.DATABASE_URL == \
            "postgresql+psycopg://proofops:test-db-pass@db:5432/proofops"

    def test_explicit_database_url_wins(self, monkeypatch, tmp_path):  # UNIT
        url = "postgresql+psycopg://u:pw@localhost:5432/db"
        s = make(monkeypatch, tmp_path, **{**BASE_ENV, "DATABASE_URL": url})
        assert s.DATABASE_URL == url

    def test_constructor_beats_environment(self, monkeypatch, tmp_path):  # UNIT
        # Precedence part 1: runtime/constructor override > environment variable.
        for k in KNOWN_KEYS:
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("EXECUTOR", "docker")
        empty = tmp_path / ".env.empty"
        empty.write_text("", encoding="utf-8")
        rest = {k: v for k, v in BASE_ENV.items() if k != "EXECUTOR"}
        get_settings.cache_clear()
        try:
            s = load_settings(_env_file=str(empty), EXECUTOR="mock", **rest)
        finally:
            get_settings.cache_clear()
        assert s.EXECUTOR == "mock"  # constructor beat the env var


# --- negative (UNIT) ----------------------------------------------------------

class TestInvalidConfigs:
    def _err(self, monkeypatch, tmp_path, **env) -> str:
        merged = {**BASE_ENV, **env}
        with pytest.raises(ConfigurationError) as ei:
            make(monkeypatch, tmp_path, **merged)
        return str(ei.value)

    def test_invalid_app_env(self, monkeypatch, tmp_path):  # UNIT
        assert "APP_ENV" in self._err(monkeypatch, tmp_path, APP_ENV="staging")

    def test_invalid_executor_and_kind_rejected(self, monkeypatch, tmp_path):  # UNIT
        for bad in ("kind", "kubernetes", "shell", ""):
            msg = self._err(monkeypatch, tmp_path, EXECUTOR=bad)
            assert "EXECUTOR" in msg, bad

    def test_missing_approval_secret(self, monkeypatch, tmp_path):  # UNIT
        assert "APPROVAL_SECRET" in self._err(
            monkeypatch, tmp_path, APPROVAL_SECRET="")

    def test_production_debug_forbidden(self, monkeypatch, tmp_path):  # UNIT
        assert "DEBUG" in self._err(
            monkeypatch, tmp_path, **{**PROD_ENV, "DEBUG": "true"})

    def test_production_placeholder_secret_rejected(self, monkeypatch, tmp_path):  # UNIT
        msg = self._err(monkeypatch, tmp_path, **{
            **PROD_ENV,
            "APPROVAL_SECRET": "change-me-generate-with-python-secrets-token_hex-32",
        })
        assert "APPROVAL_SECRET" in msg

    def test_production_short_secret_rejected(self, monkeypatch, tmp_path):  # UNIT
        assert "APPROVAL_SECRET" in self._err(
            monkeypatch, tmp_path, **{**PROD_ENV, "APPROVAL_SECRET": "abc"})

    def test_production_mock_executor_rejected(self, monkeypatch, tmp_path):  # UNIT
        assert "EXECUTOR" in self._err(
            monkeypatch, tmp_path, **{**PROD_ENV, "EXECUTOR": "mock"})

    def test_production_dev_api_key_rejected(self, monkeypatch, tmp_path):  # UNIT
        assert "PROOFOPS_API_KEY" in self._err(
            monkeypatch, tmp_path,
            **{**PROD_ENV, "PROOFOPS_API_KEY": "dev-key-change-me"})

    def test_production_dev_db_password_rejected(self, monkeypatch, tmp_path):  # UNIT
        assert "POSTGRES_PASSWORD" in self._err(
            monkeypatch, tmp_path,
            **{**PROD_ENV, "POSTGRES_PASSWORD": "change-me-pw"})

    def test_invalid_database_url_scheme(self, monkeypatch, tmp_path):  # UNIT
        assert "DATABASE_URL" in self._err(
            monkeypatch, tmp_path, DATABASE_URL="sqlite:///x.db")

    def test_nonpositive_ttl(self, monkeypatch, tmp_path):  # UNIT
        for bad in ("0", "-30"):
            assert "APPROVAL_TTL_SECONDS" in self._err(
                monkeypatch, tmp_path, APPROVAL_TTL_SECONDS=bad)

    def test_empty_policy_version(self, monkeypatch, tmp_path):  # UNIT
        assert "POLICY_VERSION" in self._err(
            monkeypatch, tmp_path, POLICY_VERSION="  ")

    def test_invalid_seed_variant(self, monkeypatch, tmp_path):  # UNIT
        assert "SEED_VARIANT" in self._err(
            monkeypatch, tmp_path, SEED_VARIANT="CHAOS")

    def test_invalid_log_level(self, monkeypatch, tmp_path):  # UNIT
        assert "LOG_LEVEL" in self._err(
            monkeypatch, tmp_path, LOG_LEVEL="VERBOSE")


# --- security (SECURITY) ------------------------------------------------------

class TestSecretSafety:
    FAKE = "sk-FAKE-planted-secret-0123456789abcdef"

    def test_snapshot_redacts_and_omits(self, monkeypatch, tmp_path):  # SECURITY
        s = make(monkeypatch, tmp_path, **{
            **BASE_ENV, "LYZR_API_KEY": self.FAKE,
            "DATABASE_URL": "postgresql+psycopg://u:pw@h/db",
        })
        snap = s.snapshot()
        for field in SECRET_FIELDS:
            assert snap[field] == REDACTED, field
        assert "DATABASE_URL" not in snap  # embeds password: never snapshotted
        assert self.FAKE not in repr(snap)
        assert snap["EXECUTOR"] == "mock"  # non-secrets stay visible

    def test_repr_str_leak_free(self, monkeypatch, tmp_path):  # SECURITY
        s = make(monkeypatch, tmp_path, **{
            **BASE_ENV, "LYZR_API_KEY": self.FAKE,
            "APPROVAL_SECRET": self.FAKE, "POSTGRES_PASSWORD": self.FAKE,
        })
        assert self.FAKE not in repr(s) and self.FAKE not in str(s)

    def test_error_messages_leak_free(self, monkeypatch, tmp_path):  # SECURITY
        # A bad secret value must never echo back inside the failure text.
        with pytest.raises(ConfigurationError) as ei:
            make(monkeypatch, tmp_path, **{**PROD_ENV, "APPROVAL_SECRET": "abc"})
        assert "abc" not in str(ei.value) or "APPROVAL_SECRET" in str(ei.value)
        assert "abc123" not in str(ei.value)
        with pytest.raises(ConfigurationError) as ei2:
            make(monkeypatch, tmp_path, **{
                **BASE_ENV, "DATABASE_URL": "mysql://root:hunter2@h/db"})
        assert "hunter2" not in str(ei2.value)

    def test_frozen_immutability(self, monkeypatch, tmp_path):  # SECURITY
        s = make(monkeypatch, tmp_path, **BASE_ENV)
        with pytest.raises(Exception, match="frozen"):
            s.EXECUTOR = "docker"  # type: ignore[misc]

    def test_unknown_var_has_no_effect(self, monkeypatch, tmp_path):  # SECURITY
        # Attack 5: unknown vars are ignored (extra=ignore), documented.
        s = make(monkeypatch, tmp_path, **BASE_ENV)
        monkeypatch.setenv("PROOFOPS_FUTURE_X", "1")
        get_settings.cache_clear()
        try:
            s2 = load_settings(_env_file=str(tmp_path / ".env.empty"))
        finally:
            get_settings.cache_clear()
        assert not hasattr(s2, "PROOFOPS_FUTURE_X")
        assert s2.snapshot() == s.snapshot()

    def test_template_ships_no_live_secrets(self):  # SECURITY
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        assert "sk-" not in text
        keys = {}
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                keys[k.strip()] = v.strip()
        assert keys.get("LYZR_API_KEY", "x") == ""
        assert "change-me" in keys.get("APPROVAL_SECRET", "")


# --- parity (INTEGRATION) -----------------------------------------------------

ENV_CALL_RE = re.compile(r"os\.environ(?:\.get)?\(\s*[\"']([A-Z][A-Z0-9_]*)[\"']")
# Compose interpolation operators: :-, :?, -, +, = ... (the :? hard-require
# form is load-bearing for fail-closed passwords — see hard-require test).
COMPOSE_VAR_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?:[:?+\-=][^}]*)?\}")


def _code_used_keys() -> set[str]:
    """AST-based: string literals don't count, comments don't count, dead
    strings don't count — only real os.environ/os.getenv call arguments."""
    used: set[str] = set()
    for path in list((ROOT / "backend").rglob("*.py")) + \
            list((ROOT / "scripts").rglob("*.py")) + \
            list((ROOT / "telemetry").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("get", "getenv", "__getitem__"):
                    val = node.func.value
                    is_environ = (
                        (isinstance(val, ast.Attribute) and val.attr == "environ"
                         and isinstance(val.value, ast.Name) and val.value.id == "os")
                        or (isinstance(val, ast.Call) and isinstance(val.func, ast.Name)
                            and val.func.id == "getenv")
                    )
                    if not is_environ:
                        continue
                    if node.args and isinstance(node.args[0], ast.Constant) \
                            and isinstance(node.args[0].value, str):
                        used.add(node.args[0].value)
    used |= set(COMPOSE_VAR_RE.findall(
        (ROOT / "docker-compose.yml").read_text(encoding="utf-8")))
    return used


def _template_keys(text: str | None = None) -> dict[str, str]:
    keys: dict[str, str] = {}
    src = text if text is not None else (ROOT / ".env.example").read_text(
        encoding="utf-8")
    for line in src.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            keys[k.strip()] = v.strip()
    return keys


class TestParity:
    def test_used_subset_of_template(self):  # INTEGRATION
        missing = sorted(_code_used_keys() - set(_template_keys()))
        assert not missing, f"runtime-used vars missing from template: {missing}"

    def test_template_extras_are_documented_future(self):  # INTEGRATION
        extras = set(_template_keys()) - _code_used_keys()
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        assert "FUTURE" in text, "template must label future reservations"
        undocumented = extras - DOCUMENTED_FUTURE - {
            # M00.2-owned contract: validated by Settings, consumed by later
            # modules (registry-verified; each has an explicit validator/test).
            "APP_ENV", "LOG_LEVEL", "DEBUG", "EXECUTOR", "APPROVAL_SECRET",
            "APPROVAL_TTL_SECONDS", "POLICY_VERSION", "PROOFOPS_API_KEY",
            "LYZR_API_KEY", "LYZR_AGENT_ID", "LYZR_RAI_POLICY",
            "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
            "DATABASE_URL", "SEED_SCENARIO", "SEED_VARIANT", "SEED_SEED",
        }
        assert not undocumented, f"undocumented template extras: {sorted(undocumented)}"

    def test_corrupted_template_detected(self):  # INTEGRATION (Attack 7)
        # Remove a key real code reads (verify_lyzr.py); the detector must fire.
        src = (ROOT / ".env.example").read_text(encoding="utf-8")
        corrupted = "\n".join(
            ln for ln in src.splitlines() if not ln.startswith("LYZR_API_KEY="))
        missing = sorted(_code_used_keys() - set(_template_keys(corrupted)))
        assert "LYZR_API_KEY" in missing  # detector fires on template corruption

    def test_new_keys_templated(self):  # INTEGRATION
        keys = _template_keys()
        assert {"APP_ENV", "LOG_LEVEL", "DEBUG"} <= set(keys)

    def test_compose_db_contract_consistent(self):  # INTEGRATION (Attack 8)
        # api.DATABASE_URL must be built from the SAME vars the db service
        # consumes — no divergent literal credentials between services.
        doc = yaml.safe_load((ROOT / "docker-compose.yml").read_text(
            encoding="utf-8"))
        db_vars = set(doc["services"]["db"]["environment"])
        api_url = str(doc["services"]["api"]["environment"]["DATABASE_URL"])
        refs = set(COMPOSE_VAR_RE.findall(api_url))
        assert refs <= db_vars, f"api DATABASE_URL refs {refs} outside db {db_vars}"
        assert {"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"} <= refs

    def test_compose_password_fail_closed(self):  # INTEGRATION
        # POSTGRES_PASSWORD must use the :? hard-require form (compose aborts
        # with an actionable message when unset) — never a soft dev default
        # that could silently cross into production. Adopted M00.2 contract.
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        assert "${POSTGRES_PASSWORD:?" in text, \
            "compose must hard-require POSTGRES_PASSWORD (:?)"
        assert "${POSTGRES_PASSWORD:-" not in text, \
            "soft dev-default fallback for the DB password is forbidden"


# --- reproducibility + process behavior ---------------------------------------

class TestReproducibility:
    def test_same_env_same_snapshot_and_fingerprint(  # UNIT
            self, monkeypatch, tmp_path):
        a = make(monkeypatch, tmp_path, **BASE_ENV)
        b = make(monkeypatch, tmp_path, **BASE_ENV)
        assert a.snapshot() == b.snapshot()
        assert a.fingerprint() == b.fingerprint()
        assert len(a.fingerprint()) == 64  # sha256 hex

    def test_secret_change_keeps_fingerprint(self, monkeypatch, tmp_path):  # UNIT
        a = make(monkeypatch, tmp_path, **BASE_ENV)
        b = make(monkeypatch, tmp_path, **{
            **BASE_ENV, "APPROVAL_SECRET": "a-different-secret-value-00"})
        assert a.fingerprint() == b.fingerprint()  # secrets excluded by design

    def test_nonsecret_change_moves_fingerprint(self, monkeypatch, tmp_path):  # UNIT
        a = make(monkeypatch, tmp_path, **BASE_ENV)
        b = make(monkeypatch, tmp_path, **{**BASE_ENV, "SEED_SEED": "43"})
        assert a.fingerprint() != b.fingerprint()

    def test_singleton_load_once(self, monkeypatch, tmp_path):  # RUNTIME
        for k in KNOWN_KEYS:
            monkeypatch.delenv(k, raising=False)
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)
        get_settings.cache_clear()
        try:
            assert get_settings() is get_settings()
        finally:
            get_settings.cache_clear()

    def test_env_beats_dotenv_file(self, monkeypatch, tmp_path):  # RUNTIME
        # Precedence part 2 (documented): environment > .env file > default.
        for k in KNOWN_KEYS:
            monkeypatch.delenv(k, raising=False)
        dotenv = tmp_path / ".env"
        dotenv.write_text(
            "EXECUTOR=docker\nAPPROVAL_SECRET=file-secret-16-chars-ok\n"
            "POSTGRES_PASSWORD=file-db-pass\nPROOFOPS_API_KEY=file-api-key\n",
            encoding="utf-8")
        monkeypatch.setenv("EXECUTOR", "mock")
        get_settings.cache_clear()
        try:
            s = load_settings(_env_file=str(dotenv))
        finally:
            get_settings.cache_clear()
        assert s.EXECUTOR == "mock"  # env beat the file
        assert s.APPROVAL_SECRET == "file-secret-16-chars-ok"  # file beat default
