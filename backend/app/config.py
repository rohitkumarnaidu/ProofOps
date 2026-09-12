"""M00.2 configuration trust boundary.

Single source of truth for every runtime setting. ENV -> typed Settings ->
validation -> safe runtime config. Everything later (policy, HITL, sandbox,
agents) reads through here; nothing reads os.environ directly.

Rules enforced here (see docs/CONFIGURATION.md):
- fail-closed: missing/invalid required values raise ConfigurationError.
- secrets (SECRET_FIELDS) never appear in repr, snapshot, or error text.
- APP_ENV=production: explicit real secrets, DEBUG=false, EXECUTOR != mock.
- EXECUTOR is mock|docker only (kind rejected until its tier lands).
- LYZR_*_ID per-agent ids are FUTURE (M13); only LYZR_AGENT_ID is CURRENT.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Any, Literal

from pydantic import ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REDACTED = "<REDACTED>"

# Values that must never be treated as real secrets (template placeholders).
PLACEHOLDER_MARKERS = ("change-me", "dev-key-change-me", "proofops-dev-only")

SECRET_FIELDS = frozenset({
    "LYZR_API_KEY",
    "APPROVAL_SECRET",
    "POSTGRES_PASSWORD",
    "PROOFOPS_API_KEY",
})

# DATABASE_URL embeds the DB password, so it is secret-adjacent even though the
# field name is not in SECRET_FIELDS.
SECRET_ADJACENT_FIELDS = frozenset({"DATABASE_URL"})

AppEnv = Literal["development", "test", "demo", "production"]
Executor = Literal["mock", "docker"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
SeedVariant = Literal["NORMAL", "NOISY", "INCOMPLETE", "CONTRADICTORY", "ADVERSARIAL"]


class ConfigurationError(ValueError):
    """Startup-blocking config failure. Message is always secret-safe."""


def _sanitized_message(exc: ValidationError) -> str:
    """Rebuild a ValidationError as static text with no input values.

    Pydantic echoes offending inputs (input_value=...) in str(exc); that would
    leak secrets into logs. We keep only field + static reason, and redact
    secret fields entirely.
    """
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", ())) or "config"
        if loc in SECRET_FIELDS or loc in SECRET_ADJACENT_FIELDS:
            parts.append(f"{loc}: invalid value {REDACTED}")
        else:
            parts.append(f"{loc}: {err.get('msg', 'invalid value')}")
    return "; ".join(parts) or "invalid configuration"


class Settings(BaseSettings):
    """Canonical application configuration. Frozen: load once, never mutate."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # unknown vars have no effect (documented, tested)
        frozen=True,  # runtime mutation raises; tests assert this
    )

    # --- application mode ---
    APP_ENV: AppEnv = "development"
    LOG_LEVEL: LogLevel = "INFO"
    DEBUG: bool = False

    # --- execution ---
    EXECUTOR: Executor = "mock"

    # --- security ---
    APPROVAL_SECRET: str = ""
    APPROVAL_TTL_SECONDS: int = 600
    POLICY_VERSION: str = "v1"
    PROOFOPS_API_KEY: str = ""

    # --- Lyzr (LYZR_AGENT_ID is CURRENT via scripts/verify_lyzr.py;
    #     per-agent ids are FUTURE, M13) ---
    LYZR_API_KEY: str = ""
    LYZR_AGENT_ID: str = ""
    LYZR_AGENT_TRIAGE_ID: str = ""
    LYZR_AGENT_DIAGNOSTIC_ID: str = ""
    LYZR_AGENT_PLANNER_ID: str = ""
    LYZR_AGENT_REPORTER_ID: str = ""
    LYZR_RAI_POLICY: str = "PS03-Governed"

    # --- database (DATABASE_URL derived from POSTGRES_* when unset) ---
    POSTGRES_USER: str = "proofops"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "proofops"
    DATABASE_URL: str = ""

    # --- demo / eval seeding ---
    SEED_SCENARIO: str = "bad-deploy"
    SEED_VARIANT: SeedVariant = "NORMAL"
    SEED_SEED: int = 42

    # --- derived, not configured ---
    @property
    def LYZR_ENABLED(self) -> bool:  # noqa: N802 (env-var naming is canonical)
        return bool(self.LYZR_API_KEY.strip())

    # --- field rules (messages are static: never interpolate values) ---
    @field_validator("APPROVAL_SECRET")
    @classmethod
    def _secret_required(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("APPROVAL_SECRET is required; set it in .env")
        return v

    @field_validator("POSTGRES_PASSWORD")
    @classmethod
    def _db_password_required(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("POSTGRES_PASSWORD is required; set it in .env")
        return v

    @field_validator("PROOFOPS_API_KEY")
    @classmethod
    def _api_key_required(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("PROOFOPS_API_KEY is required; set it in .env")
        return v

    @field_validator("APPROVAL_TTL_SECONDS")
    @classmethod
    def _ttl_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("APPROVAL_TTL_SECONDS must be a positive integer")
        return v

    @field_validator("POLICY_VERSION")
    @classmethod
    def _policy_version_shape(cls, v: str) -> str:
        if not v or not v.strip() or any(c.isspace() for c in v):
            raise ValueError("POLICY_VERSION must be a non-empty token without whitespace")
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def _database_url_scheme(cls, v: str) -> str:
        if v and not v.startswith("postgresql"):
            raise ValueError("DATABASE_URL must use a postgresql scheme")
        return v

    @model_validator(mode="after")
    def _cross_field_rules(self) -> "Settings":
        if not self.DATABASE_URL.strip():
            object.__setattr__(
                self,
                "DATABASE_URL",
                "postgresql+psycopg://"
                f"{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@db:5432/{self.POSTGRES_DB}",
            )
        if self.APP_ENV == "production":
            if len(self.APPROVAL_SECRET) < 16 or \
                    any(m in self.APPROVAL_SECRET for m in PLACEHOLDER_MARKERS):
                raise ValueError(
                    "production requires a real APPROVAL_SECRET "
                    "(>=16 chars, not a template placeholder)"
                )
            if self.DEBUG:
                raise ValueError("production forbids DEBUG=true")
            if any(m in self.PROOFOPS_API_KEY for m in PLACEHOLDER_MARKERS) \
                    or not self.PROOFOPS_API_KEY.strip():
                raise ValueError(
                    "production requires an explicit PROOFOPS_API_KEY "
                    "(not a dev default)"
                )
            if any(m in self.POSTGRES_PASSWORD for m in PLACEHOLDER_MARKERS):
                raise ValueError(
                    "production requires an explicit POSTGRES_PASSWORD "
                    "(not a dev default)"
                )
            if self.EXECUTOR == "mock":
                raise ValueError(
                    "production forbids EXECUTOR=mock; "
                    "authorize an explicit execution tier"
                )
        return self

    def snapshot(self) -> dict[str, Any]:
        """Sanitized config for debugging/audit. Secrets are always redacted."""
        data = self.model_dump()
        data.pop("DATABASE_URL", None)  # embeds the DB password; never snapshot it
        for field in SECRET_FIELDS:
            if field in data:
                data[field] = REDACTED
        data["LYZR_ENABLED"] = self.LYZR_ENABLED
        return data

    def fingerprint(self) -> str:
        """Stable sha256 over canonical NON-SECRET config (reproducibility)."""
        snap = self.snapshot()
        canonical = "\n".join(f"{k}={snap[k]}" for k in sorted(snap))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def __repr__(self) -> str:  # secret-safe by construction
        return f"Settings({self.snapshot()!r})"

    def __str__(self) -> str:
        return self.__repr__()


def load_settings(**overrides: Any) -> Settings:
    """Build Settings; convert any ValidationError into secret-safe error."""
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        raise ConfigurationError(_sanitized_message(exc)) from None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide singleton. Load once per process (M00.2 immutability)."""
    return load_settings()
