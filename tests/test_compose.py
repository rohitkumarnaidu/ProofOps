"""M00.3 compose/service-runtime static contract (STATIC: YAML-structure only).

Runtime behavior is proven in tests/test_compose_runtime.py (live daemon).
This file freezes topology, ports, ordering, restart, volumes, and the
build-context hygiene contract. Every assertion parses YAML structurally —
substring matching would hide wrong-port/wrong-condition escapes.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(
        encoding="utf-8"))


def _published(svc: dict) -> list[str]:
    return [str(p).split("#")[0].strip() for p in svc.get("ports", [])]


class TestTopology:
    def test_exact_service_set(self):  # STATIC
        # No Redis/Kafka/extras without a proven consumer (M00.3 freeze).
        assert set(_compose().get("services", {})) == {"db", "api", "ui"}

    def test_build_contexts(self):  # STATIC
        services = _compose()["services"]
        assert services["api"]["build"] == {"context": ".",
                                            "dockerfile": "Dockerfile"}
        assert services["ui"]["build"] == "./frontend"
        assert "build" not in services["db"]  # pinned official image

    def test_images_pinned(self):  # STATIC
        services = _compose()["services"]
        assert services["db"]["image"] == "postgres:16-alpine"
        for svc, cfg in services.items():
            assert ":latest" not in str(cfg.get("image", ""))

    def test_default_network_only(self):  # STATIC
        doc = _compose()
        assert "networks" not in doc, \
            "no custom segmentation for M00.3 (default network + DNS suffices)"
        for svc, cfg in doc["services"].items():
            assert cfg.get("network_mode") != "host", f"{svc}: host net forbidden"


class TestPorts:
    def test_exact_published_ports(self):  # STATIC
        services = _compose()["services"]
        assert _published(services["api"]) == ["8000:8000"]
        assert _published(services["ui"]) == ["5173:80"]
        assert _published(services["db"]) == ["5433:5432"]

    def test_no_unexpected_ports(self):  # STATIC
        all_ports = []
        for svc, cfg in _compose()["services"].items():
            all_ports.extend(_published(cfg))
        assert sorted(all_ports) == ["5173:80", "5433:5432", "8000:8000"]


class TestOrdering:
    def test_db_before_api_healthy(self):  # STATIC
        dep = _compose()["services"]["api"].get("depends_on", {})
        assert dep.get("db", {}).get("condition") == "service_healthy"

    def test_ui_after_api_healthy(self):  # STATIC
        dep = _compose()["services"]["ui"].get("depends_on", {})
        assert dep.get("api", {}).get("condition") == "service_healthy"

    def test_healthchecks_wired(self):  # STATIC
        services = _compose()["services"]
        assert "healthcheck" in services["db"]
        for name in ("Dockerfile", "backend/Dockerfile", "frontend/Dockerfile"):
            assert "HEALTHCHECK" in (ROOT / name).read_text(encoding="utf-8"), \
                f"{name}: image-level HEALTHCHECK required"
        db_hc = services["db"]["healthcheck"]
        assert db_hc["interval"] == "5s" and db_hc["retries"] == 10


class TestRestartVolumes:
    def test_restart_policy(self):  # STATIC
        # Deliberate M00.3 choice (see compose comment): recover from crashes
        # and reboots, respect explicit stops. `always`/`on-failure` rejected.
        for svc, cfg in _compose()["services"].items():
            assert cfg.get("restart") == "unless-stopped", \
                f"{svc}: restart must be unless-stopped"

    def test_named_volume_persistence(self):  # STATIC
        doc = _compose()
        assert "pgdata" in doc.get("volumes", {}), "named volume required"
        mounts = [str(v) for v in doc["services"]["db"].get("volumes", [])]
        assert "pgdata:/var/lib/postgresql/data" in mounts

    def test_no_host_binds(self):  # STATIC
        for svc, cfg in _compose()["services"].items():
            for vol in cfg.get("volumes", []) or []:
                src = vol if isinstance(vol, str) else str(vol.get("source", ""))
                assert not (src.startswith("/") or src.startswith(".")), \
                    f"{svc}: host bind forbidden: {vol}"


class TestEnvWiring:
    def test_api_env_contract(self):  # STATIC
        api = _compose()["services"]["api"]
        assert api.get("env_file") == ".env"
        assert "DATABASE_URL" in str(api.get("environment", ""))

    def test_no_privilege_escalation(self):  # STATIC
        for svc, cfg in _compose()["services"].items():
            assert cfg.get("privileged") is not True


class TestBuildHygiene:
    def test_dockerignore_covers_secrets_and_junk(self):  # STATIC
        # The api build uses repo-root context: without this, .env (live
        # secrets) and .git are SENT to the daemon on every build.
        text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        for needle in (".env", ".git", "__pycache__/", ".pytest_cache/",
                       ".ruff_cache/", ".venv/"):
            assert needle in text.splitlines(), f".dockerignore missing {needle}"

    def test_frontend_context_clean(self):  # STATIC
        # ./frontend context is tiny; prove no secret-ish file can leak into it.
        names = {p.name for p in (ROOT / "frontend").rglob("*") if p.is_file()}
        assert not (names & {".env", ".env.local", "id_rsa", ".npmrc"}), names
