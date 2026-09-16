"""M00.3 compose hardening (90+ pass, host-safe STATIC).

New-file companion to tests/test_compose.py (untouched): proves the ADR-007
disk-exhaustion guard (log rotation on every service) without editing the
frozen test.
"""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(
        encoding="utf-8"))


class TestLogRotation:
    def test_every_service_rotates_logs(self):  # STATIC
        for svc, cfg in _compose()["services"].items():
            logging = cfg.get("logging", {})
            assert logging.get("driver") == "json-file", \
                f"{svc}: json-file logging required"
            options = logging.get("options", {})
            assert options.get("max-size") == "10m", \
                f"{svc}: max-size 10m required"
            assert options.get("max-file") == "3", \
                f"{svc}: max-file 3 required"

    def test_docs_promise_matches_compose(self):  # STATIC
        body = (ROOT / "docs" / "COMPOSE.md").read_text(encoding="utf-8")
        assert "max-size 10m" in body and "max-file 3" in body
        assert "M00.3" in body
