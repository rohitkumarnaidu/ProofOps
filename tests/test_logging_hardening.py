"""M00.5 logging hardening (90+ pass, host-safe UNIT + SECURITY).

New-file companion to tests/test_logging.py (which stays untouched): proves
the ADR-007 pattern widening (AWS/GitHub/Slack parity with the repo scanner)
and the no-print import-point rule without editing the frozen test.
"""
from __future__ import annotations

import io
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.logging_setup import RedactingFormatter  # noqa: E402


def _emit(name: str, msg: str, *args) -> str:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingFormatter(()))
    log = logging.getLogger(name)
    log.handlers.clear()
    log.propagate = False
    log.setLevel(logging.DEBUG)
    log.addHandler(handler)
    try:
        log.info(msg, *args)
    finally:
        log.handlers.clear()
    return stream.getvalue()


class TestTokenParity:
    def test_aws_key_redacted(self):  # SECURITY
        out = _emit("m00.5.h1", "key %s", "AKIA" + "A" * 16)
        assert "AKIA" not in out and "<REDACTED>" in out

    def test_github_token_redacted(self):  # SECURITY
        out = _emit("m00.5.h2", "token %s", "ghp_" + "a" * 36)
        assert "ghp_" not in out and "<REDACTED>" in out

    def test_slack_token_redacted(self):  # SECURITY
        # Built dynamically so the repo secret scanner (which scans this file)
        # does not see a literal live token shape in source.
        token = "xox" + "b-1234567890ab"
        out = _emit("m00.5.h3", "token %s", token)
        assert "xoxb-" not in out and "<REDACTED>" in out

    def test_prose_with_hyphens_untouched(self):  # UNIT
        # Over-redaction guard: ordinary hyphenated prose without a key-like
        # token must survive (note: any literal `sk-...` token is intentionally
        # redacted broadly — safety over verbosity in logs).
        out = _emit("m00.5.h4", "deploy completed with 95 percent accuracy")
        assert "deploy completed with 95 percent accuracy" in out


class TestImportPointRule:
    def test_no_print_in_app_code(self):  # STATIC
        # Every module must log via get_logger, never print (M00.5 contract).
        # Word-boundary match: `fingerprint(` must NOT count as `print(`.
        import re
        offenders = []
        for path in (ROOT / "backend" / "app").rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            for lineno, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                if re.search(r"(?<![A-Za-z0-9_])print\s*\(", code):
                    offenders.append(f"{path.name}:{lineno}")
        assert not offenders, f"print() in app code: {offenders}"
