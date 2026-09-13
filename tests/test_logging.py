"""M00.5 logging foundation (host-safe UNIT + SECURITY).

logging_setup imports stdlib only, so these run on ANY host Python.
Live container shape/hygiene is proven in tests/test_logging_runtime.py.
"""
from __future__ import annotations

import io
import logging
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import logging_setup  # noqa: E402
from app.logging_setup import (  # noqa: E402
    RedactingFormatter,
    configure_logging,
    get_logger,
)

FAKE_SECRET = "hunter2-fake-secret-value"
FAKE_DB_URL = "postgresql://proofops:hunter2-fake-db-pass@db:5432/proofops"

LINE_RE = re.compile(
    r"^ts=\S+ level=(DEBUG|INFO|WARNING|ERROR) logger=\S+ msg=.*$")


def _emit(logger_name: str, secrets: tuple = (),
          fn=None) -> str:
    """Emit one record through a RedactingFormatter into a string."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingFormatter(secrets))
    log = logging.getLogger(logger_name)
    log.handlers.clear()
    log.propagate = False
    log.setLevel(logging.DEBUG)
    log.addHandler(handler)
    try:
        (fn or (lambda: log.info("hello world")))()
    finally:
        log.handlers.clear()
    return stream.getvalue()


class TestPositive:
    def test_line_shape(self):  # UNIT
        out = _emit("m00.5.shape")
        assert LINE_RE.match(out.strip()), out
        assert "logger=m00.5.shape" in out and "msg=hello world" in out

    def test_level_wiring(self):  # UNIT
        fmt = configure_logging("WARNING", secrets=())
        try:
            assert logging.getLogger().level == logging.WARNING
            assert logging.getLogger().isEnabledFor(logging.DEBUG) is False
        finally:
            configure_logging("INFO", secrets=())
        assert isinstance(fmt, RedactingFormatter)

    def test_level_case_insensitive(self):  # UNIT
        try:
            configure_logging("debug", secrets=())
            assert logging.getLogger().level == logging.DEBUG
        finally:
            configure_logging("INFO", secrets=())

    def test_idempotent_no_handler_stack(self):  # UNIT
        configure_logging("INFO", secrets=())
        configure_logging("INFO", secrets=())
        assert len(logging.getLogger().handlers) == 1

    def test_get_logger_naming(self):  # UNIT
        assert get_logger("proofops.x").name == "proofops.x"

    def test_non_secret_text_untouched(self):  # UNIT
        out = _emit("m00.5.plain", (FAKE_SECRET,),
                    lambda: logging.getLogger("m00.5.plain").info(
                        "env=demo level=INFO executor=mock"))
        assert "env=demo level=INFO executor=mock" in out


class TestNegative:
    @pytest.mark.parametrize("bad", ["", "   ", "VERBOSE", "TRACE", "info2"])
    def test_bad_level_fails_closed(self, bad):  # UNIT
        with pytest.raises(ValueError, match="unknown log level"):
            configure_logging(bad, secrets=())

    def test_short_secret_skipped(self):  # UNIT
        fmt = RedactingFormatter(secrets=("abc",))
        assert fmt._values == ()
        # ...but its generic-pattern paths still work (see security tests).

    def test_logging_never_raises_on_weird_input(self):  # UNIT
        out = _emit("m00.5.weird", (FAKE_SECRET,),
                    lambda: logging.getLogger("m00.5.weird").info(
                        "obj=%r none=%s num=%d", {"k": 1}, None, 42))
        assert LINE_RE.match(out.strip()), out


class TestSecurity:
    def test_exact_secret_redacted(self):  # SECURITY
        out = _emit("m00.5.s1", (FAKE_SECRET,),
                    lambda: logging.getLogger("m00.5.s1").info(
                        "connecting with %s", FAKE_SECRET))
        assert FAKE_SECRET not in out and "<REDACTED>" in out

    def test_database_url_redacted(self):  # SECURITY
        out = _emit("m00.5.s2", (FAKE_DB_URL,),
                    lambda: logging.getLogger("m00.5.s2").info(
                        "dsn=%s", FAKE_DB_URL))
        assert "hunter2-fake-db-pass" not in out

    def test_uri_credentials_pattern(self):  # SECURITY
        out = _emit("m00.5.s3", (),
                    lambda: logging.getLogger("m00.5.s3").info(
                        "dial postgresql://admin:s3cr3t-pw@db:5432/x"))
        assert "s3cr3t-pw" not in out and "://<REDACTED>@" in out

    def test_password_assignment_pattern(self):  # SECURITY
        for msg in ("password=hunter2-fake-db-pass",
                    "passwd: hunter2-fake-db-pass",
                    "PWD='hunter2-fake-db-pass'"):
            out = _emit("m00.5.s4", (),
                        lambda m=msg: logging.getLogger("m00.5.s4").info(m))
            assert "hunter2-fake-db-pass" not in out, msg

    def test_bearer_and_sk_patterns(self):  # SECURITY
        out = _emit("m00.5.s5", (),
                    lambda: logging.getLogger("m00.5.s5").info(
                        "auth Bearer abcdefghijklmnopqrst1234 key sk-fakeKey12345678"))
        assert "abcdefghijklmnopqrst1234" not in out
        assert "sk-fakeKey12345678" not in out

    def test_pem_block_redacted(self):  # SECURITY
        pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
               "MIIFakeKeyMaterial hunter2-fake\n"
               "-----END RSA PRIVATE KEY-----")
        out = _emit("m00.5.s6", (),
                    lambda: logging.getLogger("m00.5.s6").info("key:\n%s", pem))
        assert "MIIFakeKeyMaterial" not in out and "hunter2-fake" not in out

    def test_exception_trace_redacted(self):  # SECURITY
        def boom():
            log = logging.getLogger("m00.5.s7")
            try:
                raise ValueError(f"auth failed for {FAKE_SECRET}")
            except ValueError:
                log.exception("request failed")
        out = _emit("m00.5.s7", (FAKE_SECRET,), boom)
        assert FAKE_SECRET not in out
        assert "request failed" in out and "ValueError" in out

    def test_installed_root_formatter_redacts(self):  # SECURITY
        stream = io.StringIO()
        configure_logging("INFO", secrets=(FAKE_SECRET,))
        root = logging.getLogger()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(root.handlers[0].formatter)
        root.addHandler(handler)
        try:
            logging.getLogger("m00.5.root").warning("leak? %s", FAKE_SECRET)
        finally:
            root.handlers.remove(handler)
            configure_logging("INFO", secrets=())
        assert FAKE_SECRET not in stream.getvalue()

    def test_error_text_lists_levels_without_echoing_secrets(self):  # SECURITY
        with pytest.raises(ValueError) as exc:
            configure_logging("VERBOSE", secrets=(FAKE_SECRET,))
        assert FAKE_SECRET not in str(exc.value)
        assert "DEBUG" in str(exc.value)
        configure_logging("INFO", secrets=())


def test_no_hardcoded_real_secrets_in_module():  # SECURITY
    src = (ROOT / "backend" / "app" / "logging_setup.py").read_text()
    # The module must contain patterns, never credential values.
    assert "hunter2" not in src
    assert logging_setup.REDACTED == "<REDACTED>"
