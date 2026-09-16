"""M00.5 logging foundation (format + redaction + level wiring).

Single import point for all ProofOps logging. Every future module must log
through ``get_logger(__name__)`` — never ``print`` — so that two guarantees
hold process-wide (spec PS03_FINAL_SPEC_V2: "no secrets in prompts/logs"):

1. STRUCTURE: one greppable line per record —
   ``ts=<UTC ISO-8601> level=<LEVEL> logger=<name> msg=<message>``.
   Tracebacks (exc_info) are appended after the line, also scrubbed.
2. SECRECY: ``RedactingFormatter`` scrubs the *formatted* line (message +
   args + traceback), so secrets can never escape via an unformatted field:
   - explicit secret values registered at ``configure_logging`` time
     (main.py passes every M00.2 secret + DATABASE_URL; values shorter than
     ``MIN_SECRET_LEN`` are skipped — scrubbing short substrings would mangle
     ordinary words; generic patterns below still cover their realistic
     emission paths);
   - generic patterns: URI credentials (``://user:pass@``), password-style
     assignments (``password=...`` / ``passwd: ...`` / ``pwd=...``), bearer
     tokens, API keys, PEM private-key blocks, plus AWS access keys,
     GitHub tokens, and Slack tokens (parity with the repo secret scanner,
     ADR-007 90+ pass).

``configure_logging`` is idempotent (re-calls replace handlers, never stack
them) and fail-closed on unknown levels. This module owns stdlib wiring only;
no product behavior.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable

REDACTED = "<REDACTED>"

# Scrubbing short substrings (e.g. a 4-char dev password) would redact
# ordinary words across every line. Generic patterns cover short secrets'
# realistic emission paths (URIs, assignments); exact-value scrubbing is
# reserved for values long enough to be unambiguous.
MIN_SECRET_LEN = 8

ALLOWED_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

_FORMAT = "ts=%(asctime)s level=%(levelname)s logger=%(name)s msg=%(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

_GENERIC_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # URI credentials: postgresql://user:password@host -> ://<REDACTED>@
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://<REDACTED>@"),
    # password-style assignments: password=secret / passwd: secret / pwd='x'
    (re.compile(r"(?i)(password|passwd|pwd)(\s*[:=]\s*)(['\"]?)[^\s'\"]+\3"),
     r"\1\2" + REDACTED),
    # bearer tokens: "Bearer abc..." (20+ non-space chars to avoid mangling words)
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/=]{20,}"), "Bearer " + REDACTED),
    # sk- style API keys
    (re.compile(r"sk-[A-Za-z0-9\-_]{8,}"), REDACTED),
    # Cloud/token shapes (parity with scripts/secret_scan.py live patterns,
    # ADR-007: runtime redaction is broad on purpose — over-redaction in logs
    # is safe, while the repo scanner stays precise to avoid false positives).
    (re.compile(r"AKIA[0-9A-Z]{16}"), REDACTED),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"), REDACTED),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    # PEM private key blocks (multiline: DOTALL so the whole block is one match)
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                re.DOTALL), REDACTED),
)


class RedactingFormatter(logging.Formatter):
    """Format-then-scrub: redacts the whole rendered line, incl. tracebacks."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__(_FORMAT, datefmt=_DATE_FORMAT)
        self._values: tuple[str, ...] = tuple(
            s for s in dict.fromkeys(secrets) if s and len(s) >= MIN_SECRET_LEN
        )

    def redact(self, text: str) -> str:
        for value in self._values:
            text = text.replace(value, REDACTED)
        for pattern, replacement in _GENERIC_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def format(self, record: logging.LogRecord) -> str:
        return self.redact(super().format(record))


def configure_logging(level: str = "INFO",
                       secrets: Iterable[str] = ()) -> RedactingFormatter:
    """Install the ProofOps handler on the root logger. Idempotent.

    Raises ValueError on unknown level (fail-closed: LOG_LEVEL comes from the
    M00.2 typed Settings Literal, so this fires only on programmer error).
    Returns the installed formatter (tests/runtime introspection).
    """
    normalized = (level or "").strip().upper()
    if normalized not in ALLOWED_LEVELS:
        raise ValueError(
            f"unknown log level {level!r}; expected one of "
            f"{', '.join(ALLOWED_LEVELS)}"
        )
    formatter = RedactingFormatter(secrets)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(normalized)
    return formatter


def get_logger(name: str) -> logging.Logger:
    """Single import point for module loggers: ``get_logger(__name__)``."""
    return logging.getLogger(name)
