# ProofOps Logging Foundation (M00.5)

Single import point: `backend/app/logging_setup.py`. All modules log via
`get_logger(__name__)` — never `print`.

## Format (one greppable line per record)

`ts=<UTC ISO-8601> level=<LEVEL> logger=<name> msg=<message>`

Level comes from the M00.2 `LOG_LEVEL` setting (`DEBUG|INFO|WARNING|ERROR`;
fail-closed on anything else). `configure_logging` is idempotent.

## Redaction (format-then-scrub)

`RedactingFormatter` scrubs the fully rendered line — message, args, and
tracebacks (`logger.exception` included) — covering:

- exact secret values registered at startup (`APPROVAL_SECRET`,
  `POSTGRES_PASSWORD`, `PROOFOPS_API_KEY`, `LYZR_API_KEY`, `DATABASE_URL`);
  values shorter than 8 chars are skipped as exact matches (they would mangle
  ordinary words) and remain covered by the patterns below;
- generic patterns: URI credentials (`://user:pass@` → `://<REDACTED>@`),
  `password/passwd/pwd` assignments, bearer tokens, `sk-` keys, PEM blocks.

## Boundary (deliberate)

Uvicorn keeps its own formatter for server boot lines (it applies its logging
config after app import; taking it over would need deprecated hooks). The
M00.5 guarantee covers every **application** record. Uvicorn boot lines are
secret-free by nature (no bodies/credentials at INFO) and are asserted
hygienic live in `tests/test_logging_runtime.py`.

## Troubleshooting

- `ValueError: unknown log level` at startup: `LOG_LEVEL` bypassed the
  `Settings` Literal — fix the caller, not the log call.
- Over-redacted ordinary words: a registered secret value is a common
  substring — rotate to a longer secret (production already requires ≥16).
- `level=DEBUG` lines in prod logs: `LOG_LEVEL` misconfigured — restart with
  `INFO` (M00.2 immutability: level is fixed at process start).
