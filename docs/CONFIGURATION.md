# ProofOps Configuration (M00.2 trust boundary)

`backend/app/config.py` (`Settings`) is the single source of truth for every
runtime setting. Flow: `ENV → Typed Settings → Validation → Safe Runtime
Config → Sanitized Snapshot`. Nothing reads `os.environ` directly except
`scripts/verify_lyzr.py` (standalone stdlib tool, parity-tested).

## Variables

| Variable | Type | Default | Class | Owner |
|---|---|---|---|---|
| APP_ENV | development\|test\|demo\|production | development | PUBLIC | M00.2 |
| LOG_LEVEL | DEBUG\|INFO\|WARNING\|ERROR | INFO | PUBLIC | M00.2 (consumed M00.5) |
| DEBUG | bool | false | PUBLIC | M00.2 |
| EXECUTOR | mock\|docker (`kind` rejected until its tier lands) | mock | PUBLIC | M00.2 |
| APPROVAL_SECRET | str, required | — (fail-closed) | SECRET | M00.2 → M07 |
| APPROVAL_TTL_SECONDS | int > 0 | 600 | PUBLIC | M00.2 → M07 |
| POLICY_VERSION | non-empty token | v1 | PUBLIC | M00.2 → M06 |
| PROOFOPS_API_KEY | str, required | — (fail-closed) | SECRET | M00.2 |
| LYZR_API_KEY | str, empty = disabled | "" | SECRET | M00.2 → M13 |
| LYZR_AGENT_ID | str (CURRENT, verify script) | "" | SENSITIVE | M00.2 |
| LYZR_AGENT_TRIAGE/DIAGNOSTIC/PLANNER/REPORTER_ID | str (FUTURE, M13) | "" | FUTURE | M13 |
| LYZR_RAI_POLICY | str | PS03-Governed | PUBLIC | M00.2 → M13 |
| POSTGRES_USER / POSTGRES_DB | str | proofops | PUBLIC | compose + M00.2 |
| POSTGRES_PASSWORD | str, required | — (fail-closed) | SECRET | compose + M00.2 |
| DATABASE_URL | postgresql* URL, derived if empty | derived | SECRET-adjacent | M00.2 |
| SEED_SCENARIO | str | bad-deploy | PUBLIC | M00.2 → demo/eval |
| SEED_VARIANT | 5 spec variants | NORMAL | PUBLIC | M00.2 → demo/eval |
| SEED_SEED | int | 42 | PUBLIC | M00.2 → demo/eval |

`LYZR_ENABLED` is computed (`bool(LYZR_API_KEY)`), never configured.

## Environments

- **development**: friendly defaults; secrets still required (via `.env`).
- **test**: hermetic; tests inject env directly, never touch repo `.env`.
- **demo**: seeded trio (`SEED_*`) for reproducible runs.
- **production** fails closed: real `APPROVAL_SECRET` (≥16 chars, no
  `change-me`), `DEBUG=false`, explicit `PROOFOPS_API_KEY`/`POSTGRES_PASSWORD`
  (no dev markers), `EXECUTOR != mock`.

## Secret classification

PUBLIC (loggable) · SENSITIVE (ids; snapshot-visible, never in errors) ·
SECRET (redacted everywhere: `snapshot()`, `repr`, error text) ·
FUTURE (reserved, empty). `DATABASE_URL` is never snapshotted (embeds password).

## Precedence (deterministic, tested)

1. constructor/runtime override 2. environment variable 3. `.env` file
4. safe default. Unknown vars are ignored (`extra=ignore`, tested, no effect).

## Validation & startup

`backend/app/main.py` calls `get_settings()` at import: bad config raises
`ConfigurationError` with secret-safe messages (field + static reason, values
never echoed) before the app serves traffic. `Settings` is frozen — runtime
mutation raises. Singleton via `get_settings()` (load once per process).

## Compose guards

`POSTGRES_PASSWORD` uses the `:?` hard-require form in `docker-compose.yml`:
compose aborts with an actionable message when unset — no soft dev default may
silently cross into production. `api.DATABASE_URL` is built from the same
three vars the `db` service consumes (parity-tested).

## Safe vs unsafe commands

- SAFE: `docker compose config --quiet` (validate only),
  `docker compose config --services` (names only).
- UNSAFE: plain `docker compose config` prints secret VALUES (env_file merge).

## Reproducibility

Same env → same `snapshot()` → same `fingerprint()` (sha256 over canonical
non-secret config; secrets excluded by design, so rotating a secret keeps the
fingerprint — proving no leakage into it).

## Troubleshooting

- `ConfigurationError: APPROVAL_SECRET is required` → `cp .env.example .env`
  and fill secrets (never commit `.env`).
- `EXECUTOR` must be `mock` or `docker`; `kind` is rejected until its tier
  lands (explicit error, not silent fallback).
- Host Python runs offline structure tests only; the container
  (`python:3.12-slim`) is the supported runtime (see README Setup).
