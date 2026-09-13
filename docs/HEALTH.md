# ProofOps Health Checks & Readiness (M00.4)

Two signals, never conflated (see `backend/app/health.py`):

## Liveness — `GET /healthz` (M00.1 contract, frozen)

`{"status":"ok","service":"proofops-api","spec":"PS03_FINAL_SPEC_V2"}`.
Always 200 while the process lives — **even with dependencies down**. Drives
the image `HEALTHCHECK` and compose `service_healthy`: only a dead process
restarts a container. A flapping database must never restart the api, hence
readiness is deliberately NOT the healthcheck.

## Readiness — `GET /readyz` (M00.4)

200 + `{"status":"ready",...}` only when every dependency serves; otherwise
503 + `{"status":"not-ready",...}`. Current checks: `database` (`SELECT 1`
over the M00.2 `DATABASE_URL`, 2s bounded timeout, latency reported in
`latency_ms`). Body shape is exact and secret-free: no DSN, no passwords, no
`APPROVAL_*` — driver errors are replaced with static text (`database
unreachable` / `database query failed`).

## Dependency-down behavior (runtime-verified matrix)

| State | `/healthz` | `/readyz` |
|---|---|---|
| all up | 200 ok | 200 ready |
| db stopped | 200 ok | 503 not-ready (`database unreachable`) |
| db back | 200 ok | 200 ready (no api restart needed) |
| api restarted | 200 ok | 200 ready |

## Timeouts

Probe timeout 2s (`DEFAULT_PROBE_TIMEOUT_S`): readiness degrades fast instead
of hanging callers. Refused/fast-fail paths return in milliseconds; only a
black-holed host burns the full budget.

## Troubleshooting

- `503 not-ready` + `database unreachable` with db `healthy`: the pg_isready
  gate needs no auth, the probe does — suspect `.env`↔volume password drift
  (volume passwords are init-only; see `docs/COMPOSE.md` stickiness note).
  M00.4 testing realigned one such drift via `ALTER USER` (no data touched).
- `503` right after `up`: db still initializing — wait for `service_healthy`,
  then re-check (orchestrated start already orders this).
- Never put secrets in health bodies: `readiness()` output is asserted
  secret-free in `tests/test_health.py` and live in
  `tests/test_health_runtime.py`.
