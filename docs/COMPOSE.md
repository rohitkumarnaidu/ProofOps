# ProofOps Local Runtime (M00.3: compose/service foundation)

## Services

| Service | Source | Purpose |
|---|---|---|
| db | `postgres:16-alpine` (pinned, no `:latest`) | Local Postgres |
| api | built from repo-root `Dockerfile` (non-root `appuser`) | FastAPI control plane |
| ui | built from `./frontend` (static nginx stub until M19) | Demo UI |

Topology: `ui → api → db` (HTTP ui→api; api→db internal service DNS `db:5432`).

## Ports (host-published, exact — tests enforce)

- api `8000:8000` · ui `5173:80` · db `5433:5432` (5433 avoids host-local clash).
- DB stays host-published deliberately: developers need direct access and there
  is no production here. Going internal-only is an M00.4+/prod decision, not
  M00.3 scope. Any mapping change fails `test_exact_published_ports`.

## Networks

Default compose network only — service DNS (`db`, `api`) suffices. No custom
segmentation, no host networking (tested). Revisit only with a proven need.

## Volumes

Named volume `pgdata` → `/var/lib/postgresql/data`. No host binds (tested).
Survives `down`/`up` and container recreation (runtime-tested with a scratch
table). `down -v` DESTROYS dev data — never run it casually.

### Password stickiness (read this before rotating secrets)

`POSTGRES_PASSWORD` applies at volume **initialization only**. Changing `.env`
later does NOT change the live DB password (postgres semantics, verified live:
ambient mismatch discovered by M00.3 testing). After a password change either
`ALTER USER proofops WITH PASSWORD '...'` inside db, or `down -v` + fresh
`up` (data loss). The compose `:?` guard ensures fresh setups fail fast instead
of silently diverging.

## Startup order

`db (healthy via pg_isready) → api (healthy via /healthz) → ui (healthy via
wget /)`, enforced with `service_healthy` conditions (runtime-verified creation
order db ≤ api ≤ ui). "Started" ≠ "ready": dependents wait for health, not
existence. Deep readiness (DB-depth checks) is M00.4 scope. Compose declares
its own `healthcheck` blocks mirroring the image HEALTHCHECKs (90+ pass):
`service_healthy` must never depend on an implicit image contract.

## Health semantics (wiring only — M00.4 owns depth)

- db: `pg_isready`; api: stdlib `/healthz` probe (liveness-only: answers even
  with db down — pinned as current contract, M00.4 closes it); ui: `wget /`.
- Intervals/timeouts/retries/start-periods are in compose/Dockerfiles and
  asserted structurally.

## Restart semantics

`restart: unless-stopped` on all three (deliberate): recovers from crashes and
daemon/host reboots, respects explicit `stop` (unlike `always`). `on-failure`
rejected: a config-broken api would loop identically with no benefit.

## Log rotation (M00.3 90+ pass, ADR-007)

Every service sets `logging: json-file max-size 10m max-file 3`: a runaway
service can never fill the host disk via container logs. Limits are generous
enough for demo debugging (`compose logs` still shows recent history) and are
asserted structurally in `tests/test_compose_hardening.py`. Full log shipping
(SIEM, retention) is FUTURE, post-hackathon.

Observed limit (M00.3, Docker Desktop 29.6.2): a SIGKILLed api stayed
`Exited (137)` / `RestartCount 0` for 25s+ on a fresh container — daemon
auto-resurrection was NOT observed on this host (possible Desktop quirk, not
a config defect: the daemon reports the policy correctly). Manual
restart/stop/start and full down/up recovery are proven by the runtime matrix.
M00.7 must re-confirm auto-resurrection on Linux dockerd.

## Safe vs unsafe commands

- SAFE: `docker compose config --quiet`, `config --services`, `ps`, `logs`.
- UNSAFE in captured logs: plain `docker compose config` (renders secrets);
  `down -v` (destroys `pgdata`).

## Failure recovery (all runtime-tested)

- api restart → healthy, config unchanged · ui restart → 200 · db restart →
  healthy, api servable (no DB path in skeleton) · full restart → 3×healthy.
- db down → api still answers `/healthz` (liveness-only by design; DB-depth readiness closed by M00.4 via `/readyz` — see `docs/HEALTH.md`).
- api down → ui still serves static stub (M19 owns real wiring).

## Development usage

```bash
cp .env.example .env   # once; fill secrets (never commit .env)
docker compose build --no-cache api   # clean api image
docker compose up -d                  # ordered, health-gated start
docker compose ps                     # expect 3x healthy
curl http://localhost:8000/healthz    # {"status":"ok",...}
```

## Resource limits

DEFERRED with reason: arbitrary CPU/memory caps risk OOM-killing postgres on
small hosts and breaking demos; no measurements exist. M20 owns budgets —
limits return with data, not guesses.
