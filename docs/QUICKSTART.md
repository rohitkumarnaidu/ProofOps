# Quickstart: from clone to first incident

Authoritative spec: [`PS03_FINAL_SPEC_V2.md`](PS03_FINAL_SPEC_V2.md) §40 (API
surface), §44 (documentation), §55 (demo) · Registry: [`MODULE_REGISTRY.md`](MODULE_REGISTRY.md)
· API detail: [`API.md`](API.md) · Configuration detail:
[`CONFIGURATION.md`](CONFIGURATION.md)

Status: every command below was run against this tree at commit `6d02749` on
Docker Desktop 29.6.2 and observed working. Where a step is not available yet it
says so rather than describing an intention.

Owning module: M00.1–M00.4 (repository, compose, configuration, and the
reproducible runtime surface this page documents). Registered into the canonical
doc set by ADR-016 in [`DECISIONS.md`](DECISIONS.md). It describes no capability
of its own; if a command here disagrees with the code, the code is the truth and
this page is the bug.

You will end up with the control plane running, six UI views, and at least one
incident you can walk through end to end. Nothing here needs a real Lyzr
credential or a real cluster: the default stack is honest about running on a
mock executor.

> On Windows, run these from Git Bash rather than PowerShell. `scripts/*.sh` and
> the `curl` examples assume a POSIX shell. The `docker compose` commands work
> in either.

## What you need

| Tool | Why | Check |
|------|-----|-------|
| Docker + Compose v2 | runs db, api, ui | `docker version` and `docker compose version` |
| Python 3.12+ | only to generate a secret and run the test suite | `python --version` |
| Git | clone | `git --version` |

Node is optional. It is needed only for the browser-rendered UI checks
(`scripts/ui_browser_check.mjs`), which skip cleanly when it is absent.

## Step 1: Create your environment file

The repository ships `.env.example`, a commented template. Compose reads `.env`,
and it will not start without one.

```bash
cp .env.example .env
```

Three values need your attention before the first start.

1. **Database password.** `POSTGRES_PASSWORD` is empty in the template and
   compose fails closed on it (`:?` in `docker-compose.yml`). Pick any value;
   nothing in this repository validates its strength, so use something you would
   not be embarrassed to paste into a public issue.

2. **Approval secret.** `APPROVAL_SECRET` ships as a placeholder. Generate a
   real one, because this key signs every human approval token:

   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

   Paste the output into `APPROVAL_SECRET`. A placeholder here means anyone who
   read this repository can mint valid approvals for your deployment.

3. **API key.** `PROOFOPS_API_KEY` is the bearer credential for every mutating
   endpoint. Set it to any non-empty string; the API hashes it and compares by
   digest, so the plaintext is never stored.

Two rules that save real pain:

- **Never run plain `docker compose config`.** It resolves `env_file` and prints
  your secrets to stdout. Use `docker compose config --quiet` to validate, or
  `docker compose config --services` to list service names.
- **Never commit `.env`.** It is already in `.gitignore`.

Leave `LIVE_CLUSTER=false` and `EXECUTOR=mock` for this walkthrough. The live
tier is a separate, optional step further down.

## Step 2: Start the stack

```bash
docker compose up -d
```

Compose starts in dependency order and waits for health: db must report healthy
before api starts, and api must report healthy before ui starts. The first build
compiles images, so allow several minutes.

```bash
docker compose ps
```

Expect three rows, all `healthy`:

```
db    postgres:16-alpine     Up (healthy)
api   lyzrcloudagent-api     Up (healthy)
ui    lyzrcloudagent-ui      Up (healthy)
```

If a service is restarting, read its log rather than guessing:

```bash
docker compose logs api --tail 40
```

## Step 3: Confirm the control plane answers

```bash
curl http://localhost:8000/healthz
```

```json
{"status":"ok","service":"proofops-api","spec":"PS03_FINAL_SPEC_V2"}
```

`/healthz` is liveness. It answers as long as the process is up and it does not
touch the database, which is deliberate: a database outage must not make the
container look dead to the orchestrator.

```bash
curl http://localhost:8000/readyz
```

`/readyz` is readiness. It returns 200 only when the database actually serves.
This is the probe that tells you the control plane can do work, as opposed to
merely existing.

Now the interesting one, the honest status of every engine:

```bash
curl http://localhost:8000/meta/engines
```

On a stock start you should see something close to:

```json
{
  "database":   {"healthy": true, "dialect": "postgresql", "degraded": false, "fallback_reason": null},
  "kubernetes": {"connected": false, "tier": "offline", "version": null, "error": "ConfigException"},
  "prometheus": {"connected": false, "tier": "standby-sandbox"},
  "llm_hub":    {"provider": "scripted-oracle", "status": "OFFLINE", "tier": "deterministic-baseline"}
}
```

Read the tier strings literally, because this project treats mislabelling a
tier as a defect rather than a rounding error:

| Field | Values | Meaning |
|-------|--------|---------|
| `kubernetes.tier` | `k8s` / `offline` | `k8s` means a real API server answered `/version` **and** authorized a pod list in the configured namespace. `offline` means it did not. |
| `prometheus.tier` | `live-promql` / `standby-sandbox` | `live-promql` means the real query path will be used. This describes the **verifier**, not the executor. |
| `llm_hub.status` | `UNVERIFIED` / `OFFLINE` | A configured key reports `UNVERIFIED`, never `CONNECTED`. Holding a credential is not a connection, and the backend will not claim otherwise. |

`llm_hub` reporting `UNVERIFIED` with a key set is the designed behavior, not a
fault. To get a real verified provider, set `LYZR_API_KEY` and confirm it with
`python scripts/verify_lyzr.py`.

## Step 4: Open the UI

<http://localhost:5173>

Six views, wired in `frontend/src/App.tsx`:

| View | Fetches | What it is for |
|------|---------|----------------|
| Command Center | `/runs`, `/meta/engines`, `/orchestrator` | Engine status, incident list, KPI filters, and the button that opens an incident |
| Incident Detail | `/runs/{id}`, audit stream | Hypotheses, evidence chips, pinned runbook, planned action, transition timeline. Read-only. |
| Safety Gate | `/identity`, `/approvals/{id}`, audit stream | Request an approval, then approve or deny. The only place a human grants authority. |
| Execution | `/runs/{id}`, audit stream | State diff, terminal logs, verification verdicts, rollback eligibility. Read-only. |
| RCA and Eval | audit chain, `/runs/{id}` | Hash-chained audit list with chain validity, plus the six-gate scorecard. |
| Agents | `/agents/{id}/thread` | Ask the read-only investigator a question. It can propose; it cannot act. |

Five of the six views carry a mode badge in the corner reading `LIVE`, `REPLAY`,
`MOCK`, `OFFLINE`, or `PROBING`. It is derived from `GET /meta`, not hardcoded,
and `PROBING` is shown while the probe is in flight so a slow load never reads
as an outage. The Agents view does not carry the badge.

## Step 5: Get an incident

There is no `POST /demo/seed` endpoint in this tree. It is spec §40 surface
marked PLANNED in [`DEMO.md`](DEMO.md), and it does not exist yet.

What does exist is an orchestrator that seeds and drives incidents on its own,
so on a fresh stack incidents often appear in the Command Center within about
45 seconds. Confirm the worker is alive:

```bash
curl http://localhost:8000/orchestrator
```

It returns worker counters plus a note describing whether the agent brain is a
scripted oracle. If the counter is not moving, submit one yourself with an
explicit scenario instead of waiting:

```bash
curl -X POST http://localhost:8000/alerts/ingest \
  -H "X-API-Key: $PROOFOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "incident_id": "demo-bad-deploy-1",
        "scenario": "bad-deploy",
        "telemetry": {
          "service": "checkout-api",
          "env": "prod",
          "error_signature": "OOMKilled",
          "metrics": [{"name": "container_memory_rss", "value": 990000000}]
        },
        "process": true
      }'
```

`process: true` hands the bundle to the worker, which runs triage, evidence,
diagnosis, planning, the action validator, and the policy engine. A reversible
action stops at `AWAITING_APPROVAL` and waits for a human. The worker can never
approve anything itself.

List what exists:

```bash
curl http://localhost:8000/runs
```

## Step 6: Watch it move

The audit stream is a live server-sent event feed, not a replay-and-close
response. It sends the backlog, a completion marker, then holds the connection
open with a keepalive comment every 15 seconds for up to an hour:

```bash
curl -N http://localhost:8000/stream/incidents/demo-bad-deploy-1
```

For the same incident, the audit chain is a SHA-256 hash chain where each entry
commits to the previous one. Tampering with any row breaks verification, and the
verify endpoint says where:

```bash
curl http://localhost:8000/incidents/demo-bad-deploy-1/audit
curl -X POST http://localhost:8000/incidents/demo-bad-deploy-1/audit/verify
```

If you would rather click through than read JSON, open
<http://localhost:5173> and follow the incident into the Safety Gate.

## Step 7: Approve something (optional)

The Safety Gate is where authority changes hands. A YELLOW action needs a valid,
single-use, expiring approval bound to the exact action and the exact
parameters. From the UI, open the incident, copy the action JSON from the
template, request an approval, then approve it.

Over HTTP, with the key and the token:

```bash
curl http://localhost:8000/approvals -X POST \
  -H "X-API-Key: $PROOFOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action": { ... }, "actor": "sre-1", "ttl_seconds": 600}'
```

The response carries the `token`. Spend it once:

```bash
curl -X POST http://localhost:8000/approvals/<approval_id>/approve \
  -H "X-API-Key: $PROOFOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"actor": "approver-1", "token": "<token>", "role": "approver"}'
```

The approving role must differ in enforcement terms from the requesting actor,
and the token is burned on use. Replaying it fails.

`POST /runs/{id}/advance` moves a run one FSM edge at a time and requires the
approval credentials on the `APPROVED` edge specifically. It is a manual
control surface, not the main path; the orchestrator is. No UI button calls it,
which is why the Incident Detail empty state says to advance from the API.

## Optional: the live tier

The default stack is deliberately non-live: `EXECUTOR=mock` and
`LIVE_CLUSTER=false`. Reaching a cluster is not consent to mutate it.

To stand up a real Kubernetes API server and a real Prometheus, on a host with
`docker`, `kind`, and `kubectl` on `PATH`:

```bash
bash scripts/live_tier.sh up
```

This creates a kind cluster named `proofops`, a namespace `proofops-demo`, an
instrumented demo workload, kube-state-metrics, and a Prometheus container, then
writes credentials into `var/live/`. Inspect the result:

```bash
bash scripts/live_tier.sh status
```

It reports the cluster version, what the agent ServiceAccount is actually
allowed to do (`kubectl auth can-i`), whether Prometheus answers, and the
measured error rate, or an explicit `UNMEASURED` when there are not enough series
yet.

Then opt in, in `.env`:

```
LIVE_CLUSTER=true
```

Restart the api service and re-read `/meta/engines`. What changes:

- Execution goes to the real API server instead of the in-memory sandbox.
- Verification goes to real PromQL instead of the deterministic verifier.
- **A live failure is reported as a live failure.** With `LIVE_CLUSTER=true` the
  control plane refuses to fall back to the mock sandbox, because a success from
  a dict that never touched the cluster would be an audit entry for a
  remediation that did not happen.

Tear it down with `bash scripts/live_tier.sh down`. Note that this deletes the
kind cluster and therefore the `kind` Docker network, which `docker-compose.yml`
declares as external; recreate that network (`docker network create kind`) before
the next `docker compose up`.

## Verify your install

Run the host-safe suite. It needs no daemon and no network:

```bash
python -m pytest tests/ -q -p no:warnings \
  --ignore=tests/test_compose_runtime.py \
  --ignore=tests/test_config_runtime.py \
  --ignore=tests/test_health_runtime.py \
  --ignore=tests/test_logging_runtime.py
```

Those four ignored files are the runtime suites. They drive a live Docker daemon
and mutate the running stack, so they are excluded from the default pass. See
[`TESTING.md`](TESTING.md) for the full suite map.

Two repo guards worth knowing about, both host-safe:

```bash
python scripts/secret_scan.py    # credential-shaped strings in tracked files
python scripts/freeze.py --check # lockfile covers every requirement at an exact pin
```

## Troubleshooting

**`POSTGRES_PASSWORD ... required` or a compose `:?` interpolation error.** The
`.env` file is missing, or `POSTGRES_PASSWORD` is still blank. Compose fails
closed here on purpose.

**`api` restarts in a loop.** Read `docker compose logs api --tail 40`. The most
common cause is a placeholder `APPROVAL_SECRET` combined with
`APP_ENV=production`, which is designed to refuse to start.

**`/readyz` returns 503 while `/healthz` returns 200.** The database is not
serving. Check `docker compose ps` for db and `docker compose logs db --tail 20`.

**`/meta/engines` shows `dialect: "sqlite"`.** The API fell back to a local file
because Postgres was unreachable. `degraded` is `true` and `fallback_reason`
carries the cause. The audit trail is not in Postgres in that state; treat it as
a real problem, not a warning.

**UI shows a blank page.** The UI container is up but cannot reach the API. Check
`docker compose logs ui --tail 20` and confirm `api` is healthy, since ui waits
for it.

**`/auth/identity` returns 401.** Working as intended. Send
`X-API-Key: $PROOFOPS_API_KEY`. Without it, a bootstrap identity is used, which
is permitted for local demo use and flagged as such in the Safety Gate.

**Incident never appears.** The orchestrator seeds on an interval. Check
`GET /orchestrator` for a moving counter, then submit explicitly with the
`/alerts/ingest` call in Step 5.

## What is not here yet

Honest gaps, so you do not go looking for them:

- `POST /demo/seed` and `scripts/demo.sh --check` are PLANNED (M22.1, M22.5).
  There is no one-command demo, and no rehearsal log.
- The RCA view renders the audit chain and the six-gate scorecard. It does not
  render an RCA document; that surface is PLANNED.
- Prometheus is optional and reports `standby-sandbox` unless the live tier is up.
- No route rate-limits or throttles requests. PLANNED, not built.
- `AgentsView` is the one view not covered by the rendered browser check, which
  covers the other five at three viewport widths.
