# ProofOps Architecture (M00.6 foundation; built through M21, owned per module)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §62 (final architecture), §63 (agent graph),
§43 (repository), §47 (stack), §15 (14-state FSM).

Status: M00–M21 implemented with hardening pending. Per-module naming and
per-row status live in `docs/MODULE_REGISTRY.md` (the authority; a summary
line here cannot go stale independently of it). Nothing here claims production
readiness or certification.

## Built today (M00–M21, tested)

- Layout (M00.1): `/agents /frontend /backend /policies /runbooks /telemetry
  /tools /evaluation /benchmarks /tests /docs /scripts` plus `Dockerfile`,
  `docker-compose.yml`, `.env.example`, `README.md`. Tests:
  `tests/test_repo_structure.py`.
- Config trust boundary (M00.2): `backend/app/config.py` typed `Settings`,
  fail-closed, redacted snapshot. Detail: `docs/CONFIGURATION.md`.
- Runtime (M00.3): `db (postgres:16-alpine)` → `api (FastAPI, non-root)` →
  `ui (nginx, Vite app, unprivileged 8080)` with health-gated ordering.
  Detail: `docs/COMPOSE.md`.
- Health split (M00.4): liveness `GET /healthz` (frozen) vs readiness
  `GET /readyz` (DB-depth, 2s bound, secret-free). Detail: `docs/HEALTH.md`.
- Logging (M00.5): `RedactingFormatter`, format-then-scrub, uvicorn boundary
  stated. Detail: `docs/LOGGING.md`.
- Contracts + data pipeline (M01–M05): canonical contracts, deterministic
  telemetry, normalization, correlation, evidence service. Detail:
  `docs/CONTRACTS.md`.
- Governance + safety (M06–M11): validator, policy engine, HMAC HITL, mock
  sandbox, verifier, rollback, runbook loader (hash/pin/params).
- Intelligence (M12–M14): lexical KB retrieval + Evidence Pack, 4 Lyzr agents
  (deterministic-first, mocked-LLM contracts), canonical FSM + guards +
  idempotency, runs/approvals routers.
- Audit + evaluation (M15–M18): SHA256 hash chain + verify/export, eval
  runner (CASE→…→REPORT) + rubric, deep-5×5 + stub-7 suites, 14-attack
  adversarial suite + kill-switch.
- Product surface (M19): 5-view Vite UI + Safety Gate approvals API + eval
  smoke endpoint + SSE client + unprivileged UI image.
- Observability (M20, Lane 2): stdlib metrics registry, `/metrics`
  (Prometheus text) and `/alerts` (SLO states), fed by one ASGI middleware.
  Only HTTP route/code/latency counters are wired; the router-fed counters
  exist but are never incremented, so they render zero — see `docs/API.md`.
- Identity + incident stream (M21, Lane 1 + Lane 3): per-key SHA256 identity
  store with server-side roles and a `bootstrap` fallback (`/identity`), and
  `GET /stream/incidents/{id}`, a **replay-only** SSE projection of the audit
  chain with a `?since=` cursor.

## Runtime path and state model

Two layouts resolve the same assets; `backend/app/paths.py` is the single path
boundary for both.

| | Source tree | API image (`Dockerfile`) |
|---|---|---|
| Backend package | `backend/app` | `/app/app` (`COPY backend/app ./app`) |
| Agents | `agents/` | `/app/agents` |
| Telemetry generator | `telemetry/` | `/app/telemetry` |
| Policies | `policies/` (repo root) | `/app/policies` |
| Runbooks | `runbooks/` (repo root) | `/app/runbooks` |
| State root | `<repo>/var` | `/app/var` (pre-created and chowned to `appuser`, uid 10001) |
| Working dir | repo root | `WORKDIR /app` |

- **Resolution is location-derived, never environment-derived.**
  `paths.repo_root()` walks up from `paths.py` to the first ancestor that holds
  both `policies/` and `runbooks/` (repo root in the source tree, `/app` in the
  image); `state_dir()` is `<that root>/var`, `policies_dir()` and
  `runbooks_dir()` sit beside it. There is deliberately no environment
  override: `os.environ` access is forbidden anywhere under `backend/`, so no
  path can be moved by env var. An operator relocates state by mounting a
  volume at the resolved `state_dir()` (`backend/app/paths.py:1-51`).
- **What lives in `var/`.** `api_keys.json` (SHA256 digests + owner + roles),
  `approvals.json` (the HITL request queue), `runs.json` (FSM runs),
  `nonces.jsonl` (the nonce journal), and `audit-<incident_id>.jsonl` (one file
  per incident chain, id sanitized). `var/*` is gitignored with
  `!var/*.example`, so the only tracked file is `var/api_keys.json.example` —
  every one of these files is local state, never a committed artifact.
- **Persistence in compose.** The named volume `api_state` is mounted at
  `/app/var` (`docker-compose.yml:46-52`); an empty named volume inherits the
  image's `/app/var` ownership, which is why the image pre-creates it as
  `appuser`. `pgdata` is the separate Postgres volume.
- **Single resolver, adopted everywhere (M22, closed).** The durable-state
  owners previously computed their own paths as
  `Path(__file__).resolve().parents[3] / "var"`. In the source tree
  `parents[3]` *is* the repo root, so the divergence was invisible to every
  host test; in the image the module path is `/app/app/routers/...`, so
  `parents[3]` is `/` and those files resolved to `/var/...` while
  `paths.state_dir()` resolved to `/app/var`. The consequence was not
  cosmetic: the per-key identity store was never found, so every request
  silently fell back to the full-authority `bootstrap` identity with no
  server-side roles and no separation of duties, while approvals, runs, audit
  chains, and the nonce journal stayed memory-only under a uid that cannot
  write `/var`. All of them now call `paths` (`auth.py`, `approvals.py`,
  `runs.py`, `audit.py`, `policy.py`, `budgets.py`, `runbooks.py`), the image
  creates and chowns `/app/var` and ships `policies/` + `runbooks/`, and
  compose mounts the named volume `api_state` there.
  `tests/test_paths_state_m22.py` pins the invariant three ways: an AST check
  that rejects any hand-rolled `parents[...]` path outside `sys.path.insert`,
  a synthetic image-layout replay that proves the resolver lands on the
  WORKDIR while the old guess does not, and an assertion that the compose
  mount target, the Dockerfile `mkdir`/`chown`, and the resolver name the same
  directory. Runtime behavior in a live container is still `[UNVERIFIED]`
  here: this pass read code and started no container.
- **Eval run artifacts** are not runtime state: `scripts/run_baseline.py`
  writes `runs/baseline-<date>.jsonl` in the source tree, and `runs/` plus
  `*.jsonl` are gitignored. No run artifact is committed.

## Target (spec §62, quoted direction, not implemented)

```text
Telemetry(gen/SIM) -> Normalize/Pre-digest(CUSTOM) -> Correlate(CUSTOM) ->
A1 Triage(LYZR) -> Evidence Pack(CUSTOM) + KB(LYZR) -> A2 Diagnostic(LYZR) ->
Hypotheses -> Runbook pin -> A3 Planner(LYZR) -> Action -> Validator(CUSTOM) ->
Policy(CUSTOM) -> RAI(LYZR) -> HITL(CUSTOM HMAC) -> Sandbox+Execute(CUSTOM) ->
Verify(CUSTOM) -> Rollback?(CUSTOM) -> A4 RCA(LYZR, gated) ->
Audit hash(CUSTOM) + Trace(AIMS/LYZR) -> Eval runner(CUSTOM) + AgentEval(LYZR) ->
UI 5 views + incident stream (replay today; push is PLANNED).
```

Control plane (spec §04-G01, frozen): custom FastAPI FSM is canonical;
SuperFlow is `[OPTIONAL]` mirror only; Automata is banned as control plane.
Agents (spec §13): exactly 4 (A1 Triage, A2 Diagnostic, A3 Planner, A4 RCA
Reporter); no 5th without `docs/DECISIONS.md` justification.

## Lyzr vs custom vs simulated (today vs target)

| Layer | Today | Target (later phases) |
|---|---|---|
| Agents A1–A4 | IMPLEMENTED (M13: deterministic-first, mocked-LLM contracts, prompts, ACLs). Live Lyzr ADK/API execution is `[UNVERIFIED]` in this tree — no committed run artifact shows it. | LYZR-NATIVE (live ADK/API execution where keyed) |
| Safety (RAI) | IMPLEMENTED (M13 local guards + CUSTOM policy engine as authz boundary) | LYZR-NATIVE per-agent Studio guards in addition |
| Retrieval/memory | IMPLEMENTED (M12 local KB + pre-digestion) | LYZR-NATIVE Classic KB + Cognis where keyed |
| Trace | IMPLEMENTED CUSTOM hash audit (M15, labelled non-AIMS) | LYZR-NATIVE AIMS trace where supported |
| FSM/validator/policy/HITL/sandbox/verifier/rollback | IMPLEMENTED (M06–M11/M14) | CUSTOM-DETERMINISTIC (FastAPI + Postgres) |
| Telemetry/mock K8s/mock executor | IMPLEMENTED (M02/M08) | SIMULATED (deterministic seeds; docker tier local-real) |
| Eval/benchmarks/adversarial | IMPLEMENTED (M16–M18 machinery + M20 budgets). Pipeline runs to date are SCRIPTED-ORACLE SIMULATIONS — see `docs/EVALUATION.md`. | MEASURED SYSTEM RUN with live-model agents: PLANNED, UNMEASURED today |
| UI + incident stream | IMPLEMENTED (M19: 5 views, approvals API, SSE client; M21 identity + audit-chain replay stream). The stream is a **finite replay with a `?since=` cursor** — no push, no heartbeat, unauthenticated read (`docs/API.md`). | push/long-poll stream, M22 demo hardening |
| Kind/voice/vendor/SSO/SIEM | FUTURE, never claimed | FUTURE post-hackathon |

## PLANNED (owning modules, not implemented)

- Demo hardening (M22).
- Execute/verify/rollback HTTP endpoints and the rest of the spec §40 surface
  (alerts ingest, triage/evidence/diagnose/remediation, RCA publish,
  `POST /demo/seed`).
- Live Lyzr execution where keyed — UNVERIFIED today.
- A push or long-poll incident stream, plus rate limiting, SSO/OIDC, key
  expiry/revocation, and reconciliation of the durable-state path modules onto
  `paths.state_dir()` — all unassigned.

## Repro (host-safe)

```bash
python -m pytest tests/test_repo_structure.py tests/test_config.py -q
```
