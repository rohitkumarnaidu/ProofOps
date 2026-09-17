# ProofOps Architecture (M00.6 foundation; built through M19, owned per module)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §62 (final architecture), §63 (agent graph),
§43 (repository), §47 (stack), §15 (14-state FSM).

Status: implemented through M19.10 (Wave 6 open, M20 live frontier).
Per-module truth lives in `docs/MODULE_REGISTRY.md`. Nothing
here claims production readiness or certification.

## Built today (M00–M19, tested)

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
- Contracts + data pipeline (M01–M05, M01–M06 HUMAN_APPROVED): canonical
  contracts, deterministic telemetry, normalization, correlation, evidence
  service. Detail: `docs/CONTRACTS.md`.
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

## Target (spec §62, quoted direction, not implemented)

```text
Telemetry(gen/SIM) -> Normalize/Pre-digest(CUSTOM) -> Correlate(CUSTOM) ->
A1 Triage(LYZR) -> Evidence Pack(CUSTOM) + KB(LYZR) -> A2 Diagnostic(LYZR) ->
Hypotheses -> Runbook pin -> A3 Planner(LYZR) -> Action -> Validator(CUSTOM) ->
Policy(CUSTOM) -> RAI(LYZR) -> HITL(CUSTOM HMAC) -> Sandbox+Execute(CUSTOM) ->
Verify(CUSTOM) -> Rollback?(CUSTOM) -> A4 RCA(LYZR, gated) ->
Audit hash(CUSTOM) + Trace(AIMS/LYZR) -> Eval runner(CUSTOM) + AgentEval(LYZR) ->
UI 5 views + dual SSE.
```

Control plane (spec §04-G01, frozen): custom FastAPI FSM is canonical;
SuperFlow is `[OPTIONAL]` mirror only; Automata is banned as control plane.
Agents (spec §13): exactly 4 (A1 Triage, A2 Diagnostic, A3 Planner, A4 RCA
Reporter); no 5th without `docs/DECISIONS.md` justification.

## Lyzr vs custom vs simulated (today vs target)

| Layer | Today (M19) | Target (later phases) |
|---|---|---|
| Agents A1–A4 | IMPLEMENTED (M13: deterministic-first, mocked-LLM contracts, prompts, ACLs) | LYZR-NATIVE (live ADK/API execution where keyed) |
| Safety (RAI) | IMPLEMENTED (M13 local guards + CUSTOM policy engine as authz boundary) | LYZR-NATIVE per-agent Studio guards in addition |
| Retrieval/memory | IMPLEMENTED (M12 local KB + pre-digestion) | LYZR-NATIVE Classic KB + Cognis where keyed |
| Trace | IMPLEMENTED CUSTOM hash audit (M15, labelled non-AIMS) | LYZR-NATIVE AIMS trace where supported |
| FSM/validator/policy/HITL/sandbox/verifier/rollback | IMPLEMENTED (M06–M11/M14) | CUSTOM-DETERMINISTIC (FastAPI + Postgres) |
| Telemetry/mock K8s/mock executor | IMPLEMENTED (M02/M08) | SIMULATED (deterministic seeds; docker tier local-real) |
| Eval/benchmarks/adversarial | IMPLEMENTED (M16–M18) | measured baselines + M20 budgets |
| UI/SSE | IMPLEMENTED (M19: 5 views, approvals API, SSE client) | backend SSE + M21 integration |
| Kind/voice/vendor/SSO/SIEM | FUTURE, never claimed | FUTURE post-hackathon |

## PLANNED (owning modules, not implemented)

- Budgets + token/latency/cost measurement (M20); integration + API guard
  matrix + demo hardening (M21/M22); backend SSE endpoint; execute/verify
  endpoints (need M21 guards first); live Lyzr execution where keyed.

## Repro (host-safe)

```bash
python -m pytest tests/test_repo_structure.py tests/test_config.py -q
```
