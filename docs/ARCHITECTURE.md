# ProofOps Architecture Foundation (M00.6 foundation; full system owned by later phases)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §62 (final architecture), §63 (agent graph),
§43 (repository), §47 (stack), §15 (14-state FSM).

Status: foundation only. This doc records what M00.1–M00.5 built and tested
today plus the spec-defined target the later phases will implement. Nothing
here claims production readiness or certification.

## Built today (M00.1–M00.5, tested)

- Layout (M00.1): `/agents /frontend /backend /policies /runbooks /telemetry
  /tools /evaluation /benchmarks /tests /docs /scripts` plus `Dockerfile`,
  `docker-compose.yml`, `.env.example`, `README.md`. Tests:
  `tests/test_repo_structure.py`.
- Config trust boundary (M00.2): `backend/app/config.py` typed `Settings`,
  fail-closed, redacted snapshot. Detail: `docs/CONFIGURATION.md`.
- Runtime (M00.3): `db (postgres:16-alpine)` → `api (FastAPI, non-root)` →
  `ui (nginx stub)` with health-gated ordering. Detail: `docs/COMPOSE.md`.
- Health split (M00.4): liveness `GET /healthz` (frozen) vs readiness
  `GET /readyz` (DB-depth, 2s bound, secret-free). Detail: `docs/HEALTH.md`.
- Logging (M00.5): `RedactingFormatter`, format-then-scrub, uvicorn boundary
  stated. Detail: `docs/LOGGING.md`.

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

| Layer | Today (M00) | Target (later phases) |
|---|---|---|
| Agents A1–A4 | PLANNED (M13) | LYZR-NATIVE (ADK/API, Structured Output, session_id=incident_id) |
| Safety (RAI) | PLANNED (M06/M13) | LYZR-NATIVE per-agent guard + CUSTOM policy engine as authz boundary |
| Retrieval/memory | PLANNED (M12) | LYZR-NATIVE Classic KB + Cognis/Global Context + CUSTOM pre-digestion |
| Trace | PLANNED (M15) | LYZR-NATIVE AIMS trace + CUSTOM hash audit (labelled non-AIMS) |
| FSM/validator/policy/HITL/sandbox/verifier/rollback | PLANNED (M06–M11/M14) | CUSTOM-DETERMINISTIC (FastAPI + Postgres) |
| Telemetry/mock K8s/mock executor | PLANNED (M02/M08) | SIMULATED (deterministic seeds; docker tier local-real) |
| Kind/voice/vendor/SSO/SIEM | FUTURE, never claimed | FUTURE post-hackathon |

## PLANNED (owning modules, not implemented)

- FSM 14 states + guards + idempotency (M14); validator + policy ALLOW/ESCALATE/DENY (M06);
  HMAC HITL (M07); mock/docker sandbox (M08); verifier + rollback (M09/M10);
  runbook loader + hash/pin (M11); retrieval + Evidence Pack (M12); 4 Lyzr agents (M13);
  hash audit + eval runner + benchmarks + adversarial (M15–M18); 5-view UI + SSE (M19);
  budgets (M20); integration + demo hardening (M21/M22).

## Repro (host-safe)

```bash
python -m pytest tests/test_repo_structure.py tests/test_config.py -q
```
