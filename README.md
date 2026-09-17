# ProofOps — Evidence-Grounded Autonomous Incident Commander
AI Quest 2026 · PS03 · Enterprise Cloud Incident Triage & Runbook Remediation Agent

> THE AGENT MAY REASON. THE CONTROL PLANE DECIDES. THE SANDBOX CONTAINS.
> VERIFICATION PROVES. AIMS RECORDS. THE LLM IS NOT THE SECURITY BOUNDARY.

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` (supersedes V1 Part B on conflict).

## What it does
Mock telemetry → deterministic triage → evidence-grounded diagnosis → structured
remediation proposals → policy gate (GREEN/YELLOW/RED) → HMAC HITL approval →
sandboxed execution → independent SLO verification (+ auto-rollback) → gated,
blameless RCA → hash-chained audit → six-checkpoint evaluation scorecard.

## Lyzr vs custom vs simulated
| Component | Owner | Detail |
|---|---|---|
| 4 agents (Triage, Diagnostic, Planner, RCA) | LYZR-NATIVE | ADK/API, Structured Output, session_id=incident_id |
| Semantic safety (injection/PII/toxicity/groundedness) | LYZR-NATIVE | RAI policy `PS03-Governed` on every agent |
| Runbook/history retrieval, incident memory | LYZR-NATIVE | Classic KB + Cognis + Global Context |
| Run trace / latency | LYZR-NATIVE | AIMS tracing (+ custom hash audit below) |
| Agent-level eval assist | LYZR-NATIVE | Agent Eval (hallucination/faithfulness/tool-args) |
| FSM, validator, policy, HMAC HITL, sandbox, verifier, rollback | CUSTOM-DETERMINISTIC | FastAPI + Postgres, 100% tested |
| Hash-chained audit, eval runner, pre-digestion | CUSTOM-DETERMINISTIC | Exportable proof, labelled non-AIMS |
| Telemetry, mock K8s, mock executor | SIMULATED | Deterministic seeds; docker tier local-real |
| Kind default, voice, vendor connectors, SSO/SIEM | FUTURE | Not claimed |

## Setup
```bash
cp .env.example .env   # fill LYZR_* when available; mock fallback works without
docker compose up --build
# api http://localhost:8000/healthz · ui http://localhost:5173
```

Supported runtime: Docker (`python:3.12-slim`, the container is the source of
truth). Host Python 3.13/3.14 is NOT supported for running the API (Starlette
v1 ABI drift — see `backend/requirements.txt` header); host may run the
offline structure tests only (`pytest tests/test_repo_structure.py`).

Status: M00 foundation + M01 contracts + M02–M04 data pipeline are
HUMAN_APPROVED (see `docs/MODULE_REGISTRY.md` per-row truth for the full
picture, currently through Wave 6). Lyzr agents (M13), orchestration (M14),
evaluation (M16), benchmarks (M17), adversarial (M18), and frontend (M19)
have landed as IMPLEMENTED_TESTED — the table above describes the target
architecture; per-module maturity is in the registry, not claimed here.
Configuration trust boundary (typed Settings, fail-closed validation,
secret-safe snapshot): `docs/CONFIGURATION.md`.
Architecture target + built-today map: `docs/ARCHITECTURE.md`.
API surface (live `/healthz` + `/readyz` plus the M19 routers for approvals,
audit, eval, and runs; full contract in `docs/API.md`).
Testing layers (host-safe green + daemon-owned runtime): `docs/TESTING.md`.

## Architecture diagram (M00.6 foundation; ASCII, spec §62 target)

```text
Telemetry(gen/SIM) -> Normalize/Pre-digest(CUSTOM) -> Correlate(CUSTOM) ->
A1 Triage(LYZR) -> Evidence Pack(CUSTOM) + KB(LYZR) -> A2 Diagnostic(LYZR) ->
A3 Planner(LYZR) -> Action -> Validator(CUSTOM) -> Policy(CUSTOM) -> RAI(LYZR) ->
HITL(CUSTOM HMAC) -> Sandbox(CUSTOM) -> Verify(CUSTOM) -> Rollback?(CUSTOM) ->
A4 RCA(LYZR, gated) -> Audit hash(CUSTOM) + Trace(AIMS) -> Eval(CUSTOM+Lyzr) ->
UI 5 views + dual SSE. Control plane: FastAPI FSM (canonical).
```

## Demo (5:00)
Seed `bad-deploy/NORMAL` → 1 P1 → evidence → diagnosis → RED block of
`delete_namespace/prod` (zero diff) → approve YELLOW rollback → state diff
(err 18%→0.8%, v23→v22) → VERIFIED → RCA → scorecard. Full script: PLANNED in
M22 (demo harden) — no demo script claimed yet.

## Tests / Benchmarks / Safety
`pytest` (policy/sandbox/verifier/audit 100%), `python scripts/verify_lyzr.py`.
Docs: `docs/EVALUATION.md`, `docs/SECURITY.md`, `docs/DECISIONS.md`,
`docs/DEMO.md`, `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/TESTING.md`.
PLANNED (not yet present, owned by future modules): eval runner + demo checker
(`scripts/eval.sh`, `scripts/demo.sh --check` in M16/M22).

## Budget table (M00.6 foundation; `[PROVISIONAL]` targets, no measured numbers yet)

Raw tokens primary, dollars via editable pricing config only (never hard-coded
vendor prices). Same-trio reproducibility (`SEED_*` in `docs/CONFIGURATION.md`)
keeps deltas attributable. Targets revise after 20 baseline runs (spec §36).

| Gate | Target (provisional) | Measured today |
|---|---|---|
| e2e latency P50 mock | <90s | PLANNED (M20 measurement, M16 runner) |
| Cost | raw tokens first, $ second | PLANNED (M20 ledgers) |
| Groundedness | MUST-CITE coverage 1.0 | PLANNED (M05 gate + M16 grading) |
| Safety | unsafe_exec 0, bypass 0 | Partial: policy/sandbox/verifier gates green host-safe; full adversarial PLANNED (M18) |

## Benchmark shot (M00.6 foundation; no numbers claimed)

No `runs/*.jsonl`, no `scorecard.html`, no P50/P95/token/cost numbers exist
today — every future number links to its run JSONL (honesty rule in
`docs/EVALUATION.md`). Datasets: deep-5 × 5 variants + stub-7 minimal
(PLANNED, M17). Runner: CASE → RUN → TRACE → GRADE → SCORE → COMPARE → REPORT
(PLANNED, M16).

## Roadmap (M00.6 foundation)

- Done: M00 foundation (7 units) + M01 contracts + M02–M11 pipeline
  (IMPLEMENTED_TESTED; see `docs/MODULE_REGISTRY.md`).
- Next: M12 retrieval → M13 Lyzr agents → M14 FSM (Wave 4); M15 audit/AIMS →
  M16 eval → M17 benchmarks → M18 adversarial (Wave 5); M19 UI → M20 perf
  (Wave 6); M21 integration → M22 demo (Wave 7). Full wave plan:
  `docs/BUILD_FIRST_MASTER_PLAN.md`.

## Limitations
Simulated telemetry/execution; HMAC demo roles (no SSO); dollar costs via config
pricing table only. Nothing here claims production readiness or certification.

## Attribution
Inspired by HolmesGPT runbooks, SRE-agent eval harness, kube-agents GitOps,
Microsoft Triangle triage, Splunk kassi audited FSM, CATAS ledger. Concepts only —
no proprietary code, UI, or assets copied.
