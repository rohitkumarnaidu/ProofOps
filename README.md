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

Status: M00.1 is foundation only (layout, Docker baseline, env hygiene). Lyzr
agents, FSM, eval, and demo hardening land in their own modules — see
`docs/MODULE_REGISTRY.md`. The table above describes the target architecture,
not claimed-today implementation.

## Demo (5:00)
Seed `bad-deploy/NORMAL` → 1 P1 → evidence → diagnosis → RED block of
`delete_namespace/prod` (zero diff) → approve YELLOW rollback → state diff
(err 18%→0.8%, v23→v22) → VERIFIED → RCA → scorecard. Full script: PLANNED in
M22 (demo harden) — no demo script claimed yet.

## Tests / Benchmarks / Safety
`pytest` (policy/sandbox/verifier/audit 100%), `python scripts/verify_lyzr.py`.
PLANNED (not yet present, owned by future modules): eval runner + demo checker
(`scripts/eval.sh`, `scripts/demo.sh --check` in M16/M22), consolidated
`docs/EVALUATION.md`, `docs/SECURITY.md`, `docs/DECISIONS.md`, `docs/DEMO.md`
in M00.6/M22.

## Limitations
Simulated telemetry/execution; HMAC demo roles (no SSO); dollar costs via config
pricing table only. Nothing here claims production readiness or certification.

## Attribution
Inspired by HolmesGPT runbooks, SRE-agent eval harness, kube-agents GitOps,
Microsoft Triangle triage, Splunk kassi audited FSM, CATAS ledger. Concepts only —
no proprietary code, UI, or assets copied.
