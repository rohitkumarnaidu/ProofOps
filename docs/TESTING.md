# ProofOps Testing Foundation (M00.6 foundation; full suites owned by later phases)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §45 (testing), §46 (CI/CD),
§36 (six quality gates), §33–§34 (eval/benchmarks).

Status: this tree carries **85 host-safe test files** and 4 runtime files that
need a live daemon. Nothing here claims production readiness or certification.

**On "green":** an earlier revision of this doc opened by asserting the host-safe
suites were green and quoted a pass count measured on 2026-09-16. That number is
withdrawn. Roughly a dozen commits have landed since, including the live tier,
the token carriers, and the honesty work, and none of them re-ran that count. A
stale pass count in a testing doc is worse than no number, because it reads as
current. **Run the commands below and quote your own output.** A skip is
reported as a skip, never as a pass.

## Run it

```bash
python -m pytest tests/ -q -p no:warnings \
  --ignore=tests/test_compose_runtime.py \
  --ignore=tests/test_config_runtime.py \
  --ignore=tests/test_health_runtime.py \
  --ignore=tests/test_logging_runtime.py
python -m ruff check backend tests scripts telemetry
python -m mypy backend/app
python scripts/secret_scan.py
python scripts/freeze.py --check
```

- The four ignored `*_runtime.py` files need a live Docker daemon and **mutate
  the running stack** (stop/start/restart), so they are excluded from the default
  pass. Include them deliberately, and leave the stack up and healthy afterwards.
  They prove compose, config, health, and logging against the real stack
  (M00.3/M00.4). Their names are pinned in `tests/test_ci.py` and asserted into
  both the workflow and `scripts/ci.sh`, so the exclusion list cannot silently
  drift.
- The one expected skip is `test_healthz_runtime_parity`, which compares the host
  interpreter against the container. Host Python 3.14 with starlette v1.x cannot
  reproduce the container's fastapi testclient, so it skips rather than passing.
  The container (`python:3.12-slim`) is the source of truth for runtime shape.

## Layer map (what runs where)

- **Host-safe (any Python, no daemon, no network): 80 files.** The full
  inventory is in the table below; the previous revision of this doc named only
  ten of these areas, which made most of the tree invisible.
- **Daemon-only: 4 files** (`test_compose_runtime`, `test_config_runtime`,
  `test_health_runtime`, `test_logging_runtime`).
- **Browser-only: 1 file.** `tests/test_ui_browser_gate.py` drives
  `scripts/ui_browser_check.mjs`, which attaches to a real Chrome over the
  DevTools Protocol and asserts on the **rendered** result for 5 views × 3
  viewports (360/768/1440) = 15 combinations. It is the only gate here that can
  see a runtime UI defect, and that is not hypothetical: in one frontend pass it
  found a blank white screen on every view, a form control rendering with no
  border because a `{...rest}` spread sat after `className`, and a false "stream
  disconnected" banner on a healthy backend. All three passed every other gate in
  this repo. It uses Node's built-in `WebSocket` and `fetch` (Node ≥ 22) and adds
  **no** dependency; a test asserts that. It skips cleanly when `node` is absent
  or the stack is unreachable.
  - **Known coverage gap:** the browser gate covers 5 of the 6 views. The Agents
    view is not rendered by it. Owning module: M19, PLANNED.
  - Before trusting a green result, note that it disables the browser cache: a
    reused profile otherwise serves the previous bundle and looks like a passing
    build of broken code.
- **CI** (`.github/workflows/ci.yml` + `scripts/ci.sh`): lockfile → ruff → mypy →
  unit (host-safe, 4 runtime files ignored) → security (secret scan) → lockfile
  `--check`. Mirrored stage-for-stage except the install source: CI installs from
  `backend/requirements.lock` (deterministic, ubuntu py3.12), the local runner
  keeps portable `requirements.txt` (manylinux pins cannot install on Windows,
  ADR-010); the freeze `--check` gate itself runs identically everywhere.
  `pip check` gates the starlette upper bound in CI.

## Host-safe suite map (85 files)

Counts are static `def test_*` tallies, before parametrisation inflates the
collected total.

| Area | Files | Key suites |
|------|-------|-----------|
| Contracts (M01) | 10 | `test_contracts_m01_2_incident` (62), `test_contracts_m01_3_alert` (86), `test_contracts_m01_8_15` (75), plus `*_hardening` escape and mutation suites |
| Safety, policy, execution, rollback | 8 | `test_safety` , `test_safety_m06_hardening`, `test_execution`, `test_execution_m07_10`, `test_verifier_honesty` (M09: `EXIT 0 ≠ RESOLVED`), `test_resume_execution` ("an approved action executes, it is never re-planned") |
| Data plane, telemetry, correlation | 8 | `test_dataplane`, `test_telemetry_m02_safety` (**ground-truth isolation**), `test_correlate_m04_hardening`, `test_evidence_m05_hardening`, `test_db_persistence` (async, 6) |
| Frontend | 8 | 7 static source-reading gates plus the browser gate. `test_frontend_design_system` asserts WCAG contrast rather than assuming it |
| Repo, compose, CI, freeze, secret, paths | 8 | `test_repo_structure`, `test_compose` (static YAML contract), `test_ci` (workflow shape + `ci.sh` parity), `test_freeze`, `test_secret_scan`, `test_paths_state_m22` |
| Agents (M13) and LLM honesty | 6 | `test_agents_m13` (44), `test_agents_platform_m13` (45), `test_agent_surface` ("the agent surface investigates, it cannot act"), `test_llm_honesty` (forbids reporting `CONNECTED` on a config string) |
| FSM, runs, pipeline, orchestrator | 6 | `test_fsm_m14`, `test_fsm_branches_m14`, `test_runs_router_m14`, `test_pipeline_m21`, `test_pipeline_branches_m21`, `test_orchestrator_live` (the worker drives incidents for real and can never approve one) |
| Config, health, logging (host halves) | 6 | `test_config` (41), `test_health`, `test_logging` (21), each with a `_hardening` twin |
| Approvals, HITL, auth | 3 | `test_approvals_m19` (32), `test_approval_token_delivery` (18, zero-trust token carriers), `test_auth_jwt` (7) |
| Stream and SSE | 4 | `test_stream_m21`, `test_stream_live` ("the audit stream is live, not replay-and-close"), `test_stream_replay_completion`, `test_http_guards` (every mutating handler requires a key) |
| M20 budgets and metrics | 2 | `test_budgets_m20` (25), `test_metrics_m20` (25) |
| Eval, benchmarks, adversarial | 4 | `test_eval_m16` (27, C1–C6 gates), `test_eval_baseline`, `test_benchmarks_m17` (deep-5×5 + stub-7, seal-verified), `test_adversarial_m18` (14) |
| Live tier | 3 | `test_live_dispatch_safety` (reads compose as text, does not run Docker), `test_k8s_executor`, `test_prom_verifier` |
| Audit chain | 1 | `test_audit_m15` (30) — includes tamper, swap, and foreign-event detection, persistence after a memory wipe, and `test_custom_rows_never_labeled_aims` |
| Retrieval | 1 | `test_retrieval_m12` (54) — KB, metadata filters, MMR, Evidence Pack, p@5/r@5/MRR/nDCG |
| Runbooks | 1 | `test_runbooks_m11` (21) — loader, hash, pin, params, seeds |
| Docs | 1 | `test_docs` — pins the canonical 12-doc set, spec links, no-fabrication patterns, secret markers |
| Webhooks | 1 | `test_cloud_webhooks` (4) |

Safety-critical assertions live in named suites rather than being spread thin:
the 14-state FSM and no-skip permit gate, default-deny plus 40+ policy cases,
shell and DROP rejection pre-policy, HMAC tamper/replay/expiry, zero-diff blocks,
`exit-0-with-bad-SLO` not counting as resolved, poisoned runbook rejection, and
audit-chain tamper detection.

## Landed vs PLANNED (registry governs per-row truth in `docs/MODULE_REGISTRY.md`)

Landed, and previously mislabelled PLANNED in this doc:

- Integration (happy/block/rollback paths) + no-skip `POLICY_CHECK→EXECUTING` +
  tamper tests (M14/M21).
- Eval runner CASE→RUN→TRACE→GRADE→SCORE→COMPARE→REPORT, JSONL, scorecard, six
  gates C1–C6 (`[PROVISIONAL]`, revise after 20 baseline runs) — IMPLEMENTED_TESTED,
  hardening pending (M16).
- Golden benchmarks deep-5×5 + stub-7 (M17) and adversarial-14 (M18) —
  IMPLEMENTED_TESTED, hardening pending.
- Token, latency, and cost ledgers plus budget asserts (M20) — IMPLEMENTED_TESTED.
  An earlier revision of this doc was the only place in the repository still
  calling M20 PLANNED.

Still PLANNED:

- CI daemon jobs (image build + compose smoke on ubuntu runners, which have a
  daemon) + eval gates wired into CI (M16/M22). NOT in CI today: the unit job is
  host-safe only by design; runtime proofs live in `tests/test_*_runtime.py`.
- `scripts/eval.sh` and `scripts/demo.sh --check`. Neither exists. `scripts/`
  currently holds `ci.sh`, `freeze.py`, `live_tier.sh`, `pip_audit_allowlist.txt`,
  `run_baseline.py`, `secret_scan.py`, `ui_browser_check.mjs`, `verify_lyzr.py`.
- Browser-gate coverage of the Agents view (M19).
- A committed baseline run in JSONL. The machinery is proven by
  `test_eval_baseline`; there is no committed product-quality run yet, so no
  C1–C6 number in this repo is a measured product result.

## Honesty rules (binding)

- Every number links to its run JSONL. Raw tokens first, dollars second.
- Skipped evals report SKIP, never PASS. A skip is never a pass.
- No benchmark-free percentages, and no pass count quoted from a run you did not
  execute in this session.
- The `connectED` spelling check: `tests/test_llm_honesty.py` asserts the literal
  `CONNECTED` is absent from the provider source. The backend reports `UNVERIFIED`
  when a credential is present, because holding a config string is not a
  connection. A doc or UI that shows a green "live AI" tile is contradicting this.

## Repro (host-safe)

```bash
python -m pytest tests/test_docs.py tests/test_repo_structure.py -q
python -m pytest tests/ -q -p no:warnings \
  --ignore=tests/test_compose_runtime.py \
  --ignore=tests/test_config_runtime.py \
  --ignore=tests/test_health_runtime.py \
  --ignore=tests/test_logging_runtime.py
```
