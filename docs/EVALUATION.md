# ProofOps Evaluation Foundation (M00.6 foundation; runner owned by M16)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §33 (evaluation engine),
§36 (six quality gates), §34 (golden benchmarks), §45–§46 (testing/CI).

Status: M16 implements the runner (`backend/app/services/eval.py`,
per-row status in `docs/MODULE_REGISTRY.md`). Run artifacts land under
`runs/*.jsonl`, which is **gitignored** (`.gitignore:24`), so no run artifact
is committed and a clean-clone reviewer cannot verify a historical run
without re-running the script that produced it. Every number in this doc
therefore carries its provenance label (vocabulary below) and, where
applicable, the script that regenerates it. `tests/test_eval_m16.py` proves
the machinery. Nothing here claims production readiness or certification.

## Vocabulary (used consistently below)

- **SCRIPTED-ORACLE SIMULATION** — the deterministic control plane ran end to
  end, but the agents (and the human approver) were supplied by fixed
  payloads instead of a model and a person. Proves machinery and control
  ordering. Proves nothing about model or human quality.
- **MEASURED SYSTEM RUN** — a number produced by executed control-plane code
  (validator, policy, FSM, sandbox, verifier, rollback, HMAC, audit,
  session-store accounting) rather than a constant.
- **PERSISTED EVIDENCE** — an artifact a reviewer can read without trusting
  this doc. Because `runs/` is gitignored, **no baseline run is PERSISTED
  EVIDENCE today**; every figure below is a claim about a local artifact
  until the reader re-runs `python scripts/run_baseline.py`.
- **UNMEASURED** — the block is absent, hard-coded, or mock-fed. An UNMEASURED
  input that happens to clear a threshold is trivially green, not a pass.

## Reserved today (M00.2 only, tested)

- Deterministic seed trio `SEED_SCENARIO` / `SEED_VARIANT` / `SEED_SEED`
  (defaults `bad-deploy` / `NORMAL` / `42`) with `test` and `demo`
  environments, validated by `tests/test_config.py`. These are the inputs a
  runner reseeds; they are not results.
- Reproducibility contract: same env gives same `snapshot()` and same
  `fingerprint()` (secrets excluded by design), so eval deltas are
  attributable to config, not leakage.

## Spec contract (quoted, not implemented)

- Runner pipeline: CASE → RUN → TRACE → GRADE → SCORE → COMPARE → REPORT,
  storing run JSONL plus an HTML scorecard with metrics JSON (spec §33).
- Split with Lyzr (spec §04-G14): Lyzr Agent Eval covers agent-level
  (hallucination/faithfulness/tool-args) via `export_cases_csv()` rows; the
  custom runner covers pipeline-level
  (policy/adversarial/SLO/regression).
- Six quality gates C1–C6 (spec §36) are all `[PROVISIONAL]` and revise after
  20 baseline runs: hallucination, groundedness (MUST-CITE coverage 1.0),
  retrieval (p@5/r@5/MRR/nDCG), cost (raw tokens primary, dollars via
  config pricing table only), prompt/adversarial (injection 0/10,
  unsafe_exec 0), latency (e2e P50 <90s mock). Numbers are targets under test,
  never measured results — no budget is asserted green today.
- Datasets (spec §34): deep-5 scenarios × 5 variants fully seeded plus stub-7
  minimal fixtures — LANDED under M17 (`benchmarks/suites/*.jsonl`,
  seal-verified against the generator).

## PLANNED + LANDED (registry governs — per-row truth in docs/MODULE_REGISTRY.md; PLANNED marks only what is still unbuilt)

- Eval runner, graders, rubric estimator, scorecard, JSONL — landed as
  IMPLEMENTED_TESTED per docs/MODULE_REGISTRY.md per-row table, hardening
  pending (M16: `backend/app/services/eval.py`).
- Benchmark fixtures incl. adversarial-14 attack files — landed as
  IMPLEMENTED_TESTED per docs/MODULE_REGISTRY.md per-row table, hardening
  pending (M17/M18: log-injection, prompt-injection-direct, poisoned-runbook,
  fake/stale/contradictory-telemetry, unsafe-command, policy-bypass,
  param-injection, secret-exfiltration, approval-replay, duplicate-execution,
  verification-spoofing, runaway-loop).
- Token/latency/cost ledgers per incident (M20 measurement modules).
- `scripts/eval.sh` and `scripts/demo.sh --check` entry points (M16/M22).
  Referenced here as PLANNED paths; they do not exist in this tree
  (`scripts/` ships `ci.sh` only).
- A MEASURED SYSTEM RUN with live-model agents: PLANNED, UNMEASURED today.

## Honesty rules (binding on this and later modules)

- Every reported number must name its artifact and its provenance label from
  the vocabulary above. No unlabeled percentages.
- Because `runs/` is gitignored, an artifact path is a pointer, not proof: the
  reader must re-run the named script to reproduce the figure. Never present a
  run artifact path as if the artifact were in the repository.
- Raw tokens first, dollars second; never trade verification/citation for
  tokens (spec §49).
- A skipped eval is reported SKIP, never PASS (M00.1 precedent).
- A gate whose inputs are mock-fed or hard-coded is reported as a mock-harness
  pass rate, never as a measured quality result.

## Repro (host-safe)

```bash
python -m pytest tests/test_config.py -q   # seed-trio + reproducibility only
```

Eval-gate tests live in `tests/test_eval_m16.py`; this module keeps
asserting honesty rules instead of simulating results. To regenerate the
first-baseline artifact (needs no API key and makes no network call):
`python scripts/run_baseline.py`.

## First baselines — SCRIPTED-ORACLE SIMULATION (run label `baseline-scripted`)

Provenance of this section, stated once: the run below is a
**SCRIPTED-ORACLE SIMULATION**. Config `baseline-scripted`, 25 deep5 rows
(deep-5 scenarios × the 5 variants, seal-verified against the generator),
machinery tests in `tests/test_eval_baseline.py`, runner
`scripts/run_baseline.py`. It is **not** a MEASURED SYSTEM RUN, and it is
**not** PERSISTED EVIDENCE: the artifact `runs/baseline-2026-09-24.jsonl` is
gitignored, so the figures below are re-derivable only by re-running the
script.

### What was real (MEASURED, from executed control-plane code)

- Action contract validation + the M06.1 validator on every plan.
- Policy engine evaluation from the versioned bundle (decision + matched rule).
- FSM ordering, no-skip guards, permit issuance, and the terminal state.
- Mock sandbox execution and the resulting state diff.
- The independent verifier (`M09`) verdicts, plus the single-attempt
  auto-rollback path (`M10`) with its own re-verification.
- HMAC approval mechanics from M07 — issue, signature verify, scope and exact
  parameter-hash binding, nonce burn, TTL, and derived-nonce permit
  single-use.
- Per-run SHA256 audit chain emission (`M15`).
- Session-store LLM call accounting (`budgets.calls` = 3 per case, 75 across
  the 25 cases).
- Evidence-pack evidence ids from the pre-digester (`M05`), and the
  post-action `after_error_rate` read back from the sandbox.

### What was scripted (SCRIPTED, not measured quality)

- **All three agents.** `triage`, `diagnostic`, and `planner` were served fixed
  golden payloads by a stub client that reports mode `CONNECTED` but performs no
  network call and reads no API key (`scripts/run_baseline.py:107-127`,
  `:252-254`). Triage severity came from the real deterministic function, but
  the diagnostic hypotheses and the remediation plan were pinned per scenario
  by the script's `ORACLE` table (`:65-91`).
- **The human approver.** The pipeline requests and then approves in-process
  with the same scripted actor (`APPROVER = {"role": "approver", "id": "sre-1"}`
  in `backend/app/services/pipeline.py:53`, used by `_hitl_permit` at
  `:466-486`). The crypto path is real; the *decision* is scripted, and
  separation of duties is therefore not exercised by this run.
- **The RCA stage is absent, not passed.** `run_pipeline` never calls the A4
  reporter, and `to_eval_trace` hard-codes `stages.report.ok = True` and
  `agents = ["triage", "diagnostic", "planner"]`
  (`backend/app/services/pipeline.py:434-463`). The report stage in this run is
  **UNMEASURED**.

### Why "C1–C6 = 1.000" is a mock-harness pass rate, not six measured gates

All 25 rows report `passed: true` with each of C1–C6 green 25/25. That is the
M16 harness executing correctly over its own inputs — not six measured quality
results. `to_eval_trace` hard-codes or receives mock shapes for exactly the
blocks the gates read (`backend/app/services/pipeline.py:434-463`,
`scripts/run_baseline.py:93-100,217-224`):

| Gate | Input it reads | Status in this run |
|---|---|---|
| C1 hallucination | `hallucination` block | **MOCK** — `eval.mock_trace()` constants (`unsupported: 0`, `fabricated_cmd: 0`, `invalid_args_rate: 0.0`, `replay_identical: 1.0`). Nothing was counted from model text, because there is no model text. Trivially green. |
| C2 groundedness | `citations.coverage` | **MOCK** — set to 1.0 iff the evidence pack returned a non-empty id list (`scripts/run_baseline.py:275`). MUST-CITE coverage is *not* computed on this path, so the gate is measuring "did the pack have ids", not "is every claim cited". Trivially green. |
| C3 retrieval | `retrieval` block | **MOCK** — `mock_trace()` constants (p5 0.9 / r5 0.85 / mrr 0.9 / ndcg 0.9 / irr 0.1). No retrieval was scored. Trivially green. |
| C4 cost | `budgets` | **PARTLY MOCK** — `tokens_in` 4000, `tokens_out` 1000, `ctx_per_call` 6000, `cache_hit` 0.7 are `mock_trace()` shapes; only `calls` (3/case) is measured. Green because the mock token counts sit under the `[PROVISIONAL]` bounds. Not a cost measurement. |
| C5 prompt / adversarial | `prompt` block, `attacks`, `unsafe_exec` | **MOCK / VACUOUS** — `prompt` is `mock_trace()`; `attacks` is the empty list, so `attack_contained` passes with "no attacks in trace"; `unsafe_exec: 0` is hard-coded in `to_eval_trace`, not counted. Trivially green. This run says nothing about the adversarial-14 suite, which is exercised by its own tests. |
| C6 latency | `latencies` block | **MOCK** — fixed constants (triage 2.0, retrieval 3.0, diagnosis 8.0, policy 0.5, exec 5.0, verify 6.0, e2e 30.0). No wall clock was taken. Trivially green. |

### Control-plane figures that are real, and the honest reading of the 20 escalations

Policy decision, FSM path, and verifier verdict do come from executed code.
The cross-tab over the 25 cases:

| Policy decision | FSM path | Final verifier verdict | Cases |
|---|---|---|---|
| `ESCALATE` | `resolved` | `RESOLVED` | 5 (`bad-deploy` × 5 variants — the scripted approver grants, and the mock rollback heals the error spike) |
| `ALLOW` | `escalated` | `ROLLBACK_REQUIRED` | 15 (`crashloop-oom`, `db-exhaust`, `net-dep-fail` × 5 each) |
| `ESCALATE` | `escalated` | `ROLLBACK_REQUIRED` | 5 (`injection` × 5) |

**The 20 escalations are a mock-tier limitation, not evidence that escalation
is correct.** The mock sandbox cannot drive `error_rate` down by a config
change or a rescale, so those cases verify `ROLLBACK_REQUIRED` and the run
ends `ESCALATED` by design. Read the other way: a 5/25 resolution rate here
says nothing about real healing capability either. Grades in this harness
measure safety and correctness *properties* of the run, not resolution
outcome — a `pass_rate` of 1.000 sitting next to 20 escalations is the
expected shape of a safety-first scripted run, and must not be reported as a
quality result.

Also note: every written row is a graded row — none of the no-trace
`PipelineBlocked` / `PipelineStalled` / `PipelineFailed` outcome rows
(`scripts/run_baseline.py:321-342`) was emitted on this run, so that
recording path is unexercised here. The graded rows do carry the `path`
field (`resolved` / `escalated`) taken from the run report.

### Bottom line

- The control plane, the safety boundary, and the eval machinery are
  implemented and tested (`tests/test_eval_m16.py`,
  `tests/test_eval_baseline.py`, `tests/test_pipeline_m21.py`).
- Agent quality, RCA quality, human-approval quality, retrieval quality, cost,
  and latency are **UNMEASURED**. No live-model run exists in this tree.
- Thresholds stay `[PROVISIONAL]`; stub7 and live-model runs are PLANNED
  (M16/M22 owned).
- Nothing here claims production readiness or certification.
