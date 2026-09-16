# ProofOps Evaluation Foundation (M00.6 foundation; runner owned by M16)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §33 (evaluation engine),
§36 (six quality gates), §34 (golden benchmarks), §45–§46 (testing/CI).

Status: M16 implements the runner (`backend/app/services/eval.py`,
IMPLEMENTED_TESTED). Measured numbers land in `runs/*.jsonl` (gitignored
run artifacts) + scorecard HTML, never as committed claims — this doc keeps
the spec contract; `tests/test_eval_m16.py` proves the machinery.
Nothing here claims production readiness or certification.

## Reserved today (M00.2 only, tested)

- Deterministic seed trio `SEED_SCENARIO` / `SEED_VARIANT` / `SEED_SEED`
  (defaults `bad-deploy` / `NORMAL` / `42`) with `test` and `demo`
  environments, validated by `tests/test_config.py`. These are the inputs a
  future runner will reseed; they are not results.
- Reproducibility contract: same env gives same `snapshot()` and same
  `fingerprint()` (secrets excluded by design), so future eval deltas will be
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
  minimal fixtures. PLANNED under M17 (benchmarks).

## PLANNED (owning modules, not implemented)

- Eval runner, graders, rubric estimator, scorecard, JSONL (M16
  IMPLEMENTED_TESTED: `backend/app/services/eval.py`).
- Benchmark fixtures incl. adversarial-10 attack files (M17/M18).
- Token/latency/cost ledgers per incident (M20 measurement modules).
- `scripts/eval.sh` and `scripts/demo.sh --check` entry points (M16/M22).
  Referenced here as PLANNED paths; they do not exist in this tree.

## Honesty rules (binding on future modules)

- Every reported number links to its run JSONL; no benchmark-free percentages.
- Raw tokens first, dollars second; never trade verification/citation for
  tokens (spec §49).
- A skipped eval is reported SKIP, never PASS (M00.1 precedent).

## Repro (host-safe)

```bash
python -m pytest tests/test_config.py -q   # seed-trio + reproducibility only
```

Eval-gate tests live in `tests/test_eval_m16.py`; this module keeps
asserting honesty rules instead of simulating results.
