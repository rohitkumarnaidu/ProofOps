# ProofOps Testing Foundation (M00.6 foundation; full suites owned by later phases)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §45 (testing), §46 (CI/CD),
§36 (six quality gates), §33–§34 (eval/benchmarks).

Status: host-safe unit/structure/security suites exist and are green today.
Runtime-daemon, integration, eval, adversarial, and perf suites are marked
PLANNED with owners below. Nothing here claims production readiness or
certification.

## Green today (M00.1–M00.5 + M01–M11 build-first, host-safe)

```bash
python -m pytest tests/ -q -p no:warnings --ignore=tests/test_compose_runtime.py --ignore=tests/test_config_runtime.py --ignore=tests/test_health_runtime.py --ignore=tests/test_logging_runtime.py
python -m ruff check backend tests scripts
python -m mypy backend/app
python scripts/secret_scan.py
```

- Baseline (measured 2026-09-16, refreshed by each wave landing — current:
  FULL suite `2338 passed, 1 skipped` incl. all 4 `*_runtime.py` daemon files,
  proven on Docker Desktop 29.6.2 with the stack left UP+healthy) ·
  `ruff` pass · `mypy` pass · `secret_scan` PASS · `freeze --check` PASS ·
  `pip-audit` PASS (8 documented exceptions). The 1 skip is
  `test_healthz_runtime_parity` on drifted hosts (reported SKIP, never PASS;
  container `python:3.12-slim` is source of truth).
- `*_runtime.py` (4 files) need a live Docker daemon and are excluded host-safe;
  they prove compose/health/config/logging against the live stack (M00.3/M00.4).
- Safety/contract suites assert: 14-state checks, 20-invalid fixtures, 40+ policy
  cases (ALLOW/ESCALATE/DENY incl. default-deny), shell/DROP rejection pre-policy,
  HMAC tamper/replay/expiry, zero-diff blocks, exit-0-bad-SLO→FAILED, poisoned
  runbook rejection. Each module ships positive + negative + security tests.

## Layer map (what runs where)

- Host-safe (any Python): structure, config, compose-static, health-unit,
  logging-unit, docs, contracts, dataplane, safety, execution, runbooks.
- Daemon-only (Docker Desktop/dockerd): `test_*_runtime.py` (compose matrix,
  failure injection, persistence, live `/healthz`+`/readyz`, log hygiene).
- CI (`.github/workflows/ci.yml` + `scripts/ci.sh`): lockfile → ruff → mypy →
  unit (host-safe, 4 runtime files ignored) → security (secret scan) →
  lockfile `--check`. Mirrored stage-for-stage except the install source:
  CI installs from `backend/requirements.lock` (deterministic, ubuntu py3.12),
  the local runner keeps portable `requirements.txt` (manylinux pins cannot
  install on Windows — ADR-010); the freeze `--check` gate itself runs
  identically everywhere. `pip check` gates the starlette upper bound in CI.

## PLANNED (owning modules, not implemented)

- Integration (3 paths: happy/block/rollback) + no-skip
  `POLICY_CHECK→EXECUTING` + tamper tests (M14/M21).
- CI daemon jobs (image build + compose smoke on ubuntu runners, which have a
  daemon) + dependency vulnerability scan (`pip-audit` or equivalent) + eval
  gates (M16/M22). NOT in CI today: the unit job is host-safe only by design;
  runtime proofs live in `tests/test_*_runtime.py` + the M00.3 matrix.
- Eval runner CASE→RUN→TRACE→GRADE→SCORE→COMPARE→REPORT + JSONL + scorecard,
  six gates C1–C6 (`[PROVISIONAL]`, revise after 20 baseline runs) (M16).
- Golden benchmarks deep-5×5 + stub-7 (M17); adversarial-10 (M18);
  token/latency/cost ledgers + budget asserts (M20); `scripts/eval.sh` +
  `scripts/demo.sh --check` (M16/M22).
- Honesty rules (binding): every number links to its run JSONL; raw tokens
  first, dollars second; skipped evals report SKIP, never PASS; no
  benchmark-free percentages.

## Repro (host-safe)

```bash
python -m pytest tests/test_docs.py tests/test_repo_structure.py -q
```
