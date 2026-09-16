#!/usr/bin/env bash
# ProofOps local CI runner (M00.7 CI foundation). Mirrors .github/workflows/ci.yml
# stage-for-stage: ruff -> mypy -> unit(host-safe) -> security(scan) -> lockfile.
# Deterministic, fail-fast (set -e), no secrets echoed, never runs plain
# `docker compose config` (renders secret VALUES; see docs/COMPOSE.md safe list:
# only `config --quiet` / `config --services` / `ps` / `logs`).
# Container python:3.12-slim is the source of truth; run this from an env with
# `pip install -r backend/requirements.txt` (portable ranges work on any
# interpreter incl. Windows host; the linux/cp312 LOCK is CI-only because its
# manylinux wheels cannot install on Windows — see ADR-010. The lockfile gate
# itself [5/5] is a host-safe text compare and runs everywhere).
# NOTE: CI additionally gates `pip check` after each install (fresh env, so it
# enforces the starlette upper bound). It is deliberately NOT run here: host
# global site-packages are shared/dirty by design (documented starlette v1.x
# drift), so a local `pip check` fails on packages this repo does not own.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Portable interpreter: CI + Windows provide `python`; bare Linux may only
# have `python3`. Pick whichever exists (packages must be installed from
# backend/requirements.txt either way).
PYBIN="${PYTHON:-python}"
command -v "$PYBIN" >/dev/null 2>&1 || PYBIN=python3

echo "==> [1/5] ruff (lint correctness; format NOT gated, see pyproject.toml)"
"$PYBIN" -m ruff check backend tests scripts telemetry

echo "==> [2/5] mypy (typed control plane)"
"$PYBIN" -m mypy backend/app

echo "==> [3/5] unit (host-safe only; 4 runtime-daemon files excluded, see below)"
"$PYBIN" -m pytest tests/ -q \
  --ignore=tests/test_compose_runtime.py \
  --ignore=tests/test_config_runtime.py \
  --ignore=tests/test_health_runtime.py \
  --ignore=tests/test_logging_runtime.py

echo "==> [4/5] security (secret scan; redacted output, never prints values)"
"$PYBIN" scripts/secret_scan.py

echo "==> [5/5] lockfile (freeze check; host-safe text compare, ADR-010)"
"$PYBIN" scripts/freeze.py --check

echo "==> [5/5] audit (pip-audit; CI runs it, local runs it only if installed)"
if "$PYBIN" -c "import pip_audit" 2>/dev/null; then
  "$PYBIN" scripts/freeze.py --audit
else
  echo "SKIP: pip-audit not installed locally (CI enforces it; \`pip install \"pip-audit>=2.10,<2.11\"\` to run here) — reported SKIP, never PASS"
fi

echo "CI LOCAL GREEN: ruff + mypy + unit(host-safe) + security + lockfile all passed"
