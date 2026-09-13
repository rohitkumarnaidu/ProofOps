#!/usr/bin/env bash
# ProofOps local CI runner (M00.7 CI foundation). Mirrors .github/workflows/ci.yml
# stage-for-stage: ruff -> mypy -> unit(host-safe) -> security(scan).
# Deterministic, fail-fast (set -e), no secrets echoed, never runs plain
# `docker compose config` (renders secret VALUES; see docs/COMPOSE.md safe list:
# only `config --quiet` / `config --services` / `ps` / `logs`).
# Container python:3.12-slim is the source of truth; run this from an env with
# `pip install -r backend/requirements.txt` (CI pins python 3.12 for the same).
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

echo "==> [1/4] ruff (lint correctness; format NOT gated, see pyproject.toml)"
"$PYBIN" -m ruff check backend tests scripts

echo "==> [2/4] mypy (typed control plane)"
"$PYBIN" -m mypy backend/app

echo "==> [3/4] unit (host-safe only; 4 runtime-daemon files excluded, see below)"
"$PYBIN" -m pytest tests/ -q \
  --ignore=tests/test_compose_runtime.py \
  --ignore=tests/test_config_runtime.py \
  --ignore=tests/test_health_runtime.py \
  --ignore=tests/test_logging_runtime.py

echo "==> [4/4] security (secret scan; redacted output, never prints values)"
"$PYBIN" scripts/secret_scan.py

echo "CI LOCAL GREEN: ruff + mypy + unit(host-safe) + security all passed"
