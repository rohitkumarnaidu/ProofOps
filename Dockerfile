# ProofOps API image (repo-root context; service Dockerfile mirrored in backend/).
# python:3.12-slim chosen for max wheel coverage
# (local dev may be 3.13/3.14; CI builds this image as source of truth).
# Keep base image + CMD in parity with backend/Dockerfile (M00.1 structure freeze).
# Pinning strategy (M00.1, hardened ADR-010b): minor-pinned `3.12-slim`, NO digest — digests would
# silently freeze Debian/OpenSSL patch CVEs and add review burden per rebuild.
# Python deps install from backend/requirements.lock (34 exact cp312/manylinux
# pins, resolver report in ADR-010b); backend/requirements.txt still ships in
# the COPY so the frozen structure test keeps seeing the ranges manifest, and
# remains the source the lock is checked against (scripts/freeze.py --check).
# Reproducibility comes from the image + lock + HEALTHCHECK.
# SECURITY: non-root `appuser` (uvicorn binds unprivileged 8000, no writes at
# runtime with PYTHONDONTWRITEBYTECODE=1). read_only deferred to M00.3 (needs
# tmpfs validation). No caps needed; compose drops ALL + no-new-privileges.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend/requirements.txt backend/requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock \
    && useradd --create-home --uid 10001 appuser
COPY backend/app ./app
# M14b: agents/ ships too (routers import it at boot; without this line the
# container ImportErrors while host tests pass via repo-root CWD).
COPY agents ./agents
# M16/M17/M18: services/eval.py, benchmarks.py, adversarial.py import
# telemetry.gen at boot (routers import them at startup); without this line
# the container ImportErrors while host tests pass via repo-root CWD.
# Same failure class as the M14b agents/ line above. gen.py is stdlib-only
# (hashlib/json/random/typing); .dockerignore does not exclude telemetry/.
COPY telemetry ./telemetry
# M20: the versioned policy bundles (slo.yaml, pricing.yaml, policy bundle)
# and the sha256-pinned runbooks live at the repo root, outside the backend/
# build context, so this root-context image must copy them explicitly --
# without these lines app.paths.policies_dir() resolves to an empty /policies
# and /alerts, the policy engine, and runbook grounding all fail at runtime
# while every host test still passes. Same failure class as the agents/ and
# telemetry/ lines above; mirrored as documented parity exceptions in
# tests/test_repo_structure.py::test_backend_dockerfile_parity.
COPY policies ./policies
COPY runbooks ./runbooks
# M07/M14/M20 durability: var/ holds the API-key store, approvals, runs, audit
# chains, and the nonce journal. appuser (uid 10001) cannot mkdir inside
# /app, so the writable state root is created and owned here and mounted as a
# named volume by compose; an empty named volume inherits this ownership.
RUN mkdir -p /app/var && chown appuser:appuser /app/var
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
