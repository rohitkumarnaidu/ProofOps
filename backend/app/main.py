"""ProofOps control-plane API (T01 skeleton; routes land per T02+)."""
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.config import get_settings  # noqa: E402  (M00.2 trust boundary)
from app.health import readiness  # noqa: E402  (M00.4 readiness probes)
from app.logging_setup import configure_logging, get_logger  # noqa: E402 (M00.5)
from app.routers import runs as runs_router  # noqa: E402 (M14b runs router)
from app.routers import audit as audit_router  # noqa: E402 (M15b audit router)
from app.routers import approvals as approvals_router  # noqa: E402 (M19a)
from app.routers import eval as eval_router  # noqa: E402 (M19b smoke)

# M00.2: load typed config at startup. Missing/invalid required values raise
# ConfigurationError here (fail-closed) instead of failing mid-request later.
# Deliberate minimal touch to the M00.1-locked file: no routes changed.
settings = get_settings()

# M00.5: install structured + redacting logging before any request is served.
# Every M00.2 secret plus DATABASE_URL (embeds the DB password) is registered
# for exact-value scrubbing; empties are skipped inside the formatter.
configure_logging(settings.LOG_LEVEL,
                  secrets=(settings.APPROVAL_SECRET,
                           settings.POSTGRES_PASSWORD,
                           settings.PROOFOPS_API_KEY,
                           settings.LYZR_API_KEY,
                           settings.DATABASE_URL))
logger = get_logger(__name__)

app = FastAPI(title="ProofOps", version="0.1.0")
# M14b (deliberate minimal touch to the M00.1-locked file, like M00.2): wire
# the runs router. Guarded: host starlette drift leaves runs.router None
# (unit/structure tests only there); the container wires it. /healthz body
# below is untouched (byte-frozen contract).
if runs_router.router is not None:
    app.include_router(runs_router.router)
# M15b: same guarded pattern for the audit router (verify/export endpoints).
if audit_router.router is not None:
    app.include_router(audit_router.router)
# M19a: approvals router (Safety Gate request/approve/reject endpoints).
if approvals_router.router is not None:
    app.include_router(approvals_router.router)
# M19b: eval smoke router (harness numbers on demand for the RCA view).
if eval_router.router is not None:
    app.include_router(eval_router.router)
# Public values only (APP_ENV/LOG_LEVEL/EXECUTOR are non-secret by contract).
logger.info("proofops api starting env=%s level=%s executor=%s",
            settings.APP_ENV, settings.LOG_LEVEL, settings.EXECUTOR)


@app.get("/healthz")
def healthz() -> dict:
    # LIVENESS (M00.1 contract — body frozen): process alive. Answers even
    # with dependencies down; deep readiness lives at /readyz (M00.4).
    return {"status": "ok", "service": "proofops-api", "spec": "PS03_FINAL_SPEC_V2"}


@app.get("/meta")
def meta() -> dict:
    # META (M19 additive, read-only): honest executor-tier disclosure for the
    # UI ModeBadge. executor_tier is the M00.2 config trust boundary
    # (mock|docker only); the docker daemon shape/refusal contract lives in
    # app/services/sandbox.py (DOCKER_CONSTRAINTS + fail-closed
    # apply_docker). mode is the deployment mode (APP_ENV). Public values
    # only — never secrets. /healthz body above is untouched (byte-frozen).
    # Lane A (P2): surface nonce-store durability (R1 fail-LOUD) so the
    # degraded flag is visible instead of silent. Lazy import avoids cycles;
    # the approvals router already exposes NONCES.
    from app.routers import approvals as approvals_router  # noqa: E402 (lazy)
    nonces = getattr(approvals_router, "NONCES", None)
    return {"service": "proofops-api", "spec": "PS03_FINAL_SPEC_V2",
            "executor_tier": settings.EXECUTOR, "mode": settings.APP_ENV,
            "nonce_store_durable": bool(
                getattr(nonces, "persistent", False)),
            "nonce_store_degraded": bool(getattr(nonces, "degraded", False))}


@app.get("/readyz")
def readyz() -> JSONResponse:
    # READINESS (M00.4): 200 only when dependencies serve; 503 otherwise.
    # Bounded probe (<=2s); body is secret-free by construction.
    body = readiness(settings.DATABASE_URL)
    return JSONResponse(status_code=200 if body["status"] == "ready" else 503,
                        content=body)
