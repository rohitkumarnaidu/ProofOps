"""ProofOps control-plane API (T01 skeleton; routes land per T02+)."""
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.config import get_settings  # noqa: E402  (M00.2 trust boundary)
from app.health import readiness  # noqa: E402  (M00.4 readiness probes)
from app.logging_setup import configure_logging, get_logger  # noqa: E402  (M00.5)

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
# Public values only (APP_ENV/LOG_LEVEL/EXECUTOR are non-secret by contract).
logger.info("proofops api starting env=%s level=%s executor=%s",
            settings.APP_ENV, settings.LOG_LEVEL, settings.EXECUTOR)


@app.get("/healthz")
def healthz() -> dict:
    # LIVENESS (M00.1 contract — body frozen): process alive. Answers even
    # with dependencies down; deep readiness lives at /readyz (M00.4).
    return {"status": "ok", "service": "proofops-api", "spec": "PS03_FINAL_SPEC_V2"}


@app.get("/readyz")
def readyz() -> JSONResponse:
    # READINESS (M00.4): 200 only when dependencies serve; 503 otherwise.
    # Bounded probe (<=2s); body is secret-free by construction.
    body = readiness(settings.DATABASE_URL)
    return JSONResponse(status_code=200 if body["status"] == "ready" else 503,
                        content=body)
