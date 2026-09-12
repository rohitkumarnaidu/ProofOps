"""ProofOps control-plane API (T01 skeleton; routes land per T02+)."""
from fastapi import FastAPI

from app.config import get_settings  # noqa: E402  (M00.2 trust boundary)

# M00.2: load typed config at startup. Missing/invalid required values raise
# ConfigurationError here (fail-closed) instead of failing mid-request later.
# Deliberate minimal touch to the M00.1-locked file: no routes changed.
settings = get_settings()

app = FastAPI(title="ProofOps", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "proofops-api", "spec": "PS03_FINAL_SPEC_V2"}
