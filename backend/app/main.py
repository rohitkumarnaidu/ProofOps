"""ProofOps control-plane API (T01 skeleton; routes land per T02+)."""
from fastapi import FastAPI

app = FastAPI(title="ProofOps", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "proofops-api", "spec": "PS03_FINAL_SPEC_V2"}
