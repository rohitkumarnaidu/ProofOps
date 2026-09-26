"""ProofOps control-plane API (T01 skeleton; routes land per T02+)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.compat  # noqa: F401 (Starlette host compatibility shim)
import time  # noqa: E402  (Lane 2: middleware latency clock)
from collections.abc import Awaitable, Callable  # noqa: E402  (Lane 2)
from typing import Any  # noqa: E402  (M19b lifespan signature)

from fastapi import FastAPI, Request  # noqa: E402  (Lane 2: Request shape)
from fastapi.responses import JSONResponse, PlainTextResponse, Response  # noqa: E402  (Lane 2)

from app.config import get_settings  # noqa: E402  (M00.2 trust boundary)
from app.health import readiness  # noqa: E402  (M00.4 readiness probes)
from app.logging_setup import configure_logging, get_logger  # noqa: E402 (M00.5)
from app.routers import ingest as ingest_router  # noqa: E402
from app.routers import runs as runs_router  # noqa: E402  (M14b runs router)
from app.routers import audit as audit_router  # noqa: E402  (M15b audit router)
from app.routers import approvals as approvals_router  # noqa: E402  (M19a)
from app.routers import auth as auth_router  # noqa: E402  (M21b identity)
from app.routers import eval as eval_router  # noqa: E402  (M19b smoke)
from app.routers import agents as agents_router  # noqa: E402
from app.routers import webhooks as webhooks_router  # noqa: E402
from app.services import metrics  # noqa: E402 (Lane 2 observability registry)

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


async def _lifespan(application: Any) -> Any:
    """Start/stop database schema and the live incident orchestrator."""
    from app.db.session import init_db
    try:
        await init_db()
        logger.info("database initialized successfully")
    except Exception:
        logger.exception("database initialization warning")

    from app.services import orchestrator as orchestrator_mod
    worker = orchestrator_mod.ORCHESTRATOR
    try:
        await worker.start()
        logger.info("orchestrator started mode=%s auto_generate=%s",
                    worker.stats.mode, worker.auto_generate)
    except Exception:  # a dead worker must not stop the API from serving
        logger.exception("orchestrator failed to start; API continues without it")
    try:
        yield
    finally:
        try:
            await worker.stop()
        except Exception:  # pragma: no cover
            logger.exception("orchestrator failed to stop cleanly")


app = FastAPI(title="ProofOps", version="0.1.0", lifespan=_lifespan)
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
# M21b: identity router (GET /identity). It exists so a client never asserts
# its own identity or role: the Safety Gate reads the server-resolved
# principal, its server-side roles, and the identity MODE from here.
if auth_router.router is not None:
    app.include_router(auth_router.router)
# Lane 2 (SSE stream router, owned by another lane): include IF it exists at
# integration time -- this lane and the stream lane may land in either order.
try:
    from app.routers import stream as stream_router  # noqa: E402
except ImportError:
    stream_router = None  # type: ignore[assignment]
if stream_router is not None and \
        getattr(stream_router, "router", None) is not None:
    app.include_router(stream_router.router)
# M19b: alert ingestion + orchestrator control. The front door for incidents --
# without it, a run can only be created by hand.
if ingest_router is not None and \
        getattr(ingest_router, "router", None) is not None:
    app.include_router(ingest_router.router)
if agents_router is not None and \
        getattr(agents_router, "router", None) is not None:
    app.include_router(agents_router.router)
if webhooks_router is not None and \
        getattr(webhooks_router, "router", None) is not None:
    app.include_router(webhooks_router.router)

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
    from app.routers import approvals as approvals_router  # noqa: E402 (lazy)
    nonces = getattr(approvals_router, "NONCES", None)
    return {"service": "proofops-api", "spec": "PS03_FINAL_SPEC_V2",
            "executor_tier": settings.EXECUTOR, "mode": settings.APP_ENV,
            "nonce_store_durable": bool(
                getattr(nonces, "persistent", False)),
            "nonce_store_degraded": bool(getattr(nonces, "degraded", False))}


@app.get("/meta/engines")
async def meta_engines() -> dict:
    """Return status of all 4 foundational enterprise control plane engines."""
    from app.db.session import db_health
    from app.services.k8s_executor import K8S_EXECUTOR
    from app.services.prom_verifier import PROMETHEUS_VERIFIER
    from agents.llm_hub import LLMHub

    db_st = await db_health()
    k8s_st = K8S_EXECUTOR.cluster_status()
    prom_st = await PROMETHEUS_VERIFIER.status()
    llm_st = LLMHub.active_provider()

    return {
        "database": db_st,
        "kubernetes": k8s_st,
        "prometheus": prom_st,
        "llm_hub": llm_st,
    }


@app.get("/readyz")
def readyz() -> JSONResponse:
    # READINESS (M00.4): 200 only when dependencies serve; 503 otherwise.
    # Bounded probe (<=2s); body is secret-free by construction.
    body = readiness(settings.DATABASE_URL)
    return JSONResponse(status_code=200 if body["status"] == "ready" else 503,
                        content=body)


@app.middleware("http")
async def metrics_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    start = time.perf_counter()
    response = await call_next(request)
    try:
        route = request.url.path
        template = getattr(request.scope.get("route"), "path", None)
        if isinstance(template, str) and template:
            route = template
        metrics.observe_http(route, response.status_code,
                             time.perf_counter() - start)
    except Exception:
        pass
    return response


@app.get("/metrics")
def metrics_endpoint() -> PlainTextResponse:
    # LANE 2: Prometheus-text exposition (stdlib-only render, no client lib).
    return PlainTextResponse(content=metrics.render_prometheus(),
                             media_type="text/plain; version=0.0.4")


@app.get("/alerts")
def alerts_endpoint() -> JSONResponse:
    try:
        slo = metrics.load_slo()
        states = metrics.evaluate_alerts(metrics.snapshot(), slo)
    except Exception:
        return JSONResponse(status_code=500,
                            content={"error": "SLO configuration unavailable"})
    return JSONResponse(status_code=200,
                        content={"alerts": [a.to_dict() for a in states]})
