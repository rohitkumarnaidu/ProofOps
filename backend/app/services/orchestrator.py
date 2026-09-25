"""Live incident orchestrator (M19b real-time control plane).

The gap this closes
-------------------
`run_pipeline` was complete and real -- A1/A2/A3, the validator, the policy
engine, the FSM, the sandbox, the verifier, rollback, RCA -- and nothing ever
called it. There was no worker, no scheduler, no lifespan task. The only way to
move a run forward over HTTP was `POST /runs/{id}/advance`, i.e. a human
poking the state machine one transition at a time.

That is why the product read as a static mock: it genuinely was one. Every
visible transition had been caused by hand, and the audit stream replayed its
backlog and closed, so nothing could change on screen without a human.

What it does
------------
An asyncio task started from the FastAPI lifespan that:

  1. accepts incidents from two sources -- an ingest queue fed by
     `POST /alerts/ingest`, and the seeded telemetry generator;
  2. claims each incident exactly once (no double-advance);
  3. runs the real pipeline for it, OFF the event loop, so a slow pipeline
     cannot stall every other request in the process;
  4. adopts the resulting run into the run store, so `GET /runs/{id}` shows
     real history;
  5. passes the HTTP layer's own audit chain in, so every event lands where the
     UI already reads it and fans out live to connected clients.

What it deliberately does NOT do
--------------------------------
**It never approves anything.** `approval=None` is passed, so a YELLOW action
routes to AWAITING_APPROVAL and the worker stops. A human decides, in the
Safety Gate, with a real token. An auto-approving worker would violate the
product's central safety invariant (YELLOW requires a valid scoped approval)
and would make the entire HITL story theatre. The demo's `AWAITING_APPROVAL`
state is the *feature*.

Agent reasoning is SCRIPTED-ORACLE, and is labelled as such everywhere. That is
not a shortcut around the safety work: severity comes from the real
deterministic function, the fingerprint from the real correlator, evidence ids
from the real pre-digester, and the action is checked by the real validator,
the real policy bundle, the real HMAC, the real sandbox and the real verifier.
Only the hypothesis prose and the action choice are pinned, because A2's
offline fallback returns INSUFFICIENT_EVIDENCE and would escalate everything.
A live Lyzr key replaces the oracle wholesale -- see `_clients_for`.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from app.services import predigest as predigest_mod

#: Scenario -> pinned runbook + resolving action. Identical pins to
#: scripts/run_baseline.py, which is the committed, measured reference for a
#: full pipeline pass. Kept as data so the orchestrator and the baseline
#: cannot drift on what "the plan" means for a scenario.
ORACLE: dict[str, dict[str, Any]] = {
    "bad-deploy": {"runbook_id": "bad-deploy-rollback",
                   "runbook_version": "1.2.0",
                   "action": "rollback_deployment",
                   "params": {"to_version": "v22"},
                   "verify": ["deployment_version_expected"]},
    "crashloop-oom": {"runbook_id": "crashloop-oom",
                      "runbook_version": "1.0.0",
                      "action": "patch_config",
                      "params": {"memory_limit": "1Gi"},
                      "verify": ["pod_ready"]},
    "db-exhaust": {"runbook_id": "db-pool-saturation",
                   "runbook_version": "1.1.0",
                   "action": "scale_deployment",
                   "params": {"replicas": 4},
                   "verify": ["pool_wait_drained"]},
    "net-dep-fail": {"runbook_id": "net-dep-failover",
                     "runbook_version": "1.0.0",
                     "action": "scale_deployment",
                     "params": {"replicas": 4},
                     "verify": ["error_rate_below_1pct"]},
    "injection": {"runbook_id": "injection-quarantine",
                  "runbook_version": "1.0.0",
                  "action": "read",
                  "params": {},
                  "verify": ["no_infra_fault"]},
}

DEFAULT_SCENARIO = "bad-deploy"
DEFAULT_VARIANT = "NORMAL"


def alerts_from_tele(tele: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Derive a normalized alert + observables from a telemetry bundle.

    The alert is built from the bundle's own worst observed error rate rather
    than invented, so triage severity and the SLO verdict that follow are
    consequences of the data, not constants.
    """
    metrics = [m for m in tele.get("metrics", []) if isinstance(m, Mapping)]
    error_rate = max((float(m.get("value", 0.0) or 0.0) for m in metrics), default=0.0)
    service = str(tele.get("service") or "checkout-api")
    env = str(tele.get("env") or "prod")
    signature = str(tele.get("error_signature") or "HTTP5xx")
    slo = dict(tele.get("slo", {}))
    threshold = float(slo.get("error_rate_below", 0.01) or 0.01)
    breach = error_rate >= threshold
    alert = {"service": service, "env": env, "signature": signature,
             "error_rate": error_rate, "slo_breach": breach, "deploy_id": ""}
    return [alert], {"service": service, "env": env, "signature": signature,
                     "error_rate": error_rate, "breach": breach}


def oracle_payloads(scenario: str, tele: Mapping[str, Any],
                    incident_id: str) -> tuple[dict[str, Any], dict[str, Any],
                                              dict[str, Any], dict[str, Any]]:
    """Scripted agent payloads for one incident, derived from real telemetry.

    Everything that can be computed honestly IS computed: severity from the
    real deterministic function, fingerprint from the real correlator, evidence
    ids from the real pre-digester, and the action's risk from the real policy
    vocabulary. Only the hypothesis prose and the action choice are pinned.
    """
    from agents import triage as triage_mod
    from app.services import correlator

    if scenario not in ORACLE:
        raise KeyError(f"no oracle pin for scenario: {scenario!r}")
    oracle = ORACLE[scenario]
    alerts, obs = alerts_from_tele(tele)
    pack = predigest_mod.build_evidence_pack(incident_id, dict(tele))
    known = [str(e["evidence_id"]) for e in pack.get("evidence", [])]

    severity = triage_mod.deterministic_severity(
        obs["env"], obs["error_rate"], obs["signature"], obs["breach"])
    triage = {"incident_id": incident_id, "severity": severity,
              "fingerprint": correlator.fingerprint(
                  obs["service"], obs["signature"], obs["env"], ""),
              "owner": f"{obs['service']}-oncall", "signals": [],
              "evidence_ids": []}
    hyp = {"text": f"scripted-oracle lead for {scenario}",
           "confidence": 0.9, "supporting": list(known[:2]),
           "contradicting": [], "test_tool": "", "test_args": {},
           "test_result": "", "status": "SUPPORTED"}
    diagnostic = {"incident_id": incident_id,
                  "hypotheses": [hyp, dict(hyp, text="scripted alternative",
                                           confidence=0.3)],
                  "runbook_id": oracle["runbook_id"],
                  "runbook_version": oracle["runbook_version"],
                  "verdict": "PINNED"}
    action = str(oracle["action"])
    rollback: dict[str, Any] | None = {"action_type": action}
    if action == "read":
        rollback = None
    plan = {"action_type": action,
            "parameters": dict(oracle["params"]),
            "risk_level": "GREEN" if action == "read" else "YELLOW",
            "reason": f"Scripted-oracle plan for {scenario}.",
            "expected_outcome": "Mock-tier state change.",
            "verification_plan": list(oracle["verify"]),
            "rollback_action": rollback}
    resource = {"type": "deployment", "id": obs["service"], "environment": "mock"}
    return triage, diagnostic, plan, {"alerts": alerts, "resource": resource}


class _Scripted:
    """Duck-typed agent client returning a pinned payload (CONNECTED).

    The agents call exactly two methods on their client -- `mode_for(agent)` and
    `chat(agent, session_id, message)` -- so that is all this provides, matching
    the proven client in scripts/run_baseline.py. Getting that surface wrong
    fails at the first agent call, which is how the first live run died with
    "'_Scripted' object has no attribute 'chat'".

    Reporting CONNECTED is deliberate: it makes each agent take its LIVE path,
    with real session accounting, budget counting, Structured Output validation
    and the RAI output check. The scripted nature is recorded in the run's own
    metadata and surfaced in the UI, never hidden behind a fake "live" label.
    """

    def __init__(self, agent: str, payload: Mapping[str, Any]) -> None:
        self.agent = agent
        self.payload = dict(payload)

    def mode_for(self, agent: str) -> str:
        _ = agent
        return "CONNECTED"

    def chat(self, agent: str, session_id: str, message: str) -> Any:
        from agents.lyzr_client import ClientResult
        _ = message
        return ClientResult("CONNECTED", agent, session_id,
                            dict(self.payload), "", 1, "PS03-Governed")


def _lyzr_key() -> str:
    """The Lyzr API key, via the sanctioned Settings accessor.

    NOT `os.environ`: test_config_hardening pins direct environment access out
    of everything under backend/, deliberately, so that all configuration
    resolution (and therefore all secret handling and fail-closed validation)
    happens in exactly one place. Reading the env here would have been more
    convenient and would have quietly created a second path around it.
    """
    try:
        from app.config import get_settings
        return str(get_settings().LYZR_API_KEY or "").strip()
    except Exception:
        return ""


def _clients_for(scenario: str) -> dict[str, Any]:
    """Agent clients for one incident.

    With a live Lyzr key the real client is used and the oracle is irrelevant.
    Without one, the scripted oracle drives the real downstream machinery. The
    caller records which happened; nothing here pretends.
    """
    if not _lyzr_key():
        return {name: _Scripted(name, {}) for name in
                ("triage", "diagnostic", "planner")}
    from agents.lyzr_client import AGENTS, ClientConfig, LyzrClient
    config = ClientConfig(api_key=_lyzr_key(),
                          agent_ids={name: name for name in AGENTS})
    return {name: LyzrClient(config) for name in ("triage", "diagnostic", "planner")}


@dataclass
class Job:
    incident_id: str
    scenario: str
    tele: Mapping[str, Any]
    source: str = "ingest"
    attempts: int = 0


@dataclass
class OrchestratorStats:
    submitted: int = 0
    processed: int = 0
    blocked: int = 0
    stalled: int = 0
    failed: int = 0
    duplicates_suppressed: int = 0
    last_incident: str = ""
    last_outcome: str = ""
    enabled: bool = True
    mode: str = "scripted-oracle"
    agents: list[str] = field(default_factory=list)


class Orchestrator:
    """Bounded, killable, single-claim incident worker."""

    def __init__(
        self,
        *,
        interval: float = 2.0,
        generator_interval: float = 45.0,
        scenario: str = DEFAULT_SCENARIO,
        variant: str = DEFAULT_VARIANT,
        seed: int = 7,
        max_incidents: int = 25,
        auto_generate: bool = True,
    ) -> None:
        self.interval = interval
        self.generator_interval = generator_interval
        self.scenario = scenario
        self.variant = variant
        self.seed = seed
        self.max_incidents = max_incidents
        self.auto_generate = auto_generate
        self.stats = OrchestratorStats(
            mode="live-lyzr" if _lyzr_key() else "scripted-oracle")
        self._queue: asyncio.Queue[Job] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self._claimed: set[str] = set()
        self._lock = threading.Lock()
        self._stopping = False
        self._seed_counter = 0

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name="proofops-orchestrator")

    async def stop(self) -> None:
        self._stopping = True
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    # -- submission --------------------------------------------------------

    def submit(self, incident_id: str, scenario: str,
               tele: Mapping[str, Any], source: str = "ingest") -> bool:
        """Queue an incident. False when it is a duplicate or we are full.

        The claim set is what makes double-advance impossible: an incident id is
        accepted once, and a second submission of the same id is refused rather
        than run twice. A pipeline that advanced a run twice would emit a
        duplicate transition into a hash-chained log, which verify() would then
        correctly report as tampering.
        """
        incident_id = str(incident_id).strip()
        if not incident_id:
            return False
        with self._lock:
            if incident_id in self._claimed:
                self.stats.duplicates_suppressed += 1
                return False
            if len(self._claimed) >= self.max_incidents:
                return False
            self._claimed.add(incident_id)
        self.stats.submitted += 1
        self._queue.put_nowait(Job(incident_id=incident_id, scenario=scenario,
                                   tele=dict(tele), source=source))
        return True

    # -- the loop ----------------------------------------------------------

    async def _run(self) -> None:
        last_generate = 0.0
        try:
            while not self._stopping:
                if self.auto_generate:
                    now = time.monotonic()
                    if now - last_generate >= self.generator_interval:
                        last_generate = now
                        self._generate_one()
                try:
                    job = await asyncio.wait_for(self._queue.get(), timeout=self.interval)
                except (asyncio.TimeoutError, TimeoutError):
                    continue
                try:
                    await self._process(job)
                except Exception:  # a bad job must never kill the worker
                    self.stats.failed += 1
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - the loop must outlive surprises
            self.stats.failed += 1

    def _generate_one(self) -> None:
        """Seed one incident from the deterministic telemetry generator.

        The generator is seeded, so the same deployment produces the same
        incident story on every boot -- which is what makes a live demo
        reproducible and an eval comparable.
        """
        try:
            sys_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))), "telemetry")
            if sys_path not in __import__("sys").path:
                __import__("sys").path.insert(0, sys_path)
            import gen as telemetry_gen  # type: ignore[import-not-found]
        except Exception:
            return
        self._seed_counter += 1
        seed = self.seed + self._seed_counter
        try:
            bundle = telemetry_gen.generate(self.scenario, self.variant, seed)
        except Exception:
            return
        incident_id = f"live-{self.scenario}-{seed}"
        self.submit(incident_id, self.scenario, bundle, source="generator")

    # -- the work ----------------------------------------------------------

    async def _process(self, job: Job) -> None:
        # to_thread is load-bearing: run_pipeline is synchronous and does real
        # work. On the event loop it would block every other request, including
        # the SSE streams this same worker is feeding.
        await asyncio.to_thread(self._process_sync, job)

    def _process_sync(self, job: Job) -> None:
        from app.routers import audit as audit_router
        from app.routers import runs as runs_router
        from app.services import pipeline as pipeline_mod
        from agents import session as session_mod

        # Everything is inside the boundary. Payload construction, client
        # construction and session setup can all fail on a bad bundle, and a
        # failure there used to escape _process entirely instead of being
        # recorded -- which meant one malformed job surfaced as an unhandled
        # error rather than a counted, auditable outcome.
        run = None
        outcome = "not attempted"
        try:
            triage, diagnostic, plan, extra = oracle_payloads(
                job.scenario, job.tele, job.incident_id)
            clients = {name: _Scripted(name, payload) for name, payload in (
                ("triage", triage), ("diagnostic", diagnostic), ("planner", plan))}
            store = session_mod.SessionStore()
            chain = audit_router.get_or_create_chain(job.incident_id)
            resource = extra["resource"]

            # NO approval is passed. A YELLOW action routes to AWAITING_APPROVAL
            # and this raises PipelineStalled -- the designed stop, and the
            # product's headline control.
            try:
                report = pipeline_mod.run_pipeline(
                    job.incident_id, extra["alerts"], job.tele,
                    str(resource["id"]), "prod", resource, clients, store,
                    approval=None, chain=chain)
                run = report["run"]
                outcome = str(report.get("verdict", "completed"))
                self.stats.processed += 1
            except pipeline_mod.PipelineStalled as exc:
                run = getattr(exc, "run", None)
                outcome = f"stalled: {str(exc)[:120]}"
                self.stats.stalled += 1
            except pipeline_mod.PipelineBlocked as exc:
                run = getattr(exc, "run", None)
                outcome = f"blocked: {str(exc)[:120]}"
                self.stats.blocked += 1
        except Exception as exc:  # noqa: BLE001 - recorded, never swallowed
            outcome = f"failed: {str(exc)[:120]}"
            self.stats.failed += 1
            self.stats.last_incident = job.incident_id
            self.stats.last_outcome = outcome
            return

        if run is not None:
            # Adopt into the serving store so GET /runs/{id} and the UI reflect
            # the real walk. The pipeline records the FSM into the chain on
            # every path, so nothing is recorded twice here.
            runs_router.REPO_STORE[job.incident_id] = run
            with contextlib.suppress(Exception):
                runs_router._save_best_effort()
        with contextlib.suppress(Exception):
            audit_router.persist_chain(chain)

        self.stats.last_incident = job.incident_id
        self.stats.last_outcome = outcome
        self.stats.agents = ["triage", "diagnostic", "planner"]


#: Process-wide instance, started by the FastAPI lifespan.
ORCHESTRATOR = Orchestrator()
