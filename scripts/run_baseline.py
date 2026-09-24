"""ProofOps first measured baselines (M16.4 lane 5; scripted-oracle, honest labels).

Runs the committed suites (benchmarks/suites/deep5.jsonl, stub7.jsonl)
through the REAL pipeline/system path available in-repo
(backend/app/services/pipeline.py run_pipeline with per-agent scripted
oracle clients shaped like tests/test_pipeline_m21.py), grades + gates
every completed case with the M16 engine, writes rows to
runs/baseline-<date>.jsonl (gitignored run artifacts), and prints a
summary table.

Honesty (binding -- this script never invents numbers):
- Agents are SCRIPTED ORACLES: golden triage/diagnostic/planner payloads
  derived from the public bundle + committed expectations. No LYZR_API_KEY
  is read, no network call is made. Every row carries degraded=true and
  system="pipeline+scripted-oracle". What IS real: validator, policy,
  HITL, sandbox, verifier, FSM ordering, audit chain.
- Measured per completed case: policy decision, action type, FSM path,
  verdict(s), after_error_rate, evidence ids, session-store LLM calls.
- Mock blocks (explicit, labeled in baseline_meta.mock_blocks): token
  counts (no LLM text exists to count), retrieval / hallucination /
  prompt / latency harness blocks (eval.mock_trace() shapes), citation
  coverage (the pipeline does not compute MUST-CITE coverage; 1.0 is
  assumed iff evidence ids are non-empty and LABELED mock).
- PipelineBlocked / PipelineStalled / PipelineFailed outcomes are recorded
  as no-trace rows with passed=false -- never graded green, never
  silently skipped.
- Exit code is 0 when the machinery ran; red numbers never fail the run.

Usage:
  python scripts/run_baseline.py [--suite deep5|stub7|both]
      [--out PATH] [--config-name NAME] [--limit N]
"""
from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from agents import triage as triage_mod  # noqa: E402 (M13.2 severity fn)
from agents.lyzr_client import ClientResult  # noqa: E402 (M13.1 shape)
from app.services import benchmarks as bench_mod  # noqa: E402 (M17 suites)
from app.services import correlator  # noqa: E402 (M04 fingerprint)
from app.services import eval as eval_mod  # noqa: E402 (M16 engine)
from app.services import pipeline as pipeline_mod  # noqa: E402 (M21 path)
from app.services import predigest as predigest_mod  # noqa: E402 (M05 pack)

import telemetry.gen as gen_mod  # noqa: E402 (M02 generator)

CONFIG_DEFAULT = "baseline-scripted"
APPROVAL_SECRET = "baseline-local-approval"
APPROVAL_ACTOR = "sre-1"

#: Scripted oracle per scenario: pinned runbook + resolving action with
#: runbook-schema-conformant params + verification plan. crashloop uses
#: patch_config (the semantically coherent OOM fix under its schema; the
#: mock tier cannot heal error_rate by config change, so FAILED ->
#: rollback -> ESCALATED is the honest expected path there).
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

MEASURED_BLOCKS = ("policy.decision", "policy.action", "fsm.path",
                   "fsm.states", "verifier.verdict", "verifier.verdicts",
                   "sandbox.after_error_rate", "evidence.ids",
                   "budgets.calls")
MOCK_BLOCKS = ("budgets.tokens_in", "budgets.tokens_out",
               "budgets.ctx_per_call", "budgets.cache_hit",
               "retrieval.*", "hallucination.*", "prompt.*",
               "latencies.*", "citations.coverage")


class BaselineError(Exception):
    """Suite-load or wiring failure (fail-closed, never estimated)."""


class _Scripted:
    """Per-agent scripted oracle client (CONNECTED golden payloads).

    Duck-typed like tests/test_pipeline_m21.py Scripted: mode_for reports
    CONNECTED so agents take their live paths with session accounting, but
    no network or key is involved (DEGRADED, labeled on every row).
    """

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def mode_for(self, agent: str) -> str:
        _ = agent
        return "CONNECTED"

    def chat(self, agent: str, session_id: str,
             message: str) -> ClientResult:
        _ = message
        return ClientResult("CONNECTED", agent, session_id,
                            dict(self.payload), "", 1, "PS03-Governed")


def load_committed_suite(suite: str) -> list[dict[str, Any]]:
    """Load + seal-verify a committed suite file (fail-closed on drift)."""
    if suite not in ("deep5", "stub7"):
        raise BaselineError(f"unknown suite: {suite!r}")
    path = ROOT / "benchmarks" / "suites" / f"{suite}.jsonl"
    rows = bench_mod.load_suite_file(path)
    verdict = bench_mod.verify_suite(rows)
    if not verdict["valid"]:
        raise BaselineError(f"suite drift: {verdict['bad']}")
    return rows


def alerts_from_tele(tele: Mapping[str, Any]) -> tuple[list[dict[str, Any]],
                                                      dict[str, Any]]:
    """Build pipeline alert input + observables from a public bundle.

    Only PUBLIC telemetry is read (ground truth never enters here); error
    rate comes from bundle metrics, breach from the bundle SLO gate.
    """
    alerts_raw = list(tele.get("alerts", []))
    if not alerts_raw:
        raise BaselineError("public bundle carries no alerts")
    first = dict(alerts_raw[0])
    service = str(first.get("service", "")).strip()
    env = str(first.get("environment", "prod")).strip()
    signature = str(first.get("signature", "")).strip()
    if not service or not signature:
        raise BaselineError("alert lacks service/signature")
    metrics = [float(m.get("value", 0.0)) for m in tele.get("metrics", [])
               if isinstance(m, Mapping)]
    err = max(metrics) if metrics else 0.0
    slo = dict(tele.get("slo", {}))
    threshold = float(slo.get("error_rate_below", 0.01))
    breach = err >= threshold
    alert = {"service": service, "env": env, "signature": signature,
             "error_rate": err, "slo_breach": breach, "deploy_id": ""}
    return [alert], {"service": service, "env": env, "signature": signature,
                     "error_rate": err, "breach": breach}


def oracle_payloads(scenario: str, tele: Mapping[str, Any],
                    incident_id: str) -> tuple[dict[str, Any], dict[str, Any],
                                              dict[str, Any], dict[str, Any]]:
    """Golden agent payloads + resource for one case (scripted oracle).

    Triage severity uses the real deterministic function over observables;
    diagnosis cites real evidence-pack ids; the plan uses the scenario
    oracle pin. Sealed answers are never read here.
    """
    if scenario not in ORACLE:
        raise BaselineError(f"no oracle pin for scenario: {scenario!r}")
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
    resource = {"type": "deployment", "id": obs["service"],
                "environment": "mock"}
    return triage, diagnostic, plan, {"alerts": alerts, "resource": resource}


def mock_harness_blocks() -> dict[str, dict[str, Any]]:
    """Explicit mock blocks (labeled MOCK in every row's baseline_meta)."""
    harness = eval_mod.mock_trace()
    return {"retrieval": dict(harness["retrieval"]),
            "hallucination": dict(harness["hallucination"]),
            "prompt": dict(harness["prompt"]),
            "latencies": dict(harness["latencies"]),
            "budgets_base": dict(harness["budgets"])}


def run_one(row: Mapping[str, Any], config_name: str) -> tuple[Any | None,
                                                              dict[str, Any]]:
    """Run one committed row through pipeline -> grade -> gate.

    Returns (RunRecord | None, outcome). Outcome always carries case_id,
    status (completed/blocked/stalled/failed), path or error, measured
    LLM calls, and degraded labels. Only PUBLIC bundle data reaches the
    pipeline; sealed allowed/forbidden grade afterwards.
    """
    from agents import session as session_mod  # noqa: E402 (M13.7 store)
    from app.routers import approvals as approvals_mod  # noqa: E402 (M07)

    case_id = str(row["case_id"])
    scenario, variant = str(row["scenario"]), str(row["variant"])
    seed = int(row["seed"])
    incident_id = f"baseline-{scenario}-{variant}-{seed}"
    store = session_mod.SessionStore()
    approvals_mod.reset_demo_state()
    try:
        bundle = gen_mod.generate(scenario, variant, seed)
        if not gen_mod.verify_bundle(bundle):
            raise BaselineError(f"bundle seal failed: {case_id}")
        tele = gen_mod.public_bundle(bundle)
        triage, diagnostic, plan, inputs = oracle_payloads(
            scenario, tele, incident_id)
        clients = {agent: _Scripted(payload) for agent, payload in
                   (("triage", triage), ("diagnostic", diagnostic),
                    ("planner", plan))}
        try:
            report = pipeline_mod.run_pipeline(
                incident_id, inputs["alerts"], tele,
                inputs["resource"]["id"], "prod", inputs["resource"],
                clients, store,
                approval={"secret": APPROVAL_SECRET,
                          "actor": APPROVAL_ACTOR})
        except (pipeline_mod.PipelineBlocked, pipeline_mod.PipelineStalled,
                pipeline_mod.PipelineFailed) as exc:
            calls = store.incident_calls(incident_id)
            return None, {"case_id": case_id, "status": type(exc).__name__,
                          "path": getattr(getattr(exc, "run", None),
                                          "state", "unknown"),
                          "error": str(exc)[:300], "llm_calls": calls,
                          "degraded": True,
                          "system": "pipeline+scripted-oracle"}
        calls = store.incident_calls(incident_id)
        harness = mock_harness_blocks()
        budgets = dict(harness["budgets_base"])
        budgets["calls"] = calls
        coverage = 1.0 if report.get("evidence_ids") else 0.0
        trace = pipeline_mod.to_eval_trace(
            report, tele, budgets, harness["retrieval"],
            harness["hallucination"], harness["prompt"],
            harness["latencies"], coverage=coverage)
        grades = eval_mod.grade(trace, {"allowed": list(row["allowed"]),
                                        "forbidden": list(row["forbidden"])})
        gates = eval_mod.gate_scores(trace, grades)
        passed = all(g.passed for g in grades) and \
            all(gate["passed"] for gate in gates.values())
        record = eval_mod.RunRecord(
            run_id=f"{case_id}::{config_name}::{uuid.uuid4().hex[:8]}",
            case_id=case_id, config={"name": config_name}, trace=trace,
            grades=grades, gates=gates, passed=passed)
        outcome = {"case_id": case_id, "status": "completed",
                   "path": report.get("path"),
                   "decision": report.get("decision"),
                   "action": report.get("action_type"),
                   "verdict": report.get("verdict"),
                   "llm_calls": calls, "degraded": True,
                   "system": "pipeline+scripted-oracle"}
        return record, outcome
    finally:
        approvals_mod.reset_demo_state()


def to_baseline_row(record: Any, outcome: Mapping[str, Any]) -> dict[str, Any]:
    """JSONL row: M16 evaluation block + honest baseline labels."""
    row = eval_mod.to_evaluation_row(record)
    row["case_id"] = record.case_id
    row["config"] = record.config.get("name", "")
    row["path"] = outcome.get("path")
    row["degraded"] = True
    row["system"] = "pipeline+scripted-oracle"
    row["baseline_meta"] = {
        "measured_blocks": list(MEASURED_BLOCKS),
        "mock_blocks": list(MOCK_BLOCKS),
        "budgets_source": "calls measured from session store; "
                          "tokens/ctx/cache are mock_trace shapes",
        "coverage_note": "citations.coverage assumed 1.0 iff evidence "
                         "ids non-empty (pipeline computes none); MOCK",
        "agents": "scripted oracles (no LYZR_API_KEY, no network)",
    }
    return row


def to_outcome_row(outcome: Mapping[str, Any], config_name: str,
                   run_id: str) -> dict[str, Any]:
    """No-trace row for blocked/stalled/failed outcomes (passed=false)."""
    from app.contracts.evaluation import (  # noqa: E402 (M01.15 rows)
        EvaluationRun,
    )
    evaluation = EvaluationRun(
        run_id=run_id, suite=config_name,
        case_id=str(outcome["case_id"]), passed=False,
        llm_calls=int(outcome.get("llm_calls", 0)))
    return {"evaluation": evaluation.model_dump(mode="json"),
            "trace": None, "grades": [], "gates": {},
            "outcome": dict(outcome), "case_id": outcome["case_id"],
            "config": config_name, "degraded": True,
            "system": "pipeline+scripted-oracle",
            "baseline_meta": {
                "measured_blocks": ("outcome.status", "outcome.path",
                                    "budgets.calls"),
                "mock_blocks": ("no trace: nothing graded",),
                "note": "pipeline stopped before a report; "
                        "recorded, never skipped",
            }}


def run_suite(rows: Sequence[Mapping[str, Any]],
              config_name: str) -> tuple[list[Any], list[dict[str, Any]]]:
    """Run every row; returns (records, outcomes) in suite order."""
    records: list[Any] = []
    outcomes: list[dict[str, Any]] = []
    for row in rows:
        record, outcome = run_one(row, config_name)
        outcomes.append(dict(outcome))
        if record is not None:
            records.append(record)
    return records, outcomes


def summarize(records: Sequence[Any],
              outcomes: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Summary math over graded records + outcome counts (no assertions)."""
    outcomes = list(outcomes)
    completed = [o for o in outcomes if o.get("status") == "completed"]
    by_status: dict[str, int] = {}
    by_path: dict[str, int] = {}
    for outcome in outcomes:
        by_status[str(outcome.get("status"))] = \
            by_status.get(str(outcome.get("status")), 0) + 1
        by_path[str(outcome.get("path"))] = \
            by_path.get(str(outcome.get("path")), 0) + 1
    gate_names = ("C1", "C2", "C3", "C4", "C5", "C6")
    gates_rate = {gate: (sum(1 for r in records if r.gates[gate]["passed"])
                         / len(records) if records else 0.0)
                  for gate in gate_names}
    tokens_in = sum(int(r.trace["budgets"]["tokens_in"]) for r in records)
    tokens_out = sum(int(r.trace["budgets"]["tokens_out"]) for r in records)
    calls = sum(int(o.get("llm_calls", 0)) for o in outcomes)
    return {"n": len(outcomes), "completed": len(completed),
            "passed": sum(1 for r in records if r.passed),
            "pass_rate": (sum(1 for r in records if r.passed) / len(records)
                          if records else 0.0),
            "gates_rate": gates_rate, "by_status": by_status,
            "by_path": by_path, "tokens_in": tokens_in,
            "tokens_out": tokens_out, "llm_calls_measured": calls}


def write_rows(path: str | Path, records: Sequence[Any],
               outcomes: Sequence[Mapping[str, Any]],
               config_name: str) -> tuple[int, list[str]]:
    """Append baseline rows; returns (count, jsonl refs)."""
    out = Path(path)
    refs: list[str] = []
    count = 0
    by_case = {o["case_id"]: o for o in outcomes}
    for record in records:
        row = to_baseline_row(record, by_case[record.case_id])
        lineno = eval_mod.append_run(out, row)
        count += 1
        refs.append(f"{out}#{lineno}")
    for outcome in outcomes:
        if outcome.get("status") == "completed":
            continue
        run_id = (f"{outcome['case_id']}::{config_name}::"
                  f"{uuid.uuid4().hex[:8]}")
        lineno = eval_mod.append_run(
            out, to_outcome_row(outcome, config_name, run_id))
        count += 1
        refs.append(f"{out}#{lineno}")
    return count, refs


def print_summary(summary: Mapping[str, Any], out: Path) -> None:
    """Human-readable summary table (measured numbers, whatever they are)."""
    print("ProofOps baseline (DEGRADED: pipeline+scripted-oracle, no live Lyzr)")
    print(f"rows: {summary['n']}  completed: {summary['completed']}  "
          f"passed: {summary['passed']}  "
          f"pass_rate: {summary['pass_rate']:.3f}")
    gates = "  ".join(f"{g}={summary['gates_rate'][g]:.3f}"
                      for g in ("C1", "C2", "C3", "C4", "C5", "C6"))
    print(f"gates: {gates}")
    print(f"tokens_in(mock)={summary['tokens_in']}  "
          f"tokens_out(mock)={summary['tokens_out']}  "
          f"llm_calls(measured)={summary['llm_calls_measured']}")
    print(f"by_status={dict(summary['by_status'])}  "
          f"by_path={dict(summary['by_path'])}")
    print(f"jsonl: {out}")


def main(argv: Sequence[str] | None = None) -> int:
    """CLI: suite -> pipeline -> grade -> JSONL -> summary table."""
    parser = argparse.ArgumentParser(description="ProofOps measured baseline")
    parser.add_argument("--suite", default="deep5",
                        choices=("deep5", "stub7", "both"))
    parser.add_argument("--out", default="",
                        help="JSONL path (default runs/baseline-<date>.jsonl)")
    parser.add_argument("--config-name", default=CONFIG_DEFAULT)
    parser.add_argument("--limit", type=int, default=0,
                        help="run only the first N rows (0 = all)")
    args = parser.parse_args(argv)

    suites = ("deep5", "stub7") if args.suite == "both" else (args.suite,)
    rows: list[dict[str, Any]] = []
    for suite in suites:
        rows.extend(load_committed_suite(suite))
    if args.limit and args.limit > 0:
        rows = rows[:args.limit]
    if not rows:
        print("BASELINE FAIL: no rows loaded")
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out = Path(args.out) if args.out else ROOT / "runs" / \
        f"baseline-{stamp}.jsonl"
    records, outcomes = run_suite(rows, args.config_name)
    count, _ = write_rows(out, records, outcomes, args.config_name)
    summary = summarize(records, outcomes)
    print_summary(summary, out)
    print(f"wrote {count} rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
