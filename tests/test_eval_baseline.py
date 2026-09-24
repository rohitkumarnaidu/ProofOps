"""M16.4 first baselines: scripted-oracle runner shape/validity (host-safe).

Proves scripts/run_baseline.py machinery: oracle pins cover deep5 with
loader-consistent runbook versions, public bundles yield alert inputs,
one real pipeline case grades + gates with degraded labels, JSONL rows
round-trip, summary math holds. NEVER asserts specific pass rates --
behavior may legitimately be <1.0; shape and validity only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

import run_baseline as RB  # noqa: E402 (M16.4 baseline script)

from app.contracts.evaluation import (  # noqa: E402 (M01.15 rows)
    EvaluationRun,
)
from app.services import benchmarks as bench_mod  # noqa: E402 (M17 suites)
from app.services import eval as eval_mod  # noqa: E402 (M16 engine)
from app.services import runbooks as runbooks_mod  # noqa: E402 (M11 pins)

import telemetry.gen as gen_mod  # noqa: E402 (M02 generator)


def _deep5_rows() -> list[dict]:
    return RB.load_committed_suite("deep5")


def _row(rows: list[dict], case_id: str) -> dict:
    return next(r for r in rows if r["case_id"] == case_id)


# ---------------------------------------------------------------------------
# Oracle pins: coverage + loader consistency
# ---------------------------------------------------------------------------

def test_oracle_covers_deep5_with_pinned_runbooks():
    assert set(RB.ORACLE) == set(eval_mod.DEEP5)
    for scenario, pin in RB.ORACLE.items():
        loaded = runbooks_mod.load_runbook(pin["runbook_id"])
        assert loaded.version == pin["runbook_version"], scenario
        assert pin["action"] in {str(a) for a in loaded.allowed_actions}, \
            scenario


def test_suite_load_seal_verified():
    rows = _deep5_rows()
    assert len(rows) == 25
    assert bench_mod.verify_suite(rows)["valid"] is True


def test_unknown_suite_rejected():
    import pytest
    with pytest.raises(RB.BaselineError):
        RB.load_committed_suite("nope")
    with pytest.raises(RB.BaselineError):
        RB.oracle_payloads("nope", {"alerts": []}, "inc-x")


# ---------------------------------------------------------------------------
# Alert derivation from public bundles only
# ---------------------------------------------------------------------------

def test_alerts_from_public_bundle():
    tele = gen_mod.public_bundle(gen_mod.generate("bad-deploy", "NORMAL", 42))
    alerts, obs = RB.alerts_from_tele(tele)
    assert len(alerts) == 1
    assert alerts[0]["service"] == "web"
    assert alerts[0]["signature"] == "http_5xx_spike"
    assert obs["error_rate"] >= 0.0
    blob = json.dumps(tele)
    assert "expected_cause" not in blob  # GT never in pipeline input


# ---------------------------------------------------------------------------
# One real pipeline case: grades + gates + degraded labels (no rate assert)
# ---------------------------------------------------------------------------

def test_run_one_grades_and_labels():
    rows = _deep5_rows()
    record, outcome = RB.run_one(_row(rows, "bad-deploy/NORMAL/42"),
                                 "test-config")
    assert outcome["status"] == "completed"
    assert outcome["degraded"] is True
    assert outcome["system"] == "pipeline+scripted-oracle"
    assert outcome["llm_calls"] == 3  # scripted session accounting
    assert record is not None
    assert len(record.grades) == 8 and set(record.gates) == \
        {"C1", "C2", "C3", "C4", "C5", "C6"}
    assert isinstance(record.passed, bool)  # shape only, never greenness
    row = RB.to_baseline_row(record, outcome)
    EvaluationRun(**row["evaluation"])  # contract conformance (M01.15)
    assert row["degraded"] is True
    assert row["baseline_meta"]["mock_blocks"]  # mocks labeled, never silent


def test_mock_harness_blocks_present():
    blocks = RB.mock_harness_blocks()
    assert set(blocks) == {"retrieval", "hallucination", "prompt",
                           "latencies", "budgets_base"}
    eval_mod.check_trace(eval_mod.mock_trace())  # shapes grade cleanly


# ---------------------------------------------------------------------------
# JSONL round-trip + summary math on a small subset (tmp paths only)
# ---------------------------------------------------------------------------

def test_subset_jsonl_and_summary_math(tmp_path):
    rows = _deep5_rows()[:2]
    records, outcomes = RB.run_suite(rows, "test-config")
    assert len(outcomes) == 2
    out = tmp_path / "runs" / "subset.jsonl"
    count, _ = RB.write_rows(out, records, outcomes, "test-config")
    assert count == 2
    loaded = eval_mod.load_runs(out)
    assert len(loaded) == 2
    for entry in loaded:
        EvaluationRun(**entry["evaluation"])
    summary = RB.summarize(records, outcomes)
    assert summary["n"] == 2
    assert summary["completed"] == len(records)
    assert summary["pass_rate"] == \
        (sum(1 for r in records if r.passed) / len(records) if records
         else 0.0)
    assert set(summary["gates_rate"]) == {"C1", "C2", "C3", "C4", "C5", "C6"}
    assert sum(summary["by_status"].values()) == 2
    assert summary["llm_calls_measured"] == \
        sum(int(o.get("llm_calls", 0)) for o in outcomes)
    assert summary["tokens_in"] == sum(
        int(r.trace["budgets"]["tokens_in"]) for r in records)


def test_outcome_row_shape_for_blocked(tmp_path):
    outcome = {"case_id": "bad-deploy/NORMAL/42", "status": "PipelineBlocked",
               "path": "BLOCKED", "error": "policy DENY", "llm_calls": 2,
               "degraded": True, "system": "pipeline+scripted-oracle"}
    row = RB.to_outcome_row(outcome, "test-config", "run-1")
    EvaluationRun(**row["evaluation"])
    assert row["evaluation"]["passed"] is False
    assert row["trace"] is None and row["grades"] == []
    out = tmp_path / "blocked.jsonl"
    assert eval_mod.append_run(out, row) == 1
    assert eval_mod.load_runs(out)[0]["outcome"]["status"] == \
        "PipelineBlocked"
