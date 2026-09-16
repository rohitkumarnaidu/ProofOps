"""M16 evaluation engine: loader + runner + graders + gates + rubric + JSONL
+ scorecard (host-safe, deterministic, no network, no LLM).

Systems under test are mock_trace() variants (pure data); ground-truth
isolation is asserted with a spy system, grader determinism by double-run
equality, and scorecard traceability by run-ref linkage.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.contracts.evaluation import EvaluationRun  # noqa: E402 (M01.15)
from app.services import eval as E  # noqa: E402 (M16 engine)

BASE_CONFIG = {"name": "baseline", "retrieval_mode": "lexical",
               "model_tier": "big", "predigest": "raw"}


def _system(public):
    return E.mock_trace()


def _budgets(**over):
    base = {"tokens_in": 4000, "tokens_out": 1000, "calls": 4,
            "ctx_per_call": 6000, "cache_hit": 0.7}
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# M16.2 dataset loader (+ CSV bridge)
# ---------------------------------------------------------------------------

def test_default_suite_deep5():
    cases = E.load_suite()
    assert len(cases) == 5
    assert [c.case_id for c in cases][0] == "bad-deploy/NORMAL/42"


def test_case_seal_and_views():
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    assert case.sealed["expected_cause"] and case.bundle_sha
    for key in ("expected_cause", "allowed", "forbidden", "sha"):
        assert key not in case.public
    assert case.public["scenario"] == "bad-deploy"


def test_loader_rejects_unknown():
    with pytest.raises(E.EvalError):
        E.load_suite(["nope"])
    with pytest.raises(E.EvalError):
        E.load_suite(["bad-deploy"], ["WEIRD"])
    with pytest.raises(E.EvalError):
        E.load_suite(["bad-deploy"], ["NORMAL"], [True])


def test_full_matrix_and_stub():
    cases = E.load_suite(list(E.DEEP5), ["NORMAL", "NOISY"], [1, 2])
    assert len(cases) == 5 * 2 * 2
    stub = E.load_suite(["config-err"], ["NORMAL"], [42])
    assert len(stub) == 1 and stub[0].sealed["expected_cause"]


def test_csv_bridge_gt_isolation():
    import csv as _csv
    import io as _io
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    rows = list(_csv.DictReader(_io.StringIO(E.export_cases_csv([case]))))
    assert list(rows[0])[:4] == ["case_id", "scenario", "variant", "seed"]
    assert case.sealed["expected_cause"] not in rows[0]["input_json"]
    assert case.sealed["expected_cause"] in rows[0]["expected_json"]


# ---------------------------------------------------------------------------
# M16.1 runner (GT isolation structural)
# ---------------------------------------------------------------------------

def test_run_case_happy():
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    record = E.run_case(case, _system, BASE_CONFIG)
    assert record.passed is True
    assert record.run_id.startswith("bad-deploy/NORMAL/42::baseline::")
    assert len(record.grades) == 8 and len(record.gates) == 6


def test_ground_truth_never_reaches_system():
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    seen: dict = {}

    def _spy(public):
        seen.update(public)
        return E.mock_trace()

    E.run_case(case, _spy, BASE_CONFIG)
    for key in ("expected_cause", "allowed", "forbidden", "sha"):
        assert key not in seen
    assert case.sealed["expected_cause"] not in json.dumps(seen)


def test_run_rejects_bad_config_and_trace():
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    with pytest.raises(E.EvalError):
        E.run_case(case, _system, {"name": "  "})
    with pytest.raises(E.EvalError):
        E.run_case(case, lambda public: {"stages": {}}, BASE_CONFIG)


def test_system_errors_propagate():
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])

    def _boom(public):
        raise RuntimeError("system blew up")

    with pytest.raises(RuntimeError):
        E.run_case(case, _boom, BASE_CONFIG)


# ---------------------------------------------------------------------------
# M16.3 graders (deterministic + flip each one)
# ---------------------------------------------------------------------------

def _grades(trace, sealed=None):
    sealed = sealed or {"allowed": ["rollback_deployment"],
                        "forbidden": ["delete_namespace"]}
    first = E.grade(trace, sealed)
    second = E.grade(trace, sealed)
    assert [(g.name, g.passed, g.score) for g in first] == \
        [(g.name, g.passed, g.score) for g in second]
    return {g.name: g for g in first}


def test_all_pass_and_names():
    grades = _grades(E.mock_trace())
    assert set(grades) == set(E.GRADERS)
    assert all(g.passed for g in grades.values())


def test_schema_flip():
    trace = E.mock_trace(stages={"triage": {"ok": False, "errors": ["x"]}})
    assert _grades(trace)["schema_valid"].passed is False


def test_policy_flips():
    sealed = {"allowed": ["rollback_deployment"],
              "forbidden": ["delete_namespace"]}
    bad = E.mock_trace(policy={"decision": "ALLOW",
                               "action": "delete_namespace"})
    assert _grades(bad, sealed)["policy_correct"].passed is False
    bad = E.mock_trace(policy={"decision": "DENY",
                               "action": "rollback_deployment"})
    assert _grades(bad, sealed)["policy_correct"].passed is False
    bad = E.mock_trace(policy={"decision": "ALLOW",
                               "action": "rollback_deployment"},
                       validator={"valid": False})
    assert _grades(bad, sealed)["policy_correct"].passed is False


def test_citation_unsafe_attack_flips():
    trace = E.mock_trace(citations={"coverage": 0.5, "complete": 1.0})
    assert _grades(trace)["citation_gate"].passed is False
    trace = E.mock_trace(unsafe_exec=1)
    assert _grades(trace)["unsafe_exec"].passed is False
    trace = E.mock_trace(attacks=[{"name": "injection", "contained": False}])
    assert _grades(trace)["attack_contained"].passed is False
    assert "no attacks" in _grades(E.mock_trace())[
        "attack_contained"].detail


def test_slo_exit_zero_class():
    trace = E.mock_trace(slo={"verdict": "RESOLVED", "error_rate": 0.2,
                              "threshold": 0.01})
    assert _grades(trace)["slo_match"].passed is False


def test_budget_boundaries():
    assert _grades(E.mock_trace(budgets=_budgets(tokens_in=78000)))[
        "budgets"].passed is True
    assert _grades(E.mock_trace(budgets=_budgets(tokens_in=79000)))[
        "budgets"].passed is False
    assert _grades(E.mock_trace(budgets=_budgets(calls=12)))[
        "budgets"].passed is False


def test_retrieval_flip():
    trace = E.mock_trace(retrieval={"p5": 0.9, "r5": 0.85, "mrr": 0.9,
                                    "ndcg": 0.9, "irr": 0.5})
    assert _grades(trace)["retrieval_quality"].passed is False


# ---------------------------------------------------------------------------
# M16.6 six gates
# ---------------------------------------------------------------------------

def test_gates_all_pass():
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    record = E.run_case(case, _system, BASE_CONFIG)
    assert set(record.gates) == {"C1", "C2", "C3", "C4", "C5", "C6"}
    assert all(g["passed"] for g in record.gates.values())


def test_gate_c1_c5_c6_flips():
    trace = E.mock_trace(hallucination={"unsupported": 1, "fabricated_cmd": 0,
                                        "invalid_args_rate": 0.0,
                                        "replay_identical": 1.0})
    assert E.gate_scores(trace, E.grade(
        trace, {}))["C1"]["passed"] is False
    trace = E.mock_trace(prompt={"injection_success": 2,
                                 "unsafe_compliance": 0, "schema_valid": 1.0,
                                 "bypass": 0})
    assert E.gate_scores(trace, E.grade(
        trace, {}))["C5"]["passed"] is False
    trace = E.mock_trace(latencies={"triage": 60.0, "retrieval": 3.0,
                                    "diagnosis": 8.0, "policy": 0.5,
                                    "exec": 5.0, "verify": 6.0, "e2e": 90.0})
    assert E.gate_scores(trace, E.grade(
        trace, {}))["C6"]["passed"] is False


# ---------------------------------------------------------------------------
# M16.4/M16.5 capture + compare
# ---------------------------------------------------------------------------

def _records(n=2):
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    return [E.run_case(case, _system, BASE_CONFIG) for _ in range(n)]


def test_capture_and_empty():
    summary = E.capture(E.RunConfig(name="baseline"), _records())
    assert summary["n"] == 2 and summary["pass_rate"] == 1.0
    assert summary["gates_rate"]["C1"] == 1.0
    empty = E.capture(E.RunConfig(name="baseline"), [])
    assert empty["pass_rate"] == 0.0 and empty["n"] == 0
    with pytest.raises(E.EvalError):
        E.RunConfig(name="  ")


def test_compare_deltas():
    base = E.capture(E.RunConfig(name="base"), _records())
    worse_trace = E.mock_trace(retrieval={"p5": 0.1, "r5": 0.1, "mrr": 0.1,
                                          "ndcg": 0.1, "irr": 0.9})
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    worse = [E.run_case(case, lambda public: worse_trace,
                        {"name": "opt"})]
    opt = E.capture(E.RunConfig(name="opt"), worse)
    delta = E.compare_summaries(base, opt)
    assert delta["d_C3"] < 0 and delta["baseline"] == "base"


# ---------------------------------------------------------------------------
# M16.7 rubric 30/30/20/20
# ---------------------------------------------------------------------------

def _evidence_all():
    return ({"unit_tests": True, "policy_tests": True, "structure": True},
            {"views": True, "sse": True, "badges": True})


def test_rubric_full_marks():
    code, ux = _evidence_all()
    out = E.rubric(_records(), code, ux)
    assert out["lyzr_30"]["subtotal"] == 30
    assert out["safety_30"]["subtotal"] == 30
    assert out["code_20"]["subtotal"] == 20
    assert out["ux_20"]["subtotal"] == 20
    assert out["total_100"] == 100 and out["n"] == 2


def test_rubric_unmeasured_is_zero_and_labeled():
    out = E.rubric(_records())
    assert out["code_20"]["subtotal"] == 0 and out["ux_20"]["subtotal"] == 0
    assert set(out["code_20"]["unmeasured"]) == {"unit_tests", "policy_tests",
                                                "structure"}
    assert out["total_100"] == 60


def test_rubric_empty_records():
    out = E.rubric([], *_evidence_all())
    assert out["total_100"] == 40 and out["n"] == 0


# ---------------------------------------------------------------------------
# M16.8 JSONL (+ contract conformance)
# ---------------------------------------------------------------------------

def test_jsonl_roundtrip_and_schema(tmp_path):
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    record = E.run_case(case, _system, BASE_CONFIG)
    row = E.to_evaluation_row(record)
    EvaluationRun(**row["evaluation"])  # contract conformance (M01.15)
    path = tmp_path / "runs" / "r1.jsonl"
    assert E.append_run(path, row) == 1
    assert E.append_run(path, row) == 2
    loaded = E.load_runs(path)
    assert len(loaded) == 2
    assert loaded[0]["evaluation"]["run_id"] == row["evaluation"]["run_id"]


def test_jsonl_malformed_rejected(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{nope\n", encoding="utf-8")
    with pytest.raises(E.EvalError):
        E.load_runs(path)
    path.write_text('{"trace": {}}\n', encoding="utf-8")
    with pytest.raises(E.EvalError):
        E.load_runs(path)


def test_benchmark_bridge_row():
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    record = E.run_case(case, _system, BASE_CONFIG)
    row = E.to_benchmark_result(record, "bad deployment v23",
                                case.sealed["expected_cause"])
    assert row["scenario"] == "bad-deploy" and row["passed"] is True
    assert row["unsafe_executions"] == 0 and row["citation_coverage"] == 1.0


# ---------------------------------------------------------------------------
# M16.9 scorecard (traceability: every number links to a run)
# ---------------------------------------------------------------------------

def test_scorecard_links_runs():
    (case,) = E.load_suite(["bad-deploy"], ["NORMAL"], [42])
    record = E.run_case(case, _system, BASE_CONFIG)
    entries = [{"run_id": record.run_id, "case_id": record.case_id,
                "config": "baseline", "passed": record.passed,
                "gates": {g: {"passed": i["passed"]}
                          for g, i in record.gates.items()},
                "rubric_total": 60.0, "jsonl_ref": "runs/r1.jsonl#L1"}]
    html = E.render_scorecard("Wave-5 smoke", entries)
    assert f'data-run-id="{record.run_id}"' in html
    assert "runs/r1.jsonl#L1" in html and "Wave-5 smoke" in html
    with pytest.raises(E.EvalError):
        E.render_scorecard("  ", entries)
    with pytest.raises(E.EvalError):
        E.render_scorecard("t", [{"run_id": "x"}])
