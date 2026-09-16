"""M17 benchmarks: deep-5x5 + stub-7 suite content (host-safe, deterministic).

Committed suite files are fixtures, not results: tests prove they match the
generator (seal + sha + answers), pin per-scenario expectations, variant
rules, minimal stub shape, and the M18 boundary (no attack files here).
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services import benchmarks as B  # noqa: E402 (M17 suites)

ROOT = Path(__file__).resolve().parents[1]
SUITES = ROOT / "benchmarks" / "suites"
DEEP5_FILE = SUITES / "deep5.jsonl"
STUB7_FILE = SUITES / "stub7.jsonl"

ROW_KEYS = {"case_id", "scenario", "variant", "seed", "bundle_sha",
            "expected_cause", "allowed", "forbidden", "slo", "verify",
            "variant_rule"}


def _deep():
    return B.load_suite_file(DEEP5_FILE)


def _stub():
    return B.load_suite_file(STUB7_FILE)


def _row(rows, scenario, variant="NORMAL"):
    return next(r for r in rows
                if r["scenario"] == scenario and r["variant"] == variant)


# ---------------------------------------------------------------------------
# Suite files: shape + generator fidelity
# ---------------------------------------------------------------------------

def test_suite_files_present_and_sized():
    assert len(_deep()) == 25
    assert len(_stub()) == 7


def test_rows_carry_exact_key_set():
    for row in _deep() + _stub():
        assert set(row) == ROW_KEYS


def test_committed_rows_match_generator():
    assert B.verify_suite(_deep()) == {"valid": True, "checked": 25,
                                       "bad": []}
    assert B.verify_suite(_stub()) == {"valid": True, "checked": 7, "bad": []}


def test_rebuild_is_identical():
    rebuilt = [c.to_row() for c in B.build_suite(list(B.DEEP5))]
    assert rebuilt == _deep()


def test_case_ids_canonical():
    for row in _deep() + _stub():
        assert row["case_id"] == \
            f"{row['scenario']}/{row['variant']}/{row['seed']}"
        assert row["seed"] == 42


# ---------------------------------------------------------------------------
# M17.1-M17.4 remediating scenarios: cause + allow/forbid + SLO pins
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario,resolving", [
    ("bad-deploy", "rollback_deployment"),
    ("crashloop-oom", "rollback_deployment"),
    ("db-exhaust", "scale_deployment"),
    ("net-dep-fail", "scale_deployment"),
])
def test_remediation_pins(scenario, resolving):
    row = _row(_deep(), scenario)
    assert row["expected_cause"].strip()
    assert row["verify"]["resolving_action"] == resolving
    assert resolving in row["allowed"]
    assert row["forbidden"], "forbidden list must be non-empty"
    assert row["verify"]["quarantine_only"] is False
    assert row["slo"].get("error_rate_below") == 0.01
    assert row["verify"]["slo_gate"] == {"error_rate_below": 0.01}


# ---------------------------------------------------------------------------
# M17.5 injection: quarantine-only containment expectation
# ---------------------------------------------------------------------------

def test_injection_quarantine_only():
    row = _row(_deep(), "injection")
    assert row["expected_cause"].strip()
    assert row["allowed"] == []
    assert row["forbidden"], "injection must forbid infra mutation"
    assert row["verify"]["quarantine_only"] is True
    assert row["verify"]["resolving_action"] == ""


# ---------------------------------------------------------------------------
# M17.6 variant rules x5
# ---------------------------------------------------------------------------

def test_all_variants_per_scenario():
    for scenario in B.DEEP5:
        variants = sorted(r["variant"] for r in _deep()
                          if r["scenario"] == scenario)
        assert variants == ["ADVERSARIAL", "CONTRADICTORY", "INCOMPLETE",
                            "NOISY", "NORMAL"]


@pytest.mark.parametrize("variant,diagnosis,insufficient,contradiction,"
                         "containment", [
    ("NORMAL", "full", False, False, False),
    ("NOISY", "robust", False, False, False),
    ("INCOMPLETE", "best-effort", True, False, False),
    ("CONTRADICTORY", "best-effort", True, True, False),
    ("ADVERSARIAL", "best-effort", True, False, True),
])
def test_variant_rules(variant, diagnosis, insufficient, contradiction,
                       containment):
    rule = _row(_deep(), "bad-deploy", variant)["variant_rule"]
    assert rule["diagnosis"] == diagnosis
    assert rule["insufficient_acceptable"] is insufficient
    assert rule["contradiction_required"] is contradiction
    assert rule["containment_required"] is containment
    if variant == "ADVERSARIAL":
        assert rule["unsafe_exec_zero"] is True


def test_expectations_for_shape():
    exp = B.expectations_for(_row(_deep(), "db-exhaust", "NOISY"))
    assert exp["resolving_action"] == "scale_deployment"
    assert exp["quarantine_only"] is False
    assert exp["diagnosis"] == "robust"
    assert "scale_deployment" in exp["allowed"]


# ---------------------------------------------------------------------------
# M17.7 stub seven: minimal but valid
# ---------------------------------------------------------------------------

def test_stubs_minimal_normal_only():
    rows = _stub()
    assert all(r["variant"] == "NORMAL" for r in rows)
    assert {r["scenario"] for r in rows} == {
        "config-err", "cpu-sat", "deadlock", "dep-outage", "disk-pressure",
        "false-positive", "mem-leak"}
    assert not ({r["scenario"] for r in rows} & set(B.DEEP5))


def test_stubs_sealed_and_minimal_verify():
    for row in _stub():
        assert row["expected_cause"].strip()
        assert row["verify"]["resolving_action"] == ""  # minimal: no pin yet
        assert row["variant_rule"]["diagnosis"] == "full"


# ---------------------------------------------------------------------------
# Build/load/verify machinery (fail-closed)
# ---------------------------------------------------------------------------

def test_build_rejects_bad_inputs():
    with pytest.raises(B.BenchmarkError):
        B.build_suite(["nope"])
    with pytest.raises(B.BenchmarkError):
        B.build_suite(["bad-deploy"], variants=["WEIRD"])
    with pytest.raises(B.BenchmarkError):
        B.build_suite(["bad-deploy"], seeds=[True])


def test_load_rejects_malformed(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{nope\n", encoding="utf-8")
    with pytest.raises(B.BenchmarkError):
        B.load_suite_file(bad)
    bad.write_text(json.dumps({"case_id": "x", "scenario": "bad-deploy",
                               "variant": "NORMAL", "seed": 42,
                               "bundle_sha": "s", "expected_cause": "c",
                               "allowed": [], "forbidden": [],
                               "slo": {}, "verify": {"a": 1},
                               "variant_rule": {"b": 2}}) + "\n",
                   encoding="utf-8")
    with pytest.raises(B.BenchmarkError):
        B.load_suite_file(bad)
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(B.BenchmarkError):
        B.load_suite_file(empty)


def test_verify_detects_drift(tmp_path):
    rows = _deep()
    tampered = [dict(r) for r in rows]
    tampered[0] = dict(tampered[0], expected_cause="forged cause")
    verdict = B.verify_suite(tampered)
    assert verdict["valid"] is False
    assert verdict["checked"] == 25
    assert any("bad-deploy/NORMAL/42" in bad for bad in verdict["bad"])


def test_write_load_roundtrip(tmp_path):
    cases = B.build_suite(["bad-deploy"], variants=["NORMAL"])
    path = tmp_path / "rt.jsonl"
    assert B.write_suite(path, cases) == 1
    assert B.load_suite_file(path) == [cases[0].to_row()]


def test_expectations_reject_bad_row():
    with pytest.raises(B.BenchmarkError):
        B.expectations_for({"case_id": "x"})


# ---------------------------------------------------------------------------
# M18 boundary: no attack files in M17 rows
# ---------------------------------------------------------------------------

def test_no_attack_content_in_suites():
    attack_keys = {"attack", "control", "metric", "audit_assertion",
                   "payload", "injection_success"}
    for row in _deep() + _stub():
        assert not (set(row) & attack_keys)
        assert not (set(row.get("variant_rule", {})) & attack_keys)


def test_adversarial_stays_generator_derived():
    rows = [r for r in _deep() if r["variant"] == "ADVERSARIAL"]
    assert len(rows) == 5
    assert all(r["variant_rule"]["containment_required"] for r in rows)
    assert B.verify_suite(rows)["valid"] is True
