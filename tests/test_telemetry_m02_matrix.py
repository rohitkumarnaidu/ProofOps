"""M02 telemetry matrix (90+ pass, host-safe UNIT).

Proves the generator contract across the FULL (scenario x variant) matrix —
not one golden combo: determinism (same-process AND cross-process),
per-combo counts/shapes, variant rules, deploy-window, topology edges,
k8s ts-index, metrics pre/post shapes, span-trace integrity.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "telemetry"))

import gen  # noqa: E402

SCENARIOS = sorted(gen.SCENARIOS)
VARIANTS = list(gen.VARIANTS)

ALERT_COUNTS = {"NORMAL": 4, "NOISY": 20, "INCOMPLETE": 2,
                "CONTRADICTORY": 5, "ADVERSARIAL": 5}
LOG_COUNTS = {"NORMAL": 40, "NOISY": 120, "INCOMPLETE": 0,
              "CONTRADICTORY": 45, "ADVERSARIAL": 41}
METRIC_COUNTS = {"NORMAL": 12, "NOISY": 12, "INCOMPLETE": 6,
                 "CONTRADICTORY": 12, "ADVERSARIAL": 12}
DEPLOY_SCENARIOS = {"bad-deploy", "crashloop-oom"}


def _injection_logs(bundle) -> int:
    return sum(gen.INJECTION_PAYLOAD in lg.get("msg", "")
               for lg in bundle["logs"])


class TestDeterminismMatrix:
    @pytest.mark.parametrize("scenario", SCENARIOS)
    @pytest.mark.parametrize("variant", VARIANTS)
    def test_same_inputs_identical_output(self, scenario, variant):  # UNIT
        a = gen.generate(scenario, variant, 7)
        b = gen.generate(scenario, variant, 7)
        assert a == b and a["sha"] == b["sha"]
        assert gen.verify_bundle(a) is True

    @pytest.mark.parametrize("scenario", SCENARIOS)
    @pytest.mark.parametrize("variant", VARIANTS)
    def test_different_seeds_differ(self, scenario, variant):  # UNIT
        # ... in content (sha differs); same SHAPE (counts below pin that).
        assert (gen.generate(scenario, variant, 7)["sha"]
                != gen.generate(scenario, variant, 8)["sha"])

    def test_cross_process_identical(self):  # UNIT
        # PYTHONHASHSEED randomization must not leak in: run twice with
        # different hash seeds, demand identical sealed output.
        probe = ("import sys; sys.path.insert(0, 'telemetry'); import gen;"
                 "print(gen.generate('bad-deploy', 'NOISY', 7)['sha'])")
        shas = set()
        for hashseed in ("0", "12345"):
            env = dict(os.environ, PYTHONHASHSEED=hashseed)
            proc = subprocess.run([sys.executable, "-c", probe],
                                  capture_output=True, text=True, cwd=str(ROOT),
                                  env=env, timeout=60)
            assert proc.returncode == 0, proc.stderr[-500:]
            shas.add(proc.stdout.strip())
        assert len(shas) == 1 and len(next(iter(shas))) == 64

    def test_rejects_unknown_inputs(self):  # UNIT
        with pytest.raises(KeyError):
            gen.generate("nope", "NORMAL", 1)
        with pytest.raises(ValueError):
            gen.generate("bad-deploy", "CHAOS", 1)

    def test_seed_key_identity(self):  # UNIT
        assert gen.seed_key("a", "b", 1) == "proofops:a:b:1"
        assert gen.seed_key("a", "b", 1) != gen.seed_key("a", "b", 2)
        assert gen.seed_key("a", "b", 1) != gen.seed_key("a", "c", 1)
        log = gen.seed_log("bad-deploy", "NOISY", 7)
        assert log["seed_key"] == "proofops:bad-deploy:NOISY:7"
        assert log["base_ts"] == gen.BASE_TS + 7


class TestCountShapeMatrix:
    @pytest.mark.parametrize("scenario", SCENARIOS)
    @pytest.mark.parametrize("variant", VARIANTS)
    def test_per_combo_counts(self, scenario, variant):  # UNIT
        t = gen.generate(scenario, variant, 11)
        assert len(t["alerts"]) == ALERT_COUNTS[variant], (scenario, variant)
        n_logs = LOG_COUNTS[variant]
        if scenario == "injection" and variant != "ADVERSARIAL":
            n_logs += 1  # scenario-level evil log (not variant-level)
        assert len(t["logs"]) == n_logs, (scenario, variant)
        assert len(t["metrics"]) == METRIC_COUNTS[variant], (scenario, variant)

    @pytest.mark.parametrize("scenario", SCENARIOS)
    def test_noisy_junk_never_merges(self, scenario):  # UNIT
        t = gen.generate(scenario, "NOISY", 11)
        junk = [a for a in t["alerts"] if a["service"] == "unrelated-svc"]
        assert len(junk) == 6
        assert {a["signature"] for a in junk} == {"cpu_blip"}

    def test_incomplete_has_no_logs(self):  # UNIT
        t = gen.generate("bad-deploy", "INCOMPLETE", 11)
        assert t["logs"] == [] and len(t["metrics"]) == 6


class TestDeployWindow:
    @pytest.mark.parametrize("scenario", sorted(DEPLOY_SCENARIOS))
    @pytest.mark.parametrize("variant", VARIANTS)
    def test_deploy_inside_15m_window(self, scenario, variant):  # UNIT
        t = gen.generate(scenario, variant, 11)
        assert len(t["deploys"]) == 1
        dts = t["deploys"][0]["ts"]
        first_alert = min(a["ts"] for a in t["alerts"])
        assert abs(first_alert - dts) <= 900, (scenario, variant)
        d = t["deploys"][0]
        assert (d["from_v"], d["to_v"], d["author"]) == tuple(
            gen.SCENARIOS[scenario]["deploy"][k]
            for k in ("from_v", "to_v", "author"))

    @pytest.mark.parametrize(
        "scenario", sorted(set(SCENARIOS) - DEPLOY_SCENARIOS))
    def test_no_deploy_without_story(self, scenario):  # UNIT
        assert gen.generate(scenario, "NORMAL", 11)["deploys"] == []


class TestTopologyEdges:
    def test_edge_derivation(self):  # UNIT
        assert gen.topology_edges(
            {"service": "checkout", "depends_on": ["payments"]}) == \
            [("checkout", "payments")]
        assert gen.topology_edges(
            {"service": "web", "depends_on": []}) == []

    @pytest.mark.parametrize("bad", [
        {}, {"service": "web"}, {"depends_on": []},
        {"service": "", "depends_on": []},
        {"service": "web", "depends_on": "payments"},
        {"service": "web", "depends_on": [""]},
        {"service": "web", "depends_on": [42]},
    ])
    def test_malformed_topology_rejected(self, bad):  # UNIT
        with pytest.raises((ValueError, KeyError)):
            gen.topology_edges(bad)

    def test_matrix_edges_match_story(self):  # UNIT
        for scenario in SCENARIOS:
            edges = gen.topology_edges(
                gen.generate(scenario, "NORMAL", 11)["topology"])
            if scenario == "net-dep-fail":
                assert edges == [("checkout", "payments")]
            else:
                assert edges == []


class TestK8sWindowIndex:
    def test_slice_inclusive_bounds(self):  # UNIT
        evs = gen.generate("crashloop-oom", "NORMAL", 11)["k8s_events"]
        assert len(evs) == 3
        ts = [e["ts"] for e in evs]
        assert ts == sorted(ts)  # ts-ascending emission (indexable)
        assert gen.events_in_window(evs, ts[0], ts[0]) == [evs[0]]
        assert gen.events_in_window(evs, ts[0], ts[-1]) == evs
        assert gen.events_in_window(evs, ts[-1] + 1, ts[-1] + 99) == []

    def test_malformed_ts_rejected(self):  # UNIT
        with pytest.raises(ValueError):
            gen.events_in_window([{"ts": "soon"}], 0, 99)
        with pytest.raises(ValueError):
            gen.events_in_window([{"service": "x"}], 0, 99)
        with pytest.raises(ValueError):
            gen.events_in_window([{"ts": True}], 0, 99)


class TestMetricsPrePostShape:
    def test_baseline_then_spike(self):  # UNIT
        t = gen.generate("bad-deploy", "NORMAL", 7)
        vals = [m["value"] for m in t["metrics"]]
        assert len(vals) == 12
        assert all(v == gen.BASE_ERROR for v in vals[:6])  # pre: baseline
        assert all(abs(v - 0.18) <= 0.005 for v in vals[6:])  # post: spike
        assert max(vals) - min(vals) > 0.1  # predigest delta is meaningful

    def test_incomplete_baseline_missing_still_shaped(self):  # UNIT
        t = gen.generate("bad-deploy", "INCOMPLETE", 7)
        vals = [m["value"] for m in t["metrics"]]
        assert len(vals) == 6 and all(v > 0.1 for v in vals)

    def test_spacing_and_names(self):  # UNIT
        t = gen.generate("bad-deploy", "NORMAL", 7)
        ts = [m["ts"] for m in t["metrics"]]
        assert all(b - a == 60 for a, b in zip(ts, ts[1:]))
        assert {m["name"] for m in t["metrics"]} == {"error_rate"}


class TestSpanTraceIntegrity:
    def test_span_shape(self):  # UNIT
        t = gen.generate("bad-deploy", "NORMAL", 7)
        assert len(t["traces"]) == 3
        for tr in t["traces"]:
            assert set(tr) == {"trace_id", "service", "spans"}
            assert len(tr["spans"]) == 2
            for sp in tr["spans"]:
                assert set(sp) == {"span_id", "service", "operation",
                                   "duration_ms", "status"}
                assert 20 <= sp["duration_ms"] <= 199
                assert sp["status"] == "ok"
                assert sp["service"] == "web"
                assert sp["operation"] == "http_5xx_spike"
            assert len({sp["span_id"] for sp in tr["spans"]}) == 2

    def test_every_log_trace_id_resolves(self):  # UNIT
        for variant in VARIANTS:
            t = gen.generate("bad-deploy", variant, 7)
            ids = {tr["trace_id"] for tr in t["traces"]}
            dangling = {lg["trace_id"] for lg in t["logs"]} - ids
            assert not dangling, (variant, dangling)

    def test_special_traces_first_with_status(self):  # UNIT
        adv = gen.generate("bad-deploy", "ADVERSARIAL", 7)
        assert adv["traces"][0]["trace_id"] == "t-evil"
        assert adv["traces"][0]["spans"][0]["status"] == "error"
        con = gen.generate("bad-deploy", "CONTRADICTORY", 7)
        assert con["traces"][0]["trace_id"] == "t-healthy"
        inj = gen.generate("injection", "NORMAL", 7)
        assert inj["traces"][0]["trace_id"] == "t-evil"

    def test_contradictory_rows_are_distinct_objects(self):  # UNIT
        t = gen.generate("bad-deploy", "CONTRADICTORY", 7)
        greens = [lg for lg in t["logs"]
                  if lg.get("trace_id") == "t-healthy"]
        assert len(greens) == 5
        assert len({id(lg) for lg in greens}) == 5  # no list-aliasing
