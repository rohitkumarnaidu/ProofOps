"""M02/M03/M04 data-plane contracts: generator, normalization, correlation.

Registry verify methods:
- M02: determinism (same-seed->same-sha), seed-log + replay-identical,
  per-source shapes (alerts/logs/metrics/traces/k8s/deploys/topology),
  telemetry hashing (sha-log completeness).
- M03: malformed-input + missing-field rejects; log DATA-not-instructions;
  metrics window/delta shape; trace ref integrity; deployment diff shape;
  canonical telemetry model join.
- M04: fingerprint stability; grouping; dedup <=5s; P1-P4 rules;
  dependency merge (edge+10m+sim>0.7); split/merge edge cases.

Existing tests/test_dataplane.py pins legacy behavior (counts, severities);
this file proves the rewired canonical layer. Both stay green.
"""
from __future__ import annotations

import ast
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "telemetry"))

import gen  # noqa: E402
from app.contracts.alert import Alert  # noqa: E402
from app.contracts.enums import Severity  # noqa: E402
from app.contracts.incident import Incident  # noqa: E402
from app.services.correlator import (  # noqa: E402
    DEDUP_WINDOW_S,
    DEPLOY_WINDOW_S,
    correlate,
    deduplicate,
    fingerprint,
)
from app.services.normalizer import (  # noqa: E402
    alert_hash,
    normalize_alert,
    normalize_deployment,
    normalize_k8s_event,
    normalize_log,
    normalize_metric,
    normalize_telemetry,
    normalize_trace,
)


def raw_alert(**over) -> dict:
    base = dict(alert_id="al-1", ts=1700000042, service="web",
                environment="prod", severity_raw="critical",
                signature="http_5xx_spike", labels={"team": "sre"})
    base.update(over)
    return base


# ------------------------------------------------------- M02 generator
class TestGenerator:
    def test_seed_log_replay_identical(self):  # UNIT (M02.2)
        log = gen.seed_log("bad-deploy", "NORMAL", 7)
        assert log["seed_key"] == "proofops:bad-deploy:NORMAL:7"
        assert log["base_ts"] == gen.BASE_TS + 7
        a = gen.generate("bad-deploy", "NORMAL", 7)
        b = gen.generate("bad-deploy", "NORMAL", 7)
        assert a == b and a["sha"] == b["sha"]  # replay identical

    def test_seed_log_rejects_unknown(self):  # UNIT
        with pytest.raises(KeyError):
            gen.seed_log("nope", "NORMAL", 1)
        with pytest.raises(ValueError):
            gen.seed_log("bad-deploy", "WEIRD", 1)

    def test_verify_bundle(self):  # UNIT (M02.10 sha-log)
        bundle = gen.generate("bad-deploy", "NORMAL", 7)
        assert gen.verify_bundle(bundle) is True
        tampered = dict(bundle, expected_cause="something else")
        assert gen.verify_bundle(tampered) is False
        assert gen.verify_bundle({}) is False

    def test_bundle_hash_stable(self):  # UNIT
        a = gen.generate("crashloop-oom", "NOISY", 5)
        assert gen.bundle_hash(a) == a["sha"]
        assert len(a["sha"]) == 64

    def test_k8s_events_shape(self):  # UNIT (M02.7)
        crash = gen.generate("crashloop-oom", "NORMAL", 3)
        assert len(crash["k8s_events"]) == 3
        for ev in crash["k8s_events"]:
            assert set(ev) == {"ts", "service", "kind", "reason", "pod",
                               "count"}
            assert ev["reason"] == "OOMKilling" and ev["count"] >= 1
        deploy = gen.generate("bad-deploy", "NORMAL", 3)
        assert deploy["k8s_events"] and deploy["k8s_events"][0]["kind"] == \
            "Deployment"
        # honest absence: no fault observed, no events fabricated
        assert gen.generate("db-exhaust", "NORMAL", 3)["k8s_events"] == []
        # deterministic across replays
        assert (gen.generate("crashloop-oom", "NORMAL", 3)["k8s_events"]
                == crash["k8s_events"])

    def test_source_shapes(self):  # UNIT (M02.3-M02.6, M02.8-M02.9)
        t = gen.generate("bad-deploy", "NORMAL", 3)
        assert all(set(a) >= {"alert_id", "ts", "service", "environment",
                              "severity_raw", "signature", "labels"}
                   for a in t["alerts"])
        assert all(set(entry) >= {"ts", "service", "msg", "trace_id"}
                   for entry in t["logs"])
        assert all(isinstance(m["value"], float) for m in t["metrics"])
        assert all("trace_id" in tr for tr in t["traces"])
        assert t["deploys"][0]["from_v"] == "v22"
        assert t["deploys"][0]["to_v"] == "v23"
        assert t["topology"] == {"service": "web", "depends_on": []}
        net = gen.generate("net-dep-fail", "NORMAL", 3)
        assert net["topology"]["depends_on"] == ["payments"]


# ------------------------------------------------------- M03 normalization
class TestNormalizeAlert:
    def test_valid_maps_to_canonical(self):  # UNIT (M03.1)
        a = normalize_alert(raw_alert())
        assert isinstance(a, Alert)
        assert a.service == "web" and a.severity is Severity.P1
        assert a.metadata["signature"] == "http_5xx_spike"
        assert a.metadata["severity_raw"] == "critical"
        assert a.status == "firing" and a.source == "unknown"
        assert len(a.fingerprint) == 64
        assert a.timestamp == datetime.fromtimestamp(1700000042,
                                                     tz=timezone.utc)

    def test_gen_alerts_all_normalize(self):  # UNIT
        for sc in gen.SCENARIOS:
            for alert in gen.generate(sc, "NORMAL", 11)["alerts"]:
                normalize_alert(alert)  # must not raise

    def test_missing_alert_id_autogenerated(self):  # UNIT
        raw = raw_alert()
        del raw["alert_id"]
        assert len(normalize_alert(raw).alert_id) == 32

    def test_ts_shapes(self):  # UNIT
        assert normalize_alert(raw_alert(ts=None)).timestamp is not None
        iso = normalize_alert(raw_alert(ts="2026-09-15T10:00:00+00:00"))
        assert iso.timestamp.year == 2026
        dt = datetime(2026, 9, 15, 10, 0, tzinfo=timezone.utc)
        assert normalize_alert(raw_alert(ts=dt)).timestamp == dt

    @pytest.mark.parametrize("field,value", [
        ("severity_raw", "mild"), ("severity_raw", ""),
        ("environment", "production"), ("environment", ""),
        ("signature", ""), ("signature", "   "),
        ("labels", "team=sre"), ("labels", ["x"]),
        ("ts", "yesterday"), ("ts", -5), ("ts", True),
        ("ts", datetime(2026, 9, 15, 10, 0)),  # naive rejected
        ("status", "HEALED"),
        ("source", "  "),
    ])
    def test_malformed_rejected(self, field, value):  # UNIT (M03.1)
        with pytest.raises((ValidationError, ValueError)):
            normalize_alert(raw_alert(**{field: value}))

    def test_non_object_rejected(self):  # UNIT
        for bad in (None, "alert!", [("a", 1)], 42):
            with pytest.raises(ValueError):
                normalize_alert(bad)

    def test_hash_stable_out_of_model(self):  # UNIT
        a = normalize_alert(raw_alert())
        assert alert_hash(a) == alert_hash(normalize_alert(raw_alert()))
        assert len(alert_hash(a)) == 64


class TestNormalizeLogMetricTraceDeploy:
    def test_log_data_not_instructions(self):  # SECURITY (M03.2)
        rec = normalize_log({"ts": 1, "service": "web", "msg":
                             f"note: {gen.INJECTION_PAYLOAD}"})
        assert gen.INJECTION_PAYLOAD in rec["msg"]  # verbatim, inert
        assert len(rec["hash"]) == 64

    def test_log_truncation_and_shape(self):  # UNIT
        rec = normalize_log({"msg": "x" * 5000})
        assert len(rec["msg"]) == 2000 and rec["service"] == "unknown"
        with pytest.raises(ValueError):
            normalize_log("not an object")

    def test_metric_shape(self):  # UNIT (M03.3 window/delta shape)
        m = normalize_metric({"ts": 100, "service": "web",
                              "name": "error_rate", "value": 0.18})
        assert m["value"] == 0.18 and len(m["hash"]) == 64
        for bad in ({"service": "w", "name": "n"},  # missing ts/value
                    {"ts": 1, "name": "n", "value": float("nan")},
                    {"ts": 1, "name": "n", "value": True},
                    {"ts": 1, "name": "", "value": 0.1},
                    {"ts": "soon", "name": "n", "value": 0.1}):
            with pytest.raises(ValueError):
                normalize_metric(bad)

    def test_trace_ref_integrity(self):  # UNIT (M03.4)
        t = normalize_trace({"trace_id": "t-7-3", "service": "web"})
        assert t["trace_id"] == "t-7-3"  # verbatim join key
        with pytest.raises(ValueError):
            normalize_trace({"service": "web"})  # no trace_id, no record

    def test_deployment_diff_shape(self):  # UNIT (M03.5)
        d = normalize_deployment({"deploy_id": "dep-1", "ts": 99,
                                  "service": "web", "from_v": "v22",
                                  "to_v": "v23", "author": "ci-bot"})
        assert (d["from_v"], d["to_v"], d["author"]) == ("v22", "v23",
                                                        "ci-bot")
        with pytest.raises(ValueError):
            normalize_deployment({"ts": 1})  # no service, no record

    def test_k8s_event_shape(self):  # UNIT
        e = normalize_k8s_event({"ts": 5, "service": "worker",
                                 "kind": "Pod", "reason": "OOMKilling",
                                 "pod": "worker-2", "count": 3})
        assert e["count"] == 3
        with pytest.raises(ValueError):
            normalize_k8s_event({"service": "worker"})


class TestCanonicalModel:
    def test_full_bundle_join(self):  # UNIT (M03.6)
        t = gen.generate("bad-deploy", "NORMAL", 3)
        model = normalize_telemetry(t)
        assert len(model["alerts"]) == 4 and len(model["logs"]) == 40
        assert len(model["metrics"]) == 12 and len(model["traces"]) == 3
        assert len(model["deployments"]) == 1
        assert model["topology"] == {"service": "web", "depends_on": []}
        assert model["by_service"]["web"]["alerts"] == 4
        assert all(isinstance(a, Alert) for a in model["alerts"])

    def test_empty_bundle_no_crash(self):  # UNIT
        model = normalize_telemetry({})
        assert model["alerts"] == [] and model["by_service"] == {}

    def test_malformed_bundle_fails_closed(self):  # SECURITY
        with pytest.raises(ValueError):
            normalize_telemetry("bundle?")
        bad = dict(gen.generate("bad-deploy", "NORMAL", 3))
        bad["alerts"] = [{"severity_raw": "mild"}]
        with pytest.raises((ValidationError, ValueError)):
            normalize_telemetry(bad)  # no silent source drop
        bad2 = {"topology": {"depends_on": "payments"}}
        with pytest.raises(ValueError):
            normalize_telemetry(bad2)


# ------------------------------------------------------- M04 correlation
class TestFingerprint:
    def test_stable_16_hex(self):  # UNIT (M04.1)
        fp = fingerprint("web", "http_5xx_spike", "prod", "dep-7")
        assert len(fp) == 16 and all(c in "0123456789abcdef" for c in fp)
        assert fp == fingerprint("web", "http_5xx_spike", "prod", "dep-7")

    def test_binds_all_parts(self):  # UNIT
        base = fingerprint("web", "sig", "prod", "dep")
        assert fingerprint("api", "sig", "prod", "dep") != base
        assert fingerprint("web", "other", "prod", "dep") != base
        assert fingerprint("web", "sig", "mock", "dep") != base
        assert fingerprint("web", "sig", "prod", "none") != base

    def test_deploy_window_binds(self):  # UNIT (±15m)
        assert DEPLOY_WINDOW_S == 900


class TestDedup:
    def _alert(self, aid: str, ts: int) -> Alert:
        return normalize_alert(raw_alert(alert_id=aid, ts=ts))

    def test_exact_id_dupes_suppressed(self):  # UNIT (M04.3)
        unique, suppressed = deduplicate(
            [self._alert("a", 100), self._alert("a", 100)])
        assert len(unique) == 1 and suppressed == 1

    def test_near_dupes_within_5s_suppressed(self):  # UNIT
        unique, suppressed = deduplicate(
            [self._alert("a1", 100), self._alert("a2", 100 + DEDUP_WINDOW_S)])
        assert len(unique) == 1 and suppressed == 1

    def test_beyond_window_kept(self):  # UNIT
        unique, suppressed = deduplicate(
            [self._alert("a1", 100), self._alert("a2", 100 + DEDUP_WINDOW_S + 1)])
        assert len(unique) == 2 and suppressed == 0

    def test_order_preserved(self):  # UNIT
        alerts = [self._alert(f"a{i}", 100 + i * 10) for i in range(4)]
        unique, _ = deduplicate(alerts)
        assert [a.alert_id for a in unique] == [f"a{i}" for i in range(4)]


class TestCorrelate:
    def test_incident_linkage_populated(self):  # UNIT
        t = gen.generate("bad-deploy", "NORMAL", 3)
        (inc,) = correlate(t["alerts"], t["deploys"], t["metrics"],
                           t["topology"])
        assert isinstance(inc, Incident) and inc.status == "CORRELATED"
        assert inc.service == "web" and str(inc.environment) == "prod"
        assert len(inc.source_alert_ids) == 4
        assert inc.detected_at is not None and inc.detected_at.tzinfo is not None
        assert inc.metadata["alert_count"] == 4
        assert len(inc.fingerprint) == 16

    def test_accepts_canonical_alerts(self):  # UNIT
        t = gen.generate("bad-deploy", "NORMAL", 3)
        alerts = [normalize_alert(a) for a in t["alerts"]]
        inc = correlate(alerts, t["deploys"], t["metrics"], t["topology"])
        assert len(inc) == 1 and inc[0].severity == "P1"

    def test_staging_degraded_is_p3(self):  # UNIT (M04.4 P1-P4)
        alerts = [raw_alert(alert_id="s1", ts=100, service="web",
                            environment="staging", severity_raw="warning",
                            signature="cpu_saturation")]
        (inc,) = correlate(alerts)
        assert inc.severity == "P3"

    def test_prod_degraded_is_p2(self):  # UNIT
        alerts = [raw_alert(alert_id="p1", ts=100, service="web",
                            environment="prod", severity_raw="warning",
                            signature="mild_latency")]
        (inc,) = correlate(alerts, metrics=[{"value": 0.01}])
        assert inc.severity == "P2"

    def test_dependency_merge(self):  # UNIT (M04.5 edge+10m+sim>0.7)
        topo = {"service": "checkout", "depends_on": ["payments"]}
        pair = [
            raw_alert(alert_id="c1", ts=1000, service="checkout",
                      environment="prod", severity_raw="critical",
                      signature="dependency_timeout"),
            raw_alert(alert_id="p1", ts=1030, service="payments",
                      environment="prod", severity_raw="critical",
                      signature="dependency_timeout"),
        ]
        assert len(correlate(pair, topology=topo)) == 1

    def test_dissimilar_no_merge(self):  # UNIT
        topo = {"service": "checkout", "depends_on": ["payments"]}
        pair = [
            raw_alert(alert_id="c1", ts=1000, service="checkout",
                      environment="prod", severity_raw="critical",
                      signature="dependency_timeout_payments"),
            raw_alert(alert_id="p1", ts=1030, service="payments",
                      environment="prod", severity_raw="critical",
                      signature="cpu_saturation_unrelated"),
        ]
        assert len(correlate(pair, topology=topo)) == 2

    def test_split_unrelated_services(self):  # UNIT (M04.6 split)
        assert len(correlate([
            raw_alert(alert_id="a1", ts=100, service="web",
                      signature="http_5xx_spike"),
            raw_alert(alert_id="a2", ts=110, service="search",
                      signature="upstream_5xx"),
        ])) == 2

    def test_merge_same_fingerprint(self):  # UNIT (M04.6 merge)
        assert len(correlate([
            raw_alert(alert_id="a1", ts=100, signature="http_5xx_spike"),
            raw_alert(alert_id="a2", ts=120, signature="http_5xx_spike"),
        ])) == 1

    def test_empty_is_empty(self):  # UNIT
        assert correlate([]) == []

    def test_malformed_fails_closed(self):  # SECURITY
        with pytest.raises((ValidationError, ValueError)):
            correlate([{"severity_raw": "mild"}])
        with pytest.raises(ValueError):
            correlate("not a list")  # type: ignore
        with pytest.raises(ValueError):
            correlate([42])  # type: ignore

    def test_injection_flows_through_inert(self):  # SECURITY
        t = gen.generate("bad-deploy", "ADVERSARIAL", 3)
        inc = correlate(t["alerts"], t["deploys"], t["metrics"],
                        t["topology"])
        assert inc  # grouped as DATA; payload never executed anywhere
        model = normalize_telemetry(t)
        assert any(gen.INJECTION_PAYLOAD in entry["msg"]
                   for entry in model["logs"])


# ------------------------------------------------------- integrity
class TestIntegrity:
    def test_no_bypass_apis_in_services(self):  # UNIT
        for path in (ROOT / "backend" / "app" / "services" / name
                     for name in ("normalizer.py", "correlator.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in (
                        "model_construct", "__setattr__"):
                    if isinstance(node.value, ast.Name) and \
                            node.value.id == "object":
                        pytest.fail(f"bypass in {path.name}:{node.lineno}")
                    if node.attr == "model_construct":
                        pytest.fail(f"bypass in {path.name}:{node.lineno}")

    def test_no_enum_definitions_in_services(self):  # UNIT
        for path in (ROOT / "backend" / "app" / "services" / name
                     for name in ("normalizer.py", "correlator.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    bases = {getattr(b, "id", None) or
                             getattr(b, "attr", None) for b in node.bases}
                    assert bases & {"Enum", "StrEnum"} == set(), node.name

    def test_no_unvalidated_incident_construction(self):  # UNIT
        # correlator must only build Incidents via validated construction.
        tree = ast.parse((ROOT / "backend" / "app" / "services"
                          / "correlator.py").read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call)
                 and getattr(node.func, "id", "") == "Incident"]
        assert calls, "correlator must construct canonical Incidents"

    def test_gen_stays_stdlib_only(self):  # UNIT
        tree = ast.parse((ROOT / "telemetry" / "gen.py").read_text(
            encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                assert {a.name.split(".")[0] for a in node.names} <= {
                    "hashlib", "json", "random", "sys", "typing"}, node.names
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] in (
                    "__future__", "typing"), node.module
