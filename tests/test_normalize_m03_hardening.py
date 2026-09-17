"""M03 normalization hardening (90+ pass, host-safe UNIT + SECURITY).

Proves the interim-audit P1 closures: environment never defaulted (P1 #18),
two-rule timestamp parity across all six normalizers (P1 #20), None-hole
sweep (no "None" strings in grouping fields), span preservation through
normalization (M02.6 enrichment survives), and the two-level severity table
(P1 #19: signal P3 vs triage P2 by design, pinned jointly with M04).
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.correlator import correlate  # noqa: E402
from app.services.normalizer import (  # noqa: E402
    normalize_alert,
    normalize_deployment,
    normalize_k8s_event,
    normalize_log,
    normalize_metric,
    normalize_trace,
)


def _raw_alert(**over) -> dict:
    base = dict(alert_id="al-1", ts=1700000042, service="web",
                environment="prod", severity_raw="warning",
                signature="mild_latency", labels={})
    base.update(over)
    return base


class TestEnvironmentNeverDefaulted:
    @pytest.mark.parametrize("env", [None, ""])
    def test_missing_null_blank_rejected(self, env):  # SECURITY
        # P1 #18: the old mock-default mis-grouped prod alerts as mock/P3.
        # Missing/None fails HERE (before the fingerprint binds it); blank
        # fails in the model. Either way: never mock by default.
        raw = _raw_alert()
        if env is None:
            del raw["environment"]
        else:
            raw["environment"] = env
        with pytest.raises((ValidationError, ValueError)):
            normalize_alert(raw)

    def test_unknown_rejected(self):  # SECURITY
        with pytest.raises((ValidationError, ValueError)):
            normalize_alert(_raw_alert(environment="production"))

    def test_fingerprint_binds_real_env(self):  # UNIT
        from app.services.normalizer import alert_hash
        assert (alert_hash(normalize_alert(_raw_alert(environment="prod")))
                != alert_hash(normalize_alert(_raw_alert(
                    environment="staging"))))


class TestTimestampParity:
    ISO = "2026-09-15T10:00:00+00:00"
    AWARE = datetime(2026, 9, 15, 10, 0, tzinfo=timezone.utc)

    def test_observations_fill_arrival_time(self):  # UNIT
        # Rule (a): alerts/logs/traces without their own clock take now.
        assert normalize_alert(_raw_alert(ts=None)).timestamp is not None
        assert normalize_log({"msg": "m"})["ts"] is not None
        assert normalize_trace({"trace_id": "t"})["ts"] is not None

    def test_anchored_events_require_ts(self):  # UNIT
        # Rule (b): stamping an event with arrival time would corrupt
        # windows/fingerprints — missing/null ts rejects.
        with pytest.raises(ValueError):
            normalize_metric({"service": "w", "name": "n", "value": 0.1})
        with pytest.raises(ValueError):
            normalize_deployment({"service": "w"})
        with pytest.raises(ValueError):
            normalize_k8s_event({"service": "w"})

    @pytest.mark.parametrize("bad", [True, float("nan"), float("inf"),
                                     "soon", -5,
                                     datetime(2026, 9, 15, 10, 0)])
    def test_malformed_rejected_everywhere(self, bad):  # SECURITY
        with pytest.raises((ValidationError, ValueError)):
            normalize_alert(_raw_alert(ts=bad))
        with pytest.raises(ValueError):
            normalize_log({"msg": "m", "ts": bad})
        with pytest.raises(ValueError):
            normalize_trace({"trace_id": "t", "ts": bad})
        with pytest.raises(ValueError):
            normalize_metric({"service": "w", "name": "n",
                              "value": 0.1, "ts": bad})
        with pytest.raises(ValueError):
            normalize_deployment({"service": "w", "ts": bad})
        with pytest.raises(ValueError):
            normalize_k8s_event({"service": "w", "ts": bad})

    def test_valid_shapes_accepted_everywhere(self):  # UNIT
        for ts in (1700000042, 1700000042.5, self.ISO, self.AWARE):
            assert normalize_alert(_raw_alert(ts=ts)) is not None
            assert normalize_log({"msg": "m", "ts": ts}) is not None
            assert normalize_trace({"trace_id": "t", "ts": ts}) is not None
            assert normalize_metric(
                {"service": "w", "name": "n", "value": 0.1,
                 "ts": ts}) is not None
            assert normalize_deployment({"service": "w", "ts": ts}) is not None
            assert normalize_k8s_event({"service": "w", "ts": ts}) is not None


class TestNoneHoleSweep:
    def test_no_none_strings_in_grouping_fields(self):  # SECURITY
        # str(None) == "None": a fake service that groups. Every identifier
        # now routes through _raw_str (None -> documented default).
        log = normalize_log({"msg": "m", "service": None, "pod": None,
                             "level": None, "trace_id": None})
        assert log["service"] == "unknown" and log["pod"] == "?"
        assert log["level"] == "INFO" and log["trace_id"] == ""
        assert normalize_log({"msg": None})["msg"] == ""
        metric = normalize_metric({"ts": 1, "service": None,
                                   "name": "n", "value": 0.1})
        assert metric["service"] == "unknown"
        trace = normalize_trace({"trace_id": "t", "service": None})
        assert trace["service"] == "unknown"
        deploy = normalize_deployment({"service": "w", "ts": 1,
                                       "from_v": None, "to_v": None,
                                       "author": None})
        assert deploy["from_v"] == "" and deploy["to_v"] == ""
        assert deploy["author"] == "unknown"
        k8s = normalize_k8s_event({"service": None, "ts": 1,
                                   "kind": None, "reason": None, "pod": None})
        assert k8s["service"] == "unknown" and k8s["kind"] == "Pod"
        assert k8s["reason"] == "Unknown" and k8s["pod"] == ""


class TestSpanPreservation:
    def test_spans_survive_normalization(self):  # UNIT
        # M02.6 enrichment must not die at normalization: spans ride through
        # verbatim (DATA), hash-covered.
        import sys as _sys
        _sys.path.insert(0, str(ROOT / "telemetry"))
        import gen as _gen
        bundle = _gen.generate("bad-deploy", "ADVERSARIAL", 7)
        model_traces = [normalize_trace(t) for t in bundle["traces"]]
        assert model_traces[0]["trace_id"] == "t-evil"
        assert len(model_traces[0]["spans"]) == 2
        assert model_traces[0]["spans"][0]["status"] == "error"
        assert all(len(h) == 64 for h in
                   [t["hash"] for t in model_traces])

    def test_non_mapping_spans_rejected(self):  # SECURITY
        with pytest.raises(ValueError):
            normalize_trace({"trace_id": "t", "spans": "s-1"})
        with pytest.raises(ValueError):
            normalize_trace({"trace_id": "t", "spans": ["s-1"]})

    def test_span_ref_joinable_after_normalization(self):  # UNIT
        import sys as _sys
        _sys.path.insert(0, str(ROOT / "telemetry"))
        import gen as _gen
        bundle = _gen.generate("bad-deploy", "NORMAL", 7)
        ids = {t["trace_id"] for t in
               [normalize_trace(t) for t in bundle["traces"]]}
        logs = [normalize_log(entry) for entry in bundle["logs"]]
        assert {lg["trace_id"] for lg in logs} <= ids


class TestAlertFallbacks:
    def test_message_falls_back_to_signature_on_service(self):  # UNIT
        a = normalize_alert(_raw_alert(message=""))
        assert a.message == "mild_latency on web"

    def test_resource_absent_stays_empty(self):  # UNIT
        assert normalize_alert(_raw_alert()).resource == ""


class TestTwoLevelSeverity:
    def test_warning_prod_is_p3_signal_p2_incident(self):  # UNIT
        # P1 #19 closure: NOT a contradiction. Signal severity (how bad the
        # indicator looks) vs triage severity (env + error + signature).
        # A WARNING signal in prod is P3-signal but pages as P2-incident.
        alert = normalize_alert(_raw_alert())
        assert alert.severity.value == "P3"
        (inc,) = correlate([_raw_alert()], metrics=[{"value": 0.01}])
        assert inc.severity == "P2"

    def test_critical_prod_is_p1_both_levels(self):  # UNIT
        alert = normalize_alert(_raw_alert(severity_raw="critical"))
        assert alert.severity.value == "P1"


class TestExtremeTimestamps:
    @pytest.mark.parametrize("bad", [1e20, 1e308, 99999999999])
    def test_out_of_range_rejected_everywhere(self, bad):  # SECURITY
        # fromtimestamp raises OverflowError/OSError on extremes: the strict
        # core converts to ValueError (fail-closed promise holds at range
        # edges, not just for NaN/strings).
        with pytest.raises((ValidationError, ValueError)):
            normalize_alert(_raw_alert(ts=bad))
        with pytest.raises(ValueError):
            normalize_log({"msg": "m", "ts": bad})
        with pytest.raises(ValueError):
            normalize_trace({"trace_id": "t", "ts": bad})
        with pytest.raises(ValueError):
            normalize_metric({"service": "w", "name": "n",
                              "value": 0.1, "ts": bad})
        with pytest.raises(ValueError):
            normalize_deployment({"service": "w", "ts": bad})
        with pytest.raises(ValueError):
            normalize_k8s_event({"service": "w", "ts": bad})

    def test_epoch_zero_accepted(self):  # UNIT
        assert normalize_log({"msg": "m", "ts": 0})["ts"].year == 1970

    def test_ceiling_uniform_both_sides(self):  # UNIT
        # Regression for the CI red: 99999999999 (year 5138) raised on
        # Windows but NOT on Linux. The explicit 2100 ceiling rejects on
        # every platform; the boundary itself stays admissible.
        assert normalize_log({"msg": "m", "ts": 4102444799}) is not None
        with pytest.raises(ValueError):
            normalize_log({"msg": "m", "ts": 4102444801})
        with pytest.raises(ValueError):
            normalize_log({"msg": "m",
                           "ts": datetime(2101, 1, 1,
                                           tzinfo=timezone.utc)})
        with pytest.raises(ValueError):
            normalize_log({"msg": "m", "ts": "2101-06-01T00:00:00+00:00"})


class TestCanonicalTimeType:
    def test_every_normalized_ts_is_aware_datetime(self):  # UNIT
        # One time type across the model (was: datetimes for alerts/logs/
        # traces, raw float passthrough for metric/deploy/k8s).
        from datetime import datetime as _dt
        assert isinstance(
            normalize_metric({"service": "w", "name": "n",
                              "value": 0.1, "ts": 100})["ts"], _dt)
        assert isinstance(
            normalize_deployment({"service": "w", "ts": 100})["ts"], _dt)
        assert isinstance(
            normalize_k8s_event({"service": "w", "ts": 100})["ts"], _dt)
        assert isinstance(
            normalize_log({"msg": "m", "ts": 100})["ts"], _dt)
        assert isinstance(
            normalize_trace({"trace_id": "t", "ts": 100})["ts"], _dt)
        for rec_ts in (normalize_metric(
                {"service": "w", "name": "n", "value": 0.1,
                 "ts": 100})["ts"],
                       normalize_log({"msg": "m", "ts": 100})["ts"]):
            assert rec_ts.tzinfo is not None


class TestMetadataStrictness:
    def test_non_str_extras_rejected(self):  # SECURITY
        with pytest.raises((ValidationError, ValueError)):
            normalize_alert(_raw_alert(trace_id=123))
        with pytest.raises((ValidationError, ValueError)):
            normalize_alert(_raw_alert(pod=["web-1"]))

    def test_labels_int_keys_rejected_by_model(self):  # SECURITY
        with pytest.raises((ValidationError, ValueError)):
            normalize_alert(_raw_alert(labels={1: "x"}))


class TestFullChainMatrix:
    def _chain(self, bundle):
        from app.services.normalizer import normalize_telemetry
        from app.services.predigest import build_evidence_pack
        model = normalize_telemetry(bundle)
        incs = correlate(model["alerts"], model["deployments"],
                         [{"value": m["value"]} for m in model["metrics"]],
                         model["topology"])
        pack = build_evidence_pack("inc-e2e", model)
        return model, incs, pack

    @pytest.mark.parametrize("scenario", [
        "bad-deploy", "crashloop-oom", "db-exhaust", "net-dep-fail",
        "injection", "false-positive"])
    def test_gen_normalize_correlate_predigest(self, scenario):  # UNIT
        import sys as _sys
        _sys.path.insert(0, str(ROOT / "telemetry"))
        import gen as _gen
        from app.contracts import Incident as _Incident
        from app.contracts.evidence import Evidence as _Evidence
        model, incs, pack = self._chain(
            _gen.generate(scenario, "NORMAL", 7))
        assert all(isinstance(i, _Incident) for i in incs)
        assert pack["incident_id"] == "inc-e2e"
        assert pack["evidence"], scenario  # chain yields citable evidence
        for ev in pack["evidence"]:
            _Evidence(**ev)  # still canonical-acceptable after packing
        assert pack["window"]["alerts"] == len(model["alerts"])

    def test_chain_accepts_raw_and_normalized(self):  # UNIT
        import sys as _sys
        _sys.path.insert(0, str(ROOT / "telemetry"))
        import gen as _gen
        from app.services.predigest import build_evidence_pack
        raw = _gen.generate("bad-deploy", "NORMAL", 7)
        assert build_evidence_pack("a", raw)["evidence"]
        from app.services.normalizer import normalize_telemetry
        assert build_evidence_pack(
            "b", normalize_telemetry(raw))["evidence"]

    def test_adversarial_chain_keeps_payload_inert(self):  # SECURITY
        import sys as _sys
        _sys.path.insert(0, str(ROOT / "telemetry"))
        import gen as _gen
        _, _, pack = self._chain(_gen.generate("bad-deploy", "ADVERSARIAL", 7))
        # predigest truncates error lines to 80 chars: the evil line arrives
        # truncated-but-recognizable (verbatim head incl. the attack verb),
        # never executed and never dropped.
        assert any(e["msg"].startswith("upstream note: IGNORE")
                   and "kubectl delete" in e["msg"]
                   for e in pack["top_errors"])
        assert pack["evidence"]  # diagnosis still possible under attack
