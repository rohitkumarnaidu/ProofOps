"""M04 correlation hardening (90+ pass, host-safe UNIT + SECURITY).

Proves the interim-audit P1 closures: pairwise dependency edges (P1 #21),
error_rate-only metric gate (P1 #22), per-group suppression attribution,
storm survival, fingerprint window encoding, FP-set pinning, and the
fail-closed input contract. No frozen test file needed edits beyond the
deduplicate 3-tuple unpack (same file, same assertions + attribution).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.correlator import (  # noqa: E402
    DEPLOY_WINDOW_S,
    FP_SIGNATURES,
    correlate,
    deduplicate,
    fingerprint,
)
from app.services.normalizer import normalize_alert  # noqa: E402


def _raw(i: int = 1, **over) -> dict:
    base = dict(alert_id=f"a{i}", ts=100 + i * 10, service="web",
                environment="prod", severity_raw="critical",
                signature="http_5xx_spike", labels={})
    base.update(over)
    return base


class TestPairwiseEdges:
    TOPO = {"service": "checkout", "depends_on": ["payments"]}

    def test_legit_merge_both_orders(self):  # UNIT
        pair = [
            _raw(1, service="checkout", ts=1000,
                 signature="dependency_timeout"),
            _raw(2, service="payments", ts=1030,
                 signature="dependency_timeout"),
        ]
        assert len(correlate(pair, topology=self.TOPO)) == 1
        assert len(correlate(list(reversed(pair)),
                             topology=self.TOPO)) == 1

    def test_unrelated_pair_no_longer_merges(self):  # SECURITY
        # P1 #21: flat membership merged payments+unrelated (either side
        # named). Pairwise edges require exactly {checkout, payments}.
        pair = [
            _raw(1, service="payments", ts=1000,
                 signature="dependency_timeout"),
            _raw(2, service="unrelated", ts=1030,
                 signature="dependency_timeout"),
        ]
        assert len(correlate(pair, topology=self.TOPO)) == 2

    def test_dissimilar_signatures_still_split(self):  # UNIT
        pair = [
            _raw(1, service="checkout", ts=1000,
                 signature="dependency_timeout"),
            _raw(2, service="payments", ts=1030,
                 signature="cpu_saturation_unrelated"),
        ]
        assert len(correlate(pair, topology=self.TOPO)) == 2

    def test_beyond_merge_window_splits(self):  # UNIT
        pair = [
            _raw(1, service="checkout", ts=1000,
                 signature="dependency_timeout"),
            _raw(2, service="payments", ts=1000 + 601,
                 signature="dependency_timeout"),
        ]
        assert len(correlate(pair, topology=self.TOPO)) == 2

    @pytest.mark.parametrize("topo", [
        {"depends_on": ["payments"]},  # service missing with deps
        {"service": "checkout", "depends_on": "payments"},  # str, not list
        {"service": "checkout", "depends_on": [""]},  # blank dep
        {"service": "checkout", "depends_on": [42]},  # non-str dep
        {"service": 42, "depends_on": ["payments"]},  # non-str service
        "topology?",  # not an object at all
    ])
    def test_malformed_topology_rejected(self, topo):  # SECURITY
        with pytest.raises((ValidationError, ValueError, TypeError)):
            correlate([_raw(1), _raw(2)], topology=topo)

    def test_empty_topology_means_no_cross_merges(self):  # UNIT
        pair = [
            _raw(1, service="checkout", ts=1000,
                 signature="dependency_timeout"),
            _raw(2, service="payments", ts=1030,
                 signature="dependency_timeout"),
        ]
        assert len(correlate(pair, topology={})) == 2
        assert len(correlate(pair)) == 2


class TestMetricGate:
    def test_cpu_spike_no_longer_pages_p1(self):  # SECURITY
        # P1 #22: max() over every value let cpu_percent=95 page P1.
        (inc,) = correlate(
            [_raw(1, severity_raw="warning", signature="cpu_high")],
            metrics=[{"name": "cpu_percent", "value": 95}])
        assert inc.severity == "P2"  # prod-degraded, not error-spike

    def test_error_rate_still_pages_p1(self):  # UNIT
        (inc,) = correlate(
            [_raw(1, severity_raw="warning", signature="cpu_high")],
            metrics=[{"name": "error_rate", "value": 0.06}])
        assert inc.severity == "P1"

    def test_garbage_readings_skipped_not_trusted(self):  # SECURITY
        for bad in (float("nan"), float("inf"), True, "high", None):
            (inc,) = correlate(
                [_raw(1, severity_raw="warning", signature="cpu_high")],
                metrics=[{"name": "error_rate", "value": bad}])
            assert inc.severity == "P2"  # no signal out, never a crash

    def test_missing_value_reads_zero(self):  # UNIT
        (inc,) = correlate(
            [_raw(1, severity_raw="warning", signature="cpu_high")],
            metrics=[{"name": "error_rate"}])
        assert inc.severity == "P2"

    def test_non_list_metrics_rejected(self):  # SECURITY
        with pytest.raises((ValidationError, ValueError, TypeError)):
            correlate([_raw(1)], metrics="error_rate?")
        with pytest.raises((ValidationError, ValueError, TypeError)):
            correlate([_raw(1)], deploys="dep-1")


class TestFingerprintWindow:
    def test_deploy_splits_groups_across_boundary(self):  # UNIT
        # Deploy at ts=1000, window ±900: ts=50 is out (leg "none"), ts=1100
        # is in (leg "dep-9") -> different fingerprints -> 2 groups. Both
        # out (ts=50, ts=1951) share leg "none" -> 1 group.
        deploys = [{"deploy_id": "dep-9", "ts": 1000, "service": "web"}]
        assert len(correlate([_raw(1, ts=50), _raw(2, ts=1100)],
                             deploys=deploys)) == 2
        assert len(correlate([_raw(1, ts=50), _raw(2, ts=1951)],
                             deploys=deploys)) == 1

    def test_window_boundary_exact(self):  # UNIT
        assert DEPLOY_WINDOW_S == 900
        deploys = [{"deploy_id": "d", "ts": 1000, "service": "web"}]
        # |100-1000| = 900 <= 900: in-window -> same leg -> 1 group.
        assert len(correlate([_raw(1, ts=100), _raw(2, ts=1000)],
                             deploys=deploys)) == 1
        # |99-1000| = 901 > 900: out -> leg "none" vs "d" -> 2 groups.
        assert len(correlate([_raw(1, ts=99), _raw(2, ts=1000)],
                             deploys=deploys)) == 2

    def test_shape_is_16_hex(self):  # UNIT
        fp = fingerprint("web", "sig", "prod", "none")
        assert len(fp) == 16 and all(c in "0123456789abcdef" for c in fp)

    def test_malformed_deploys_skipped(self):  # SECURITY
        deploys = ["dep-1", {"service": "web"},  # noqa
                   {"service": "web", "ts": True},
                   {"service": "web", "ts": "soon"}]
        assert len(correlate([_raw(1)], deploys=deploys)) == 1


class TestSuppressionAttribution:
    def test_counts_stay_with_their_group(self):  # SECURITY
        # P2: the global total used to stamp every incident. Two groups must
        # split the counts, and the sum must still equal the total.
        web = [_raw(i, ts=100 + i, service="web",
                    signature="http_5xx_spike") for i in range(1, 4)]
        search = [_raw(i, ts=100 + i, service="search",
                       signature="upstream_5xx") for i in range(10, 13)]
        incs = correlate(web + search)
        assert len(incs) == 2
        counts = sorted(i.metadata["suppressed_duplicates"] for i in incs)
        assert counts == [2, 2]
        assert sum(counts) == 4

    def test_dedup_returns_attribution_map(self):  # UNIT
        alerts = [normalize_alert(_raw(1, ts=100)),
                  normalize_alert(_raw(2, ts=101))]
        unique, suppressed, by_key = deduplicate(alerts)
        assert len(unique) == 1 and suppressed == 1
        assert by_key == {("web", "http_5xx_spike", "prod"): 1}


class TestStormSurvival:
    def test_200_alert_storm_yields_one_capped_incident(self):  # SECURITY
        # The old code ValidationError'd the whole correlation past 100 ids:
        # the biggest incidents produced NOTHING. Now: first 100 ids, full
        # count preserved, capped flag set.
        incs = correlate([_raw(i, ts=100 + i * 10) for i in range(200)])
        assert len(incs) == 1
        (inc,) = incs
        assert len(inc.source_alert_ids) == 100
        assert inc.metadata["alert_count"] == 200
        assert inc.metadata["source_alert_ids_capped"] is True

    def test_small_group_uncapped(self):  # UNIT
        (inc,) = correlate([_raw(i, ts=100 + i * 10) for i in range(4)])
        assert len(inc.source_alert_ids) == 4
        assert inc.metadata["source_alert_ids_capped"] is False

    def test_30_fixture_mixed_storm(self):  # UNIT
        web = [_raw(i, ts=100 + i * 10) for i in range(20)]
        search = [_raw(100 + i, ts=100 + i * 10, service="search",
                       signature="upstream_5xx") for i in range(10)]
        incs = correlate(web + search)
        assert len(incs) == 2
        assert sum(i.metadata["alert_count"] for i in incs) == 30


class TestSeverityTable:
    def test_fp_signatures_page_p4(self):  # UNIT
        assert FP_SIGNATURES == {"flapping_probe", "cpu_blip"}
        for sig in ("flapping_probe", "cpu_blip"):
            (inc,) = correlate(
                [_raw(1, service="web", environment="staging",
                       severity_raw="warning", signature=sig)],
                metrics=[{"name": "error_rate", "value": 0.001}])
            assert inc.severity == "P4", sig

    def test_non_fp_low_err_is_not_p4(self):  # UNIT
        (inc,) = correlate(
            [_raw(1, service="web", environment="staging",
                   severity_raw="warning", signature="mild_latency")],
            metrics=[{"name": "error_rate", "value": 0.001}])
        assert inc.severity == "P3"

    def test_security_pages_p1_everywhere(self):  # SECURITY
        for env in ("prod", "staging"):
            (inc,) = correlate(
                [_raw(1, service="web", environment=env,
                       severity_raw="warning",
                       signature="suspicious_log_instruction")])
            assert inc.severity == "P1", env

    def test_spike_keywords_fail_closed_without_metrics(self):  # SECURITY
        # Documented heuristic: a prod error-spike with NO metrics is a data
        # gap, and data gaps escalate. Removing these arms would downgrade
        # real spikes to P2 on missing evidence — fail-open downward.
        (inc,) = correlate(
            [_raw(1, severity_raw="warning", signature="http_5xx_spike")])
        assert inc.severity == "P1"
        (inc,) = correlate(
            [_raw(1, severity_raw="warning", signature="db_pool_exhausted")])
        assert inc.severity == "P1"


class TestSimilarityGuard:
    def test_empty_signatures_never_match(self):  # SECURITY
        from app.services.correlator import _sig_sim
        assert _sig_sim("", "") == 0.0
        assert _sig_sim("a", "") == 0.0

    def test_identical_is_one_disjoint_is_zero(self):  # UNIT
        from app.services.correlator import _sig_sim
        assert _sig_sim("http_5xx_spike", "http_5xx_spike") == 1.0
        assert _sig_sim("aaa_bbb", "ccc_ddd") == 0.0
