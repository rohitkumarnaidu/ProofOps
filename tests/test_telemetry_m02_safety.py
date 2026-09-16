"""M02 ground-truth safety + hash completeness (90+ pass, host-safe SECURITY).

The sealed fixture carries eval answers; model-visible paths must never see
them. Proves: the strip primitive removes exactly the answer keys, every
telemetry section is hash-covered (tamper anywhere breaks the seal), the
injection payload is present-but-inert where the story demands it and absent
everywhere else.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "telemetry"))

import gen  # noqa: E402

TELEMETRY_KEYS = {"alerts", "logs", "metrics", "traces", "deploys",
                  "topology", "k8s_events", "slo"}


class TestPublicBundleStrip:
    def test_answer_keys_removed_telemetry_intact(self):  # SECURITY
        full = gen.generate("bad-deploy", "ADVERSARIAL", 7)
        view = gen.public_bundle(full)
        assert set(gen.GROUND_TRUTH_KEYS) == {
            "expected_cause", "allowed", "forbidden"}
        for key in gen.GROUND_TRUTH_KEYS:
            assert key not in view
        assert "sha" not in view  # derived view, not independently sealed
        for key in TELEMETRY_KEYS:
            assert view[key] == full[key]  # DATA passes through untouched
        assert gen.INJECTION_PAYLOAD in str(view)  # inert content, not answers

    def test_full_bundle_still_sealed(self):  # SECURITY
        full = gen.generate("bad-deploy", "ADVERSARIAL", 7)
        assert gen.verify_bundle(full) is True
        assert gen.public_bundle(full) != full

    def test_view_deterministic(self):  # UNIT
        a = gen.public_bundle(gen.generate("db-exhaust", "NOISY", 3))
        b = gen.public_bundle(gen.generate("db-exhaust", "NOISY", 3))
        assert a == b


class TestTamperPerSection:
    @pytest.mark.parametrize("section", sorted(TELEMETRY_KEYS) + [
        "expected_cause", "allowed", "scenario"])
    def test_tamper_anywhere_breaks_seal(self, section):  # SECURITY
        bundle = gen.generate("bad-deploy", "NORMAL", 7)
        tampered = copy.deepcopy(bundle)
        current = tampered[section]
        if isinstance(current, list):
            tampered[section] = current + [{"forged": True}]
        elif isinstance(current, dict):
            tampered[section] = dict(current, forged=True)
        elif isinstance(current, str):
            tampered[section] = current + "-forged"
        else:
            tampered[section] = "forged"
        assert gen.verify_bundle(tampered) is False
        assert gen.verify_bundle(bundle) is True  # original untouched


class TestPayloadRules:
    @pytest.mark.parametrize("scenario", sorted(gen.SCENARIOS))
    def test_adversarial_always_carries_payload_once(self, scenario):  # SECURITY
        t = gen.generate(scenario, "ADVERSARIAL", 7)
        assert sum(gen.INJECTION_PAYLOAD in lg.get("msg", "")
                   for lg in t["logs"]) == 1

    @pytest.mark.parametrize("variant", list(gen.VARIANTS))
    def test_injection_scenario_always_carries_payload(self, variant):  # SECURITY
        # Even INCOMPLETE carries exactly its marker log (the scenario IS the
        # injection; dropping the marker would blind the safety suite).
        t = gen.generate("injection", variant, 7)
        assert sum(gen.INJECTION_PAYLOAD in lg.get("msg", "")
                   for lg in t["logs"]) == 1

    @pytest.mark.parametrize("scenario", sorted(gen.SCENARIOS))
    def test_normal_non_injection_clean(self, scenario):  # SECURITY
        if scenario == "injection":
            return  # story IS the injection; covered above
        t = gen.generate(scenario, "NORMAL", 7)
        assert all(gen.INJECTION_PAYLOAD not in lg.get("msg", "")
                   for lg in t["logs"])

    def test_payload_is_inert_data(self):  # SECURITY
        t = gen.generate("bad-deploy", "ADVERSARIAL", 7)
        evil = [lg for lg in t["logs"]
                if gen.INJECTION_PAYLOAD in lg.get("msg", "")]
        assert len(evil) == 1 and evil[0]["level"] == "ERROR"
        assert set(evil[0]) >= {"ts", "service", "pod", "msg", "trace_id"}
