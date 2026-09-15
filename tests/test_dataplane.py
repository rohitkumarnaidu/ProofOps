"""Data-plane tests: determinism, grouping edge cases, pack budgets."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "telemetry"))

import gen  # noqa: E402
from app.schemas import sha256_hex  # noqa: E402
from app.services.correlator import correlate  # noqa: E402
from app.services.normalizer import (  # noqa: E402
    alert_hash,
    hash_record,
    normalize_alert,
)
from app.services.predigest import build_evidence_pack  # noqa: E402


def test_determinism_same_seed_same_sha():
    assert gen.generate("bad-deploy", "NORMAL", 7)["sha"] == \
        gen.generate("bad-deploy", "NORMAL", 7)["sha"]


def test_different_seed_different_output():
    assert gen.generate("bad-deploy", "NORMAL", 7)["sha"] != \
        gen.generate("bad-deploy", "NORMAL", 8)["sha"]


def test_all_12_scenarios_valid():
    assert len(gen.SCENARIOS) == 12
    for sc in gen.SCENARIOS:
        out = gen.generate(sc, "NORMAL", 1)
        assert out["expected_cause"] and out["alerts"] and "sha" in out


def test_deep5_have_deploys_or_cause():
    assert gen.generate("bad-deploy", "NORMAL", 1)["deploys"]
    assert gen.generate("injection", "NORMAL", 1)["expected_cause"]


def test_adversarial_embeds_payload_normal_does_not():
    adv = gen.generate("bad-deploy", "ADVERSARIAL", 1)
    norm = gen.generate("bad-deploy", "NORMAL", 1)
    assert any(gen.INJECTION_PAYLOAD in lg["msg"] for lg in adv["logs"])
    assert all(gen.INJECTION_PAYLOAD not in lg["msg"] for lg in norm["logs"])


def test_bad_deploy_correlates_to_single_p1():
    t = gen.generate("bad-deploy", "NORMAL", 3)
    inc = correlate(t["alerts"], t["deploys"], t["metrics"], t["topology"])
    assert len(inc) == 1 and inc[0].severity == "P1"


def test_noisy_junk_does_not_merge():
    t = gen.generate("bad-deploy", "NOISY", 3)
    inc = correlate(t["alerts"], t["deploys"], t["metrics"], t["topology"])
    assert len(inc) == 2  # real group + junk group


def test_false_positive_is_p4():
    t = gen.generate("false-positive", "NORMAL", 3)
    inc = correlate(t["alerts"], t["deploys"], t["metrics"], t["topology"])
    assert all(i.severity == "P4" for i in inc)


def test_injection_is_p1_security():
    t = gen.generate("injection", "NORMAL", 3)
    inc = correlate(t["alerts"], t["deploys"], t["metrics"], t["topology"])
    assert inc and all(i.severity == "P1" for i in inc)


def test_unrelated_services_split():
    alerts = [
        {"alert_id": "a1", "ts": 100, "service": "web", "environment": "prod",
         "severity_raw": "critical", "signature": "http_5xx_spike", "labels": {}},
        {"alert_id": "a2", "ts": 110, "service": "search", "environment": "prod",
         "severity_raw": "critical", "signature": "upstream_5xx", "labels": {}},
    ]
    assert len(correlate(alerts)) == 2


def test_normalizer_hash_stable():
    # M03 rewire: the in-model .hash hack is gone (frozen canonical Alert);
    # custody hashes are computed OUT of model over the canonical dump.
    raw = {"alert_id": "a", "service": "web", "environment": "prod",
           "severity_raw": "critical", "signature": "s", "labels": {}, "ts": 1}
    assert alert_hash(normalize_alert(raw)) == alert_hash(normalize_alert(raw))
    assert hash_record({"x": 1}) == sha256_hex('{"x":1}')


def test_pack_budgets_and_hashes():
    t = gen.generate("bad-deploy", "NOISY", 3)
    pack = build_evidence_pack("inc-1", t)
    assert len(pack["top_errors"]) <= 5
    assert len(pack["trace_exemplars"]) <= 3
    assert pack["deploy_diff"] == ["v22->v23"]
    for e in pack["evidence"]:
        assert len(e["hash"]) == 64 and e["incident_id"] == "inc-1"


def test_pack_empty_telemetry_no_crash():
    pack = build_evidence_pack("inc-1", {})
    assert pack["error_signature"] == "none" and pack["evidence"] == []
