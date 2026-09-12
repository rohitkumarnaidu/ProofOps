"""T02 schema contract tests: 1 valid baseline + 20 invalid fixtures + helpers."""
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.schemas import (  # noqa: E402
    Action,
    ApprovalToken,
    AuditEvent,
    Evidence,
    Incident,
    VerificationResult,
    params_hash,
    utcnow,
)


def valid_action(**over) -> dict:
    base = dict(
        incident_id="inc-1",
        agent_id="planner",
        action_type="rollback_deployment",
        resource_type="deployment",
        resource_id="web",
        environment="mock",
        namespace="default",
        parameters={"to_version": "v22"},
        reason="bad deploy v23, error 18%",
        evidence_ids=["ev-1"],
        runbook_id="bad-deploy-rollback",
        runbook_version="1.2.0",
        expected_outcome="error back under 1%",
        verification_plan=["error_rate_below_1pct"],
    )
    base.update(over)
    return base


def test_valid_action_passes():
    a = Action(**valid_action())
    assert a.namespace == "default" and a.risk_level == "GREEN"  # advisory default


# --- 20 invalid fixtures: each must raise ValidationError -------------------
@pytest.mark.parametrize(
    "mut",
    [
        {"action_type": "nuke_everything"},          # 1 unknown type
        {"action_type": "ROLLBACK_DEPLOYMENT"},      # 2 case-sensitive
        {"environment": "production"},               # 3 not in enum
        {"environment": ""},                         # 4 empty env
        {"namespace": "Default"},                    # 5 uppercase ns
        {"namespace": "my_ns"},                      # 6 underscore ns
        {"namespace": ""},                           # 7 empty ns
        {"runbook_version": "1.2"},                  # 8 unpinned semver
        {"runbook_version": "latest"},               # 9 floating version
        {"runbook_version": "v1.2.0"},               # 10 v-prefix
        {"parameters": "kubectl delete ns prod"},    # 11 string params (shell!)
        {"parameters": ["--force"]},                 # 12 list params
        {"reason": ""},                              # 13 empty reason
        {"expected_outcome": ""},                    # 14 empty outcome
        {"incident_id": ""},                         # 15 empty incident
        {"agent_id": ""},                            # 16 empty agent
        {"resource_id": ""},                         # 17 empty resource
        {"resource_type": ""},                       # 18 empty rtype
        {"runbook_id": ""},                          # 19 empty runbook
        {"risk_level": "CRITICAL"},                  # 20 unknown risk
    ],
    ids=[f"invalid-{i:02d}" for i in range(1, 21)],
)
def test_invalid_actions_rejected(mut):
    with pytest.raises(ValidationError):
        Action(**valid_action(**mut))


def test_incident_rejects_unknown_state():
    with pytest.raises(ValidationError):
        Incident(fingerprint="f", severity="P1", status="HEALED")


def test_incident_rejects_bad_severity():
    with pytest.raises(ValidationError):
        Incident(fingerprint="f", severity="P0")


def test_evidence_bounds():
    with pytest.raises(ValidationError):
        Evidence(incident_id="i", source_type="log", source_id="s", ref="r",
                 hash="h", freshness_s=-1, relevance=0.5)
    with pytest.raises(ValidationError):
        Evidence(incident_id="i", source_type="log", source_id="s", ref="r",
                 hash="h", freshness_s=1, relevance=1.5)
    with pytest.raises(ValidationError):
        Evidence(incident_id="i", source_type="pagerduty", source_id="s", ref="r",
                 hash="h", freshness_s=1, relevance=0.5)


def test_verdict_closed_set():
    with pytest.raises(ValidationError):
        VerificationResult(execution_id="e", verdict="FIXED")


def test_params_hash_deterministic_and_sensitive():
    assert params_hash({"a": 1, "b": 2}) == params_hash({"b": 2, "a": 1})
    assert params_hash({"replicas": 3}) != params_hash({"replicas": 4})


def test_approval_token_expiry():
    t = ApprovalToken(token="t", approval_id="a", action_id="x", actor="sre",
                      params_hash="h", expires_at=utcnow() - timedelta(seconds=1))
    assert t.is_expired() is True


def test_audit_hash_chain_links():
    h0 = AuditEvent.compute_hash("GENESIS", '{"seq":0}')
    h1 = AuditEvent.compute_hash(h0, '{"seq":1}')
    assert h0 != h1 and len(h0) == 64
    assert AuditEvent.compute_hash(h0, '{"seq":1}') == h1  # deterministic
