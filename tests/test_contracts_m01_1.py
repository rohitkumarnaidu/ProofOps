"""M01.1 shared types: canonical-enum + freeze-surface tests (host-safe).

Proves the locked M01.1 decisions, not just that "tests pass":
- every domain enum has exactly one definition (in app.contracts.enums);
- schemas.py defines no domain vocabulary (re-export layer only);
- app.contracts is the freeze surface; schemas.X is contracts.X;
- ActionType == ACTION_TYPES allowlist; IncidentStatus == FSM_STATES;
- JSON serialization stable; invalid values rejected;
- legacy schema behavior compatible (plus unmodified tests/test_schemas.py).
"""
from __future__ import annotations

import inspect
import json
import sys
from enum import Enum
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import app.contracts as C  # noqa: E402
import app.schemas as S  # noqa: E402
from app.contracts.enums import ACTION_TYPES, FSM_STATES  # noqa: E402
from app.contracts.values import (  # noqa: E402
    MAX_PAGE_SIZE,
    PageParams,
    confidence_bucket,
    new_id,
)
from app.contracts.enums import ConfidenceLevel  # noqa: E402

ENUM_NAMES = [
    "Severity", "Environment", "RiskLevel", "Decision", "Verdict",
    "HypothesisStatus", "TrustLevel", "ClaimClass", "ActionType",
    "IncidentStatus", "SourceType", "ActorType",
    "ApprovalStatus", "ExecutionStatus", "ConfidenceLevel", "FailureCode",
    "ExecutorTier",
]

EXPECTED_MEMBERS: dict[str, set[str]] = {
    "Severity": {"P1", "P2", "P3", "P4"},
    "Environment": {"dev", "staging", "prod", "mock"},
    "RiskLevel": {"GREEN", "YELLOW", "RED"},
    "Decision": {"ALLOW", "ESCALATE", "DENY"},
    "Verdict": {"RESOLVED", "PARTIAL", "FAILED", "WORSENED",
                "ROLLBACK_REQUIRED", "ESCALATE"},
    "HypothesisStatus": {"SUPPORTED", "REJECTED", "UNCERTAIN",
                         "INSUFFICIENT_EVIDENCE"},
    "TrustLevel": {"high", "med", "low"},
    "ActionType": set(ACTION_TYPES),
    "ClaimClass": {"MUST-CITE", "SHOULD-CITE", "OPTIONAL"},
    "IncidentStatus": set(FSM_STATES),
    "SourceType": {"log", "metric", "trace", "deploy", "topology",
                   "runbook", "history"},
    # EvidenceType intentionally absent: alias asserted equal to SourceType.
    "ActorType": {"human", "agent", "system", "policy"},
    "ApprovalStatus": {"PENDING", "APPROVED", "DENIED", "EXPIRED",
                       "CONSUMED"},
    "ExecutionStatus": {"PENDING", "RUNNING", "SUCCEEDED", "FAILED",
                        "BLOCKED", "CACHED"},
    "ConfidenceLevel": {"low", "medium", "high"},
    "FailureCode": {"none", "timeout", "policy_denied", "approval_expired",
                    "precondition_failed", "executor_error",
                    "verification_failed", "unknown"},
    "ExecutorTier": {"mock", "docker"},
}


class TestSingleDefinition:
    @pytest.mark.parametrize("name", ENUM_NAMES)
    def test_exact_member_set(self, name):  # UNIT
        cls = getattr(C, name)
        assert issubclass(cls, Enum)
        assert {m.value for m in cls} == EXPECTED_MEMBERS[name]

    def test_evidence_type_alias_members(self):  # UNIT
        assert {m.value for m in C.EvidenceType} == EXPECTED_MEMBERS["SourceType"]

    def test_actiontype_matches_allowlist(self):  # UNIT
        assert {m.value for m in C.ActionType} == set(ACTION_TYPES)
        assert {m.name for m in C.ActionType} == {v.upper() for v in ACTION_TYPES}
        assert len(ACTION_TYPES) == len(set(ACTION_TYPES)) == 18

    def test_incidentstatus_matches_fsm(self):  # UNIT
        assert {m.value for m in C.IncidentStatus} == set(FSM_STATES)
        assert len(FSM_STATES) == 18

    def test_evidence_type_is_source_type(self):  # UNIT
        assert C.EvidenceType is C.SourceType  # alias, not a duplicate

    def test_kind_tier_reserved_absent(self):  # UNIT
        assert "kind" not in {m.value for m in C.ExecutorTier}

    def test_no_duplicate_class_definitions(self):  # UNIT
        import app.contracts.enums as E
        seen: dict[str, str] = {}
        for _, obj in vars(E).items():
            if inspect.isclass(obj) and issubclass(obj, Enum) and obj is not Enum:
                if obj.__name__ in seen and seen[obj.__name__] != obj.__module__:
                    pytest.fail(f"duplicate enum: {obj.__name__}")
                seen[obj.__name__] = obj.__module__


class TestFreezeSurface:
    def test_contract_version_pinned(self):  # UNIT
        assert C.CONTRACT_VERSION == "1.0"

    @pytest.mark.parametrize("name", ENUM_NAMES)
    def test_schemas_reexports_identity(self, name):  # UNIT
        assert getattr(S, name) is getattr(C, name), name

    def test_evidence_type_reexport_identity(self):  # UNIT
        assert S.EvidenceType is C.EvidenceType is C.SourceType

    def test_helpers_reexport_identity(self):  # UNIT
        for fn in ("utcnow", "canonical_json", "sha256_hex", "params_hash"):
            assert getattr(S, fn) is getattr(C, fn), fn

    def test_schemas_defines_no_enum(self):  # UNIT
        import ast
        tree = ast.parse((ROOT / "backend" / "app" / "schemas.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                    isinstance(b, ast.Name) and b.id in ("Enum", "StrEnum")
                    for b in node.bases):
                pytest.fail(f"schemas.py defines enum: {node.name}")
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id.isupper() and
                    "RE" not in t.id for t in node.targets):
                pytest.fail(f"schemas.py defines constant: {node.lineno}")

    def test_no_m00_config_enums_migrated(self):  # UNIT
        # M00.2 stays frozen: AppEnv/LogLevel/Executor live ONLY in config.
        from app.config import AppEnv, Executor, LogLevel, SeedVariant  # noqa: F401
        for name in ("AppEnv", "Executor", "LogLevel", "SeedVariant"):
            assert not hasattr(C, name), f"M00 enum leaked: {name}"


class TestSerialization:
    @pytest.mark.parametrize("name", ENUM_NAMES)
    def test_str_equality_and_json(self, name):  # UNIT
        cls = getattr(C, name)
        for m in cls:
            assert m == m.value  # str equality: legacy string code keeps working
            assert json.dumps({"v": m}) == json.dumps({"v": m.value})

    def test_model_round_trip_stable(self):  # UNIT
        a = S.Action(incident_id="i", agent_id="a",
                     action_type="rollback_deployment",
                     resource_type="deployment", resource_id="web",
                     reason="r", runbook_id="rb", runbook_version="1.2.0",
                     expected_outcome="o")
        blob = a.model_dump_json()
        b = S.Action.model_validate_json(blob)
        assert b.action_type is S.ActionType.ROLLBACK_DEPLOYMENT
        assert b.risk_level is S.RiskLevel.GREEN
        assert b.model_dump_json() == blob  # byte-stable re-serialization

    def test_ids_unique_and_hash_stable(self):  # UNIT
        assert new_id() != new_id() and len(new_id()) == 32
        assert S.params_hash({"a": 1}) == S.params_hash({"a": 1})

    def test_confidence_buckets(self):  # UNIT
        assert confidence_bucket(0.0) is ConfidenceLevel.LOW
        assert confidence_bucket(0.39) is ConfidenceLevel.LOW
        assert confidence_bucket(0.4) is ConfidenceLevel.MEDIUM
        assert confidence_bucket(0.69) is ConfidenceLevel.MEDIUM
        assert confidence_bucket(0.7) is ConfidenceLevel.HIGH
        assert confidence_bucket(1.0) is ConfidenceLevel.HIGH
        with pytest.raises(ValueError):
            confidence_bucket(1.5)

    def test_page_params_bounded(self):  # UNIT
        assert PageParams().page_size == 50
        assert PageParams(page_size=MAX_PAGE_SIZE).page_size == 500
        with pytest.raises(ValidationError):
            PageParams(page_size=501)
        with pytest.raises(ValidationError):
            PageParams(page=0)


class TestNegative:
    @pytest.mark.parametrize("field,value", [
        ("action_type", "nuke_everything"),
        ("action_type", "ROLLBACK_DEPLOYMENT"),  # case-sensitive
        ("environment", "production"),  # AppEnv is NOT a domain Environment
        ("environment", ""),
        ("risk_level", "CRITICAL"),
        ("namespace", "Default"),
        ("runbook_version", "latest"),
        ("parameters", "kubectl delete ns prod"),  # shell string rejected
        ("tier", "kind"),  # reserved tier rejected
    ])
    def test_invalid_rejected(self, field, value):  # UNIT
        base = dict(incident_id="i", agent_id="a",
                    action_type="rollback_deployment",
                    resource_type="deployment", resource_id="web",
                    reason="r", runbook_id="rb", runbook_version="1.2.0",
                    expected_outcome="o", idempotency_key="k")
        if field == "tier":
            with pytest.raises(ValidationError):
                S.Execution(action_id="a", incident_id="i",
                            tier=value, idempotency_key="k")
        else:
            base[field] = value
            with pytest.raises(ValidationError):
                S.Action(**{k: v for k, v in base.items()
                            if k != "idempotency_key"})

    def test_incident_status_closed(self):  # UNIT
        assert S.Incident(fingerprint="f", severity="P1").status == "NEW"
        with pytest.raises(ValidationError):
            S.Incident(fingerprint="f", severity="P1", status="HEALED")

    def test_errors_are_field_attributed(self):  # SECURITY
        # Pydantic echoes rejected inputs (standard); the safety property is
        # that every rejection names its field, so callers never guess.
        try:
            S.Action(incident_id="i", agent_id="a", action_type="nuke_it",
                     resource_type="r", resource_id="r", reason="r",
                     runbook_id="r", runbook_version="1.2.0",
                     expected_outcome="o")
        except ValidationError as exc:
            locs = [e["loc"][0] for e in exc.errors()]
            assert "action_type" in locs
        else:
            pytest.fail("expected ValidationError")
