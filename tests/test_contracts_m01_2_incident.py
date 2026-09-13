"""M01.2 Incident contract: positive, negative, serialization, timestamp, ID, legacy, security, integration.

Proves:
- canonical Incident is single definition (app.contracts.incident), re-exported via app.schemas
- immutable identity, enum-typed from M01.1 only, valid tz-aware timestamps, ordering
- serialization stability, invalid enum / bypass rejected, legacy compat preserved
- correlator integration still produces valid incidents
"""
from __future__ import annotations

import ast
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import app.contracts as C  # noqa: E402
import app.schemas as S  # noqa: E402
from app.contracts.enums import FSM_STATES  # noqa: E402
from app.contracts.incident import Incident  # noqa: E402

UTC = timezone.utc


def _utc(y=2026, m=1, d=1, h=10, mi=0, s=0) -> datetime:
    return datetime(y, m, d, h, mi, s, tzinfo=UTC)


def _valid_kwargs(**over):
    base = dict(fingerprint="fp-abc-123", severity="P1")
    base.update(over)
    return base


# ------------------------------------------------------------------ positive


class TestIncidentPositive:
    def test_minimal_legacy(self):
        inc = Incident(fingerprint="f", severity="P1")
        assert inc.fingerprint == "f"
        assert inc.severity == C.Severity.P1
        assert inc.status == C.IncidentStatus.NEW
        assert inc.service == "unknown"
        assert inc.environment == C.Environment.MOCK

    @pytest.mark.parametrize("sev", ["P1", "P2", "P3", "P4"])
    def test_all_severities(self, sev):
        inc = Incident(fingerprint="f", severity=sev)
        assert inc.severity.value == sev

    @pytest.mark.parametrize("env", ["dev", "staging", "prod", "mock"])
    def test_all_environments(self, env):
        inc = Incident(fingerprint="f", severity="P2", environment=env)
        assert inc.environment.value == env

    @pytest.mark.parametrize("status", FSM_STATES)
    def test_all_statuses(self, status):
        inc = Incident(fingerprint="f", severity="P1", status=status)
        assert inc.status.value == status

    def test_full_fields(self):
        t0 = _utc(2026, 1, 1, 10, 0)
        t1 = _utc(2026, 1, 1, 11, 0)
        t2 = _utc(2026, 1, 1, 9, 0)
        t3 = _utc(2026, 1, 1, 12, 0)
        inc = Incident(
            incident_id="inc-1",
            status="CORRELATED",
            severity="P2",
            service="checkout",
            environment="prod",
            impact={"replicas": 3, "error_rate": 0.18},
            fingerprint="abc123",
            created_at=t0,
            updated_at=t1,
            detected_at=t2,
            resolved_at=t3,
            source_alert_ids=["a1", "a2"],
            evidence_ids=["ev-1"],
            diagnosis_reference="diag-1",
            action_references=["act-1"],
            metadata={"owner": "sre", "tags": ["critical"]},
        )
        assert inc.incident_id == "inc-1"
        assert inc.service == "checkout"
        assert inc.impact["error_rate"] == 0.18
        # hardened (M01.2 zero-trust pass): ID lists stored immutable as tuple
        # (list input still accepted); mappings stored as FrozenDict.
        assert inc.source_alert_ids == ("a1", "a2")
        assert list(inc.source_alert_ids) == ["a1", "a2"]  # reads stay ergonomic
        assert inc.diagnosis_reference == "diag-1"
        assert inc.metadata["owner"] == "sre"

    def test_impact_and_metadata_arbitrary(self):
        inc = Incident(fingerprint="f", severity="P3", impact={"x": [1, 2]}, metadata={"y": {"z": 1}})
        assert inc.impact == {"x": [1, 2]}
        assert inc.metadata == {"y": {"z": 1}}

    def test_lists_allow_empty(self):
        inc = Incident(fingerprint="f", severity="P1", source_alert_ids=[], evidence_ids=[], action_references=[])
        assert inc.source_alert_ids == ()

    def test_diagnosis_reference_none(self):
        inc = Incident(fingerprint="f", severity="P1", diagnosis_reference=None)
        assert inc.diagnosis_reference is None

    def test_timestamps_default_tz_aware(self):
        inc = Incident(fingerprint="f", severity="P1")
        assert inc.created_at.tzinfo is not None
        assert inc.updated_at.tzinfo is not None
        assert inc.created_at.utcoffset() is not None


# ------------------------------------------------------------------ negative


class TestIncidentNegative:
    def test_missing_fingerprint(self):
        with pytest.raises(ValidationError):
            Incident(severity="P1")  # type: ignore

    def test_missing_severity(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f")  # type: ignore

    def test_empty_fingerprint(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="", severity="P1")

    def test_whitespace_fingerprint(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="   ", severity="P1")

    def test_blank_service(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", service="")

    def test_whitespace_service(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", service="  ")

    def test_blank_incident_id(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", incident_id="")

    def test_invalid_severity(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P0")  # type: ignore
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="p1")  # case
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="CRITICAL")  # type: ignore

    def test_invalid_status(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", status="HEALED")  # type: ignore
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", status="new")  # lower

    def test_invalid_environment(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", environment="production")  # type: ignore
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", environment="")  # type: ignore

    def test_diagnosis_reference_blank(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", diagnosis_reference="")
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", diagnosis_reference="  ")

    def test_source_alert_ids_null(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", source_alert_ids=None)  # type: ignore

    def test_source_alert_ids_not_list(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", source_alert_ids="a1")  # type: ignore

    def test_source_alert_ids_blank_entry(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", source_alert_ids=["", "a2"])

    def test_source_alert_ids_non_string_entry(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", source_alert_ids=[123])  # type: ignore

    def test_evidence_ids_blank(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", evidence_ids=[" "])

    def test_action_references_non_string(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", action_references=[None])  # type: ignore

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", unknown_field="x")  # type: ignore

    def test_errors_are_field_attributed(self):
        try:
            Incident(fingerprint="", severity="P0")  # type: ignore
        except ValidationError as exc:
            locs = {e["loc"][0] for e in exc.errors()}
            assert "fingerprint" in locs or "severity" in locs
        else:
            pytest.fail("expected ValidationError")


# ------------------------------------------------------------------ timestamp


class TestIncidentTimestamp:
    def test_naive_created_rejected(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", created_at=datetime(2026, 1, 1, 10, 0, 0))

    def test_naive_detected_rejected(self):
        with pytest.raises(ValidationError):
            Incident(
                fingerprint="f",
                severity="P1",
                detected_at=datetime(2026, 1, 1, 10, 0, 0),
            )

    def test_naive_resolved_rejected(self):
        with pytest.raises(ValidationError):
            Incident(
                fingerprint="f",
                severity="P1",
                resolved_at=datetime(2026, 1, 1, 10, 0, 0),
            )

    def test_updated_before_created(self):
        t0 = _utc(2026, 1, 1, 11, 0)
        t1 = _utc(2026, 1, 1, 10, 0)
        with pytest.raises(ValidationError) as exc:
            Incident(fingerprint="f", severity="P1", created_at=t0, updated_at=t1)
        assert "updated_at" in str(exc.value)

    def test_resolved_before_created(self):
        t0 = _utc(2026, 1, 1, 10, 0)
        t1 = _utc(2026, 1, 1, 11, 0)
        t_res = _utc(2026, 1, 1, 9, 0)
        with pytest.raises(ValidationError) as exc:
            Incident(fingerprint="f", severity="P1", created_at=t0, updated_at=t1, resolved_at=t_res)
        assert "resolved_at" in str(exc.value)

    def test_resolved_before_detected(self):
        t0 = _utc(2026, 1, 1, 9, 0)
        t1 = _utc(2026, 1, 1, 10, 0)
        t_det = _utc(2026, 1, 1, 11, 0)
        t_res = _utc(2026, 1, 1, 10, 30)
        with pytest.raises(ValidationError) as exc:
            Incident(
                fingerprint="f",
                severity="P1",
                created_at=t0,
                updated_at=t1,
                detected_at=t_det,
                resolved_at=t_res,
            )
        assert "resolved_at" in str(exc.value)

    def test_resolved_equal_created_allowed(self):
        t0 = _utc(2026, 1, 1, 10, 0)
        inc = Incident(fingerprint="f", severity="P1", created_at=t0, updated_at=t0, resolved_at=t0)
        assert inc.resolved_at == t0

    def test_detected_before_created_allowed(self):
        # diagnosis may be detected before incident created (ingest lag) - allowed
        t0 = _utc(2026, 1, 1, 10, 0)
        t1 = _utc(2026, 1, 1, 11, 0)
        t_det = _utc(2026, 1, 1, 9, 59)
        inc = Incident(fingerprint="f", severity="P1", created_at=t0, updated_at=t1, detected_at=t_det)
        assert inc.detected_at == t_det

    def test_status_does_not_require_resolved(self):
        # M01.2 deliberately does NOT couple status->resolved_at (M14 owns FSM)
        t0 = _utc()
        inc = Incident(fingerprint="f", severity="P1", status="RESOLVED", created_at=t0, updated_at=t0)
        assert inc.status == C.IncidentStatus.RESOLVED
        assert inc.resolved_at is None

    def test_resolved_does_not_require_status_resolved(self):
        t0 = _utc()
        t1 = _utc(2026, 1, 1, 11, 0)
        inc = Incident(fingerprint="f", severity="P1", status="NEW", created_at=t0, updated_at=t1, resolved_at=t1)
        assert inc.resolved_at == t1
        assert inc.status == C.IncidentStatus.NEW

    def test_no_auto_touch_updated_at(self):
        t0 = _utc(2026, 1, 1, 10, 0)
        t1 = _utc(2026, 1, 1, 10, 5)
        inc = Incident(fingerprint="f", severity="P1", created_at=t0, updated_at=t1, status="NEW")
        # status change would not auto-update updated_at; caller must set explicitly
        assert inc.updated_at == t1


# ------------------------------------------------------------------ ID


class TestIncidentId:
    def test_generated_id_unique_and_hex(self):
        a = Incident(fingerprint="f", severity="P1")
        b = Incident(fingerprint="f", severity="P1")
        assert a.incident_id != b.incident_id
        assert len(a.incident_id) == 32
        int(a.incident_id, 16)  # must be hex

    def test_explicit_id_preserved(self):
        inc = Incident(fingerprint="f", severity="P1", incident_id="my-id-123")
        assert inc.incident_id == "my-id-123"

    def test_fingerprint_preserved(self):
        inc = Incident(fingerprint="abc", severity="P1")
        assert inc.fingerprint == "abc"


# ------------------------------------------------------------------ serialization


class TestIncidentSerialization:
    def test_roundtrip_stable(self):
        t0 = _utc()
        t1 = t0 + timedelta(seconds=5)
        inc = Incident(fingerprint="fp", severity="P2", service="web", environment="prod", status="CORRELATED", created_at=t0, updated_at=t1, source_alert_ids=["a1"], evidence_ids=["ev1"], metadata={"k": "v"})
        blob = inc.model_dump_json()
        inc2 = Incident.model_validate_json(blob)
        assert inc2.model_dump_json() == blob
        assert inc2.severity is C.Severity.P2
        assert inc2.environment is C.Environment.PROD
        assert inc2.status is C.IncidentStatus.CORRELATED

    def test_json_enums_as_values(self):
        inc = Incident(fingerprint="f", severity="P1", environment="mock", status="NEW")
        dumped = json.loads(inc.model_dump_json())
        assert dumped["severity"] == "P1"
        assert dumped["environment"] == "mock"
        assert dumped["status"] == "NEW"
        # str equality (M01.1 decision): enum equals its value
        assert inc.severity == "P1"
        assert json.dumps({"v": inc.severity}) == json.dumps({"v": "P1"})

    def test_model_dump_enums(self):
        inc = Incident(fingerprint="f", severity="P3")
        d = inc.model_dump()
        assert d["severity"] == C.Severity.P3
        d_json = inc.model_dump(mode="json")
        assert d_json["severity"] == "P3"

    def test_optional_fields_omitted_vs_none(self):
        inc = Incident(fingerprint="f", severity="P1")
        d = inc.model_dump(mode="json")
        assert d["detected_at"] is None
        assert d["resolved_at"] is None
        assert d["diagnosis_reference"] is None

    def test_legacy_string_severity_accepted(self):
        inc = Incident(fingerprint="f", severity="P1")  # type: ignore - string coerced to enum
        assert inc.severity is C.Severity.P1

    def test_different_data_different_json(self):
        a = Incident(fingerprint="f", severity="P1", service="web")
        b = Incident(fingerprint="f", severity="P1", service="api")
        assert a.model_dump_json() != b.model_dump_json()


# ------------------------------------------------------------------ legacy / compat


class TestIncidentLegacy:
    def test_legacy_minimal_still_works(self):
        # exactly the call existing tests use: Incident(fingerprint, severity)
        inc = S.Incident(fingerprint="f", severity="P1")
        assert inc.status == C.IncidentStatus.NEW or inc.status == "NEW"
        inc2 = C.Incident(fingerprint="f", severity="P1")
        assert inc2.status == C.IncidentStatus.NEW

    def test_schemas_reexport_identity(self):
        assert S.Incident is C.Incident
        assert S.Incident is Incident

    def test_schemas_incident_accepts_new_optional_fields(self):
        # callers using old import path get new fields for free
        inc = S.Incident(fingerprint="f", severity="P2", service="web", environment="prod", evidence_ids=["ev1"])
        assert inc.service == "web"
        assert inc.evidence_ids == ("ev1",)  # hardened: stored immutable, list in accepted

    def test_incident_defaults_unchanged(self):
        inc = Incident(fingerprint="f", severity="P1")
        assert inc.service == "unknown"
        assert inc.environment == C.Environment.MOCK
        assert inc.status == C.IncidentStatus.NEW
        assert inc.impact == {}
        assert inc.metadata == {}

    def test_correlator_produces_valid_incident(self):
        sys.path.insert(0, str(ROOT / "telemetry"))
        sys.path.insert(0, str(ROOT / "backend"))
        from app.services.correlator import correlate  # noqa: E402
        import gen  # noqa: E402

        bundle = gen.generate("bad-deploy", "NORMAL", 3)
        incidents = correlate(bundle["alerts"], bundle["deploys"], bundle["metrics"], bundle["topology"])
        assert len(incidents) == 1
        assert incidents[0].severity == C.Severity.P1 or incidents[0].severity == "P1"
        assert incidents[0].fingerprint
        assert incidents[0].status == C.IncidentStatus.CORRELATED or incidents[0].status == "CORRELATED"
        # new fields are present
        assert hasattr(incidents[0], "incident_id")
        assert hasattr(incidents[0], "created_at")


# ------------------------------------------------------------------ security / contract integrity


class TestIncidentSecurity:
    def test_frozen_immutable(self):
        inc = Incident(fingerprint="f", severity="P1")
        with pytest.raises(ValidationError):
            inc.severity = C.Severity.P2  # type: ignore
        with pytest.raises(ValidationError):
            inc.fingerprint = "other"  # type: ignore

    def test_no_duplicate_enum_definitions(self):
        src = (ROOT / "backend" / "app" / "contracts" / "incident.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    name = getattr(base, "id", None) or getattr(base, "attr", None)
                    if name in ("Enum", "StrEnum"):
                        pytest.fail(f"incident.py defines enum: {node.name}")

    def test_incident_imports_enums_only(self):
        src = (ROOT / "backend" / "app" / "contracts" / "incident.py").read_text()
        assert "from app.contracts.enums import" in src
        # must not redefine Severity/Environment/IncidentStatus locally
        tree = ast.parse(src)
        assigned = {n.targets[0].id for n in ast.walk(tree) if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)}
        for dup in ("Severity", "Environment", "IncidentStatus"):
            assert dup not in assigned, f"incident.py redefines {dup}"

    def test_schemas_still_no_enum(self):
        src = (ROOT / "backend" / "app" / "schemas.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                isinstance(b, ast.Name) and b.id in ("Enum", "StrEnum") for b in node.bases
            ):
                pytest.fail(f"schemas.py defines enum: {node.name}")

    def test_mutable_defaults_isolated(self):
        # hardened: empty-tuple defaults MAY be shared (immutable singletons,
        # sharing is safe); isolation is proven with populated values, and
        # construction copies inputs instead of aliasing them.
        a = Incident(fingerprint="f", severity="P1")
        b = Incident(fingerprint="f", severity="P1")
        assert a.source_alert_ids == () and b.source_alert_ids == ()
        assert a.impact == {} and b.impact == {}
        src = ["a1"]
        imp = {"k": [1]}
        meta = {"m": {"n": 1}}
        x = Incident(fingerprint="f", severity="P1", source_alert_ids=src, impact=imp, metadata=meta)
        src.append("evil")
        imp["k"].append(999)
        meta["m"]["n"] = "evil"
        assert x.source_alert_ids == ("a1",)
        assert x.impact == {"k": [1]}
        assert x.metadata == {"m": {"n": 1}}

    def test_validation_error_does_not_echo_secret(self):
        # incident has no secrets, but ensure error loc is field-named not data dump
        try:
            Incident(fingerprint="f", severity="P0")  # type: ignore
        except ValidationError as exc:
            assert any(e["loc"][0] == "severity" for e in exc.errors())


# ------------------------------------------------------------------ integration / regression


class TestIncidentIntegration:
    def test_contract_version_pinned(self):
        assert C.CONTRACT_VERSION == "1.0"

    def test_all_enums_single_source(self):
        # M01.1 gate: app.contracts exports are canonical
        assert C.Severity is S.Severity
        assert C.Environment is S.Environment
        assert C.IncidentStatus is S.IncidentStatus

    def test_json_stable_across_imports(self):
        t0 = _utc()
        a = C.Incident(fingerprint="f", severity="P1", created_at=t0, updated_at=t0)
        b = S.Incident.model_validate_json(a.model_dump_json())
        assert a == b
