"""M01.2 zero-trust hardening: escapes 1-4, mutation suite, boundaries, audit.

Proves the four verified escapes from the first audit are closed:
- Escape 1: model_construct bypass BLOCKED (+ model_copy(update) sibling),
  with AST scan forbidding bypass APIs in application code.
- Escape 2: shallow frozen containers replaced by deep immutability
  (tuple ID lists + FrozenDict mappings); every mutation vector covered.
- Escape 3: explicit documented bounds on every string/container field,
  tested at max-1 / max / max+1.
- Escape 4: reject-if-padded whitespace rule, uniform across the contract.

Also: serialization wire-compat proof (pre-hardening goldens), hostile
payloads, validation-cost measurements, correlator integration.
"""
from __future__ import annotations

import ast
import copy
import json
import pickle
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import app.contracts as C  # noqa: E402
from app.contracts.incident import (  # noqa: E402
    MAX_FINGERPRINT_LEN,
    MAX_ID_ITEM_LEN,
    MAX_ID_LIST_ITEMS,
    MAX_IMPACT_ENTRIES,
    MAX_IMPACT_JSON_BYTES,
    MAX_INCIDENT_ID_LEN,
    MAX_METADATA_DEPTH,
    MAX_METADATA_ENTRIES,
    MAX_METADATA_JSON_BYTES,
    MAX_METADATA_KEY_LEN,
    MAX_DIAGNOSIS_REF_LEN,
    MAX_SERVICE_LEN,
    FrozenDict,
    Incident,
)
from app.contracts.values import canonical_json  # noqa: E402

UTC = timezone.utc


def _utc(y=2026, m=1, d=1, h=10, mi=0, s=0) -> datetime:
    return datetime(y, m, d, h, mi, s, tzinfo=UTC)


def _nested(levels: int) -> dict:
    """Build exactly ``levels`` nested single-key dicts (depth == levels)."""
    out: object = "x"
    for _ in range(levels):
        out = {"k": out}
    assert isinstance(out, dict)
    return out


# ------------------------------------------------------------------ Escape 1


class TestEscape1BypassContained:
    def test_model_construct_blocked(self):
        with pytest.raises(TypeError):
            Incident.model_construct(fingerprint="x", severity="P1")  # type: ignore

    def test_model_construct_blocked_no_args(self):
        with pytest.raises(TypeError):
            Incident.model_construct()  # type: ignore

    def test_normal_construction_still_validates(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P0")  # type: ignore
        inc = Incident(fingerprint="f", severity="P1")
        assert inc.severity is C.Severity.P1

    def test_validate_paths_enforce(self):
        inc = Incident(fingerprint="f", severity="P1")
        with pytest.raises(ValidationError):
            Incident.model_validate({"fingerprint": "f", "severity": "P0"})
        with pytest.raises(ValidationError):
            Incident.model_validate_json('{"fingerprint": "f", "severity": "P0"}')
        assert Incident.model_validate(inc.model_dump()) == inc

    def test_revalidation_catches_tampered_instance(self):
        # Honest residual: in-process memory tampering (object.__setattr__)
        # cannot be prevented by any Python-level contract. The containment
        # is re-validation at the trust boundary, proven here.
        inc = Incident(fingerprint="f", severity="P1")
        object.__setattr__(inc, "severity", "GARBAGE")
        assert inc.severity == "GARBAGE"  # tamper happened (framework-level)
        with pytest.raises(ValidationError):
            Incident.model_validate(inc.model_dump())  # boundary rejects it

    def test_model_copy_update_invalid_rejected(self):
        inc = Incident(fingerprint="f", severity="P1")
        with pytest.raises(ValidationError):
            inc.model_copy(update={"severity": "GARBAGE"})
        with pytest.raises(ValidationError):
            inc.model_copy(update={"unknown_field": "x"})

    def test_model_copy_update_valid_works(self):
        inc = Incident(fingerprint="f", severity="P1")
        moved = inc.model_copy(update={"service": "web", "status": "CORRELATED"})
        assert moved.service == "web"
        assert moved.status is C.IncidentStatus.CORRELATED
        assert moved.fingerprint == "f"  # untouched fields preserved
        assert inc.service == "unknown"  # original untouched

    def test_model_copy_plain_and_deep(self):
        inc = Incident(fingerprint="f", severity="P1", source_alert_ids=["a1"],
                       metadata={"m": {"n": [1, 2]}})
        assert inc.model_copy() == inc
        assert inc.model_copy(deep=True) == inc

    def test_pickle_roundtrip_after_hardening(self):
        inc = Incident(fingerprint="f", severity="P1", source_alert_ids=["a1"],
                       impact={"a": [1]}, metadata={"m": {"n": 1}})
        assert pickle.loads(pickle.dumps(inc)) == inc


class TestStaticAudit:
    APP_DIRS = ("backend", "telemetry", "scripts", "tools", "agents")

    def _py_files(self):
        for d in self.APP_DIRS:
            root = ROOT / d
            if root.is_dir():
                yield from sorted(root.rglob("*.py"))

    def test_no_model_construct_in_app_code(self):
        offenders = []
        for path in self._py_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "model_construct":
                    offenders.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
        assert offenders == [], f"model_construct used in app code: {offenders}"

    def test_no_object_setattr_in_app_code_except_known_sites(self):
        # object.__setattr__ defeats frozen models. New sites in app code are
        # forbidden; the only tolerated sites are pinned below with rationale.
        # None of them constructs or mutates an Incident.
        allowed = {
            # frozen-value-object construction (M01.2-owned, this hardening)
            ("backend/app/contracts/incident.py", ("FrozenDict", "__new__")),
            # M00.2-frozen: Settings fills its own DATABASE_URL default
            ("backend/app/config.py", ("Settings", "_cross_field_rules")),
            # M02-M04 REMOVED the legacy normalizer object.__setattr__ bypass
            # (Alert ts/hash fixup): the rewired normalizer builds canonical
            # Alerts via validated construction only. The entry is deleted,
            # not relaxed - any new site still fails this test.
        }
        found = set()
        for path in self._py_files():
            rel = path.relative_to(ROOT).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))

            class Visitor(ast.NodeVisitor):
                def __init__(self) -> None:
                    self.stack: list[str] = []

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    self.stack.append(node.name)
                    self.generic_visit(node)
                    self.stack.pop()

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    self.stack.append(node.name)
                    self.generic_visit(node)
                    self.stack.pop()

                def visit_Attribute(self, node: ast.Attribute) -> None:
                    if (node.attr == "__setattr__" and isinstance(node.value, ast.Name)
                            and node.value.id == "object"):
                        found.add((rel, tuple(self.stack)))
                    self.generic_visit(node)

            Visitor().visit(tree)
        assert found == allowed, f"object.__setattr__ sites changed: {sorted(found)}"

    def test_single_incident_definition(self):
        defs = []
        for path in self._py_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "Incident":
                    defs.append(path.relative_to(ROOT).as_posix())
        assert defs == ["backend/app/contracts/incident.py"], f"duplicate Incident: {defs}"

    def test_no_enum_definitions_outside_contract_enums(self):
        offenders = []
        for path in self._py_files():
            if path.name == "enums.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    bases = {getattr(b, "id", None) or getattr(b, "attr", None) for b in node.bases}
                    if bases & {"Enum", "StrEnum"}:
                        offenders.append(f"{path.relative_to(ROOT)}:{node.name}")
        assert offenders == [], f"duplicate domain enums: {offenders}"

    def test_no_mutable_bare_defaults_in_incident(self):
        src = (ROOT / "backend" / "app" / "contracts" / "incident.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "Field":
                for kw in node.keywords:
                    if kw.arg == "default" and isinstance(kw.value, (ast.Dict, ast.List, ast.Set)):
                        offenders.append(f"Field(default=<mutable>:{node.lineno})")
        assert offenders == [], f"mutable bare defaults: {offenders}"

    def test_string_fields_carry_max_length(self):
        from annotated_types import MaxLen  # noqa: E402 (pydantic dependency)

        pinned = {
            "incident_id": MAX_INCIDENT_ID_LEN,
            "fingerprint": MAX_FINGERPRINT_LEN,
            "service": MAX_SERVICE_LEN,
            "diagnosis_reference": MAX_DIAGNOSIS_REF_LEN,
        }
        for name, expected in pinned.items():
            field = Incident.model_fields[name]
            caps = [m for m in field.metadata if isinstance(m, MaxLen)]
            assert len(caps) == 1 and caps[0].max_length == expected, f"{name} max_length drifted"

    def test_contract_shape_frozen(self):
        assert set(Incident.model_fields) == {
            "incident_id", "status", "severity", "service", "environment",
            "impact", "fingerprint", "created_at", "updated_at", "detected_at",
            "resolved_at", "source_alert_ids", "evidence_ids",
            "diagnosis_reference", "action_references", "metadata",
        }

    def test_limit_constants_pinned(self):
        assert (MAX_INCIDENT_ID_LEN, MAX_FINGERPRINT_LEN, MAX_SERVICE_LEN) == (128, 128, 128)
        assert (MAX_ID_ITEM_LEN, MAX_ID_LIST_ITEMS, MAX_DIAGNOSIS_REF_LEN) == (128, 100, 128)
        assert (MAX_IMPACT_ENTRIES, MAX_IMPACT_JSON_BYTES) == (32, 4096)
        assert (MAX_METADATA_ENTRIES, MAX_METADATA_KEY_LEN) == (64, 128)
        assert (MAX_METADATA_DEPTH, MAX_METADATA_JSON_BYTES) == (5, 16384)


# ------------------------------------------------------------------ Escape 2


class TestEscape2MutationSuite:
    def _victim(self) -> Incident:
        return Incident(
            fingerprint="f",
            severity="P1",
            impact={"error_rate": 0.18, "tags": ["critical"], "deep": {"n": [1]}},
            source_alert_ids=["a1", "a2"],
            metadata={"owner": "sre", "nested": {"z": 1}, "lst": [{"k": "v"}]},
        )

    def test_impact_item_assignment_fails(self):
        inc = self._victim()
        with pytest.raises(TypeError):
            inc.impact["x"] = "evil"  # type: ignore
        assert "x" not in inc.impact
        assert inc.impact == {"error_rate": 0.18, "tags": ["critical"], "deep": {"n": [1]}}

    def test_source_alert_ids_append_fails(self):
        inc = self._victim()
        with pytest.raises(AttributeError):
            inc.source_alert_ids.append("evil")  # type: ignore
        assert inc.source_alert_ids == ("a1", "a2")

    def test_metadata_item_assignment_fails(self):
        inc = self._victim()
        with pytest.raises(TypeError):
            inc.metadata["x"] = "evil"  # type: ignore
        assert "x" not in inc.metadata

    def test_nested_dict_mutation_fails(self):
        inc = self._victim()
        with pytest.raises(TypeError):
            inc.metadata["nested"]["z"] = "evil"  # type: ignore
        with pytest.raises(TypeError):
            inc.impact["deep"]["n"] = "evil"  # type: ignore
        assert inc.metadata["nested"] == {"z": 1}

    def test_nested_list_mutation_fails(self):
        inc = self._victim()
        with pytest.raises(AttributeError):
            inc.impact["tags"].append("evil")  # type: ignore
        with pytest.raises(AttributeError):
            inc.impact["deep"]["n"].append(999)  # type: ignore
        with pytest.raises(TypeError):
            inc.metadata["lst"][0]["k"] = "evil"  # type: ignore
        assert inc.impact["tags"] == ("critical",)

    def test_attribute_reassignment_still_blocked(self):
        inc = self._victim()
        for field, value in (("severity", C.Severity.P2), ("fingerprint", "g"),
                             ("service", "api"), ("impact", {}), ("metadata", {}),
                             ("source_alert_ids", ())):
            with pytest.raises(ValidationError):
                setattr(inc, field, value)

    def test_copy_mutation_cannot_reach_stored_state(self):
        inc = self._victim()
        clone = inc.model_copy(deep=True)
        assert clone == inc
        with pytest.raises(TypeError):
            clone.impact["x"] = "evil"  # type: ignore
        with pytest.raises(AttributeError):
            clone.source_alert_ids.append("evil")  # type: ignore
        assert inc.impact == clone.impact and inc.source_alert_ids == clone.source_alert_ids

    def test_model_dump_mutation_detached(self):
        inc = self._victim()
        for mode in ("python", "json"):
            dumped = inc.model_dump(mode=mode)  # type: ignore
            dumped["impact"]["error_rate"] = "evil"
            dumped["impact"]["tags"].append("evil")
            dumped["metadata"]["nested"]["z"] = "evil"
            dumped["source_alert_ids"].append("evil")
            assert inc.impact["error_rate"] == 0.18
            assert inc.impact["tags"] == ("critical",)
            assert inc.metadata["nested"] == {"z": 1}
            assert inc.source_alert_ids == ("a1", "a2")
            # a second dump is unaffected by the first dump's mutation
            fresh = inc.model_dump(mode=mode)  # type: ignore
            assert fresh["impact"]["error_rate"] == 0.18
            assert fresh["source_alert_ids"] == ["a1", "a2"]

    def test_dump_returns_fresh_containers_each_call(self):
        inc = self._victim()
        first = inc.model_dump()
        second = inc.model_dump()
        assert first["impact"] is not second["impact"]
        assert first["metadata"] is not second["metadata"]
        assert first["source_alert_ids"] is not second["source_alert_ids"]
        assert type(first["source_alert_ids"]) is list
        assert type(first["impact"]) is dict and type(first["metadata"]) is dict

    def test_construction_never_aliases_inputs(self):
        ids = ["a1"]
        tup = ("b1",)
        impact = {"tags": ["x"], "deep": {"n": 1}}
        meta = {"lst": [{"k": 1}]}
        inc = Incident(fingerprint="f", severity="P1", source_alert_ids=ids,
                       impact=impact, metadata=meta)
        ids.append("evil")
        impact["tags"].append("evil")
        impact["deep"]["n"] = "evil"
        meta["lst"][0]["k"] = "evil"
        assert inc.source_alert_ids == ("a1",)
        assert inc.impact == {"tags": ["x"], "deep": {"n": 1}}
        assert inc.metadata == {"lst": [{"k": 1}]}
        # tuple input accepted (already immutable: sharing is safe)
        inc2 = Incident(fingerprint="f", severity="P1", source_alert_ids=tup)
        assert inc2.source_alert_ids == ("b1",)


class TestFrozenDictContract:
    def test_reads(self):
        fd = FrozenDict({"a": 1, "n": {"x": [1, 2]}})
        assert fd["a"] == 1
        assert len(fd) == 2
        assert set(iter(fd)) == {"a", "n"}
        assert "a" in fd and "zzz" not in fd
        assert fd.get("a") == 1 and fd.get("zzz") is None and fd.get("zzz", 7) == 7
        assert dict(fd.items())["a"] == 1
        assert set(fd.keys()) == {"a", "n"}

    def test_writes_blocked(self):
        fd = FrozenDict({"a": 1})
        with pytest.raises(TypeError):
            fd["b"] = 2  # type: ignore
        with pytest.raises(TypeError):
            del fd["a"]  # type: ignore
        with pytest.raises(TypeError):
            fd.new_attr = 1  # type: ignore
        with pytest.raises(AttributeError):
            fd.append("x")  # type: ignore

    def test_equality_plain_and_frozen(self):
        assert FrozenDict({"x": [1, 2], "y": {"z": 1}}) == {"x": [1, 2], "y": {"z": 1}}
        assert {"x": [1, 2]} == FrozenDict({"x": [1, 2]})
        assert FrozenDict({"a": 1}) == FrozenDict({"a": 1})
        assert FrozenDict({"a": 1}) != {"a": 2}
        assert FrozenDict({}) == {}

    def test_copy_pickle_detached(self):
        fd = FrozenDict({"a": {"n": [1]}})
        assert copy.copy(fd) is fd  # immutable: sharing is safe
        assert copy.deepcopy(fd) == fd and copy.deepcopy(fd).to_plain() == {"a": {"n": [1]}}
        assert pickle.loads(pickle.dumps(fd)) == fd

    def test_to_plain_is_fresh_and_json_native(self):
        fd = FrozenDict({"a": {"n": [1, 2]}})
        plain = fd.to_plain()
        assert plain == {"a": {"n": [1, 2]}}
        assert type(plain["a"]) is dict and type(plain["a"]["n"]) is list
        plain["a"]["n"].append(999)
        assert fd == {"a": {"n": [1, 2]}}


# ------------------------------------------------------------------ Escape 3


class TestEscape3BoundaryMatrix:
    @pytest.mark.parametrize(("field", "max_len"), [
        ("incident_id", MAX_INCIDENT_ID_LEN),
        ("fingerprint", MAX_FINGERPRINT_LEN),
        ("service", MAX_SERVICE_LEN),
        ("diagnosis_reference", MAX_DIAGNOSIS_REF_LEN),
    ])
    def test_string_boundaries(self, field: str, max_len: int):
        def build(value: str) -> Incident:
            kw: dict = {"severity": "P1", field: value}
            if field != "fingerprint":
                kw["fingerprint"] = "f"
            return Incident(**kw)

        assert build("v").model_dump()
        assert build("v" * (max_len - 1))
        assert build("v" * max_len)
        with pytest.raises(ValidationError):
            build("v" * (max_len + 1))
        with pytest.raises(ValidationError):
            build("")
        with pytest.raises(ValidationError):
            build("v" * 10_000)

    def test_zero_and_one_lengths(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="", severity="P1")
        assert Incident(fingerprint="x", severity="P1").fingerprint == "x"

    def test_list_item_boundaries(self):
        ok_item = "a" * MAX_ID_ITEM_LEN
        assert Incident(fingerprint="f", severity="P1", source_alert_ids=[ok_item])
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1",
                     source_alert_ids=["a" * (MAX_ID_ITEM_LEN + 1)])

    @pytest.mark.parametrize("field", ["source_alert_ids", "evidence_ids", "action_references"])
    def test_list_count_boundaries(self, field: str):
        assert Incident(fingerprint="f", severity="P1", **{field: []})
        assert Incident(fingerprint="f", severity="P1", **{field: ["a"]})
        many = [f"id-{i}" for i in range(MAX_ID_LIST_ITEMS)]
        assert len(Incident(fingerprint="f", severity="P1", **{field: many}).model_dump()[field]) == MAX_ID_LIST_ITEMS
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", **{field: many + ["one-more"]})

    def test_metadata_entry_count_boundaries(self):
        ok = {f"k{i}": i for i in range(MAX_METADATA_ENTRIES)}
        assert len(Incident(fingerprint="f", severity="P1", metadata=ok).metadata) == MAX_METADATA_ENTRIES
        bad = dict(ok)
        bad["overflow"] = 1
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata=bad)

    def test_impact_entry_count_boundaries(self):
        ok = {f"k{i}": i for i in range(MAX_IMPACT_ENTRIES)}
        assert Incident(fingerprint="f", severity="P1", impact=ok)
        bad = dict(ok)
        bad["overflow"] = 1
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", impact=bad)

    def test_metadata_key_length_boundaries(self):
        assert Incident(fingerprint="f", severity="P1", metadata={"k" * MAX_METADATA_KEY_LEN: 1})
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata={"k" * (MAX_METADATA_KEY_LEN + 1): 1})

    def test_metadata_depth_boundaries(self):
        assert Incident(fingerprint="f", severity="P1", metadata=_nested(MAX_METADATA_DEPTH - 1))
        assert Incident(fingerprint="f", severity="P1", metadata=_nested(MAX_METADATA_DEPTH))
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata=_nested(MAX_METADATA_DEPTH + 1))
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata=_nested(50))

    def test_metadata_non_string_key_rejected(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata={1: "x"})  # type: ignore

    def test_metadata_non_object_rejected(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata=["x"])  # type: ignore
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", impact=None)  # type: ignore

    def test_metadata_json_byte_boundaries(self):
        pad = MAX_METADATA_JSON_BYTES - 8  # canonical '{"k":"<pad>"}' == MAX exactly
        blob = {"k": "x" * pad}
        assert len(canonical_json(blob).encode("utf-8")) == MAX_METADATA_JSON_BYTES
        assert Incident(fingerprint="f", severity="P1", metadata={"k": "x" * (pad - 1)})
        assert Incident(fingerprint="f", severity="P1", metadata=blob)
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata={"k": "x" * (pad + 1)})

    def test_impact_json_byte_boundaries(self):
        pad = MAX_IMPACT_JSON_BYTES - 8
        assert Incident(fingerprint="f", severity="P1", impact={"k": "x" * (pad - 1)})
        assert Incident(fingerprint="f", severity="P1", impact={"k": "x" * pad})
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", impact={"k": "x" * (pad + 1)})

    def test_small_normal_large_shapes(self):
        assert Incident(fingerprint="f", severity="P1")  # small
        normal = Incident(  # normal operational shape
            fingerprint="abc123", severity="P2", service="checkout", environment="prod",
            impact={"error_rate": 0.18, "replicas": 3}, source_alert_ids=["a1", "a2"],
            metadata={"owner": "sre", "runbook": "bad-deploy-rollback"})
        assert normal.service == "checkout"
        big_ok = {"k": "x" * 10_000}  # large-but-within-ceiling (~10 KiB of 16 KiB)
        assert Incident(fingerprint="f", severity="P1", metadata=big_ok)


# ------------------------------------------------------------------ Escape 4


class TestEscape4Whitespace:
    @pytest.mark.parametrize(("field", "max_len"), [
        ("incident_id", MAX_INCIDENT_ID_LEN),
        ("fingerprint", MAX_FINGERPRINT_LEN),
        ("service", MAX_SERVICE_LEN),
        ("diagnosis_reference", MAX_DIAGNOSIS_REF_LEN),
    ])
    def test_scalar_whitespace_matrix(self, field: str, max_len: int):
        def build(value: str) -> Incident:
            kw: dict = {"severity": "P1", field: value}
            if field != "fingerprint":
                kw["fingerprint"] = "f"
            return Incident(**kw)

        assert build("a1")
        assert build("a 1")  # interior ok
        for padded in (" a1", "a1 ", "  a1  ", "\ta1", "a1\n", "   ", ""):
            with pytest.raises(ValidationError):
                build(padded)

    @pytest.mark.parametrize("field", ["source_alert_ids", "evidence_ids", "action_references"])
    def test_list_item_whitespace_matrix(self, field: str):
        assert Incident(fingerprint="f", severity="P1", **{field: ["a1", "b 2"]})
        for padded in (" a1", "a1 ", "  a1  ", "   ", ""):
            with pytest.raises(ValidationError):
                Incident(fingerprint="f", severity="P1", **{field: [padded]})
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", **{field: ["ok", " bad"]})

    def test_mapping_keys_padded_rejected_values_preserved(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata={" owner": "sre"})
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", impact={"rate ": 1})
        # free-form payload VALUES are preserved as-is (documented split)
        inc = Incident(fingerprint="f", severity="P1",
                       metadata={"note": " has padding "}, impact={"msg": " trailing "})
        assert inc.metadata["note"] == " has padding "
        assert inc.impact["msg"] == " trailing "


# ------------------------------------------------------- serialization proof


class TestSerializationWireCompat:
    GOLDEN_MINIMAL_JSON = (
        '{"incident_id":"00000000000000000000000000000001","status":"NEW",'
        '"severity":"P1","service":"unknown","environment":"mock","impact":{},'
        '"fingerprint":"f","created_at":"2026-01-01T10:00:00Z",'
        '"updated_at":"2026-01-01T10:00:00Z","detected_at":null,"resolved_at":null,'
        '"source_alert_ids":[],"evidence_ids":[],"diagnosis_reference":null,'
        '"action_references":[],"metadata":{}}'
    )
    GOLDEN_FULL_JSON = (
        '{"incident_id":"inc-golden-1","status":"CORRELATED","severity":"P2",'
        '"service":"checkout","environment":"prod",'
        '"impact":{"replicas":3,"error_rate":0.18,"tags":["critical","slo"]},'
        '"fingerprint":"abc123def456","created_at":"2026-01-01T10:00:00Z",'
        '"updated_at":"2026-01-01T11:00:00Z","detected_at":"2026-01-01T09:30:00Z",'
        '"resolved_at":"2026-01-01T12:00:00Z","source_alert_ids":["a1","a2"],'
        '"evidence_ids":["ev-1"],"diagnosis_reference":"diag-1",'
        '"action_references":["act-1","act-2"],'
        '"metadata":{"owner":"sre","nested":{"z":1}}}'
    )
    GOLDEN_UNICODE_JSON = (
        '{"incident_id":"00000000000000000000000000000002","status":"NEW",'
        '"severity":"P3","service":"web","environment":"mock","impact":{},'
        '"fingerprint":"fp-unicode","created_at":"2026-01-01T10:00:00Z",'
        '"updated_at":"2026-01-01T10:00:00Z","detected_at":null,"resolved_at":null,'
        '"source_alert_ids":[],"evidence_ids":[],"diagnosis_reference":null,'
        '"action_references":[],"metadata":{"note":"d\u00e9ploiement \u00e9chou\u00e9 \u2014 \u65e5\u672c\u8a9e"}}'
    )

    def _full_kwargs(self, **over):
        base = dict(
            incident_id="inc-golden-1", status="CORRELATED", severity="P2",
            service="checkout", environment="prod",
            impact={"replicas": 3, "error_rate": 0.18, "tags": ["critical", "slo"]},
            fingerprint="abc123def456",
            created_at=_utc(2026, 1, 1, 10), updated_at=_utc(2026, 1, 1, 11),
            detected_at=_utc(2026, 1, 1, 9, 30), resolved_at=_utc(2026, 1, 1, 12),
            source_alert_ids=["a1", "a2"], evidence_ids=["ev-1"],
            diagnosis_reference="diag-1", action_references=["act-1", "act-2"],
            metadata={"owner": "sre", "nested": {"z": 1}},
        )
        base.update(over)
        return base

    def test_golden_minimal_wire_identical(self):
        inc = Incident(fingerprint="f", severity="P1",
                       incident_id="00000000000000000000000000000001",
                       created_at=_utc(), updated_at=_utc())
        assert inc.model_dump_json() == self.GOLDEN_MINIMAL_JSON

    def test_golden_full_wire_identical(self):
        assert Incident(**self._full_kwargs()).model_dump_json() == self.GOLDEN_FULL_JSON

    def test_golden_unicode_wire_identical(self):
        inc = Incident(fingerprint="fp-unicode", severity="P3", service="web",
                       incident_id="00000000000000000000000000000002",
                       created_at=_utc(), updated_at=_utc(),
                       metadata={"note": "d\u00e9ploiement \u00e9chou\u00e9 \u2014 \u65e5\u672c\u8a9e"})
        assert inc.model_dump_json() == self.GOLDEN_UNICODE_JSON

    def test_golden_full_json_mode_dict(self):
        dumped = Incident(**self._full_kwargs()).model_dump(mode="json")
        assert dumped == json.loads(self.GOLDEN_FULL_JSON)

    def test_roundtrips_stable(self):
        for kwargs in (dict(fingerprint="f", severity="P1"),
                       self._full_kwargs(),
                       dict(fingerprint="fp-u", severity="P4", metadata={"n": "v"})):
            inc = Incident(**kwargs)
            assert Incident.model_validate_json(inc.model_dump_json()) == inc
            assert Incident.model_validate(inc.model_dump()) == inc
            assert C.Incident.model_validate_json(inc.model_dump_json()) == inc

    def test_enum_wire_values(self):
        dumped = json.loads(Incident(fingerprint="f", severity="P1").model_dump_json())
        assert (dumped["severity"], dumped["environment"], dumped["status"]) == ("P1", "mock", "NEW")

    def test_timestamps_wire_shape(self):
        inc = Incident(fingerprint="f", severity="P1", created_at=_utc(), updated_at=_utc())
        dumped = json.loads(inc.model_dump_json())
        assert dumped["created_at"] == "2026-01-01T10:00:00Z"
        back = Incident.model_validate_json(inc.model_dump_json())
        assert back.created_at == inc.created_at and back.created_at.tzinfo is not None

    def test_all_statuses_roundtrip(self):
        for status in C.FSM_STATES:
            inc = Incident(fingerprint="f", severity="P1", status=status)
            assert Incident.model_validate_json(inc.model_dump_json()).status.value == status

    def test_python_dump_shape_documented(self):
        dumped = Incident(fingerprint="f", severity="P1",
                          source_alert_ids=["a1"], impact={"k": [1]}).model_dump()
        # python-mode dump exposes plain detached containers (never FrozenDict/tuple)
        assert type(dumped["source_alert_ids"]) is list
        assert type(dumped["impact"]) is dict
        assert type(dumped["metadata"]) is dict
        assert dumped["severity"] is C.Severity.P1  # enums stay typed in python mode

    def test_json_schema_generates(self):
        schema = Incident.model_json_schema()
        assert schema["type"] == "object"
        for prop in ("impact", "metadata"):
            assert schema["properties"][prop]["type"] == "object"
            assert schema["properties"][prop]["additionalProperties"] is True


# ------------------------------------------------------------- security/hostile


class TestSecurityHostilePayloads:
    def test_extremely_large_fingerprint_rejected(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f" * 100_000, severity="P1")

    def test_huge_service_name_rejected(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", service="s" * 5_000)

    def test_huge_metadata_value_rejected(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata={"blob": "x" * 100_000})

    def test_huge_metadata_entry_count_rejected_fast(self):
        start = time.perf_counter()
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata={f"k{i}": i for i in range(10_000)})
        assert time.perf_counter() - start < 5.0

    def test_nested_metadata_explosion_rejected(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", metadata=_nested(50))
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1",
                     metadata={"a": [{"b": [{"c": [{"d": ["x" * 5000]}]}]}]})

    def test_malicious_whitespace_identifiers_rejected(self):
        for bad in ("a1 ", " a1", "\u00a0a1", "a1\u2003"):
            with pytest.raises(ValidationError):
                Incident(fingerprint="f", severity="P1", source_alert_ids=[bad])

    def test_invalid_enum_timestamp_id_rejected(self):
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P0")  # type: ignore
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", status="HEALED")  # type: ignore
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", environment="production")  # type: ignore
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1",
                     created_at=datetime(2026, 1, 1, 10, 0, 0))  # naive
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", incident_id="   ")
        with pytest.raises(ValidationError):
            Incident(fingerprint="f", severity="P1", extra="injected")  # type: ignore


# ----------------------------------------------------------------- performance


class TestPerformanceValidationCost:
    def test_small_cost(self):
        start = time.perf_counter()
        for _ in range(200):
            Incident(fingerprint="f", severity="P1")
        assert (time.perf_counter() - start) / 200 < 0.05

    def test_normal_cost(self):
        kwargs = dict(
            fingerprint="abc123", severity="P2", service="checkout", environment="prod",
            impact={"error_rate": 0.18, "replicas": 3, "tags": ["a", "b"]},
            source_alert_ids=[f"a{i}" for i in range(10)],
            metadata={"owner": "sre", "nested": {"z": [1, 2, 3]}})
        start = time.perf_counter()
        for _ in range(200):
            Incident(**kwargs)
        assert (time.perf_counter() - start) / 200 < 0.05

    def test_large_rejected_fast(self):
        start = time.perf_counter()
        with pytest.raises(ValidationError):
            Incident(fingerprint="f" * 100_000, severity="P1")
        assert time.perf_counter() - start < 1.0

    def test_dump_cost(self):
        inc = Incident(fingerprint="f", severity="P1", metadata={"k": "v" * 1000})
        start = time.perf_counter()
        for _ in range(200):
            inc.model_dump_json()
        assert (time.perf_counter() - start) / 200 < 0.05


# --------------------------------------------------------------- integration


class TestIntegrationCorrelatorHardened:
    def test_bad_deploy_normal_one_valid_incident(self):
        sys.path.insert(0, str(ROOT / "telemetry"))
        sys.path.insert(0, str(ROOT / "backend"))
        from app.services.correlator import correlate  # noqa: E402
        import gen  # noqa: E402

        bundle = gen.generate("bad-deploy", "NORMAL", 3)
        incidents = correlate(bundle["alerts"], bundle["deploys"], bundle["metrics"], bundle["topology"])
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.fingerprint and len(inc.fingerprint) <= MAX_FINGERPRINT_LEN
        assert inc.severity is C.Severity.P1
        assert inc.status is C.IncidentStatus.CORRELATED
        # M02-M04 rewire: the correlator populates linkage from the alerts
        # (service/environment/source ids); "unknown"/MOCK was the legacy
        # unwired default, not a contract promise.
        assert inc.service == "web" and inc.environment is C.Environment.PROD
        assert isinstance(inc.source_alert_ids, tuple)
        assert len(inc.source_alert_ids) == 4
        assert isinstance(inc.impact, FrozenDict) and isinstance(inc.metadata, FrozenDict)
        assert inc.incident_id and inc.created_at.tzinfo is not None
        json.loads(inc.model_dump_json())  # wire-serializable
