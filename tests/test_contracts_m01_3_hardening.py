"""M01.3 zero-trust hardening: escapes 1-4, mutation suite, boundaries, audit.

Proves the four verified escapes from the forensic baseline are closed:
- Escape 1: model_construct bypass BLOCKED (+ model_copy(update) sibling),
  with AST scan forbidding bypass APIs in application code.
- Escape 2: shallow frozen containers replaced by deep immutability
  (FrozenDict for labels/metadata); every mutation vector covered.
- Escape 3: explicit documented bounds on every string/container field,
  tested at max-1 / max / max+1.
- Escape 4: reject-if-padded whitespace rule, uniform across identifiers;
  free-form message preserved verbatim but non-blank.

Also: serialization wire-compat proof, hostile payloads, validation-cost
measurements, legacy + M01.1/M01.2 compatibility, aliasing protection.
"""
from __future__ import annotations

import ast
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
from app.contracts.alert import (  # noqa: E402
    ALERT_STATUSES,
    MAX_ALERT_ID_LEN,
    MAX_FINGERPRINT_LEN,
    MAX_LABEL_KEY_LEN,
    MAX_LABEL_VALUE_LEN,
    MAX_LABELS_BYTES,
    MAX_LABELS_COUNT,
    MAX_MESSAGE_LEN,
    MAX_METADATA_BYTES,
    MAX_METADATA_COUNT,
    MAX_METADATA_KEY_LEN,
    MAX_METADATA_STR_LEN,
    MAX_NESTING_DEPTH,
    MAX_RESOURCE_LEN,
    MAX_SERVICE_LEN,
    MAX_SOURCE_LEN,
    MAX_STATUS_LEN,
    Alert,
)
from app.contracts.incident import FrozenDict  # noqa: E402
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


def valid_kwargs(**over: object) -> dict:
    base: dict = dict(
        source="prometheus",
        service="web",
        resource="default/web-7d9f",
        severity="P2",
        message="error rate above threshold",
        fingerprint="fp-" + "a" * 61,
        environment="mock",
        status="firing",
        labels={"team": "payments"},
        metadata={"runbook_hint": "bad-deploy"},
    )
    base.update(over)
    return base


# ------------------------------------------------------------------ Escape 1


class TestEscape1BypassContained:
    def test_model_construct_blocked(self):
        with pytest.raises(TypeError):
            Alert.model_construct(source="x", service="y", severity="P1", message="m", fingerprint="fp")  # type: ignore

    def test_model_construct_blocked_no_args(self):
        with pytest.raises(TypeError):
            Alert.model_construct()  # type: ignore

    def test_normal_construction_still_validates(self):
        with pytest.raises(ValidationError):
            Alert(source="x", service="y", severity="P0", message="m", fingerprint="fp")  # type: ignore
        a = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp")
        assert a.severity is C.Severity.P1

    def test_validate_paths_enforce(self):
        a = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp")
        with pytest.raises(ValidationError):
            Alert.model_validate({"source": "x", "service": "y", "severity": "P0", "message": "m", "fingerprint": "fp"})
        with pytest.raises(ValidationError):
            Alert.model_validate_json('{"source":"x","service":"y","severity":"P0","message":"m","fingerprint":"fp"}')
        assert Alert.model_validate(a.model_dump()) == a

    def test_revalidation_catches_tampered_instance(self):
        # Honest residual: in-process memory tampering (object.__setattr__)
        # cannot be prevented by any Python-level contract. The containment
        # is re-validation at the trust boundary, proven here.
        a = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp")
        object.__setattr__(a, "severity", "GARBAGE")
        assert a.severity == "GARBAGE"  # tamper happened (framework-level)
        with pytest.raises(ValidationError):
            Alert.model_validate(a.model_dump())  # boundary rejects it

    def test_model_copy_update_invalid_rejected(self):
        a = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp")
        with pytest.raises(ValidationError):
            a.model_copy(update={"severity": "GARBAGE"})
        with pytest.raises(ValidationError):
            a.model_copy(update={"unknown_field": "x"})
        with pytest.raises(ValidationError):
            a.model_copy(update={"source": " bad"})
        with pytest.raises(ValidationError):
            a.model_copy(update={"message": "   "})
        with pytest.raises(ValidationError):
            a.model_copy(update={"fingerprint": "f" * (MAX_FINGERPRINT_LEN + 1)})
        with pytest.raises(ValidationError):
            a.model_copy(update={"timestamp": datetime(2026, 1, 1, 10, 0, 0)})

    def test_model_copy_update_valid_works(self):
        a = Alert(source="prometheus", service="web", severity="P1", message="hi", fingerprint="fp1")
        moved = a.model_copy(update={"service": "api", "message": "new message", "status": "acknowledged"})
        assert moved.service == "api"
        assert moved.message == "new message"
        assert moved.status == "acknowledged"
        assert moved.fingerprint == "fp1"  # untouched fields preserved
        assert a.service == "web"  # original untouched

    def test_model_copy_plain_and_deep(self):
        a = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp",
                  labels={"k": "v"}, metadata={"m": {"n": [1, 2]}})
        assert a.model_copy() == a
        assert a.model_copy(deep=True) == a

    def test_pickle_roundtrip_after_hardening(self):
        a = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp",
                  labels={"k": "v"}, metadata={"m": {"n": 1}})
        assert pickle.loads(pickle.dumps(a)) == a


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
        # None of them constructs or mutates an Alert.
        allowed = {
            # frozen-value-object construction (M01.2-owned, this hardening reuses it)
            ("backend/app/contracts/incident.py", ("FrozenDict", "__new__")),
            # M00.2-frozen: Settings fills its own DATABASE_URL default
            ("backend/app/config.py", ("Settings", "_cross_field_rules")),
            # legacy T-series (unwired): Alert ts/hash fixup, predates M01.2
            ("backend/app/services/normalizer.py", ("normalize_alert",)),
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

    def test_single_alert_definition(self):
        defs = []
        for path in self._py_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "Alert":
                    defs.append(path.relative_to(ROOT).as_posix())
        # Only canonical + legacy schemas: same as M01.2 Incident rule
        # (legacy is allowed, any third is duplicate)
        assert defs == ["backend/app/contracts/alert.py", "backend/app/schemas.py"], f"duplicate Alert: {defs}"

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

    def test_no_mutable_bare_defaults_in_alert(self):
        src = (ROOT / "backend" / "app" / "contracts" / "alert.py").read_text(encoding="utf-8")
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
            "alert_id": MAX_ALERT_ID_LEN,
            "source": MAX_SOURCE_LEN,
            "service": MAX_SERVICE_LEN,
            "resource": MAX_RESOURCE_LEN,
            "message": MAX_MESSAGE_LEN,
            "fingerprint": MAX_FINGERPRINT_LEN,
            "status": MAX_STATUS_LEN,
        }
        for name, expected in pinned.items():
            field = Alert.model_fields[name]
            caps = [m for m in field.metadata if isinstance(m, MaxLen)]
            assert len(caps) == 1 and caps[0].max_length == expected, f"{name} max_length drifted"

    def test_contract_shape_frozen(self):
        assert set(Alert.model_fields) == {
            "alert_id", "source", "timestamp", "service", "resource",
            "severity", "message", "labels", "fingerprint", "environment",
            "status", "metadata",
        }

    def test_limit_constants_pinned(self):
        assert (MAX_ALERT_ID_LEN, MAX_SOURCE_LEN, MAX_SERVICE_LEN) == (128, 64, 128)
        assert (MAX_RESOURCE_LEN, MAX_MESSAGE_LEN, MAX_FINGERPRINT_LEN) == (256, 4096, 128)
        assert (MAX_LABELS_COUNT, MAX_LABEL_KEY_LEN, MAX_LABEL_VALUE_LEN) == (32, 128, 1024)
        assert (MAX_METADATA_COUNT, MAX_METADATA_KEY_LEN, MAX_METADATA_STR_LEN) == (32, 128, 4096)
        assert (MAX_LABELS_BYTES, MAX_METADATA_BYTES, MAX_NESTING_DEPTH) == (8192, 16384, 4)
        assert len(ALERT_STATUSES) == 4 and set(ALERT_STATUSES) == {"firing", "acknowledged", "silenced", "resolved"}


# ------------------------------------------------------------------ Escape 2


class TestEscape2MutationSuite:
    def _victim(self) -> Alert:
        return Alert(
            source="prometheus",
            service="web",
            severity="P1",
            message="disk pressure",
            fingerprint="fp-victim-1",
            labels={"team": "payments", "tier": "frontend"},
            metadata={"owner": "sre", "nested": {"z": 1}, "lst": [{"k": "v"}], "tags": ["critical"]},
        )

    def test_labels_item_assignment_fails(self):
        a = self._victim()
        with pytest.raises(TypeError):
            a.labels["x"] = "evil"  # type: ignore
        assert "x" not in a.labels

    def test_metadata_item_assignment_fails(self):
        a = self._victim()
        with pytest.raises(TypeError):
            a.metadata["x"] = "evil"  # type: ignore
        assert "x" not in a.metadata

    def test_nested_dict_mutation_fails(self):
        a = self._victim()
        with pytest.raises(TypeError):
            a.metadata["nested"]["z"] = "evil"  # type: ignore
        assert a.metadata["nested"] == {"z": 1}

    def test_nested_list_mutation_fails(self):
        a = self._victim()
        with pytest.raises((AttributeError, TypeError)):
            a.metadata["tags"].append("evil")  # type: ignore
        with pytest.raises(TypeError):
            a.metadata["lst"][0]["k"] = "evil"  # type: ignore
        assert a.metadata["tags"] == ("critical",)
        assert a.metadata["lst"] == ({"k": "v"},)

    def test_attribute_reassignment_still_blocked(self):
        a = self._victim()
        for field, value in (("severity", C.Severity.P2), ("fingerprint", "g"),
                             ("service", "api"), ("message", "new"),
                             ("labels", FrozenDict({"x": "1"})), ("metadata", FrozenDict({"x": 1}))):
            with pytest.raises(ValidationError):
                setattr(a, field, value)

    def test_copy_mutation_cannot_reach_stored_state(self):
        a = self._victim()
        clone = a.model_copy(deep=True)
        assert clone == a
        with pytest.raises(TypeError):
            clone.metadata["x"] = "evil"  # type: ignore
        with pytest.raises(TypeError):
            clone.labels["x"] = "evil"  # type: ignore
        assert a.metadata == clone.metadata and a.labels == clone.labels

    def test_model_dump_mutation_detached(self):
        a = self._victim()
        for mode in ("python", "json"):
            dumped = a.model_dump(mode=mode)  # type: ignore
            dumped["labels"]["team"] = "evil"
            dumped["metadata"]["nested"]["z"] = "evil"
            # metadata lst is tuple in frozen but dumped as list
            if isinstance(dumped["metadata"].get("lst"), list):
                dumped["metadata"]["lst"].append("evil")
            assert a.labels["team"] == "payments"
            assert a.metadata["nested"] == {"z": 1}
            # second dump unaffected
            fresh = a.model_dump(mode=mode)  # type: ignore
            assert fresh["labels"]["team"] == "payments"

    def test_dump_returns_fresh_containers_each_call(self):
        a = self._victim()
        first = a.model_dump()
        second = a.model_dump()
        assert first["labels"] is not second["labels"]
        assert first["metadata"] is not second["metadata"]
        assert type(first["labels"]) is dict and type(first["metadata"]) is dict

    def test_construction_never_aliases_inputs(self):
        labels = {"team": "payments"}
        meta = {"owner": "sre", "deep": {"n": 1}, "lst": [{"k": 1}]}
        a = Alert(source="prometheus", service="web", severity="P1", message="hi", fingerprint="fp1",
                  labels=labels, metadata=meta)
        labels["evil"] = "1"
        meta["deep"]["n"] = "evil"
        meta["lst"][0]["k"] = "evil"
        assert "evil" not in a.labels
        assert a.metadata["deep"] == {"n": 1}
        assert a.metadata["lst"] == ({"k": 1},)


class TestFrozenDictContract:
    def test_labels_are_frozendict(self):
        a = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp", labels={"k": "v"})
        assert isinstance(a.labels, FrozenDict)
        assert isinstance(a.metadata, FrozenDict)

    def test_equality_plain_and_frozen(self):
        a = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp", labels={"k": "v"}, metadata={"n": {"z": 1}})
        assert a.labels == {"k": "v"}
        assert a.metadata == {"n": {"z": 1}}
        assert {"k": "v"} == a.labels


# ------------------------------------------------------------------ Escape 3


class TestEscape3BoundaryMatrix:
    @pytest.mark.parametrize(("field", "max_len"), [
        ("alert_id", MAX_ALERT_ID_LEN),
        ("source", MAX_SOURCE_LEN),
        ("service", MAX_SERVICE_LEN),
        ("resource", MAX_RESOURCE_LEN),
        ("message", MAX_MESSAGE_LEN),
        ("fingerprint", MAX_FINGERPRINT_LEN),
    ])
    def test_string_boundaries(self, field: str, max_len: int):
        def build(value: str) -> Alert:
            kw: dict = {"severity": "P1", "message": "hi", "fingerprint": "fp"}
            if field not in ("message", "fingerprint"):
                kw["fingerprint"] = "fp"
            if field != "alert_id":
                kw["alert_id"] = "a" * 10
            # need required fields
            base = dict(source="prometheus", service="web", severity="P1", message="hi", fingerprint="fp")
            base.update({field: value})
            # message case: ensure non-blank
            if field == "message" and not value.strip():
                value = "x" * len(value)  # shouldn't happen for max tests
            return Alert(**base)

        # Use valid_kwargs helper for simpler
        assert Alert(**valid_kwargs(**{field: "v" * 1})).__getattribute__(field) == "v" * 1
        assert Alert(**valid_kwargs(**{field: "v" * (max_len - 1)})).__getattribute__(field) == "v" * (max_len - 1)
        assert Alert(**valid_kwargs(**{field: "v" * max_len})).__getattribute__(field) == "v" * max_len
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(**{field: "v" * (max_len + 1)}))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(**{field: "" if field != "resource" else "   "}))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(**{field: "v" * 100_000}))

    def test_zero_and_one_lengths(self):
        with pytest.raises(ValidationError):
            Alert(source="", service="web", severity="P1", message="hi", fingerprint="fp")
        assert Alert(source="x", service="web", severity="P1", message="hi", fingerprint="fp").source == "x"

    def test_message_nonblank_boundary(self):
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(message=""))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(message="   "))
        assert Alert(**valid_kwargs(message="x")).message == "x"
        assert Alert(**valid_kwargs(message="  hi  ")).message == "  hi  "

    @pytest.mark.parametrize("field", ["labels"])
    def test_label_count_boundaries(self, field: str):
        assert Alert(**valid_kwargs(**{field: {}}))
        assert Alert(**valid_kwargs(**{field: {"k": "v"}}))
        many = {f"k{i}": "v" for i in range(MAX_LABELS_COUNT)}
        assert len(Alert(**valid_kwargs(**{field: many})).labels) == MAX_LABELS_COUNT
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(**{field: {f"k{i}": "v" for i in range(MAX_LABELS_COUNT + 1)}}))

    def test_metadata_entry_count_boundaries(self):
        ok = {f"k{i}": i for i in range(MAX_METADATA_COUNT)}
        assert len(Alert(**valid_kwargs(metadata=ok)).metadata) == MAX_METADATA_COUNT
        bad = dict(ok)
        bad["overflow"] = 1
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata=bad))

    def test_label_key_value_boundaries(self):
        assert Alert(**valid_kwargs(labels={"k" * MAX_LABEL_KEY_LEN: "v"}))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(labels={"k" * (MAX_LABEL_KEY_LEN + 1): "v"}))
        assert Alert(**valid_kwargs(labels={"k": "v" * MAX_LABEL_VALUE_LEN}))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(labels={"k": "v" * (MAX_LABEL_VALUE_LEN + 1)}))

    def test_metadata_key_length_boundaries(self):
        assert Alert(**valid_kwargs(metadata={"k" * MAX_METADATA_KEY_LEN: 1}))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata={"k" * (MAX_METADATA_KEY_LEN + 1): 1}))

    def test_metadata_depth_boundaries(self):
        assert Alert(**valid_kwargs(metadata=_nested(MAX_NESTING_DEPTH - 1)))
        assert Alert(**valid_kwargs(metadata=_nested(MAX_NESTING_DEPTH)))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata=_nested(MAX_NESTING_DEPTH + 1)))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata=_nested(50)))

    def test_metadata_non_string_key_rejected(self):
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata={1: "x"}))  # type: ignore

    def test_labels_bytes_boundary(self):
        labels = {f"key{i:02d}": "v" * MAX_LABEL_VALUE_LEN for i in range(7)}
        cur = len(canonical_json(labels).encode("utf-8"))
        tune_len = MAX_LABELS_BYTES - cur - len(',"tune":""')
        assert 0 <= tune_len <= MAX_LABEL_VALUE_LEN
        ok_labels = dict(labels)
        ok_labels["tune"] = "v" * tune_len
        assert len(canonical_json(ok_labels).encode("utf-8")) == MAX_LABELS_BYTES
        Alert(**valid_kwargs(labels=ok_labels))
        bad_labels = dict(labels)
        bad_labels["tune"] = "v" * (tune_len + 1)
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(labels=bad_labels))

    def test_metadata_json_byte_boundaries(self):
        # leaf cap 4096 prevents single huge value reaching 16 KiB; use many entries
        meta_ok = {f"k{i}": "v" * 400 for i in range(MAX_METADATA_COUNT)}
        assert len(canonical_json(meta_ok).encode("utf-8")) <= MAX_METADATA_BYTES
        assert Alert(**valid_kwargs(metadata=meta_ok))
        big = {f"k{i}": "v" * MAX_METADATA_STR_LEN for i in range(MAX_METADATA_COUNT)}
        assert len(canonical_json(big).encode("utf-8")) > MAX_METADATA_BYTES
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata=big))

    def test_small_normal_large_shapes(self):
        assert Alert(source="prometheus", service="web", severity="P1", message="hi", fingerprint="fp1")  # small
        normal = Alert(  # normal operational shape
            source="pagerduty", service="checkout", severity="P2", message="error rate above threshold",
            fingerprint="abc123def456", labels={"team": "payments"}, metadata={"owner": "sre"})
        assert normal.service == "checkout"
        big_ok = {"k": "x" * 400 for _ in range(10)}  # large-but-within-ceiling
        assert Alert(**valid_kwargs(metadata=big_ok))


# ------------------------------------------------------------------ Escape 4


class TestEscape4Whitespace:
    @pytest.mark.parametrize(("field", "max_len"), [
        ("alert_id", MAX_ALERT_ID_LEN),
        ("source", MAX_SOURCE_LEN),
        ("service", MAX_SERVICE_LEN),
        ("fingerprint", MAX_FINGERPRINT_LEN),
    ])
    def test_scalar_whitespace_matrix(self, field: str, max_len: int):
        assert Alert(**valid_kwargs(**{field: "a1"})).__getattribute__(field) == "a1"
        assert Alert(**valid_kwargs(**{field: "a 1"})).__getattribute__(field) == "a 1"  # interior ok
        for padded in (" a1", "a1 ", "  a1  ", "\ta1", "a1\n", "   ", ""):
            with pytest.raises(ValidationError):
                Alert(**valid_kwargs(**{field: padded}))

    def test_resource_whitespace_matrix(self):
        assert Alert(**valid_kwargs(resource="")).resource == ""
        assert Alert(**valid_kwargs(resource="a 1")).resource == "a 1"
        for padded in (" a1", "a1 ", "  a1  ", "   ", " \t"):
            with pytest.raises(ValidationError):
                Alert(**valid_kwargs(resource=padded))

    def test_status_padded_rejected(self):
        for padded in (" firing", "firing ", "  firing  "):
            with pytest.raises(ValidationError):
                Alert(**valid_kwargs(status=padded))

    def test_mapping_keys_padded_rejected_values_preserved(self):
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(labels={" team": "payments"}))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata={" owner": "sre"}))
        # free-form message VALUES are preserved as-is (documented split)
        a = Alert(source="prometheus", service="web", severity="P1", message=" has padding ", fingerprint="fp1",
                  labels={"k": "v"}, metadata={"note": " has padding "})
        assert a.message == " has padding "
        assert a.metadata["note"] == " has padding "

    def test_message_verbatim(self):
        # message preserves leading/trailing whitespace, but blank rejected
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(message="   "))
        assert Alert(**valid_kwargs(message="  hello  ")).message == "  hello  "
        assert Alert(**valid_kwargs(message="\thello\n")).message == "\thello\n"


# ------------------------------------------------------- serialization proof


class TestSerializationWireCompat:
    # Goldens prove pre-hardening wire is preserved where compatible.
    # Hardening adds FrozenDict (still serializes as plain dict) and
    # message non-blank rule (strictness increase, not wire change).
    def _full_kwargs(self, **over):
        ts = _utc(2026, 1, 1, 10, 0)
        base = dict(
            alert_id="alert-1",
            source="prometheus",
            timestamp=ts,
            service="web",
            resource="default/web-7d9f",
            severity="P2",
            message="error rate above threshold",
            labels={"team": "payments", "tier": "frontend"},
            fingerprint="fp-" + "a" * 61,
            environment="prod",
            status="firing",
            metadata={"runbook_hint": "bad-deploy"},
        )
        base.update(over)
        return base

    def test_roundtrips_stable(self):
        for kwargs in (dict(source="prometheus", service="web", severity="P1", message="hi", fingerprint="fp1"),
                       self._full_kwargs(),
                       dict(source="x", service="y", severity="P4", message="m", fingerprint="fp", metadata={"n": "v"})):
            a = Alert(**kwargs)
            assert Alert.model_validate_json(a.model_dump_json()) == a
            assert Alert.model_validate(a.model_dump()) == a
            assert Alert.model_validate_json(a.model_dump_json()).model_dump_json() == a.model_dump_json()

    def test_json_mode_deterministic(self):
        a = Alert(**self._full_kwargs())
        first = canonical_json(a.model_dump(mode="json"))
        second = canonical_json(Alert.model_validate_json(a.model_dump_json()).model_dump(mode="json"))
        assert first == second

    def test_wire_labels_metadata_as_plain(self):
        a = Alert(**self._full_kwargs())
        dumped = json.loads(a.model_dump_json())
        assert dumped["labels"] == {"team": "payments", "tier": "frontend"}
        assert dumped["metadata"] == {"runbook_hint": "bad-deploy"}
        assert dumped["severity"] == "P2"
        assert dumped["environment"] == "prod"
        assert dumped["status"] == "firing"

    def test_python_dump_shape_documented(self):
        a = Alert(source="prometheus", service="web", severity="P1", message="hi", fingerprint="fp1",
                  labels={"k": "v"}, metadata={"n": {"z": 1}})
        dumped = a.model_dump()
        assert type(dumped["labels"]) is dict
        assert type(dumped["metadata"]) is dict
        assert dumped["severity"] is C.Severity.P1
        # metadata nested list becomes plain list in dump (FrozenDict->to_plain)
        b = Alert(source="x", service="y", severity="P1", message="m", fingerprint="fp", metadata={"lst": [1, 2]})
        assert b.model_dump()["metadata"]["lst"] == [1, 2]

    def test_json_schema_generates(self):
        schema = Alert.model_json_schema()
        assert schema["type"] == "object"
        for prop in ("labels", "metadata"):
            assert schema["properties"][prop]["type"] == "object"
            assert schema["properties"][prop]["additionalProperties"] is True


# ------------------------------------------------------------- security/hostile


class TestSecurityHostilePayloads:
    def test_extremely_large_fingerprint_rejected(self):
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(fingerprint="f" * 100_000))

    def test_huge_service_name_rejected(self):
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(service="s" * 5_000))

    def test_huge_metadata_value_rejected(self):
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata={"blob": "x" * 100_000}))

    def test_huge_metadata_entry_count_rejected_fast(self):
        start = time.perf_counter()
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata={f"k{i}": i for i in range(10_000)}))
        assert time.perf_counter() - start < 5.0

    def test_nested_metadata_explosion_rejected(self):
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata=_nested(50)))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata=_nested(500)))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata={"a": [{"b": [{"c": [{"d": ["x" * 5000]}]}]}]}))
        # list nesting depth >4 must not raise RecursionError
        nested_list: object = "x"
        for _ in range(500):
            nested_list = [nested_list]
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(metadata={"top": nested_list}))

    def test_malicious_whitespace_identifiers_rejected(self):
        for bad in ("a1 ", " a1", "\u00a0a1", "a1\u2003"):
            with pytest.raises(ValidationError):
                Alert(**valid_kwargs(alert_id=bad))
            with pytest.raises(ValidationError):
                Alert(**valid_kwargs(source=bad))

    def test_invalid_enum_timestamp_extra_rejected(self):
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(severity="P0"))  # type: ignore
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(status="HEALED"))  # type: ignore
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(environment="production"))  # type: ignore
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(timestamp=datetime(2026, 1, 1, 10, 0, 0)))  # naive
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(alert_id="   "))
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(extra="injected"))  # type: ignore
        with pytest.raises(ValidationError):
            Alert(**valid_kwargs(labels={"k": "v"}, extra_field="x"))  # type: ignore

    def test_injection_strings_remain_inert_data(self):
        payloads = [
            "'; DROP TABLE alerts; --",
            "{{ 7*7 }} SSTI probe",
            "<script>alert('xss')</script>",
            "$(rm -rf /) shell probe",
            "${jndi:ldap://evil/x} log4shell probe",
            '{"cmd":"kubectl delete ns prod"}',
        ]
        for payload in payloads:
            a = Alert(**valid_kwargs(message=payload, labels={"note": payload}))
            assert a.message == payload
            assert a.labels["note"] == payload
            # JSON round-trip preserves inertness, no execution
            b = Alert.model_validate_json(a.model_dump_json())
            assert b.message == payload
            assert b.labels["note"] == payload

    def test_control_characters_preserved_in_message(self):
        # message is verbatim, control chars are data not injection vectors
        for msg in ["hello\nworld", "a\tb", "line1\r\nline2"]:
            assert Alert(**valid_kwargs(message=msg)).message == msg


# ----------------------------------------------------------------- performance


class TestPerformanceValidationCost:
    def test_small_cost(self):
        start = time.perf_counter()
        for _ in range(200):
            Alert(source="prometheus", service="web", severity="P1", message="hi", fingerprint="fp1")
        assert (time.perf_counter() - start) / 200 < 0.05

    def test_normal_cost(self):
        kwargs = dict(
            source="prometheus", service="web", severity="P2", message="error rate above threshold",
            fingerprint="fp-" + "a" * 61, labels={"team": "payments"}, metadata={"owner": "sre"})
        start = time.perf_counter()
        for _ in range(200):
            Alert(**kwargs)
        assert (time.perf_counter() - start) / 200 < 0.05

    def test_large_rejected_fast(self):
        start = time.perf_counter()
        with pytest.raises(ValidationError):
            Alert(source="s" * 100_000, service="web", severity="P1", message="hi", fingerprint="fp1")
        assert time.perf_counter() - start < 1.0

    def test_dump_cost(self):
        a = Alert(source="prometheus", service="web", severity="P1", message="hi", fingerprint="fp1",
                  metadata={"k": "v" * 1000})
        start = time.perf_counter()
        for _ in range(200):
            a.model_dump_json()
        assert (time.perf_counter() - start) / 200 < 0.05
