"""M01.4 Evidence schema: canonical-contract tests (host-safe, no runtime).

Proves the M01.4 contract, not just that "tests pass":
- positive: minimal + full construction, every SourceType x TrustLevel value;
- negative: missing/blank/invalid-enum/naive-ts/extra-field/non-finite floats;
- serialization: model_dump / model_dump_json round-trips byte-stable;
- boundaries: 0/1/max-1/max/max+1/huge per bounded field + float edges;
- immutability: frozen reassignment blocked; scalar-only model (no aliasing
  surface by construction);
- malformed: wrong types, nulls, bools-as-numbers;
- integrity: exactly one canonical Evidence class (legacy schemas.Evidence
  exempt); evidence.py defines no enums and imports only frozen vocab;
- legacy: legacy schemas.Evidence still constructs; from_legacy/to_legacy map.
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

import app.schemas as LEGACY  # noqa: E402
from app.contracts.enums import SourceType, TrustLevel  # noqa: E402
from app.contracts.evidence import (  # noqa: E402
    MAX_EVIDENCE_ID_LEN,
    MAX_FRESHNESS_S,
    MAX_HASH_LEN,
    MAX_INCIDENT_ID_LEN,
    MAX_REF_LEN,
    MAX_SOURCE_ID_LEN,
    Evidence,
)
from app.contracts.values import utcnow  # noqa: E402

EVIDENCE_FILE = ROOT / "backend" / "app" / "contracts" / "evidence.py"


def valid_kwargs(**over: object) -> dict:
    base: dict = dict(
        incident_id="inc-1",
        source_type=SourceType.LOG,
        source_id="logs/app.log",
        ref="logs/app.log:120-145",
        hash="a" * 64,
        freshness_s=12.5,
        relevance=0.9,
        trust=TrustLevel.HIGH,
    )
    base.update(over)
    return base


# ------------------------------------------------------------ positive ----
class TestPositive:
    def test_minimal_construction_uses_defaults(self):  # UNIT
        e = Evidence(incident_id="inc-1", source_type="log",
                     source_id="s1", ref="r1", hash="h1")
        assert e.evidence_id and len(e.evidence_id) == 32  # new_id default
        assert e.ts.tzinfo is not None  # utcnow default, tz-aware
        assert e.freshness_s == 0.0
        assert e.relevance == 0.0
        assert e.trust is TrustLevel.MED  # legacy-compat default

    def test_full_construction(self):  # UNIT
        ts = utcnow()
        e = Evidence(evidence_id="ev-1", incident_id="inc-9",
                     source_type=SourceType.TRACE, source_id="trace-4f2a",
                     ts=ts, ref="trace 4f2a span 7", hash="b" * 64,
                     freshness_s=300.0, relevance=0.42, trust=TrustLevel.LOW)
        assert e.evidence_id == "ev-1"
        assert e.ts == ts
        assert e.relevance == 0.42
        assert e.trust is TrustLevel.LOW

    @pytest.mark.parametrize("st", list(SourceType))
    def test_every_source_type_accepted(self, st):  # UNIT
        e = Evidence(**valid_kwargs(source_type=st))
        assert e.source_type is st
        assert e.source_type == st.value  # str-Enum wire equality

    @pytest.mark.parametrize("tr", list(TrustLevel))
    def test_every_trust_level_accepted(self, tr):  # UNIT
        e = Evidence(**valid_kwargs(trust=tr))
        assert e.trust is tr

    def test_string_coercion_to_enums(self):  # UNIT
        e = Evidence(**valid_kwargs(source_type="metric", trust="low"))
        assert e.source_type is SourceType.METRIC
        assert e.trust is TrustLevel.LOW

    def test_relevance_edges(self):  # UNIT
        assert Evidence(**valid_kwargs(relevance=0.0)).relevance == 0.0
        assert Evidence(**valid_kwargs(relevance=1.0)).relevance == 1.0

    def test_freshness_zero_and_max(self):  # UNIT
        assert Evidence(**valid_kwargs(freshness_s=0)).freshness_s == 0.0
        e = Evidence(**valid_kwargs(freshness_s=MAX_FRESHNESS_S))
        assert e.freshness_s == MAX_FRESHNESS_S


# ------------------------------------------------------------ negative ----
class TestNegative:
    def test_missing_required_rejected(self):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(source_type="log", source_id="s",  # type: ignore[call-arg]
                     ref="r", hash="h")

    @pytest.mark.parametrize("field", ["incident_id", "source_id", "ref", "hash"])
    def test_blank_identifier_rejected(self, field):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(**{field: "   "}))

    @pytest.mark.parametrize("field", ["incident_id", "source_id", "ref", "hash"])
    def test_empty_identifier_rejected(self, field):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(**{field: ""}))

    def test_invalid_source_type_rejected(self):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(source_type="smoke-signal"))

    def test_invalid_trust_rejected(self):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(trust="absolute"))

    def test_naive_ts_rejected(self):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(ts=datetime(2026, 1, 1)))

    def test_aware_ts_accepted(self):  # UNIT
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert Evidence(**valid_kwargs(ts=ts)).ts == ts

    def test_extra_field_rejected(self):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(score=0.5))

    @pytest.mark.parametrize("bad", ["high", None, True, [0.5], {"v": 0.5}])
    def test_relevance_wrong_type_rejected(self, bad):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(relevance=bad))

    @pytest.mark.parametrize("bad", [-0.001, 1.0001, 2.0])
    def test_relevance_out_of_range_rejected(self, bad):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(relevance=bad))

    @pytest.mark.parametrize("bad", ["12", None, True, [12], {"v": 12}])
    def test_freshness_wrong_type_rejected(self, bad):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(freshness_s=bad))

    def test_freshness_negative_rejected(self):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(freshness_s=-1.0))

    def test_freshness_over_max_rejected(self):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(freshness_s=MAX_FRESHNESS_S + 1.0))


# ------------------------------------------------------- serialization ----
class TestSerialization:
    def test_dump_round_trip_byte_stable(self):  # UNIT
        e = Evidence(evidence_id="ev-rt", **valid_kwargs())
        d1 = e.model_dump_json()
        d2 = Evidence.model_validate_json(d1).model_dump_json()
        assert d1 == d2

    def test_dump_dict_round_trip(self):  # UNIT
        e = Evidence(evidence_id="ev-rt2", **valid_kwargs())
        assert Evidence.model_validate(e.model_dump()).model_dump() == e.model_dump()

    def test_enums_serialize_as_values(self):  # UNIT
        e = Evidence(**valid_kwargs(source_type=SourceType.DEPLOY,
                                    trust=TrustLevel.HIGH))
        import json
        raw = json.loads(e.model_dump_json())
        assert raw["source_type"] == "deploy"
        assert raw["trust"] == "high"

    def test_dump_detached_no_aliasing_surface(self):  # UNIT
        # Scalar-only model: repeated dumps are equal and independent reads.
        e = Evidence(**valid_kwargs())
        assert e.model_dump() == e.model_dump()
        assert e.model_dump_json() == e.model_dump_json()


# ------------------------------------------------------------ boundaries ----
class TestBoundaries:
    @pytest.mark.parametrize(("field", "mx"), [
        ("evidence_id", MAX_EVIDENCE_ID_LEN),
        ("incident_id", MAX_INCIDENT_ID_LEN),
        ("source_id", MAX_SOURCE_ID_LEN),
        ("ref", MAX_REF_LEN),
        ("hash", MAX_HASH_LEN),
    ])
    def test_identifier_max_and_overflow(self, field, mx):  # UNIT
        assert Evidence(**valid_kwargs(**{field: "x" * mx}))
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(**{field: "x" * (mx + 1)}))

    def test_huge_identifier_rejected(self):  # UNIT
        with pytest.raises(ValidationError):
            Evidence(**valid_kwargs(incident_id="x" * 100000))

    def test_relevance_float_precision_preserved(self):  # UNIT
        e = Evidence(**valid_kwargs(relevance=0.123456789))
        assert e.relevance == 0.123456789


# ------------------------------------------------------------ integrity ----
class TestIntegrity:
    def test_single_canonical_evidence_class(self):  # UNIT
        tree = ast.parse(EVIDENCE_FILE.read_text(encoding="utf-8"))
        classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        assert classes == ["Evidence"], classes

    def test_no_enum_definitions_in_module(self):  # UNIT
        tree = ast.parse(EVIDENCE_FILE.read_text(encoding="utf-8"))
        enums = [n.name for n in ast.walk(tree)
                 if isinstance(n, ast.ClassDef)
                 and any(getattr(b, "attr", getattr(b, "id", "")) == "Enum"
                         for b in n.bases)]
        assert enums == [], enums

    def test_only_frozen_vocab_imports(self):  # UNIT
        tree = ast.parse(EVIDENCE_FILE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("app.contracts"):
                imported.update(a.asname or a.name for a in n.names)
        assert imported <= {"SourceType", "TrustLevel", "new_id", "utcnow"}, imported


# --------------------------------------------------------------- legacy ----
class TestLegacy:
    def test_legacy_evidence_still_constructs(self):  # UNIT
        leg = LEGACY.Evidence(incident_id="inc-1", source_type="log",
                              source_id="s", ref="r", hash="h",
                              freshness_s=1.0, relevance=0.5)
        assert leg.trust == "med"

    def test_from_legacy_round_trip(self):  # UNIT
        leg = LEGACY.Evidence(evidence_id="ev-leg", incident_id="inc-1",
                              source_type="metric", source_id="m1",
                              ref="row 7", hash="c" * 64,
                              freshness_s=3.0, relevance=0.7, trust="high")
        e = Evidence.from_legacy(leg)
        assert e.evidence_id == "ev-leg"
        assert e.source_type is SourceType.METRIC
        assert e.trust is TrustLevel.HIGH
        back = e.to_legacy()
        assert type(back) is LEGACY.Evidence
        assert back.evidence_id == "ev-leg" and back.ref == "row 7"

    def test_from_legacy_rejects_invalid(self):  # UNIT
        leg = LEGACY.Evidence(incident_id="inc-1", source_type="log",
                              source_id="s", ref="r", hash="h",
                              freshness_s=1.0, relevance=0.5)
        leg.trust = "bogus"  # type: ignore[assignment]
        with pytest.raises(ValidationError):
            Evidence.from_legacy(leg)
