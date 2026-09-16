"""M01.1 rivalry closure (P1: schemas.py rival validators).

Proves the interim-audit P1 is dead: 15 of 16 legacy models ARE the canonical
objects (single validation path), and the one retained raw shape (Alert) is
contained by a pinned no-import rule. Any future rival model or production
import of app.schemas fails here before it can become a bypass.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import app.contracts as C  # noqa: E402
import app.schemas as S  # noqa: E402

# Every 1:1-wire model: legacy name IS the canonical object. Alert is the
# documented exception (raw-telemetry input shape for the from_legacy bridge,
# not a rival validator of the normalized shape).
ALIASED = [
    "Evidence", "Claim", "Hypothesis", "Runbook", "Action",
    "PolicyDecision", "ApprovalRequest", "ApprovalToken", "Execution",
    "VerificationResult", "Rollback", "RCA", "AuditEvent",
    "EvaluationRun", "BenchmarkResult",
]


class TestSingleValidationPath:
    def test_aliased_models_are_canonical(self):  # UNIT
        for name in ALIASED:
            assert getattr(S, name) is getattr(C, name), name

    def test_alert_is_the_documented_exception(self):  # UNIT
        assert S.Alert is not C.Alert  # raw-stage input shape, contained below
        assert "severity_raw" in S.Alert.model_fields
        assert "signature" in S.Alert.model_fields
        assert "severity_raw" not in C.Alert.model_fields

    def test_schemas_defines_exactly_one_model(self):  # STATIC
        tree = ast.parse((ROOT / "backend" / "app" / "schemas.py").read_text(
            encoding="utf-8"))
        models = [n.name for n in ast.walk(tree)
                  if isinstance(n, ast.ClassDef)]
        assert models == ["Alert"], models

    def test_schemas_defines_no_enum(self):  # STATIC
        tree = ast.parse((ROOT / "backend" / "app" / "schemas.py").read_text(
            encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                    isinstance(b, ast.Name) and b.id in ("Enum", "StrEnum")
                    for b in node.bases):
                raise AssertionError(
                    f"schemas.py defines enum: {node.name}")


class TestNoProductionSchemasImport:
    def test_no_module_level_schemas_import(self):  # SECURITY
        # The documented rule ("M01.2+ imports contracts ONLY") enforced:
        # any future validator-bypass attempt starts with this import and
        # dies here. tests/ may import schemas (bridge coverage).
        offenders = []
        for base in ("backend", "scripts", "telemetry", "tools", "agents"):
            root = ROOT / base
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*.py")):
                if "__pycache__" in path.parts:
                    continue
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for node in tree.body:
                    if isinstance(node, ast.ImportFrom) and \
                            (node.module or "").startswith("app.schemas"):
                        offenders.append(
                            f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name.split(".")[0:2] == ["app", "schemas"]:
                                offenders.append(
                                    f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
        assert offenders == [], f"production schemas import: {offenders}"

    def test_function_local_schemas_import_only_in_to_legacy(self):  # SECURITY
        # The single tolerated pattern (documented in m01_4 evidence tests):
        # to_legacy bridges import the compat layer method-locally to avoid a
        # contracts -> schemas import cycle. Anything else fails.
        offenders = []
        contracts = ROOT / "backend" / "app" / "contracts"
        for path in sorted(contracts.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for child in ast.walk(node):
                        if isinstance(child, ast.ImportFrom) and \
                                "app.schemas" in (child.module or ""):
                            if node.name != "to_legacy":
                                offenders.append(
                                    f"{path.name}:{node.lineno}:{node.name}")
        assert offenders == [], f"non-bridge schemas import: {offenders}"
