"""M06 policy/safety hardening (90+ pass, host-safe UNIT + SECURITY).

Proves the interim-audit P1 closures (validator regex + nested scan) and P2
closures (explicit-None, rule else-branch, GREEN-mutation blast, required env
context, bundle/matrix seals, reversible parity), plus per-rule DENY
attribution (the near-miss that proved rule_ids need per-rule pins: a broken
matcher still passed 141 tests because only one asserted a rule_id).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.contracts import Action  # noqa: E402
from app.services.policy import (  # noqa: E402
    _rule_matches,
    evaluate,
    load_bundle,
    load_matrix,
    validate_bundle,
)
from app.services.validator import (  # noqa: E402
    DESTRUCTIVE_SQL,
    SHELL_META,
    validate_action,
)

BUNDLE = load_bundle()
MATRIX = load_matrix()
APPROVER = {"role": "approver", "id": "sre-1"}
BLAST_SMALL = {"scope": "deploy", "replicas": 2, "traffic_pct": 10}
BLAST_BIG = {"scope": "deploy", "replicas": 8, "traffic_pct": 80}


def act(**over) -> Action:
    base = dict(incident_id="inc-1", agent_id="planner",
                action_type="read", resource_type="deployment",
                resource_id="web", environment="mock", parameters={},
                reason="r", evidence_ids=["ev-1"],
                runbook_id="bad-deploy-rollback", runbook_version="1.2.0",
                expected_outcome="o", verification_plan=["v"])
    base.update(over)
    return Action(**base)


def ev(action, actor=APPROVER, blast=BLAST_SMALL, sev="P1"):
    return evaluate(action, actor, {"environment": action.environment},
                    sev, blast, BUNDLE, MATRIX)


class TestShellMetaRegex:
    def test_no_false_positive_on_plain_words(self):  # SECURITY
        # P1 #1: the old class matched literal "n" (\\n in a raw string),
        # flagging "nginx"/"green" as shell metacharacters.
        for clean in ("nginx", "green", "v22", "web-1", "rollback"):
            assert SHELL_META.search(clean) is None, clean

    @pytest.mark.parametrize("evil", [
        "a;b", "x|y", "k&w", "`id`", "v$(x)", "f(o)", "a\\b",
        "line1\nline2", "a\rb", "col\there", "out>file", "in<file",
    ])
    def test_metacharacters_rejected(self, evil):  # SECURITY
        assert SHELL_META.search(evil) is not None, repr(evil)

    def test_validator_catches_new_classes(self):  # SECURITY
        for bad in [{"q": "a\nb"}, {"q": "x\ty"}, {"q": "o>f"},
                    {"note": "a\rb"}]:
            errs = validate_action(act(parameters=bad))
            assert any("metachar" in e for e in errs), bad


class TestDestructiveSqlShapes:
    @pytest.mark.parametrize("evil", [
        "DROP TABLE t", "drop table t", "DELETE FROM t", "TRUNCATE t",
        "UPDATE users SET role='admin'", "INSERT INTO t VALUES (1)",
    ])
    def test_destructive_shapes_rejected(self, evil):  # SECURITY
        assert DESTRUCTIVE_SQL.search(evil) is not None, evil
        assert validate_action(act(parameters={"q": evil}))

    @pytest.mark.parametrize("clean", [
        "update config", "insert key here", "last update",
        # NOTE: bare DROP/TRUNCATE match by design (fail-closed on the exact
        # destructive verbs); only shaped UPDATE/INSERT match. "drop-off" and
        # "truncate output" ARE flagged (pre-existing behavior, kept).
    ])
    def test_plain_words_pass(self, clean):  # UNIT
        # Bare UPDATE/INSERT without destructive shape must NOT match:
        # over-blocking denies legitimate parameter text.
        assert DESTRUCTIVE_SQL.search(clean) is None, clean


class TestNestedParamScan:
    def test_nested_evil_rejected_with_path(self):  # SECURITY
        # P1 #2: the old top-level loop missed {"cfg": {"cmd": "a;evil"}}.
        errs = validate_action(act(parameters={"cfg": {"cmd": "a;evil"}}))
        assert any("cfg.cmd" in e and "metachar" in e for e in errs), errs

    def test_nested_list_and_sql_rejected(self):  # SECURITY
        errs = validate_action(act(parameters={"items": ["ok", "x|y"]}))
        assert any("items[1]" in e for e in errs), errs
        errs = validate_action(
            act(parameters={"db": {"q": "DROP TABLE t"}}))
        assert any("db.q" in e and "SQL" in e for e in errs), errs

    def test_clean_nesting_passes(self):  # UNIT
        errs = validate_action(act(parameters={
            "cfg": {"replicas": 3, "tags": ["a", "b"]}}))
        assert not [e for e in errs if "metachar" in e or "SQL" in e]


class TestExplicitNone:
    def test_empty_bundle_denies_not_disk_loads(self):  # SECURITY
        d = evaluate(act(), APPROVER, {"environment": "mock"}, "P1",
                     BLAST_SMALL, {}, MATRIX)
        assert d.decision == "DENY" and d.rule_id == "DENY-invalid-bundle"

    def test_empty_matrix_denies(self):  # SECURITY
        d = evaluate(act(), APPROVER, {"environment": "mock"}, "P1",
                     BLAST_SMALL, BUNDLE, {})
        assert d.decision == "DENY" and d.rule_id == "DENY-invalid-matrix"


class TestRuleElseBranch:
    def test_unknown_when_key_never_matches(self):  # SECURITY
        assert _rule_matches({"color": "red"}, act()) is False
        assert _rule_matches({"action_type": "read", "color": "red"},
                             act()) is False

    def test_empty_when_matches_all(self):  # UNIT
        # Pinned semantic: no constraints = applies (fail-closed direction
        # for DENY rules). validate_bundle forbids empty `when` in files.
        assert _rule_matches({}, act()) is True

    def test_known_keys_still_match(self):  # UNIT
        assert _rule_matches({"action_type": "read"}, act()) is True
        assert _rule_matches({"action_type": "read",
                              "environment": "mock"}, act()) is True
        assert _rule_matches({"action_type": "shell"}, act()) is False
        assert _rule_matches({"resource_type": "deployment"},
                             act()) is True


class TestGreenMutationBlast:
    def test_mock_scale_huge_escalates(self):  # SECURITY
        d = ev(act(action_type="scale_deployment", environment="mock"),
               blast=BLAST_BIG)
        assert d.decision == "ESCALATE"
        assert d.rule_id == "ESCALATE-blast-override"
        assert d.effective_risk == "GREEN"  # matrix truth kept
        assert "blast-review" in d.obligations
        assert "required_role:approver" in d.obligations

    def test_mock_scale_small_still_allows(self):  # UNIT
        d = ev(act(action_type="scale_deployment", environment="mock"))
        assert d.decision == "ALLOW"

    def test_green_reads_ignore_blast(self):  # UNIT
        # Reads have no blast radius (executor ignores blast for reads):
        # garbage blast context must not manufacture HITL work.
        d = ev(act(action_type="read", environment="mock"), blast=BLAST_BIG)
        assert d.decision == "ALLOW"

    def test_unknown_actor_still_denied_first(self):  # SECURITY
        d = evaluate(act(action_type="scale_deployment",
                         environment="mock"),
                     {"role": "hacker"}, {"environment": "mock"}, "P1",
                     BLAST_BIG, BUNDLE, MATRIX)
        assert d.decision == "DENY" and d.rule_id == "DENY-unknown-actor"


class TestEnvContextRequired:
    def test_missing_env_context_denies(self):  # SECURITY
        d = evaluate(act(), APPROVER, {}, "P1", BLAST_SMALL, BUNDLE, MATRIX)
        assert d.decision == "DENY"
        assert d.rule_id == "DENY-missing-env-context"

    def test_non_mapping_context_denies(self):  # SECURITY
        d = evaluate(act(), APPROVER, "mock", "P1",  # type: ignore
                     BLAST_SMALL, BUNDLE, MATRIX)
        assert d.decision == "DENY"


class TestBundleMatrixSeals:
    def _sealed_body(self, path):
        doc = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
        assert isinstance(doc.get("sha256"), str) and doc["sha256"]
        return doc

    def test_sealed_files_load(self):  # UNIT
        assert load_bundle()["policy_version"] == "v1"
        assert load_matrix()["version"] == "v1"

    def test_tampered_content_refused(self, tmp_path):  # SECURITY
        import shutil
        for name, mutate in (
            ("policies/bundle_v1.yaml",
             lambda doc: doc.update(deny_rules=[])),
            ("policies/risk_matrix.yaml",
             lambda doc: doc.update(
                 tiers={**doc["tiers"],
                        "read": {e: "RED" for e in ("mock", "dev",
                                                   "staging", "prod")}})),
        ):
            dst = tmp_path / Path(name).name
            shutil.copy(ROOT / name, dst)
            doc = yaml.safe_load(dst.read_text(encoding="utf-8"))
            mutate(doc)
            dst.write_text(yaml.safe_dump(doc))
            # Loader equivalents must refuse: recompute via file content.
            from app.services.policy import _verify_seal
            with pytest.raises(ValueError):
                _verify_seal(
                    yaml.safe_load(dst.read_text(encoding="utf-8")), name)

    def test_missing_seal_refused(self):  # SECURITY
        from app.services.policy import _verify_seal
        with pytest.raises(ValueError):
            _verify_seal({"policy_version": "v1"}, "bundle.yaml")

    def test_validate_ignores_seal_key(self):  # UNIT
        # The seal must not break shape validation (existing tolerance for
        # top-level extras like effective_from).
        assert validate_bundle(dict(BUNDLE)) == []

    def test_seal_covers_current_content(self):  # UNIT
        # The committed seal matches a fresh recomputation (no stale seal).
        from app.contracts.values import canonical_json, sha256_hex
        from app.services.policy import _verify_seal
        for name in ("policies/bundle_v1.yaml", "policies/risk_matrix.yaml"):
            doc = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))
            body = {k: v for k, v in doc.items() if k != "sha256"}
            assert doc["sha256"] == sha256_hex(canonical_json(body)), name
            assert _verify_seal(doc, name)


class TestReversibleParity:
    def test_validator_set_matches_matrix(self):  # UNIT
        # P2 drift guard: the validator's hardcoded reversible set and the
        # matrix list must name the same types, or YELLOW-without-rollback
        # escapes one of them.
        import ast
        src = (ROOT / "backend" / "app" / "services"
               / "validator.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and \
                            target.id == "reversible":
                        found = {e.value for e in node.value.elts
                                 if isinstance(e, ast.Constant)}
        assert found, "validator reversible set not found"
        assert found == set(MATRIX["reversible"])


class TestSeverityContract:
    def test_severity_accepted_not_deciding(self):  # UNIT
        # Boundary pin (see ADR): triage severity does not move the matrix
        # decision today (triage owns it in M04, HITL prioritizes on it).
        # If this ever changes, the sweep must vary sev per case.
        base = ev(act(), sev="P1")
        assert ev(act(), sev="P4").decision == base.decision
        assert ev(act(), sev="P4").rule_id == base.rule_id


class TestDenyRuleAttribution:
    @pytest.mark.parametrize("atype,env,rule", [
        ("shell", "mock", "DENY-shell"),
        ("delete_namespace", "prod", "DENY-prod-delete-namespace"),
        ("delete_namespace", "mock", None),  # mock delete-ns: matrix RED...
        ("delete_deployment", "staging", "DENY-delete-deployment"),
        ("delete_pod", "prod", "DENY-prod-delete-pod"),
        ("rbac_change", "mock", "DENY-rbac"),
        ("secret_access", "mock", "DENY-secret"),
        ("db_write", "mock", "DENY-db-write"),
        ("reboot_node", "dev", "DENY-reboot"),
    ])
    def test_each_rule_fires_its_id(self, atype, env, rule):  # SECURITY
        # The near-miss that proved per-rule pins necessary: a broken matcher
        # passed 141 tests because only one asserted a rule_id.
        d = ev(act(action_type=atype, environment=env))
        assert d.decision == "DENY", (atype, env)
        if rule is not None:
            assert d.rule_id == rule, (atype, env, d.rule_id)
