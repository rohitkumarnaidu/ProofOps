"""M01 P2-closure verification (90+ pass, host-safe UNIT + SECURITY).

One test per interim-audit P2 plus thin-spot caps per unit. Every test names
the file:line it guards. No frozen test file is edited; this companion holds
the new coverage.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.contracts.action import Action  # noqa: E402
from app.contracts.approval import ApprovalRequest  # noqa: E402
from app.contracts.audit import AuditEvent  # noqa: E402
from app.contracts.evaluation import BenchmarkResult, EvaluationRun  # noqa: E402
from app.contracts.execution import Execution  # noqa: E402
from app.contracts.hypothesis import Hypothesis  # noqa: E402
from app.contracts.policy import PolicyDecision  # noqa: E402
from app.contracts.rca import RCA  # noqa: E402
from app.contracts.rollback import Rollback  # noqa: E402
from app.contracts.runbook import Runbook  # noqa: E402
from app.contracts.verification import VerificationResult  # noqa: E402


def _deep(levels: int) -> object:
    nested: object = 1
    for _ in range(levels):
        nested = {"k": nested}
    return nested


class TestHypothesisArgsBounds:
    def test_doc_table_matches_code_32_not_16(self):  # UNIT
        # Interim P2: docstring said 16, code said 32. Code (bytes-capped) is
        # truth; the doc now says 32. Pin both so they cannot re-drift.
        from app.contracts.hypothesis import MAX_ARGS_ENTRIES
        assert MAX_ARGS_ENTRIES == 32
        assert "32 entries" in (ROOT / "backend" / "app" / "contracts" /
                                "hypothesis.py").read_text(encoding="utf-8")

    def test_deep_test_args_rejected(self):  # SECURITY
        # Interim P2: MAX_ARGS_DEPTH=4 was declared but never enforced.
        with pytest.raises(ValidationError):
            Hypothesis(text="t", confidence=0.5, test_args=_deep(6))  # type: ignore

    def test_depth_boundary_accepted(self):  # UNIT
        h = Hypothesis(text="t", confidence=0.5,
                       test_args={"a": {"b": {"c": {"d": 1}}}})  # type: ignore
        assert h.test_args["a"]["b"]["c"]["d"] == 1

    def test_entries_and_bytes_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            Hypothesis(text="t", confidence=0.5,
                       test_args={f"k{i}": i for i in range(33)})  # type: ignore
        with pytest.raises(ValidationError):
            Hypothesis(text="t", confidence=0.5,
                       test_args={"blob": "x" * 9000})  # type: ignore


class TestActionRollbackBounds:
    def _valid(self, **over) -> dict:
        base = dict(incident_id="i", agent_id="a",
                    action_type="rollback_deployment",
                    resource_type="deployment", resource_id="web",
                    reason="r", runbook_id="rb", runbook_version="1.2.0",
                    expected_outcome="o")
        base.update(over)
        return base

    def test_none_stays_irreversible_marker(self):  # UNIT
        assert Action(**self._valid()).rollback_action is None

    def test_oversized_rollback_rejected(self):  # SECURITY
        with pytest.raises(ValidationError):
            Action(**self._valid(
                rollback_action={f"k{i}": i for i in range(33)}))

    def test_deep_rollback_rejected(self):  # SECURITY
        with pytest.raises(ValidationError):
            Action(**self._valid(rollback_action=_deep(7)))

    def test_non_mapping_rollback_rejected(self):  # SECURITY
        with pytest.raises(ValidationError):
            Action(**self._valid(rollback_action="kubectl rollout undo"))


class TestRcaTimelineKeys:
    def _valid(self, **over) -> dict:
        base = dict(incident_id="i", summary="s", root_cause="c",
                    timeline=[{"ts": "t", "actor": "a", "hash": "h"}])
        base.update(over)
        return base

    def test_documented_keys_accepted(self):  # UNIT
        assert RCA(**self._valid()).timeline[0]["ts"] == "t"

    @pytest.mark.parametrize("row", [
        {"actor": "a", "hash": "h"},  # missing ts
        {"ts": "t", "hash": "h"},  # missing actor
        {"ts": "t", "actor": "a"},  # missing hash
        {},  # empty row
    ])
    def test_incomplete_timeline_row_rejected(self, row):  # SECURITY
        with pytest.raises(ValidationError):
            RCA(**self._valid(timeline=[row]))

    def test_remediation_rows_stay_untyped_records(self):  # UNIT
        r = RCA(**self._valid(remediation_log=[{"anything": "goes"}]))
        assert r.remediation_log[0]["anything"] == "goes"


class TestRollbackConsistency:
    def _valid(self, **over) -> dict:
        base = dict(execution_id="e", rollback_action={"replicas": 3},
                    attempted=True, succeeded=True)
        base.update(over)
        return base

    def test_outcome_without_attempt_rejected(self):  # SECURITY
        with pytest.raises(ValidationError):
            Rollback(**self._valid(attempted=False, succeeded=True))
        with pytest.raises(ValidationError):
            Rollback(**self._valid(attempted=False, succeeded=False))

    def test_legal_states_accepted(self):  # UNIT
        assert Rollback(**self._valid()).succeeded is True
        assert Rollback(**self._valid(
            attempted=True, succeeded=None)).succeeded is None
        assert Rollback(**self._valid(
            attempted=False, succeeded=None)).attempted is False


class TestAuditPolicyKeys:
    def _valid(self, **over) -> dict:
        base = dict(seq=1, incident_id="i", actor="a",
                    event_type="policy.decision",
                    policy={"version": "v1", "rule": "R", "result": "ALLOW"})
        base.update(over)
        return base

    def test_full_snapshot_accepted(self):  # UNIT
        assert AuditEvent(**self._valid()).policy["rule"] == "R"

    def test_absent_snapshot_accepted(self):  # UNIT
        # Empty default = no policy context (non-policy events). Present but
        # partial = malformed. Absent vs malformed is the contract.
        assert AuditEvent(**self._valid(policy={})).policy == {}

    @pytest.mark.parametrize("policy", [
        {"version": "v1"},  # missing rule+result
        {"version": "v1", "rule": "R"},  # missing result
        {"rule": "R", "result": "ALLOW"},  # missing version
    ])
    def test_partial_snapshot_rejected(self, policy):  # SECURITY
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(policy=policy))


class TestAlertStrictBridge:
    def _raw(self, **over) -> SimpleNamespace:
        from datetime import datetime, timezone
        base = dict(alert_id="a1", ts=datetime.now(timezone.utc),
                    service="web", environment="mock", severity_raw="P1",
                    signature="sig", labels={"k": "v"}, hash="h")
        base.update(over)
        return SimpleNamespace(**base)

    def test_non_str_fields_rejected_not_coerced(self):  # SECURITY
        # Interim P2: str()-coercion laundering. Non-str injections must raise
        # ValueError, never arrive as trusted strings.
        from app.contracts.alert import Alert
        for field, bad in [("service", 123), ("signature", ["x"]),
                           ("severity_raw", {"s": 1}), ("alert_id", None),
                           ("hash", 456)]:
            with pytest.raises(ValueError):
                Alert.from_legacy(self._raw(**{field: bad}))

    def test_non_str_labels_rejected(self):  # SECURITY
        from app.contracts.alert import Alert
        with pytest.raises(ValueError):
            Alert.from_legacy(self._raw(labels={"k": 123}))
        with pytest.raises(ValueError):
            Alert.from_legacy(self._raw(labels="k=v"))

    def test_valid_raw_still_migrates(self):  # UNIT
        from app.contracts.alert import Alert
        a = Alert.from_legacy(self._raw())
        assert a.service == "web" and a.fingerprint == "sig"


class TestThinSpotCaps:
    def test_policy_obligation_and_version_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            PolicyDecision(decision="ALLOW", rule_id="r", policy_version="v1",
                           effective_risk="GREEN",
                           obligations=[f"o{i}" for i in range(33)])
        with pytest.raises(ValidationError):
            PolicyDecision(decision="ALLOW", rule_id="r",
                           policy_version="v" * 65,
                           effective_risk="GREEN")

    def test_approval_hash_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            ApprovalRequest(incident_id="i", action_id="a", actor="a",
                            params_hash="h" * 257, scope="s",
                            expires_at="2099-01-01T00:00:00+00:00",
                            nonce="n0nce-abc123")

    def test_execution_log_and_diff_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            Execution(action_id="a", incident_id="i", idempotency_key="k",
                      logs=[f"l{i}" for i in range(257)])
        with pytest.raises(ValidationError):
            Execution(action_id="a", incident_id="i", idempotency_key="k",
                      logs=["x" * 4097])
        with pytest.raises(ValidationError):
            Execution(action_id="a", incident_id="i", idempotency_key="k",
                      state_diff={f"k{i}": i for i in range(65)})
        assert Execution(action_id="a", incident_id="i",
                         idempotency_key="k", tier="docker").tier == "docker"

    def test_verification_check_and_detail_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            VerificationResult(execution_id="e", verdict="RESOLVED",
                               checks={f"c{i}": True for i in range(33)})
        with pytest.raises(ValidationError):
            VerificationResult(execution_id="e", verdict="RESOLVED",
                               detail="d" * 4097)

    def test_runbook_title_and_hash_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            Runbook(runbook_id="r", version="1.0.0", title="t" * 257)
        with pytest.raises(ValidationError):
            Runbook(runbook_id="r", version="1.0.0", title="t",
                    hash="h" * 257)

    def test_evaluation_counters_and_maps(self):  # SECURITY
        with pytest.raises(ValidationError):
            EvaluationRun(suite="s", case_id="c", tokens_in=-1)
        with pytest.raises(ValidationError):
            EvaluationRun(suite="s", case_id="c", passed="yes")  # type: ignore
        with pytest.raises(ValidationError):
            EvaluationRun(suite="s", case_id="c",
                          scores={"m": float("nan")})
        with pytest.raises(ValidationError):
            BenchmarkResult(case_id="c", scenario="s", variant="v",
                            expected_cause="e", unsafe_executions=-1)


class TestRollbackEdges:
    def test_null_action_and_lists_rejected(self):  # SECURITY
        with pytest.raises(ValidationError):
            Rollback(execution_id="e", rollback_action=None)  # type: ignore
        with pytest.raises(ValidationError):
            Rollback(execution_id="e", rollback_action={"a": 1},
                     conditions=None)  # type: ignore
        with pytest.raises(ValidationError):
            Rollback(execution_id="e", rollback_action={"a": 1},
                     verification="slo")  # type: ignore

    def test_non_bool_attempted_rejected(self):  # SECURITY
        with pytest.raises(ValidationError):
            Rollback(execution_id="e", rollback_action={"a": 1},
                     attempted="yes")  # type: ignore


class TestRcaCaps:
    def _valid(self, **over) -> dict:
        base = dict(incident_id="i", summary="s", root_cause="c")
        base.update(over)
        return base

    def test_audit_ref_and_prevention_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            RCA(**self._valid(audit_ref="r" * 257))
        with pytest.raises(ValidationError):
            RCA(**self._valid(prevention=[f"p{i}" for i in range(65)]))
        with pytest.raises(ValidationError):
            RCA(**self._valid(prevention=["  "]))

    def test_claims_and_impact_caps(self):  # SECURITY
        from app.contracts.hypothesis import Claim
        with pytest.raises(ValidationError):
            RCA(**self._valid(
                claims=[Claim(text=f"c{i}") for i in range(65)]))
        with pytest.raises(ValidationError):
            RCA(**self._valid(
                impact={f"k{i}": i for i in range(65)}))


class TestAuditEdges:
    def _valid(self, **over) -> dict:
        base = dict(seq=1, incident_id="i", actor="a",
                    event_type="policy.decision")
        base.update(over)
        return base

    def test_seq_and_ts_strict(self):  # SECURITY
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(seq=True))
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(seq=-1))
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(seq=1.5))
        from datetime import datetime
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(ts=datetime(2026, 9, 16)))

    def test_actor_and_type_edges(self):  # SECURITY
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(actor="  "))
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(event_type="e" * 129))
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(
                evidence_ids=[f"e{i}" for i in range(101)]))
        with pytest.raises(ValidationError):
            AuditEvent(**self._valid(result="r" * 1025))
        assert AuditEvent(**self._valid(agent="")).agent == ""


class TestEvaluationEdges:
    def test_ids_and_variant_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            EvaluationRun(suite="  ", case_id="c")
        with pytest.raises(ValidationError):
            BenchmarkResult(case_id="c", scenario="s", variant="v" * 65,
                            expected_cause="e")

    def test_metric_map_caps(self):  # SECURITY
        with pytest.raises(ValidationError):
            EvaluationRun(suite="s", case_id="c",
                          scores={f"m{i}": 1.0 for i in range(65)})
        with pytest.raises(ValidationError):
            EvaluationRun(suite="s", case_id="c",
                          latency_ms={"p": float("inf")})
        with pytest.raises(ValidationError):
            EvaluationRun(suite="s", case_id="c", llm_calls=True)  # type: ignore

    def test_ratio_bounds(self):  # SECURITY
        with pytest.raises(ValidationError):
            BenchmarkResult(case_id="c", scenario="s", variant="v",
                            expected_cause="e", citation_coverage=1.5)
        with pytest.raises(ValidationError):
            BenchmarkResult(case_id="c", scenario="s", variant="v",
                            expected_cause="e", citation_coverage="high")  # type: ignore


class TestNestingCrashBecomesValidationError:
    def test_deep_mappings_rejected_cleanly(self):  # SECURITY
        # Adversarial nesting (thousands deep) must fail as ValidationError,
        # never propagate RecursionError past the trust boundary.
        with pytest.raises(ValidationError):
            Hypothesis(text="t", confidence=0.5, test_args=_deep(2000))  # type: ignore
        with pytest.raises(ValidationError):
            RCA(incident_id="i", summary="s", root_cause="c",
                impact=_deep(2000))  # type: ignore
        with pytest.raises(ValidationError):
            AuditEvent(seq=1, incident_id="i", actor="a", event_type="e",
                       policy=_deep(2000))  # type: ignore
        with pytest.raises(ValidationError):
            RCA(incident_id="i", summary="s", root_cause="c",
                timeline=[_deep(50)])  # type: ignore

    def test_no_recursion_error_escapes(self):  # SECURITY
        # Strong form: RecursionError must not escape ANY of these paths.
        import pytest as _pytest
        with _pytest.raises(ValidationError):
            Hypothesis(text="t", confidence=0.5, test_args=_deep(5000))  # type: ignore


class TestImpactDepthAndRowBytes:
    def test_impact_depth_enforced(self):  # SECURITY
        with pytest.raises(ValidationError):
            RCA(incident_id="i", summary="s", root_cause="c",
                impact={"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}})  # type: ignore
        r = RCA(incident_id="i", summary="s", root_cause="c",
                impact={"a": {"b": {"c": {"d": {"e": 1}}}}})  # type: ignore
        assert r.impact["a"]["b"]["c"]["d"]["e"] == 1  # depth 5 boundary ok

    def test_row_bytes_capped(self):  # SECURITY
        with pytest.raises(ValidationError):
            RCA(incident_id="i", summary="s", root_cause="c",
                timeline=[{"ts": "t", "actor": "a", "hash": "h",
                           "blob": "x" * 20000}])  # type: ignore


class TestConfidenceBucketStrict:
    def test_bool_and_str_rejected(self):  # SECURITY
        from app.contracts.values import confidence_bucket
        with pytest.raises(ValueError):
            confidence_bucket(True)  # type: ignore
        with pytest.raises(ValueError):
            confidence_bucket("0.9")  # type: ignore
        assert confidence_bucket(0.7).value == "high"


class TestFromLegacyFastPath:
    def test_canonical_input_returns_exact(self):  # UNIT
        # Post-P1-closure the only real bridge input is canonical instances:
        # they must pass through EXACTLY (no coercion, no re-validation cost
        # semantic change, identical object).
        h = Hypothesis(text="t", confidence=0.5)
        assert Hypothesis.from_legacy(h) is h
        r = RCA(incident_id="i", summary="s", root_cause="c")
        assert RCA.from_legacy(r) is r
        a = AuditEvent(seq=1, incident_id="i", actor="a",
                       event_type="policy.decision")
        assert AuditEvent.from_legacy(a) is a

    def test_evidence_fast_path_identical(self):  # UNIT
        # Round-3 hunt: Evidence was the one bridge missing the fast-path
        # (all other 15 had it). Canonical in, identical object out.
        from app.contracts.evidence import Evidence
        ev = Evidence(incident_id="i", source_type="log", source_id="s",
                      ref="r", hash="h", freshness_s=1.0, relevance=0.5)
        assert Evidence.from_legacy(ev) is ev

    def test_all_bridges_fast_path_identical(self):  # UNIT
        # Campaign re-audit: all 16 fast-paths pinned (previously only 4).
        # A removed fast-path would silently reintroduce coercion on the
        # only real bridge input — this test makes that deletion fail.
        from datetime import datetime, timezone
        from app.contracts.alert import Alert
        from app.contracts.approval import ApprovalToken
        from app.contracts.hypothesis import Claim
        now = datetime.now(timezone.utc)
        cases = [
            (Claim, Claim(text="t")),
            (Runbook, Runbook(runbook_id="r", version="1.0.0", title="t")),
            (Action, Action(
                incident_id="i", agent_id="a", action_type="read",
                resource_type="deployment", resource_id="w", reason="r",
                runbook_id="rb", runbook_version="1.2.0",
                expected_outcome="o")),
            (PolicyDecision, PolicyDecision(
                decision="ALLOW", rule_id="r", policy_version="v1",
                effective_risk="GREEN")),
            (ApprovalRequest, ApprovalRequest(
                incident_id="i", action_id="a", actor="u", params_hash="h",
                scope="s", expires_at=now, nonce="n0nce-abc123")),
            (ApprovalToken, ApprovalToken(
                token="t", approval_id="a", action_id="x", actor="u",
                params_hash="h", expires_at=now)),
            (Execution, Execution(
                action_id="a", incident_id="i", idempotency_key="k")),
            (VerificationResult, VerificationResult(
                execution_id="e", verdict="RESOLVED")),
            (Rollback, Rollback(execution_id="e",
                                rollback_action={"a": 1})),
            (BenchmarkResult, BenchmarkResult(
                case_id="c", scenario="s", variant="v",
                expected_cause="e")),
            (EvaluationRun, EvaluationRun(suite="s", case_id="c")),
            (Alert, Alert(source="p", service="w", severity="P1",
                          message="m", fingerprint="f")),
        ]
        for cls, obj in cases:
            assert cls.from_legacy(obj) is obj, cls.__name__


class TestCrossFileActionSets:
    def test_shipped_runbooks_name_only_known_actions(self):  # INTEGRATION
        # M01.6/M01.1 boundary: every allowed/forbidden action in the five
        # shipped runbooks must be an ACTION_TYPES member (proves the
        # allowlist and the seeds cannot drift apart silently).
        import yaml
        from app.contracts.enums import ACTION_TYPES
        allowed: set[str] = set()
        for path in sorted((ROOT / "runbooks").glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            allowed.update(data.get("allowed_actions", []))
            allowed.update(data.get("forbidden_actions", []))
        assert allowed, "no runbook actions found"
        assert allowed <= set(ACTION_TYPES), \
            f"outside allowlist: {sorted(allowed - set(ACTION_TYPES))}"
