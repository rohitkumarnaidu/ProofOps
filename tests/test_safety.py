"""Safety tests: validator + policy engine + risk matrix + runbooks.

M05-M06 rewire: constructs canonical contracts (app.contracts) - the legacy
schemas wire is identical, but services now take canonical types only.
Behavioral pins below are unchanged.
"""
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.contracts import Action, params_hash  # noqa: E402 (M01 canonical)
from app.services.policy import evaluate, load_bundle, load_matrix  # noqa: E402
from app.services.runbooks import content_hash, load_runbook  # noqa: E402
from app.services.validator import validate_action  # noqa: E402

BUNDLE = load_bundle()
MATRIX = load_matrix()
APPROVER = {"role": "approver", "id": "sre-1"}
VIEWER = {"role": "viewer", "id": "obs-1"}
BLAST_SMALL = {"scope": "deploy", "replicas": 2, "traffic_pct": 10}
BLAST_BIG = {"scope": "deploy", "replicas": 8, "traffic_pct": 80}


def act(**over) -> Action:
    base = dict(incident_id="inc-1", agent_id="planner", action_type="read",
                resource_type="deployment", resource_id="web", environment="mock",
                parameters={}, reason="r", evidence_ids=["ev-1"],
                runbook_id="bad-deploy-rollback", runbook_version="1.2.0",
                expected_outcome="o", verification_plan=["v"])
    base.update(over)
    return Action(**base)


def ev(action, actor=APPROVER, blast=BLAST_SMALL, sev="P1"):
    return evaluate(action, actor, {"environment": action.environment},
                    sev, blast, BUNDLE, MATRIX)


# --- validator ---------------------------------------------------------------
def test_validator_shell_always_rejected():
    a = act(action_type="shell", parameters={"cmd": "echo hi"})
    assert any("shell" in e for e in validate_action(a))


def test_validator_string_params_rejected():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        act(action_type="read", parameters="kubectl get pods")  # type: ignore[arg-type]


def test_validator_param_guards():
    rb = load_runbook("db-pool-saturation")
    ok = act(action_type="scale_deployment", resource_type="deployment",
             resource_id="api", runbook_id="db-pool-saturation",
             runbook_version="1.1.0", parameters={"replicas": 3},
             rollback_action={"action_type": "scale_deployment"})
    assert validate_action(ok, rb) == []
    for bad in [{"replicas": 0}, {"replicas": 99}, {"replicas": "3"},
                {"replicas": True}, {"note": "a;b"}, {"q": "DROP TABLE t"},
                {"tag": "x|y"}]:
        errs = validate_action(act(action_type="scale_deployment",
                                   parameters=bad,
                                   rollback_action={"action_type": "x"}), rb)
        assert errs, f"param {bad} should be rejected"


def test_validator_runbook_pinning_and_allowlist():
    rb = load_runbook("bad-deploy-rollback")
    assert "not in runbook" in " ".join(validate_action(
        act(action_type="restart_pod", rollback_action={"a": 1}), rb))
    assert any("pin" in e.lower() or "exactly" in e.lower() for e in validate_action(
        act(action_type="rollback_deployment", runbook_version="9.9.9",
            rollback_action={"a": 1}), rb))
    missing_ev = act(action_type="rollback_deployment", evidence_ids=[],
                     rollback_action={"a": 1})
    assert any("evidence" in e for e in validate_action(missing_ev, rb))
    missing_rb = act(action_type="rollback_deployment",
                     rollback_action=None)  # type: ignore[arg-type]
    assert any("rollback_action" in e for e in validate_action(missing_rb, rb))


# --- policy: ALLOW ------------------------------------------------------------
@pytest.mark.parametrize("t", ["read", "describe", "logs", "metrics", "list"])
def test_green_reads_allow_everywhere(t):
    for env in ["mock", "dev", "staging", "prod"]:
        d = ev(act(action_type=t, environment=env), VIEWER)
        assert d.decision == "ALLOW" and d.effective_risk == "GREEN", (t, env)


def test_restart_mock_green_allows():
    d = ev(act(action_type="restart_pod", environment="mock"))
    assert d.decision == "ALLOW"


# --- policy: ESCALATE ----------------------------------------------------------
@pytest.mark.parametrize("t,env", [
    ("restart_pod", "prod"), ("scale_deployment", "staging"),
    ("rolling_restart", "mock"), ("rollback_deployment", "prod"),
    ("patch_config", "dev"),
])
def test_yellow_escalates_with_hitl_obligation(t, env):
    d = ev(act(action_type=t, environment=env))
    assert d.decision == "ESCALATE" and "hitl-approval" in d.obligations


def test_big_blast_adds_review_obligation():
    d = ev(act(action_type="scale_deployment", environment="staging"),
           blast=BLAST_BIG)
    assert "blast-review" in d.obligations


# --- policy: DENY ---------------------------------------------------------------
@pytest.mark.parametrize("t,env", [
    ("delete_namespace", "prod"), ("delete_namespace", "mock"),
    ("delete_deployment", "staging"), ("rbac_change", "mock"),
    ("secret_access", "mock"), ("db_write", "mock"),
    ("reboot_node", "dev"), ("shell", "mock"),
    ("delete_pod", "prod"),  # hackathon RED
])
def test_red_denied(t, env):
    d = ev(act(action_type=t, environment=env))
    assert d.decision == "DENY" and d.effective_risk == "RED", (t, env)


def test_llm_advisory_risk_ignored():
    """LLM claiming GREEN on a destructive action changes nothing."""
    d = ev(act(action_type="delete_namespace", environment="prod",
               risk_level="GREEN"))
    assert d.decision == "DENY"


def test_unknown_action_denied():
    a = act()
    # Adversarial: smuggle an off-allowlist type past construction (the
    # documented object.__setattr__ residual). The ENGINE must still DENY
    # via matrix lookup - schema validation is not the only boundary.
    object.__setattr__(a, "action_type", "teleport")
    assert ev(a).decision == "DENY"


def test_unknown_actor_denied():
    assert ev(act(), {"role": "hacker"}).decision == "DENY"


def test_env_mismatch_denied():
    a = act(environment="mock")
    d = evaluate(a, APPROVER, {"environment": "prod"}, "P1", BLAST_SMALL,
                 BUNDLE, MATRIX)
    assert d.decision == "DENY"


def test_engine_exception_fail_closed():
    d = evaluate(act(), APPROVER, {}, "P1", BLAST_SMALL, None, None)
    # None bundle/matrix would crash load only if files missing; force junk:
    d2 = evaluate(act(), APPROVER, {"environment": "mock"}, "P1", BLAST_SMALL,
                  {"deny_rules": None}, None)
    assert d2.decision == "DENY"


# --- runbooks ------------------------------------------------------------------
def test_all_runbooks_load_and_verify():
    for rid in ["bad-deploy-rollback", "crashloop-oom", "db-pool-saturation",
                "net-dep-failover", "injection-quarantine"]:
        rb = load_runbook(rid)
        assert rb.hash and rb.version


def test_tampered_runbook_rejected(tmp_path):
    import shutil
    src = Path("runbooks/bad-deploy-rollback.yaml")
    dst = tmp_path / "bad-deploy-rollback.yaml"
    shutil.copy(src, dst)
    data = yaml.safe_load(dst.read_text())
    data["allowed_actions"].append("shell")
    dst.write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError, match="hash mismatch"):
        load_runbook("bad-deploy-rollback", tmp_path)


def test_injection_runbook_allows_no_mutation():
    rb = load_runbook("injection-quarantine")
    assert [str(a) for a in rb.allowed_actions] == ["read", "describe",
                                                   "logs", "metrics", "list"]
    errs = validate_action(act(action_type="restart_pod",
                               rollback_action={"a": 1},
                               runbook_id="injection-quarantine",
                               runbook_version="1.0.0"), rb)
    assert errs


def test_params_hash_binds_scope():
    assert params_hash({"to_version": "v22"}) != params_hash({"to_version": "v23"})
