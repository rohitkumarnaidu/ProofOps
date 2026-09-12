"""Deterministic policy engine (V2 §18). PRIMARY runtime authorization boundary.

evaluate(action, actor, env_ctx, severity, blast, bundle)
  -> PolicyDecision(ALLOW | ESCALATE | DENY)

Priority: DENY > ESCALATE > ALLOW. Default DENY. Any exception -> DENY.
The LLM's `risk_level` is ignored except as an audited advisory field.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.schemas import Action, PolicyDecision  # noqa: E402

POLICY_DIR = Path(__file__).resolve().parents[3] / "policies"


def load_bundle(version: str = "v1") -> dict:
    with open(POLICY_DIR / f"bundle_{version}.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_matrix(version: str = "v1") -> dict:
    with open(POLICY_DIR / "risk_matrix.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _rule_matches(when: dict, action: Action) -> bool:
    for k, v in when.items():
        if k == "action_type" and action.action_type != v:
            return False
        if k == "environment" and action.environment != v:
            return False
        if k == "resource_type" and action.resource_type != v:
            return False
    return True


def evaluate(action: Action, actor: dict, env_ctx: dict, severity: str,
             blast: dict, bundle: dict | None = None,
             matrix: dict | None = None) -> PolicyDecision:
    """Fail-closed evaluation. Never raises: exceptions become DENY."""
    try:
        return _evaluate(action, actor, env_ctx, severity, blast,
                         bundle or load_bundle(), matrix or load_matrix())
    except Exception as exc:  # fail-closed (invariant 14)
        return PolicyDecision(decision="DENY", rule_id="DENY-engine-error",
                              policy_version="unknown", effective_risk="RED",
                              message=f"policy engine error (fail-closed): {exc}")


def _evaluate(action: Action, actor: dict, env_ctx: dict, severity: str,
              blast: dict, bundle: dict, matrix: dict) -> PolicyDecision:
    version = str(bundle.get("policy_version", "unknown"))

    # 0. context integrity: caller env must match the action's own env
    if env_ctx.get("environment", action.environment) != action.environment:
        return PolicyDecision(decision="DENY", rule_id="DENY-env-mismatch",
                              policy_version=version, effective_risk="RED",
                              message="environment context does not match action")

    # 1. explicit DENY rules
    for rule in bundle.get("deny_rules", []):
        if _rule_matches(rule.get("when", {}), action):
            return PolicyDecision(decision="DENY", rule_id=rule["id"],
                                  policy_version=version, effective_risk="RED",
                                  message=rule.get("message", ""))

    # 2. recompute effective risk from matrix (LLM advisory ignored)
    tiers = matrix.get("tiers", {})
    entry = tiers.get(action.action_type)
    if not entry:
        return PolicyDecision(decision="DENY", rule_id="DENY-unknown-action",
                              policy_version=version, effective_risk="RED",
                              message=f"action type not in risk matrix: {action.action_type}")
    risk = entry.get(action.environment, "RED")

    # 3. blast-radius override: big YELLOW blasts stay escalated with review note
    obligations = list(bundle.get("escalate_obligations", []))
    if risk == "YELLOW" and (int(blast.get("replicas", 1)) > 4
                             or float(blast.get("traffic_pct", 0)) > 50):
        obligations.append("blast-review")

    # 4. role floor (checked again at HITL; recorded here as obligation)
    roles = matrix.get("roles", {})
    floor = {"GREEN": 0, "YELLOW": 1, "RED": 2}[risk]
    have = {"viewer": 0, "approver": 1, "admin": 2}.get(actor.get("role"), -1)
    if have < 0:
        return PolicyDecision(decision="DENY", rule_id="DENY-unknown-actor",
                              policy_version=version, effective_risk="RED",
                              message="unknown actor role")

    if risk == "RED":
        return PolicyDecision(decision="DENY", rule_id="DENY-risk-RED",
                              policy_version=version, effective_risk="RED",
                              obligations=[], message="RED actions are blocked")
    if risk == "YELLOW":
        obligations.append(f"required_role:{roles.get('YELLOW', 'approver')}")
        _ = floor  # documented: floor enforced at HITL bound to identity
        return PolicyDecision(decision="ESCALATE", rule_id="ESCALATE-risk-YELLOW",
                              policy_version=version, effective_risk="YELLOW",
                              obligations=obligations, ttl_seconds=600,
                              message="controlled mutation requires HITL approval")
    return PolicyDecision(decision="ALLOW", rule_id="ALLOW-risk-GREEN",
                          policy_version=version, effective_risk="GREEN",
                          message="read-only / low-risk operation")
