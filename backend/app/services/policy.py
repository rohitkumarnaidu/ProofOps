"""Deterministic policy engine (V2 §18). PRIMARY runtime authorization boundary.

evaluate(action, actor, env_ctx, severity, blast, bundle)
  -> PolicyDecision(ALLOW | ESCALATE | DENY)

Priority: DENY > ESCALATE > ALLOW. Default DENY. Any exception -> DENY.
The LLM's `risk_level` is ignored except as an audited advisory field.
"""
from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts.action import Action  # noqa: E402 (M01.7 canonical)
from app.contracts.enums import ACTION_TYPES  # noqa: E402 (M01.1 allowlist)
from app.contracts.policy import PolicyDecision  # noqa: E402 (M01.8 canonical)

POLICY_DIR = Path(__file__).resolve().parents[3] / "policies"

# Bundle schema (M06.4): fixed shape so malformed policy can never widen
# authority. `when` keys are a closed set; values must name known vocabulary.
BUNDLE_WHEN_KEYS = frozenset({"action_type", "environment", "resource_type"})
BUNDLE_ENVS = frozenset({"dev", "staging", "prod", "mock"})


def load_bundle(version: str = "v1") -> dict:
    with open(POLICY_DIR / f"bundle_{version}.yaml", encoding="utf-8") as f:
        bundle = yaml.safe_load(f)
    errors = validate_bundle(bundle)
    if errors:
        raise ValueError(f"invalid policy bundle v{version}: {errors[0]}")
    return bundle


def validate_bundle(bundle: Any) -> list[str]:
    """Validate bundle shape (M06.4). Returns error strings; [] == valid.

    A malformed bundle must never widen authority: unknown `when` keys,
    unknown action/env values, or missing sections are all errors, and the
    engine treats any error as DENY (fail-closed).
    """
    errs: list[str] = []
    if not isinstance(bundle, dict):
        return ["bundle must be an object"]
    if not bundle.get("policy_version") or not isinstance(
            bundle.get("policy_version"), str):
        errs.append("bundle policy_version is required")
    rules = bundle.get("deny_rules")
    if not isinstance(rules, list) or not rules:
        errs.append("bundle deny_rules must be a non-empty list")
    else:
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errs.append(f"deny_rules[{i}] must be an object")
                continue
            if not rule.get("id") or not isinstance(rule["id"], str):
                errs.append(f"deny_rules[{i}] id is required")
            when = rule.get("when")
            if not isinstance(when, dict) or not when:
                errs.append(f"deny_rules[{i}] when must be a non-empty object")
                continue
            for k, v in when.items():
                if k not in BUNDLE_WHEN_KEYS:
                    errs.append(f"deny_rules[{i}] unknown when-key: {k!r}")
                elif k == "action_type" and v not in ACTION_TYPES:
                    errs.append(f"deny_rules[{i}] unknown action_type: {v!r}")
                elif k == "environment" and v not in BUNDLE_ENVS:
                    errs.append(f"deny_rules[{i}] unknown environment: {v!r}")
    esc = bundle.get("escalate_obligations", [])
    if not isinstance(esc, list) or any(not isinstance(o, str) for o in esc):
        errs.append("bundle escalate_obligations must be a list of strings")
    return errs


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
    bundle_errors = validate_bundle(bundle)
    if bundle_errors:
        return PolicyDecision(decision="DENY", rule_id="DENY-invalid-bundle",
                              policy_version="unknown", effective_risk="RED",
                              message=f"invalid policy bundle: {bundle_errors[0]}")
    version = str(bundle.get("policy_version", "unknown"))
    if not isinstance(matrix, dict) or not isinstance(
            matrix.get("tiers"), dict):
        return PolicyDecision(decision="DENY", rule_id="DENY-invalid-matrix",
                              policy_version=version, effective_risk="RED",
                              message="risk matrix missing tiers")

    # 0. context integrity: caller env must match the action's own env
    if env_ctx.get("environment", action.environment) != action.environment:
        return PolicyDecision(decision="DENY", rule_id="DENY-env-mismatch",
                              policy_version=version, effective_risk="RED",
                              message="environment context does not match action")

    # 0b. shape defense-in-depth: parameters must be a mapping. The validator
    # owns shape (pre-policy); the engine re-checks the single most dangerous
    # smuggle vector (a shell string past construction) so a validator skip
    # can never become an authorization.
    if not isinstance(action.parameters, Mapping):
        return PolicyDecision(decision="DENY", rule_id="DENY-malformed-params",
                              policy_version=version, effective_risk="RED",
                              message="parameters must be an object")

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

    # 4. role floor (checked again at HITL bound to identity; recorded here
    # as obligation - the engine never authorizes on role alone)
    roles = matrix.get("roles", {})
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
        return PolicyDecision(decision="ESCALATE", rule_id="ESCALATE-risk-YELLOW",
                              policy_version=version, effective_risk="YELLOW",
                              obligations=obligations, ttl_seconds=600,
                              message="controlled mutation requires HITL approval")
    return PolicyDecision(decision="ALLOW", rule_id="ALLOW-risk-GREEN",
                          policy_version=version, effective_risk="GREEN",
                          message="read-only / low-risk operation")
