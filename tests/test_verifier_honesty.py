"""Zero-trust tests for verification honesty (M09).

The hazard is not a wrong verdict. It is a *right-looking* verdict reached
without evidence. This module's whole purpose is that "exit 0" is not a verdict
and the verifier is independent of the planner -- so if the verifier can be talked
into RESOLVED by numbers that were never measured, independence is decorative.

The specific failure: the synthetic telemetry describes an error rate for a
service that does not exist in the real cluster. Every PromQL query returns
nothing, so the verifier substituted the sandbox's own in-memory values and
carried on. It could therefore return RESOLVED having observed nothing at all.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "backend" / "app" / "services" / "prom_verifier.py"
PIPELINE = ROOT / "backend" / "app" / "services" / "pipeline.py"


def _fn(path: Path, name: str) -> str:
    """The function's executable body, docstring removed.

    Matches async functions too: the live verifier is `async def`, and a helper
    that only walked `FunctionDef` would silently report "not found" and invite
    someone to "fix" the test by pointing it at the sync wrapper -- which is not
    where the honesty logic lives.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == name:
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)):
                node.body = node.body[1:]
            return ast.unparse(ast.Module(body=node.body, type_ignores=[]))
    raise AssertionError(f"{name} not found in {path.name}")


def test_resolved_requires_at_least_one_observed_signal():
    """A verdict of RESOLVED must be gated on having measured something."""
    body = _fn(VERIFIER, "verify")
    assert "measured" in body, (
        "the verifier must track whether any signal was actually observed")
    # The unmeasured branch must return before the all-checks-passed branch.
    unmeasured_at = body.find("if not measured")
    resolved_at = body.find("Verdict.RESOLVED")
    assert unmeasured_at != -1, (
        "there must be an explicit branch for 'nothing was observable'")
    assert unmeasured_at < resolved_at, (
        "the unmeasured branch must come first, so RESOLVED is unreachable when "
        "no signal was observed")


def test_unmeasured_evidence_cannot_claim_resolved():
    body = _fn(VERIFIER, "verify")
    unmeasured = body[body.find("if not measured"):body.find("Verdict.RESOLVED")]
    assert "Verdict.RESOLVED" not in unmeasured, (
        "the unmeasured branch must not be able to return RESOLVED")
    assert "refused to" in unmeasured, (
        "the refusal must be stated in the evidence, not just implied by a "
        "downgraded verdict -- a reader of the audit chain needs to see why")


def test_the_detail_string_leads_with_the_evidence_source():
    """A reader must be able to tell measured from assumed, unaided."""
    body = _fn(VERIFIER, "verify")
    assert "evidence_source" in body, (
        "the verifier must label its evidence source")
    assert "fallback-state" in body and "live-promql" in body, (
        "both sources must be nameable, or the label is not a label")
    assert "UNMEASURED=" in body, (
        "signals that fell back to the mock must be listed individually, not "
        "summarised away")


def test_the_verifier_is_selected_by_tier_not_by_reachability():
    """Mock tier must use the deterministic verifier, not the live one.

    Calling the PromQL verifier unconditionally meant a mock run was
    "independently verified" by a component whose queries never observed
    anything, then quietly relabelled the sandbox's own numbers as a result.
    """
    body = _fn(PIPELINE, "_verify_action")
    assert "LIVE_CLUSTER" in body, (
        "verification tier must be selected by configuration")
    assert "verifier_svc.verify" in body, "the mock tier must use the mock verifier"
    assert "PROMETHEUS_VERIFIER.verify_sync" in body, (
        "the live tier must use the PromQL verifier")
    # Live must be gated on the setting, and the setting must come first.
    assert body.index("LIVE_CLUSTER") < body.index("PROMETHEUS_VERIFIER"), (
        "the live verifier must be behind the explicit tier gate")


def test_execution_and_verification_are_gated_by_the_same_switch():
    """Two tiers, one switch -- otherwise the pair can disagree.

    Executing live while verifying against the mock (or the reverse) means the
    thing that ran and the thing that judged it are looking at different worlds.
    """
    apply_body = _fn(PIPELINE, "_apply_action")
    verify_body = _fn(PIPELINE, "_verify_action")
    assert "LIVE_CLUSTER" in apply_body
    assert "LIVE_CLUSTER" in verify_body
