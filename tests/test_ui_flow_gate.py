"""The operator path must work in a real browser, not just render.

`test_ui_browser_gate.py` proves every view renders cleanly. It cannot prove
the product is usable: a UI whose incident form posts to a route that never
drives the pipeline, whose Safety Gate shows a blank hand-written template, and
whose Execution view has no evidence, all render perfectly. That is exactly the
state this repository was in, and it is why "dynamic end to end" needed proving
rather than assuming.

This wrapper makes `scripts/ui_flow_check.mjs` a normal gate. It drives the real
path -- sign in, ingest, park for approval, load the pipeline's own proposal,
request and grant approval, then read the tier, the state diff, the executor
output, the verifier verdict with its per-check results, and the audit chain --
and asserts on what the DOM actually shows.

It SKIPS (never fails) when the stack is down or no operator key is available,
so the host-safe suite stays runnable without Docker. A credential is required
because every write is server-gated by design: a 401 there is correct security
behaviour, not a defect, and cannot be asserted on without one.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ui_flow_check.mjs"
UI_URL = os.environ.get("PROOFOPS_UI_URL", "http://127.0.0.1:5173")
# Generous: the flow includes real agent work and real approval, so it is
# minutes rather than the render sweep's ~3s per combination.
TIMEOUT_S = 900


def _stack_is_up() -> bool:
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(f"{UI_URL}/", timeout=5) as response:
            return 200 <= response.status < 400
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _operator_key() -> str:
    """The deployment's write key, for the sign-in step.

    Read from the environment, never from a committed file, and never printed.
    Without it the flow's write steps would 401 -- which is the correct security
    behaviour, so the run is skipped rather than reported as a product failure.
    """
    key = os.environ.get("PROOFOPS_API_KEY", "").strip()
    if key:
        return key
    env_file = ROOT / ".env"
    if not env_file.is_file():
        return ""
    for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip().startswith("PROOFOPS_API_KEY="):
            return line.split("=", 1)[1].strip()
    return ""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not on PATH")
@pytest.mark.skipif(not _stack_is_up(), reason=f"UI not reachable at {UI_URL}")
@pytest.mark.skipif(_operator_key() == "",
                    reason="no PROOFOPS_API_KEY: every write is server-gated, "
                           "so the flow cannot be driven")
def test_the_operator_path_works_end_to_end_in_a_real_browser():
    proc = subprocess.run(
        ["node", str(SCRIPT), "--json"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        cwd=str(ROOT),
        env={**os.environ, "PROOFOPS_UI_URL": UI_URL,
             "PROOFOPS_API_KEY": _operator_key()},
    )
    assert proc.returncode in (0, 1), (
        "the flow gate must exit 0 (path works) or 1 (a step failed); "
        f"exit {proc.returncode} means the check could not run:\n{proc.stderr[-800:]}"
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - diagnostics only
        pytest.fail(f"flow gate produced no JSON report: {exc}\n{proc.stdout[-800:]}")

    failed = [c for c in report["checks"] if not c["ok"]]
    assert not failed, (
        f"{len(failed)} of {len(report['checks'])} end-to-end steps failed for "
        f"{report['incident_id']} (final state {report['final_state']}):\n"
        + "\n".join(f"  {c['name']}: {c['detail']}" for c in failed)
    )
    # The flow is only meaningful if it actually reached a terminal state; a run
    # that stopped early would pass a shorter list.
    assert report["final_state"] in (
        "RESOLVED", "AUDITED", "ESCALATED", "ROLLBACK", "BLOCKED",
    ), f"the approved run never reached a terminal state: {report['final_state']}"


def test_flow_gate_asserts_the_steps_it_was_written_for():
    """The gate's own coverage, asserted statically so it cannot be trimmed away.

    Each entry is a step whose absence made the product unusable while every
    render check still passed.
    """
    source = SCRIPT.read_text(encoding="utf-8")

    # The front door, and that it goes to the route that drives the pipeline.
    assert "alerts/ingest" in source or "ingestApi" in source or \
        "new-incident" in source, "the gate must submit the real ingest form"
    assert "/runs/" in source, (
        "the gate must confirm the run exists server-side; a UI acknowledgement "
        "alone proves nothing about whether the pipeline was driven"
    )
    # HITL, and that the proposal is the pipeline's own rather than a template.
    assert "Load this action" in source, (
        "the gate must load the parked proposal into the request form"
    )
    assert "rollback_deployment" in source, (
        "the gate must assert the loaded action is the planned one, not a blank "
        "template that happens to be submittable"
    )
    # The decision, and the evidence only the backend can attach.
    assert "/approve" in source
    for evidence in ("execution_tier", "state_diff", "execution_logs",
                     "verification_results", "checks"):
        assert evidence in source, (
            f"the gate must assert {evidence} reached the run; it is the evidence "
            "that only exists if the backend attached it"
        )
    # The honesty regression: no invented process status.
    assert "EXIT CODE" in source, (
        "the gate must keep asserting the fabricated exit code stays gone"
    )
    # The audit proof.
    assert "audit/verify" in source
    # Sign-in, because without it every write is a 401.
    assert "operator-api-key" in source
    assert "proofops_jwt_token" in source
    # Determinism. A gate that fails on a cold stack is a gate people learn to
    # ignore, which is worse than no gate. Liveness alone is not readiness:
    # /healthz answers with dependencies down by design, so the pre-flight must
    # also wait on /readyz and a healthy database.
    assert "waitForApiReady" in source, (
        "the gate must wait for the API before driving it; a cold stack makes "
        "the first write fail and reports six phantom defects downstream"
    )
    assert "/readyz" in source, (
        "/healthz answers with dependencies down by design, so it is not a "
        "readiness precondition"
    )
    assert "database" in source and "healthy" in source, (
        "readiness must include the database, since that is what a write needs"
    )
    assert "attempt < 4" in source or "attempt < 3" in source, (
        "the sign-in and ingest steps must be retried, so one transient fault "
        "does not cascade into every downstream check"
    )
    # No new dependency, same rule as the render gate.
    imported = set(re.findall(r"^import\s+(?:[\w*\s{},]+)\s+from\s+[\"']([^\"']+)[\"']",
                              source, re.MULTILINE))
    allowed = {"node:child_process", "node:fs", "node:os", "node:path"}
    assert imported <= allowed, (
        f"the flow gate may only import Node built-ins {sorted(allowed)}; "
        f"found {sorted(imported - allowed)}"
    )
    # Cache off, or the sweep silently tests the previous build.
    assert "setCacheDisabled" in source
