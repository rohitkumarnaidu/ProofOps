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
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ui_flow_check.mjs"
UI_URL = os.environ.get("PROOFOPS_UI_URL", "http://127.0.0.1:5173")
# Generous: the flow includes real agent work, a real approval, the real
# execution and the postmortem gate, so it is tens of seconds warm and rather
# longer cold or on a loaded host. A timeout here is an environment failure,
# reported as such, and never as a product finding.
TIMEOUT_S = 900


def _newest_source_change_iso() -> str:
    """Newest commit touching code this flow actually exercises, as an ISO stamp.

    Backend and frontend only. Docs, tests and CI config do not change what the
    running bundle serves, so including them would make the freshness check
    refuse a perfectly current stack after a documentation commit.
    """
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", "backend", "frontend"],
            capture_output=True, text=True, timeout=30, cwd=str(ROOT),
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return ""
    if out.returncode != 0:
        return ""
    return out.stdout.strip()


def _stack_started_iso() -> str:
    """When the running api container started, as an ISO stamp, or "" if unknown.

    Docker's own report is the source of truth: it is the only party that knows
    when the image was actually created and started.
    """
    if shutil.which("docker") is None:
        return ""
    try:
        out = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Service}}|{{.RunningFor}}",
             "api"],
            capture_output=True, text=True, timeout=30, cwd=str(ROOT),
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return ""
    if out.returncode != 0:
        return ""
    line = (out.stdout or "").strip().splitlines()
    if not line:
        return ""
    running_for = line[0].split("|", 1)[-1].strip()
    m = re.match(r"(\d+)\s+(second|minute|hour|day|week|month|year)", running_for)
    if not m:
        # "About an hour" / "Up 2 hours (healthy)" variants: fall back to the
        # leading integer, and to "0 seconds" when docker reports nothing useful.
        m2 = re.search(r"(\d+)\s+(second|minute|hour|day)", running_for)
        if not m2:
            return ""
        amount, unit = int(m2.group(1)), m2.group(2)
    else:
        amount, unit = int(m.group(1)), m.group(2)
    now = datetime.now(timezone.utc)
    scale = {"second": 1, "minute": 60, "hour": 3600,
             "day": 86400, "week": 604800, "month": 2592000, "year": 31536000}
    return datetime.fromtimestamp(
        now.timestamp() - amount * scale[unit], tz=timezone.utc
    ).isoformat()


def _stack_is_stale() -> bool:
    """True only when the running bundle provably predates the source.

    This gate drives a real stack, so it is the only test here whose verdict
    depends on deployed code matching the checkout. When the stack is older than
    the newest backend/frontend commit, the failures it reports are the age of
    the deployment, not a defect in the product, and reporting them as a product
    verdict is actively misleading: it cost a full triage to establish that the
    container simply predated a dependency fix.

    Deliberately narrow. If either timestamp is unreadable the answer is False,
    so this can never suppress a real failure. It is a freshness precondition, not
    a retry and not a general error filter.
    """
    src, started = _newest_source_change_iso(), _stack_started_iso()
    if not src or not started:
        return False
    try:
        return datetime.fromisoformat(started) < datetime.fromisoformat(src)
    except ValueError:  # pragma: no cover - defensive
        return False


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
@pytest.mark.skipif(_stack_is_stale(),
                    reason="the running stack predates the newest backend/frontend "
                           "commit, so a failure here is the deployment's age and "
                           "not a product defect; rebuild the stack first")
@pytest.mark.skipif(_operator_key() == "",
                    reason="no PROOFOPS_API_KEY: every write is server-gated, "
                           "so the flow cannot be driven")
def test_the_operator_path_works_end_to_end_in_a_real_browser() -> None:
    try:
        proc = subprocess.run(
            ["node", str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            cwd=str(ROOT),
            env={**os.environ, "PROOFOPS_UI_URL": UI_URL,
                 "PROOFOPS_API_KEY": _operator_key()},
        )
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout
        partial: str = "" if raw is None else (
            raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
        )
        pytest.fail(
            f"the flow gate did not complete within {TIMEOUT_S}s. That is an "
            "environment failure, not a product finding: the path was not "
            f"judged. Partial output:\n{partial[-800:]}"
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


def test_stale_stack_is_skipped_rather_than_reported_as_a_product_defect() -> None:
    """The freshness precondition must exist, and must be narrow.

    Two failure modes are being prevented here. First, a container that predates
    the source produces a verdict about the deployment's age dressed up as a
    product defect, which is worse than no signal. Second, and worse, a skip
    that triggers too eagerly would hide a real regression behind an excuse.

    So: the guard must be present, it must be attached to this test, and it must
    degrade to "not stale" whenever it cannot prove staleness.
    """
    src = Path(__file__).read_text(encoding="utf-8")

    # Attached to the flow test, not merely defined somewhere in the file.
    # Matched at the start of a line so this assertion cannot count its own text.
    decorators = [
        ln for ln in src.splitlines()
        if ln.strip().startswith("@pytest.mark.skipif(_stack_is_stale()")
    ]
    assert len(decorators) == 1, (
        "the stale-stack guard must gate exactly the live-stack flow test, not "
        f"the host-safe tests around it (found {len(decorators)})"
    )

    # Narrow by construction: unprovable freshness must never suppress a run.
    body = src.split("def _stack_is_stale()", 1)[1].split("def test_", 1)[0]
    assert "return False" in body, (
        "_stack_is_stale must default to False when it cannot prove staleness, "
        "so an unreadable timestamp can never hide a real failure"
    )
    assert "if not src or not started:" in body, (
        "both timestamps are required before staleness may be claimed"
    )
    # It must read the real signals, not a heuristic: docker's own start time
    # for the bundle, git history for the source it is meant to match.
    assert "_stack_started_iso" in body and "_newest_source_change_iso" in body, (
        "_stack_is_stale must decide from both real signals, not from one"
    )
    assert '"docker", "compose", "ps"' in src and \
           '"git", "log", "-1"' in src, (
        "staleness must be read from docker's reported start time and the git "
        "history, not inferred"
    )


def test_flow_gate_asserts_the_steps_it_was_written_for() -> None:
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
    # The post-incident stage. AUDITED is reachable only by publishing a gated
    # postmortem, and before that stage was driven every run stopped at
    # RESOLVED -- so the gate must assert the terminal state AND the document.
    assert "the run reached the terminal AUDITED state" in source, (
        "the gate must assert the run reaches AUDITED; RESOLVED alone means the "
        "post-incident stage never ran"
    )
    assert "rca-document" in source, (
        "the gate must assert the postmortem is RENDERED, not merely served"
    )
    for field in ("claim_ids", "remediation_log", "prevention"):
        assert field in source, (
            f"the gate must assert the postmortem's {field} is present; an "
            "ungated or empty document would pass without them"
        )
    assert "does not render an RCA document" in source, (
        "the gate must keep asserting the stale disclaimer stays gone"
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
