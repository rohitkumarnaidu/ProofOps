"""The browser gate runs as part of the suite whenever the stack is up.

`scripts/ui_browser_check.mjs` is the only check in this repository that can
see a runtime UI defect, and the evidence for that is not theoretical. In one
frontend pass it found four separate defects that every other gate passed:

  * a blank white screen on every view (empty inlined API base);
  * a form control rendering with no border and a transparent fill, because a
    `{...rest}` spread sat after `className` and replaced the primitive's
    classes -- invisible to `tsc` and to every source-grep test;
  * a red "stream disconnected" banner on a healthy backend, because a
    replay-only stream's normal close is indistinguishable from a real drop;
  * a control-boundary border at 1.30:1, below the WCAG SC 1.4.11 minimum.

It was validated by reproduction, not assumed: reintroducing the empty API base
and defeating the Dockerfile's own default so the bundle really compiled to an
empty string made this gate exit 1 with the uncaught TypeError, and restoring
the fix returned it to 0.

This wrapper makes it a normal gate rather than a script somebody remembers to
run. It SKIPS -- never fails -- when the stack is not up, so the host-safe
suite stays runnable without Docker, and a real failure is always a real
failure rather than an environment problem in disguise.
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
SCRIPT = ROOT / "scripts" / "ui_browser_check.mjs"
UI_URL = os.environ.get("PROOFOPS_UI_URL", "http://127.0.0.1:5173")
# Generous: the sweep is 15 view/viewport combinations at ~3s each.
TIMEOUT_S = 300


def _stack_is_up() -> bool:
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(f"{UI_URL}/", timeout=5) as response:
            return 200 <= response.status < 400
    except (urllib.error.URLError, OSError, ValueError):
        return False


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not on PATH")
@pytest.mark.skipif(not _stack_is_up(), reason=f"UI not reachable at {UI_URL}")
def test_ui_renders_cleanly_in_a_real_browser():
    proc = subprocess.run(
        ["node", str(SCRIPT), "--json"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        cwd=str(ROOT),
        env={**os.environ, "PROOFOPS_UI_URL": UI_URL},
    )
    assert proc.returncode in (0, 1), (
        "the browser gate must exit 0 (clean) or 1 (findings); "
        f"exit {proc.returncode} means the check could not run:\n"
        f"{proc.stderr[-800:]}"
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - diagnostics only
        pytest.fail(f"browser gate produced no JSON report: {exc}\n{proc.stdout[-800:]}")

    findings = [r for r in report["rows"] if not r["ok"]]
    assert not findings, (
        f"{len(findings)} of {report['total']} view/viewport combinations are not "
        "clean:\n"
        + "\n".join(
            f"  {r['view']} @ {r['viewport']}: {'; '.join(r['issues'])}" for r in findings
        )
    )
    assert report["total"] == 15, (
        f"expected 5 views x 3 viewports = 15 combinations, got {report['total']}"
    )


def test_browser_gate_asserts_the_defects_it_was_written_for():
    """The gate's own coverage, asserted statically so it cannot be trimmed away.

    Each entry corresponds to a defect that reached a reviewer or a demo in
    this repository and was invisible to every other gate.
    """
    source = SCRIPT.read_text(encoding="utf-8")

    # A blank page: content length, not just a child count. A render crash can
    # leave the shell's skip link mounted with the whole operator UI gone.
    assert "MIN_TEXT" in source, (
        "the gate must assert rendered content length; a child-count check "
        "passes a half-rendered tree"
    )
    # An uncaught render exception.
    assert "Runtime.exceptionThrown" in source
    # Console errors, minus the 401 that the unauthenticated demo is supposed
    # to produce.
    assert "Log.entryAdded" in source
    assert "status of 401" in source, (
        "the 401 on a key-gated endpoint is correct behaviour for the "
        "unauthenticated demo and must not be reported as a defect"
    )
    # The false-claim scan: rendered text, because the stream defect was text.
    for phrase in ("Event stream update failed", "stream disconnected",
                   "backend unreachable", "chain INVALID"):
        assert phrase in source, (
            f"the rendered-text scan must look for {phrase!r}; console-only "
            "checking reported every view clean while all of them showed a "
            "false error"
        )
    # Structural and labelling invariants that are cheap to verify in a browser.
    assert "horizontal overflow" in source
    assert "expected exactly one h1" in source
    assert "without a label" in source
    # Cache must be off or the sweep silently tests the previous build -- which
    # is how a stale-profile run looked like a passing build of broken code.
    assert "setCacheDisabled" in source


def test_browser_gate_adds_no_new_dependency():
    """It must stay runnable on a clean clone with `npm ci` and nothing else."""
    manifest = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    deps = set(manifest.get("dependencies", {})) | set(manifest.get("devDependencies", {}))
    forbidden = {"playwright", "puppeteer", "puppeteer-core", "selenium-webdriver",
                 "chrome-remote-interface", "ws", "axios", "node-fetch"}
    assert not (deps & forbidden), (
        f"the browser gate must use Node built-ins only, found {deps & forbidden}"
    )
    # WebSocket and fetch are globals from Node 22+, so the script must not
    # import them (or anything else that would need installing).
    source = SCRIPT.read_text(encoding="utf-8")
    imported = set(re.findall(r"^import\s+(?:[\w*\s{},]+)\s+from\s+[\"']([^\"']+)[\"']",
                              source, re.MULTILINE))
    allowed = {"node:child_process", "node:fs", "node:os", "node:path"}
    assert imported <= allowed, (
        f"the browser gate may only import Node built-ins {sorted(allowed)}; "
        f"found {sorted(imported - allowed)}"
    )
