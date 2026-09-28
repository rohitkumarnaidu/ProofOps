"""The frontend must be able to DRIVE the control plane, not only read it.

Every test here exists because the product had a real end-to-end gap that
source-level greps could not see: the backend exposed a complete, working
route set and the UI called none of it, so an operator could not ingest an
incident, could not see the action the pipeline proposed, and therefore could
not approve anything. A blank screen and a static dashboard both "render fine",
so the suite had to assert the wiring explicitly.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "frontend" / "src"


def source(rel: str) -> str:
    return (UI / rel).read_text(encoding="utf-8")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)


# ---------------------------------------------------------------------------
# The front door: an incident must be able to arrive
# ---------------------------------------------------------------------------

def test_api_client_covers_every_backend_route_the_ui_depends_on() -> None:
    """Each route the product flow needs must have a client function.

    The route list is transcribed from the routers, not derived, because the
    failure mode is precisely a route existing with no client for it.
    """
    api = _strip_comments(source("api.ts"))
    required = {
        "POST /alerts/ingest": '"/alerts/ingest"',
        "GET /orchestrator": '"/orchestrator"',
        "POST /orchestrator/stop": '"/orchestrator/stop"',
        "GET /approval-proposals": '"/approval-proposals"',
        "GET /runs": '"/runs"',
        "GET /runs/{id}": "/runs/${encodeURIComponent(incidentId)}",
        "POST /runs/{id}/sweep": "/sweep",
        "POST /approvals": '"/approvals"',
        "POST /approvals/{id}/approve": "/approve",
        "POST /approvals/{id}/reject": "/reject",
        "GET /agents/{id}/thread": "/thread",
        "POST /agents/investigate": '"/agents/investigate"',
        "GET /meta/engines": '"/meta/engines"',
        "GET /alerts": '"/alerts"',
        "POST audit verify": "/verify",
        "GET audit export": "/export",
    }
    missing = [name for name, needle in required.items() if needle not in api]
    assert not missing, f"api.ts has no client for: {missing}"


def test_ingest_is_a_real_client_not_a_run_creation_alias() -> None:
    """The pipeline is only reachable through ingest, so the client must exist
    and must post a bundle rather than delegating to POST /runs."""
    api = _strip_comments(source("api.ts"))
    assert "export const ingestApi" in api
    assert "submit:" in api
    # A telemetry bundle with the four fields the server validates.
    for field in ("service", "env", "error_signature", "metrics"):
        assert field in api, f"the ingest body must carry {field}"


def test_command_center_drives_ingest_not_a_hollow_run() -> None:
    """Creating an incident must call the route that starts the pipeline.

    `runsApi.create` opens an empty run in state NEW that nothing ever moves,
    so a form built on it looks like it works and does nothing.
    """
    view = _strip_comments(source("views/CommandCenter.tsx"))
    assert "ingestApi.submit" in view, (
        "the Command Center must ingest a telemetry bundle; POST /runs alone "
        "never drives the pipeline"
    )
    assert "runsApi.create" not in view, (
        "a hollow POST /runs must not be presented as triggering an incident"
    )
    # The scenario list must come from the shared constant, not be re-typed.
    assert "INGEST_SCENARIOS" in view
    assert "ingestApi.stop" in view, "the kill-switch needs a UI surface"


def test_command_center_engine_tiles_have_an_unknown_state() -> None:
    """A failed status read must not render as a measured fact.

    `.catch(() => null)` made a 401 or 500 collapse into the negative branch, so
    a dead engine endpoint was displayed as "Mock Sandbox / SANDBOX".
    """
    view = _strip_comments(source("views/CommandCenter.tsx"))
    assert "enginesFailed" in view
    assert "UNKNOWN" in view
    assert "degraded" in view, "a degraded audit store must be labelled degraded"
    assert "PostgreSQL 16" not in view, (
        "no server version is returned by db_health; rendering \"16\" displayed "
        "a number the backend never reported"
    )
    assert "Enterprise Edition" not in view, (
        "a hardcoded edition label replaces the real APP_ENV / reasoning mode"
    )


def test_command_center_kpi_number_matches_the_rows_it_filters() -> None:
    """A KPI that counts one set and filters to another is a wrong number."""
    view = _strip_comments(source("views/CommandCenter.tsx"))
    assert '"BLOCKED"' in view
    assert 'filter === "BLOCKED"' in view
    blocked = re.search(
        r"const blockedRuns = runs\.filter\(\(r\) => (.*?)\);", view, re.DOTALL)
    assert blocked, "blockedRuns must be defined"
    assert 'r.state === "BLOCKED"' in blocked.group(1)
    assert 'r.state === "ESCALATED"' in blocked.group(1)


# ---------------------------------------------------------------------------
# The gate: HITL must be reachable from the UI
# ---------------------------------------------------------------------------

def test_safety_gate_reads_the_pipeline_s_own_proposal() -> None:
    """The gate's entry point is the parked proposal, not a blank template."""
    api = _strip_comments(source("api.ts"))
    view = _strip_comments(source("views/SafetyGate.tsx"))
    # The server wraps the list, so the client must unwrap it.
    assert "proposals: async () =>" in api
    assert "res.proposals ?? []" in api
    assert "approvalsApi.proposals" in view
    # Selecting a proposal must load the real action into the request form.
    assert "setActionText" in view
    assert "proposal.action" in view
    # A blank template cannot omit a required contract field.
    assert "namespace" in view


def test_safety_gate_risk_comes_from_the_server_never_a_literal() -> None:
    """A hardcoded tier fabricates the most consequential fact on the gate."""
    view = _strip_comments(source("views/SafetyGate.tsx"))
    for fabricated in ("YELLOW (Reversible)", "Auto-Rollback: ",
                       "1 attempt on SLO breach"):
        assert fabricated not in view, f"fabricated on the gate: {fabricated!r}"
    assert "selectedProposal.risk_level" in view
    # Real blast radius, with absent fields marked absent rather than defaulted.
    assert "BlastRadius" in view
    assert "not stated" in view


def test_safety_gate_reports_approved_as_approved_not_expired() -> None:
    """Only a genuinely expired approval is an expiry."""
    view = _strip_comments(source("views/SafetyGate.tsx"))
    assert 'setExpiredTerminal(loaded.status === "expired")' in view, (
        "any non-pending status set the expiry flag, so a load of an APPROVED "
        "or DENIED approval reported 'Terminal state: expired'"
    )
    assert 'loaded.status !== "pending"' not in view


# ---------------------------------------------------------------------------
# Evidence must be the real verifier's, not a state projection
# ---------------------------------------------------------------------------

def test_run_view_type_carries_the_real_verifier_output() -> None:
    """`verification_results` was absent from the type, which is why the
    verdict panel could substitute FSM transitions and still typecheck."""
    api = _strip_comments(source("api.ts"))
    assert "verification_results: VerificationResult[]" in api
    assert "checks: Record<string, boolean>" in api
    # The executor tier must be typed too, or the UI re-derives a label.
    assert "execution_tier?: string" in api


def test_execution_view_never_shows_an_invented_process_status() -> None:
    """The executor returns logs and a diff, never an exit code."""
    view = _strip_comments(source("views/ExecutionView.tsx"))
    for fabricated in ("EXIT CODE", "/bin/k8s-exec"):
        assert fabricated not in view, f"invented on the execution view: {fabricated}"
    assert "execution_tier" in view
    assert "const verdicts = run?.verification_results ?? []" in view
    assert "Verification-phase transitions" in view


def test_execution_view_does_not_blame_a_nonexistent_missing_endpoint() -> None:
    view = _strip_comments(source("views/ExecutionView.tsx"))
    assert "no retrieval endpoint is exposed" not in view, (
        "run_view does return state_diff; the old copy described a missing "
        "endpoint that exists and blamed a module for a persistence gap"
    )
    assert "No state diff recorded" in view


# ---------------------------------------------------------------------------
# Routing and liveness
# ---------------------------------------------------------------------------

def test_every_incident_scoped_route_resolves_the_selected_incident() -> None:
    """`/agents/:id` was missing from the parser, so deep-linking there left
    the whole header -- including the Agent link -- aria-disabled."""
    app = _strip_comments(source("App.tsx"))
    block = re.search(r"const match = /\^\\\/\(\?:([^)]*)\)", app)
    assert block, "the incident route regex must be explicit"
    for route in ("incidents", "execution", "rca", "agents"):
        assert route in block.group(1), f"{route} is not parsed for the incident id"
    # The agent view reads the same query key every other link emits.
    agents = _strip_comments(source("views/AgentsView.tsx"))
    assert 'get("incident_id")' in agents
    assert 'get("incident")' not in agents, (
        "?incident= is emitted by nothing in the product, so that branch is dead"
    )


def test_header_incident_list_stays_current_after_ingest() -> None:
    """A list loaded only on mount hides a just-ingested incident until a full
    page reload, so the operator sees the run in the table and cannot select it."""
    app = _strip_comments(source("App.tsx"))
    assert "runsApi.list()" in app
    assert "setInterval(load" in app or "setInterval(" in app
    assert "cancelled" in app


def test_event_stream_does_not_drop_backend_emitted_types() -> None:
    """The cursor advances before the type is matched, so an unlisted type is
    consumed silently and the refresh it should trigger never happens."""
    hook = _strip_comments(source("components/useIncidentEvents.ts"))
    for emitted in ("handoff", "permit.minted"):
        assert f'"{emitted}"' in hook, (
            f"the backend emits {emitted}; not matching it swallows the event"
        )
    # The terminal set must stay the FSM's own, and is pinned against the
    # Python constant by tests/test_frontend_m19c.py.
    assert 'TERMINAL_INCIDENT_STATES = new Set(["BLOCKED", "AUDITED"])' in hook


def test_non_json_response_can_no_longer_masquerade_as_a_typed_body() -> None:
    """`response.json().catch(() => ({}))` turned the SPA HTML fallback into a
    well-typed `{}`, and the caller's `.filter`/`.map` then threw and blanked
    the screen. That failure shipped once."""
    api = _strip_comments(source("api.ts"))
    assert "JSON.parse(text)" in api
    assert "the request probably hit the SPA fallback" in api
    assert "response.json().catch" not in api


def test_slo_alert_fields_match_the_real_wire_shape() -> None:
    """GET /alerts returns `state`/`observed`/`target`, not status/value/threshold.

    Guessing these names produced a `.toUpperCase()` on undefined that crashed
    the entire Command Center at render, so every view behind it mounted an
    empty #root. The browser gate is what caught it; this pins the shape.
    """
    api = _strip_comments(source("api.ts"))
    view = _strip_comments(source("views/CommandCenter.tsx"))
    for real in ("state: string", "observed: number | null", "target: number | null"):
        assert real in api, f"SloAlert must declare {real}"
    for wrong in ("status: string;\n  value: number", "threshold: number"):
        assert wrong not in api, f"SloAlert must not declare the guessed {wrong!r}"
    assert "alert.state.toUpperCase()" in view
    assert "alert.status" not in view, (
        "the wire field is `state`; reading `status` crashes the render"
    )


def test_every_new_command_center_control_is_labelled() -> None:
    """A bare input inside a wrapping label is not a programmatic label."""
    view = _strip_comments(source("views/CommandCenter.tsx"))
    assert 'id="process-now"' in view
    assert 'htmlFor="process-now"' in view
    for field in ("new-incident", "new-scenario", "new-service", "new-env",
                  "new-signature", "new-error-rate"):
        assert f'id="{field}"' in view, field


def test_every_write_route_accepts_the_token_sign_in_issues() -> None:
    """A JWT that only two routes honour makes the UI's sign-in useless.

    POST /auth/token issues a bearer token and runs.py accepted it, but the
    approvals and ingest routers read only the X-API-Key header. So an operator
    who signed in through the UI still got 401 on every approval and on ingest:
    the Safety Gate and the ingest form were reachable and unusable at the same
    time. Asserted against the source because the failure is a missing
    parameter, which no response-shape test can see.
    """
    approvals = _strip_comments(
        (ROOT / "backend" / "app" / "routers" / "approvals.py").read_text(
            encoding="utf-8"))
    ingest = _strip_comments(
        (ROOT / "backend" / "app" / "routers" / "ingest.py").read_text(
            encoding="utf-8"))

    for name, text in (("approvals.py", approvals), ("ingest.py", ingest)):
        assert "authorization: str | None = Header(default=None)" in text, (
            f"{name} must read the Authorization header, or a signed-in "
            "operator still gets 401 on every write"
        )
        # And it must actually be threaded into the guard, not merely accepted.
        assert "authorization=authorization" in text, (
            f"{name} accepts the header but does not pass it to the guard"
        )
        assert "_require_key(x_api_key)" not in text, (
            f"{name} still authenticates from the raw key alone"
        )

    # The token endpoint must have its dependency declared, or it 500s in the
    # image while working on the host -- which is how the only route that can
    # mint a credential was dead in every deployment.
    requirements = (ROOT / "backend" / "requirements.txt").read_text(
        encoding="utf-8")
    lock = (ROOT / "backend" / "requirements.lock").read_text(encoding="utf-8")
    assert "PyJWT" in requirements, (
        "auth.py does `import jwt`; without the declared dependency "
        "POST /auth/token answers HTTP 500 in the container"
    )
    assert "PyJWT==" in lock, "the image installs from the lock, not requirements.txt"

    # GET /identity must accept the token too, or the sign-in control can never
    # confirm the sign-in: the operator is shown "not authenticated" while
    # holding the only valid credential in the system.
    auth_router = _strip_comments(
        (ROOT / "backend" / "app" / "routers" / "auth.py").read_text(
            encoding="utf-8"))
    identity_block = auth_router.split("def http_identity", 1)[1].split("def ", 1)[0]
    assert "authorization" in identity_block, (
        "GET /identity must read the Authorization header, or a signed-in "
        "operator cannot read its own identity back"
    )


def test_audit_view_can_verify_and_export_the_chain() -> None:
    """A `valid` flag without first_bad_seq is undiagnosable, and the export is
    the product's proof artifact."""
    rca = _strip_comments(source("views/RCAView.tsx"))
    assert "auditApi.verify" in rca
    assert "auditApi.export" in rca
    assert "first_bad_seq" in rca
    # The audit list had no time axis, and the policy decision was invisible.
    assert "event.ts" in rca
    assert "event.policy" in rca


def test_evaluation_scorecard_shows_sample_size_and_caveat() -> None:
    """AGENTS.md requires n on every gate card, and the backend states its own
    anti-overclaim note; a rate without an n is noise."""
    api = _strip_comments(source("api.ts"))
    rca = _strip_comments(source("views/RCAView.tsx"))
    assert "config: {" in api
    assert "{smoke.note}" in rca
    assert "n={smoke.rubric.n}" in rca
    assert "isRunningSmoke" in rca, "the smoke button needs an in-flight guard"
