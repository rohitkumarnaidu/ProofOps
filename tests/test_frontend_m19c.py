from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "frontend" / "src"


def source(relative: str) -> str:
    return (UI / relative).read_text(encoding="utf-8")


def test_shell_navigation_uses_real_selected_incident() -> None:
    app = source("App.tsx")
    assert "runsApi.list()" in app
    assert 'id="current-incident"' in app
    assert "selectedIncident" in app
    assert 'aria-disabled="true"' in app
    assert "aria-label={disabledLabel}" in app
    assert "encodeURIComponent(selectedIncident)" in app
    assert "/safety?incident_id=" in app
    assert "/incidents/inc-1" not in app
    assert "/execution/inc-1" not in app
    assert "/rca/inc-1" not in app


def test_incident_views_open_the_same_context() -> None:
    detail = source("views/IncidentDetail.tsx")
    for path in (
        "/safety?incident_id=${encodeURIComponent(id)}",
        "/execution/${encodeURIComponent(id)}",
        "/rca/${encodeURIComponent(id)}",
    ):
        assert path in detail


def test_api_encodes_every_interpolated_id() -> None:
    api = source("api.ts")
    for marker in (
        "encodeURIComponent(incidentId)",
        "encodeURIComponent(approvalId)",
    ):
        assert marker in api
    assert api.count("encodeURIComponent(incidentId)") >= 3
    assert api.count("encodeURIComponent(approvalId)") >= 3


def test_identity_is_server_derived_and_read_only() -> None:
    api = source("api.ts")
    gate = source("views/SafetyGate.tsx")
    assert 'request<IdentityView>("/identity")' in api
    for field in ("key_id", "owner", "roles", "mode"):
        assert field in api
        assert f"identity.{field}" in gate
    assert "Demo-grade bootstrap identity" in gate
    assert "not an authenticated user" in gate
    assert "serverHasApproverRole" in gate
    assert "<select" not in gate
    assert "setRole" not in gate
    approve = api.split("approve:")[1].split("reject:")[0]
    reject = api.split("reject:")[1].split("auditApi")[0]
    assert '"actor"' not in approve
    assert '"role"' not in approve
    assert '"actor"' not in reject
    assert '"role"' not in reject


def test_approval_http_states_are_distinct_and_expiry_is_terminal() -> None:
    gate = source("views/SafetyGate.tsx")
    for status in (401, 403, 410, 422, 429):
        assert f"status === {status}" in gate
    assert 'data-api-status={issue.status ?? "network"}' in gate
    assert 'data-testid="approval-terminal"' in gate
    assert 'data-testid="approval-not-found"' in gate
    assert 'setToken("")' in gate
    assert "expiredTerminal" in gate
    assert "disabled={!decidable}" in gate


def test_approval_lifecycle_reuses_key_and_surfaces_polling_errors() -> None:
    gate = source("views/SafetyGate.tsx")
    assert "useRef(new Map<string, string>())" in gate
    assert "idempotencyKeysRef.current.get(view.approval_id)" in gate
    assert "idempotencyKeysRef.current.set(view.approval_id, idempotencyKey)" in gate
    assert "idempotencyKeysRef.current.delete(next.approval_id)" in gate
    assert "setPollIssue(issue)" in gate
    assert "loadApproval" in gate
    assert "lost on reload" in gate
    assert ".catch(() => undefined)" not in gate


def test_event_hook_routes_debounces_and_exposes_stream_truth() -> None:
    hook = source("components/useIncidentEvents.ts")
    for event_type in (
        "transition",
        "policy.decision",
        "verification.verdict",
        "approval.",
        "execution.",
        "rollback.",
        "rca.",
    ):
        assert event_type in hook
    assert "subscribeStream" in hook
    assert "auditApi.pollUrl(incidentId)" in hook
    assert "setTimeout" in hook
    assert "lastEventId" in hook
    assert "connectionState" in hook
    assert "onCursorReset" in hook
    assert "isTerminalIncidentState" in hook


def test_all_event_consumers_refresh_their_server_view() -> None:
    detail = source("views/IncidentDetail.tsx")
    execution = source("views/ExecutionView.tsx")
    rca = source("views/RCAView.tsx")
    gate = source("views/SafetyGate.tsx")
    for view in (detail, execution, rca, gate):
        assert "useIncidentEvents" in view
    assert "runsApi.get(id)" in detail
    assert "runsApi.get(id)" in execution
    assert "auditApi.view(id)" in rca
    assert "loadApproval(view.approval_id)" in gate


def test_stream_replays_bad_cursor_once_and_never_polls_sse_url() -> None:
    sse = source("sse.ts")
    hook = source("components/useIncidentEvents.ts")
    assert "globalThis.EventSource" in sse
    assert "streamEventId" in sse
    assert 'item.event_id' in sse
    assert "resetCursorOnce" in sse
    assert "replayedCursor" in sse
    assert "onCursorReset" in sse
    assert "scheduleReconnect(0)" in sse
    assert "fetchJson(pollUrl)" in sse
    assert "${pollUrl}?since=" not in sse
    assert "const pollUrl = auditApi.pollUrl(incidentId)" in hook


def test_terminal_states_disable_event_polling() -> None:
    """The UI's terminal set must equal the canonical FSM's, not a guess.

    An earlier version listed RESOLVED/ESCALATED, which stopped the stream
    three states before RCA_PUBLISHED/AUDITED -- exactly the transitions the
    Audit view exists to show. This reads the Python constant so the two
    languages cannot drift.
    """
    import re

    fsm = (ROOT / "backend" / "app" / "services" / "fsm.py").read_text(
        encoding="utf-8")
    match = re.search(r"^TERMINAL = frozenset\(\{([^}]*)\}\)", fsm,
                      re.MULTILINE)
    assert match, "fsm.py must still declare a TERMINAL frozenset"
    canonical = set(re.findall(r'"([^"]+)"', match.group(1)))
    assert canonical == {"BLOCKED", "AUDITED"}, \
        f"unexpected canonical terminal set: {canonical}"

    hook = source("components/useIncidentEvents.ts")
    block = re.search(r"TERMINAL_INCIDENT_STATES = new Set\(\[(.*?)\]\)",
                      hook, re.DOTALL)
    assert block, "the hook must declare an explicit terminal set"
    declared = set(re.findall(r'"([^"]+)"', block.group(1)))
    assert declared == canonical, \
        f"UI terminal set {declared} != FSM terminal set {canonical}"
    for view in (
        "IncidentDetail.tsx",
        "ExecutionView.tsx",
        "RCAView.tsx",
    ):
        assert "!isTerminalIncidentState" in source(f"views/{view}")


def test_empty_not_found_and_rca_labels_are_honest() -> None:
    command = source("views/CommandCenter.tsx")
    rca = source("views/RCAView.tsx")
    incident = source("views/IncidentDetail.tsx")
    execution = source("views/ExecutionView.tsx")
    assert "hasVisibleError ? null : runs.length === 0" in command
    assert "Run not found" in incident
    assert "Run not found" in execution
    assert 'auditError !== "" ? null : events.length === 0' in rca
    assert "Incident audit not found" in rca
    assert "Audit &amp; Evaluation" in rca
    assert "does not render an RCA document" in rca
    assert "diff={null}" in execution
    assert "no state transition is fabricated" in execution


def test_audit_view_matches_the_real_endpoint_contract() -> None:
    """The audit endpoint returns `events`, not `items`.

    Reading a field the server never sends leaves `events` undefined, so
    `events.length` throws inside render and, with no error boundary, blanks
    the SPA. The polling fallback in sse.ts had the same shape bug and ended in
    onMode("OFFLINE") against a healthy backend.
    """
    api = source("api.ts")
    assert "events: Array<Record<string, unknown>>" in api
    assert "valid: boolean" in api and "checked: number" in api
    assert "origin: string" in api
    rca = source("views/RCAView.tsx")
    assert "chain.items" not in rca, "the endpoint has no `items` field"
    assert "chain.events" in rca
    sse = source("sse.ts")
    assert "data.events" in sse
    assert 'as { items: StreamItem[] }' not in sse


def test_audit_validity_surface_is_rendered_again() -> None:
    """The chain-validity evidence the endpoint returns must stay visible."""
    rca = source("views/RCAView.tsx")
    assert "audit-valid-badge" in rca
    assert "chainValidity.valid" in rca
    assert "chainValidity.origin" in rca
    tests_m19b = (ROOT / "tests" / "test_frontend_m19b.py").read_text(
        encoding="utf-8")
    assert "audit-valid-badge" in tests_m19b, \
        "the validity marker must stay pinned in the test suite"


def test_safety_gate_can_load_another_operators_approval() -> None:
    """Four-eyes is undemonstrable without a way to load the requester's
    approval id and token on the approving operator's screen."""
    gate = source("views/SafetyGate.tsx")
    assert 'data-testid="load-approval"' in gate
    assert "loadExistingApproval" in gate
    assert "approvalsApi.view(target)" in gate
    assert 'id="load-existing"' in gate


def test_identity_contract_matches_the_endpoint() -> None:
    """/identity returns 5 fields; the client type must not under-declare them.

    A missing field is invisible to `tsc --noEmit` because the local interface
    is the lie, so the durability signal the UI needs has to be pinned here.
    """
    api = source("api.ts")
    for field in ("key_id", "owner", "roles", "mode", "server_enforced"):
        assert field in api, f"api.ts must declare identity field {field}"
    backend_view = (ROOT / "backend" / "app" / "routers" / "auth.py").read_text(
        encoding="utf-8")
    for field in ("key_id", "owner", "roles", "mode", "server_enforced"):
        assert field in backend_view, \
            f"auth.identity_view must still return {field}"


def test_approval_view_contract_matches_the_endpoint() -> None:
    """The `sod` union must cover every value the server can return."""
    api = source("api.ts")
    for value in ("enforced", "not_enforced_bootstrap", "not_recorded"):
        assert f'"{value}"' in api, f"api.ts must model sod value {value}"
    approvals = (ROOT / "backend" / "app" / "routers"
                 / "approvals.py").read_text(encoding="utf-8")
    for value in ("enforced", "not_enforced_bootstrap", "not_recorded"):
        assert value in approvals, \
            f"approval_view must still be able to return {value}"


def test_safety_gate_gate_mirrors_server_authorization() -> None:
    """A bootstrap identity carries no server-side roles, but the server
    permits it; blocking on an empty role list made the product's headline
    human-approval control impossible to exercise in the default deployment.
    A per-key identity is still gated strictly on its stored roles."""
    gate = source("views/SafetyGate.tsx")
    assert "identityIsBootstrap" in gate
    assert "identityIsBootstrap\n    ? true" in gate or \
        "identityIsBootstrap ? true" in gate
    assert "sod-bootstrap-warning" in gate
    assert "separation of duties is not enforced" in gate
