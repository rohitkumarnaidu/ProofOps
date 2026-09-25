"""M19a frontend structure: scaffold + 3 views honesty gates (host-safe).

Commit A (scaffold/CommandCenter/IncidentDetail/SafetyGate + approvals API
surface): static source assertions + backend list endpoint. No browser
needed; `npm run build` proven separately in-lane (dist/ gitignored).
"""
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.routers import runs as runs_router  # noqa: E402 (M14b runs)

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "frontend" / "src"


@pytest.fixture(autouse=True)
def _clean():
    runs_router.reset_demo_state()
    yield
    runs_router.reset_demo_state()


def _src(name):
    return (UI / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Scaffold
# ---------------------------------------------------------------------------

def test_package_manifest():
    manifest = json.loads((ROOT / "frontend" / "package.json").read_text(
        encoding="utf-8"))
    assert manifest["name"] == "proofops-ui"
    assert "react-router-dom" in manifest["dependencies"]
    assert "tailwindcss" in manifest["dependencies"]
    assert "tsc" in manifest["scripts"]["build"] \
        and "vite build" in manifest["scripts"]["build"]


def test_core_routes_wired():
    app = _src("App.tsx")
    for path in ('path="/"', 'path="/incidents/:id"', 'path="/safety"'):
        assert path in app


def test_api_layer_hits_real_endpoints():
    api = _src("api.ts")
    for endpoint in ("/healthz", "/runs", "/approvals"):
        assert endpoint in api
    assert '`/incidents/${encodeURIComponent(incidentId)}/audit`' in api


# ---------------------------------------------------------------------------
# Views honesty
# ---------------------------------------------------------------------------

def test_safety_gate_controls():
    gate = _src("views/SafetyGate.tsx")
    for marker in ("Approve", "Deny", "seconds_remaining", "TTL countdown",
                   "approver", "approvalsApi"):
        assert marker in gate


def test_badge_modes():
    badges = _src("components/badges.tsx")
    for mode in ("LIVE", "REPLAY", "MOCK", "OFFLINE"):
        assert f'"{mode}"' in badges or f"{mode}:" in badges \
            or f">{mode}<" in badges
    assert "data-mode" in badges


def test_no_stub_content_or_secrets():
    banned = ["lorem ipsum", "TODO:", "FIXME", "Coming soon",
              "Under construction"]
    secretish = re.compile(
        r"(sk-(live|proj)-[A-Za-z0-9]{8,}|api[_-]?key\s*[:=]\s*['\"][^'\"]+)")
    for path in list(UI.rglob("*.tsx")) + list(UI.rglob("*.ts")):
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for marker in banned:
            assert marker.lower() not in lowered, f"{path.name}: {marker}"
        assert not secretish.search(text), f"{path.name}: secret-like literal"


def test_no_mock_data_layer():
    for path in list(UI.rglob("*.tsx")) + list(UI.rglob("*.ts")):
        text = path.read_text(encoding="utf-8")
        for marker in ("mockRuns", "fakeData", "dummyData", "sampleIncidents"):
            assert marker not in text, f"{path.name}: {marker}"


def test_command_center_states():
    view = _src("views/CommandCenter.tsx")
    assert "queue-empty" in view and "Open run" in view
    assert "OFFLINE" in view or "ModeBadge" in view


# ---------------------------------------------------------------------------
# Backend: queue list endpoint (M19a addition to runs router)
# ---------------------------------------------------------------------------

def test_list_runs_queue():
    assert runs_router.list_runs() == []
    runs_router.create_run("inc-1", now=1700000000.0)
    runs_router.advance_run("inc-1", "TRIAGING", now=1700000000.0)
    rows = runs_router.list_runs()
    assert rows == [{"incident_id": "inc-1", "state": "TRIAGING",
                     "history_len": 1}]


# ---------------------------------------------------------------------------
# Tier-aware mode probe + API key surface (M19 honesty hardening)
# ---------------------------------------------------------------------------

def test_meta_route_static_and_healthz_untouched():
    # STATIC (mirrors test_healthz_contract_static): /meta is additive; the
    # frozen /healthz body must stay byte-identical.
    text = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert '@app.get("/meta")' in text
    assert "executor_tier" in text
    assert "nonce_store_durable" in text  # Lane A P2: durability surfaced
    assert "nonce_store_degraded" in text  # Lane A P2: degraded flag surfaced
    assert "PS03_FINAL_SPEC_V2" in text
    assert text.count('@app.get("/healthz")') == 1
    assert ('return {"status": "ok", "service": "proofops-api", '
            '"spec": "PS03_FINAL_SPEC_V2"}') in text


def test_api_key_surface():
    api = _src("api.ts")
    for marker in ("VITE_PROOFOPS_API_KEY", "X-API-Key", "hasApiKey"):
        assert marker in api
    assert "unauthenticated demo mode" in api


def test_probe_mode_tier_mapping():
    api = _src("api.ts")
    assert '"/meta"' in api
    assert '"MOCK"' in api and '"LIVE"' in api and '"REPLAY"' in api
    assert '"OFFLINE"' in api
    assert "executor_tier" in api


def test_safety_gate_key_notice():
    gate = _src("views/SafetyGate.tsx")
    assert "hasApiKey" in gate
    assert "api-key-notice" in gate
    assert "401" in gate


def test_frontend_env_example():
    example = ROOT / "frontend" / ".env.example"
    assert example.exists(), "frontend/.env.example must exist"
    text = example.read_text(encoding="utf-8")
    assert "VITE_API_URL=" in text
    assert "VITE_PROOFOPS_API_KEY=" in text
    assert "sk-" not in text


# ---------------------------------------------------------------------------
# Nav + loading honesty + decision guardrails (loop-2 UX)
# ---------------------------------------------------------------------------

def test_nav_lists_all_five_routes_plus_404():
    app = _src("App.tsx")
    for route in ('to="/"', 'selectedPath("/incidents")', 'safetyPath',
                  'selectedPath("/execution")', 'selectedPath("/rca")'):
        assert route in app, route
    assert "runsApi.list" in app
    assert 'aria-disabled="true"' in app
    assert 'aria-current=' in app
    assert 'path="*"' in app and "route-404" in app


def test_views_use_honest_loading_hook():
    hook = (UI / "components" / "useMode.ts").read_text(encoding="utf-8")
    assert "probeMode" in hook and "null" in hook
    for name in ("CommandCenter.tsx", "IncidentDetail.tsx",
                 "ExecutionView.tsx", "RCAView.tsx", "SafetyGate.tsx"):
        view = _src(f"views/{name}")
        assert "useMode" in view, name
        assert "mode-probing" in view, name
        assert 'useState<Mode>("OFFLINE")' not in view, name


def test_safety_gate_ttl_guardrail():
    gate = _src("views/SafetyGate.tsx")
    assert "decidable" in gate
    assert "seconds_remaining > 0" in gate
    assert "ttl-expired" in gate
    assert "disabled={!decidable}" in gate


def test_execution_view_readonly_rollback():
    view = _src("views/ExecutionView.tsx")
    assert "read-only" in view
    assert "endpoint lands with M21" not in view


# ---------------------------------------------------------------------------
# Lane D: SSE-subscribed mode hook + PROBING badge + viewer guardrail
# ---------------------------------------------------------------------------

def test_usemode_subscribes_to_sse():
    hook = (UI / "components" / "useMode.ts").read_text(encoding="utf-8")
    assert "subscribeStream" in hook
    assert "unsubscribe" in hook
    assert "probeMode" in hook  # initial fetch + fallback truth kept
    assert "/stream/incidents/" in hook  # spec control-plane stream shape
    for name in ("CommandCenter.tsx", "IncidentDetail.tsx",
                 "ExecutionView.tsx", "RCAView.tsx", "SafetyGate.tsx"):
        assert "ModeBadge" in _src(f"views/{name}"), name


def test_mode_badge_probing_and_no_offline_fallback():
    badges = _src("components/badges.tsx")
    assert '"PROBING"' in badges
    assert "Mode | null" in badges
    assert '?? "OFFLINE"' not in badges  # probing-null never equals OFFLINE
    for name in ("CommandCenter.tsx", "IncidentDetail.tsx",
                 "ExecutionView.tsx", "RCAView.tsx", "SafetyGate.tsx"):
        view = _src(f"views/{name}")
        assert '?? "OFFLINE"' not in view, name
        assert "<ModeBadge mode={mode}" in view, name


def test_safety_gate_server_role_guardrail():
    gate = _src("views/SafetyGate.tsx")
    assert "identity-cannot-decide" in gate
    assert "serverHasApproverRole" in gate
    assert 'normalized === "approver" || normalized === "admin"' in gate
    assert "disabled={!decidable}" in gate
    assert "403" in gate


# ---------------------------------------------------------------------------
# Lane 3: production gaps (loading, idempotency, server-field card)
# ---------------------------------------------------------------------------

def test_command_center_loading_state():
    view = _src("views/CommandCenter.tsx")
    assert "isLoading" in view
    assert "queue-loading" in view
    assert 'aria-busy="true"' in view


def test_incident_detail_loading_state():
    view = _src("views/IncidentDetail.tsx")
    assert "isLoading" in view
    assert "detail-loading" in view
    assert 'aria-busy="true"' in view


def test_safety_gate_reuses_idempotency_key_per_approval():
    gate = _src("views/SafetyGate.tsx")
    assert "useRef(new Map<string, string>())" in gate
    assert "idempotencyKeysRef.current.get(view.approval_id)" in gate
    assert "idempotencyKeysRef.current.set(view.approval_id, idempotencyKey)" in gate
    api = _src("api.ts")
    # Backend DecideBody already accepts the key on both decisions; the
    # client must forward it on both (approve already did, reject is new).
    approve_body = api.split("approve:")[1].split("reject:")[0]
    reject_body = api.split("reject:")[1].split("auditApi")[0]
    assert "idempotency_key" in approve_body
    assert "idempotency_key" in reject_body


def test_safety_gate_card_renders_server_fields_only():
    gate = _src("views/SafetyGate.tsx")
    # approval_view returns approval/incident/action/actor/scope/params_hash
    # + status/TTL/expiry: the card renders them, nothing else.
    for field in ("view.incident_id", "view.action_id", "view.actor",
                  "view.scope", "view.params_hash"):
        assert field in gate, field
    # approval_view returns NO risk/blast/policy-rule: inventing them here
    # would fabricate safety data, so they must stay absent.
    for invented in ("blast_radius", "risk_level", "policy_rule",
                     "policy-rule"):
        assert invented not in gate, invented
