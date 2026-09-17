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


def test_three_routes_wired():
    app = _src("App.tsx")
    assert app.count("<Route ") == 3
    for path in ('path="/"', 'path="/incidents/:id"', 'path="/safety"'):
        assert path in app


def test_api_layer_hits_real_endpoints():
    api = _src("api.ts")
    for endpoint in ("/healthz", "/runs", "/approvals",
                     "/incidents/${incident_id}/audit"):
        assert endpoint in api


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
