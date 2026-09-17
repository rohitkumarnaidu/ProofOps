"""M19b: execution/RCA views + SSE + smoke + Dockerfile (host-safe).

Commit B (M19.5-M19.10 surface): eval smoke numbers measured live here;
view/SSE/Dockerfile gates are static source pins (browser/container prove
the rest in CI/demo). No mock rows anywhere in src/.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.routers import eval as eval_router  # noqa: E402 (M19b smoke)

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "frontend" / "src"


def _src(name):
    return (UI / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Eval smoke: measured numbers, labeled mock systems
# ---------------------------------------------------------------------------

def test_smoke_measured_and_labeled():
    out = eval_router.smoke_eval()
    assert out["system"] == "mock-deterministic"
    assert out["cases"] == 5
    assert out["baseline"]["pass_rate"] == 1.0
    assert out["optimized"]["pass_rate"] == 0.0
    assert out["delta"]["d_C3"] < 0
    assert out["rubric"]["n"] == 10
    assert "mock" in out["note"]


def test_smoke_http_guard():
    with pytest.raises(Exception):
        eval_router.http_smoke(eval_router.SmokeBody(confirm=False))
    out = eval_router.http_smoke(eval_router.SmokeBody(confirm=True))
    assert out["cases"] == 5


def test_main_wires_eval_router():
    import ast as _ast
    src = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert "eval_router" in src
    tree = _ast.parse(src)
    assert sum(1 for n in _ast.walk(tree) if isinstance(n, _ast.Call)
               and getattr(n.func, "attr", "") == "include_router") >= 4


# ---------------------------------------------------------------------------
# Views 4-5 + routes
# ---------------------------------------------------------------------------

def test_five_routes_wired():
    app = _src("App.tsx")
    assert app.count("<Route ") == 5
    for path in ('path="/"', 'path="/incidents/:id"', 'path="/safety"',
                 'path="/execution/:id"', 'path="/rca/:id"'):
        assert path in app


def test_execution_view_honesty():
    view = _src("views/ExecutionView.tsx")
    for marker in ("exec-state", "exec-timeline", "exec-empty",
                   "rollback-eligible", "rollback-ineligible",
                   "M21"):
        assert marker in view
    assert "StateDiff" in view


def test_rca_view_audit_and_gates():
    view = _src("views/RCAView.tsx")
    for marker in ("audit-valid-badge", "audit-chain", "audit-empty",
                   "gate-cards", "Run smoke eval", "auditApi"):
        assert marker in view


def test_state_diff_renderer():
    diff = _src("components/StateDiff.tsx")
    assert "diff-table" in diff and "diff-empty" in diff
    assert "changed" in diff and "BEFORE" in diff.upper()


def test_evidence_chips():
    detail = _src("views/IncidentDetail.tsx")
    assert "evidence-chip" in detail


# ---------------------------------------------------------------------------
# SSE client contract
# ---------------------------------------------------------------------------

def test_sse_client_contract():
    sse = _src("sse.ts")
    for marker in ("EventSource", "POLL_FALLBACK_MS", "audit_event_id",
                   "onMode", "OFFLINE", "unsubscribe"):
        assert marker in sse
    assert "3000" in sse  # 3s polling fallback per spec S42


# ---------------------------------------------------------------------------
# Dockerfile + compose honesty
# ---------------------------------------------------------------------------

def test_ui_image_unprivileged_multistage():
    dockerfile = (ROOT / "frontend" / "Dockerfile").read_text(
        encoding="utf-8")
    assert "AS build" in dockerfile and "npm run build" in dockerfile
    assert "USER nginx" in dockerfile and "8080" in dockerfile
    assert ":latest" not in dockerfile
    conf = (ROOT / "frontend" / "frontend.nginx.conf").read_text(
        encoding="utf-8")
    assert "listen 8080" in conf and "try_files" in conf
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "5173:8080" in compose and "localhost:8080" in compose


def test_no_stub_content_in_src():
    import re as _re
    banned = ["lorem ipsum", "TODO:", "FIXME", "Coming soon",
              "Under construction"]
    for path in list(UI.rglob("*.tsx")) + list(UI.rglob("*.ts")):
        text = path.read_text(encoding="utf-8")
        for marker in banned:
            assert marker.lower() not in text.lower(), path.name
        assert not _re.search(r"sk-(live|proj)-[A-Za-z0-9]{8,}", text)
