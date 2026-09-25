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


def test_smoke_http_guard(monkeypatch):
    import app.config as cfg
    from types import SimpleNamespace
    monkeypatch.setattr(
        cfg, "get_settings",
        lambda: SimpleNamespace(PROOFOPS_API_KEY="test-key-123",
                                APPROVAL_SECRET="test-secret-123"))
    with pytest.raises(Exception) as exc:
        eval_router.http_smoke(eval_router.SmokeBody(confirm=True))
    assert exc.value.status_code == 401  # key gate first (P1: no open compute)
    with pytest.raises(Exception) as exc:
        eval_router.http_smoke(eval_router.SmokeBody(confirm=False),
                               x_api_key="test-key-123")
    assert exc.value.status_code == 400
    out = eval_router.http_smoke(eval_router.SmokeBody(confirm=True),
                                 x_api_key="test-key-123")
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
    # 5 MVP + explicit 404 (no fake pages); '<Routes>' excluded by matching
    # 'path="' (nav Links use 'to=', never 'path=').
    assert app.count('path="') == 6
    for path in ('path="/"', 'path="/incidents/:id"', 'path="/safety"',
                 'path="/execution/:id"', 'path="/rca/:id"', 'path="*"'):
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
    for marker in ("Audit &amp; Evaluation", "does not render an RCA document",
                   "audit-chain", "audit-empty", "gate-cards",
                   "Run smoke eval", "auditApi",
                   "audit-valid-badge"):
        assert marker in view
    # The chain-validity evidence the audit endpoint returns must be rendered,
    # not dropped: an earlier pass removed the badge and its test marker
    # together, which hid a response-shape regression (chain.items).
    assert "chainValidity" in view
    assert "chain.events" in view
    assert "chain.items" not in view


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
    # A browser whose localhost cookie jar exceeds nginx's default 8k header
    # budget got "400 Request Header Or Cookie Too Large" and the product was
    # unreachable on the stock demo URL. This SPA uses no cookies, so the
    # budget must stay raised. Pinned so a future nginx base-image bump (which
    # can reset this) cannot silently reintroduce the failure.
    assert "large_client_header_buffers 8 32k" in conf
    assert "client_header_buffer_size 16k" in conf
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


# ---------------------------------------------------------------------------
# Tier-aware probe honesty: LIVE only on backend-confirmed real tier
# ---------------------------------------------------------------------------

def test_probe_never_claims_live_without_tier():
    api = _src("api.ts")
    # docker (real execution) is the only tier mapping to LIVE; anything
    # unrecognized — including unreachable — falls through to OFFLINE.
    assert 'meta.executor_tier === "docker"' in api
    assert 'meta.executor_tier === "mock"' in api
    assert 'meta.executor_tier === "replay"' in api
    tail = api.split("export async function probeMode")[1]
    body = tail.split("}\n", 1)[0]  # probeMode body only (fail-closed catch)
    assert "catch" in body and "OFFLINE" in body
    assert "OFFLINE" in tail


def test_mode_badge_documents_tier_source():
    badges = _src("components/badges.tsx")
    assert "GET /meta" in badges or "/meta" in badges


# ---------------------------------------------------------------------------
# Lane D: execution records list + RCA per-gate cards (response data only)
# ---------------------------------------------------------------------------

def test_execution_view_renders_audit_records():
    view = _src("views/ExecutionView.tsx")
    assert "exec-records" in view
    assert "executions.map" in view
    assert "audit_records" in view
    for field in ("record.seq", "record.frm", "record.to",
                  "record.reason", "record.refs"):
        assert field in view
    assert "diff={null}" in view  # null only: no snapshot on run_view


def test_rca_per_gate_cards_from_smoke():
    api = _src("api.ts")
    assert "gates_rate" in api
    view = _src("views/RCAView.tsx")
    assert "per-gate-cards" in view
    assert "gate-card-" in view
    assert "gates_rate" in view  # cards read response data, invent nothing
    for gate in ("C1", "C2", "C3", "C4", "C5", "C6"):
        assert gate in view


# ---------------------------------------------------------------------------
# Lane 3: loading states, key notice, run_view verdicts/rollback
# ---------------------------------------------------------------------------

def test_execution_view_loading_state():
    view = _src("views/ExecutionView.tsx")
    assert "isLoading" in view
    assert "exec-loading" in view
    assert 'aria-busy="true"' in view


def test_rca_view_loading_state():
    view = _src("views/RCAView.tsx")
    assert "isLoading" in view
    assert "rca-loading" in view
    assert 'aria-busy="true"' in view


def test_rca_view_copies_key_notice():
    view = _src("views/RCAView.tsx")
    assert "hasApiKey" in view  # SafetyGate notice pattern, copied
    assert "api-key-notice" in view
    assert "401" in view  # smoke eval is key-gated; the audit chain is open


def test_run_view_verdicts_and_rollback_typed():
    api = _src("api.ts")
    assert "verification_verdicts" in api
    assert "rollback" in api
    view = _src("views/ExecutionView.tsx")
    assert "verdicts-list" in view
    assert "verdicts-empty" in view
    assert "verification_verdicts" in view  # server slice wins where present
    assert "rollback.eligible" in view or "rollback" in view
    assert "diff={null}" in view  # still no snapshot source: never invented
