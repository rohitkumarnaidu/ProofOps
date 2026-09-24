"""Lane 2 observability (M20 metrics): exposition + SLOs + alerts.

Host-safe by design (no TestClient: starlette v1.x host drift): the registry,
SLO loader, and alert evaluation are pure functions tested directly (they are
exactly what the main.py middleware/routes call); FastAPI wiring is asserted
structurally via AST over main.py, following test_runs_router_m14.py.
"""
import ast
import json
import re
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services import metrics as M  # noqa: E402 (Lane 2 registry)

ROOT = Path(__file__).resolve().parents[1]
MAIN_SRC = ROOT / "backend" / "app" / "main.py"
METRICS_SRC = ROOT / "backend" / "app" / "services" / "metrics.py"

SAMPLE_LINE_RE = re.compile(
    r"^(?P<name>[a-z_][a-z0-9_]*)"
    r"(?:\{(?P<labels>[^}]*)\})? (?P<value>\S+)$")


@pytest.fixture(autouse=True)
def _clean():
    M.reset()
    yield
    M.reset()


def _feed() -> None:
    M.observe_http("/healthz", 200, 0.01)
    M.observe_http("/healthz", 200, 0.03)
    M.observe_http("/runs", 500, 0.5)
    M.policy_decision("ALLOW")
    M.policy_decision("DENY")
    M.llm_call("triage")
    M.llm_call("triage")
    M.tool_call("planner")
    M.approval_issued()
    M.approval_approved()
    M.approval_denied()
    M.budget_exceeded()
    M.observe_approval_latency(12.0)


# ---------------------------------------------------------------------------
# Exposition format validity
# ---------------------------------------------------------------------------

def test_exposition_samples_parse():
    _feed()
    body = M.render_prometheus()
    assert body.endswith("\n") and "\r" not in body
    samples = [ln for ln in body.splitlines()
               if ln and not ln.startswith("#")]
    assert len(samples) >= 10  # every family emits at least one sample
    for line in samples:
        match = SAMPLE_LINE_RE.match(line)
        assert match, f"not exposition-shaped: {line!r}"
        float(match.group("value"))  # numeric sample value


def test_exposition_key_lines():
    _feed()
    body = M.render_prometheus()
    assert 'http_requests_total{route="/healthz",code="200"} 2' in body
    assert 'http_requests_total{route="/runs",code="500"} 1' in body
    assert 'http_request_latency_seconds_count{route="/healthz"} 2' in body
    assert 'http_request_latency_seconds_sum{route="/healthz"}' in body
    assert "approvals_issued_total 1" in body
    assert "approvals_approved_total 1" in body
    assert "approvals_denied_total 1" in body
    assert 'policy_decisions_total{decision="DENY"} 1' in body
    assert 'policy_decisions_total{decision="ALLOW"} 1' in body
    assert 'policy_decisions_total{decision="ESCALATE"} 0' in body
    assert "budget_exceeded_total 1" in body
    assert 'llm_calls_total{agent="triage"} 2' in body
    assert 'tool_calls_total{agent="planner"} 1' in body
    for family in ("http_requests_total",
                   "http_request_latency_seconds",
                   "approvals_issued_total", "approvals_approved_total",
                   "approvals_denied_total", "policy_decisions_total",
                   "budget_exceeded_total", "llm_calls_total",
                   "tool_calls_total"):
        assert f"# HELP {family} " in body, family
        assert f"# TYPE {family} " in body, family


def test_exposition_label_escaping():
    M.observe_http('/q"uote', 200, 0.01)
    M.observe_http("/back\\slash", 200, 0.01)
    M.observe_http("/li\nne", 200, 0.01)
    body = M.render_prometheus()
    assert 'route="/q\\"uote"' in body
    assert 'route="/back\\\\slash"' in body
    assert 'route="/li\\nne"' in body


def test_observe_http_rejects():
    for bad in ("", "   ", 123, None):
        with pytest.raises(M.MetricsError):
            M.observe_http(bad, 200, 0.01)  # type: ignore[arg-type]
    for bad_code in (99, 600, 200.0, True, "200"):
        with pytest.raises(M.MetricsError):
            M.observe_http("/x", bad_code, 0.01)  # type: ignore[arg-type]
    for bad_lat in (-1.0, float("nan"), float("inf"), True, "0.1"):
        with pytest.raises(M.MetricsError):
            M.observe_http("/x", 200, bad_lat)  # type: ignore[arg-type]


def test_counter_validation():
    with pytest.raises(M.MetricsError):
        M.policy_decision("MAYBE")
    with pytest.raises(M.MetricsError):
        M.policy_decision("allow")
    for bad in ("", "  ", 7, None):
        with pytest.raises(M.MetricsError):
            M.llm_call(bad)  # type: ignore[arg-type]
        with pytest.raises(M.MetricsError):
            M.tool_call(bad)  # type: ignore[arg-type]
    with pytest.raises(M.MetricsError):
        M.observe_approval_latency(-2.0)


# ---------------------------------------------------------------------------
# Snapshot math + reset isolation + threads
# ---------------------------------------------------------------------------

def test_snapshot_math():
    for i in range(1, 101):
        M.observe_http("/api", 200 if i % 2 else 500, float(i))
    snap = M.snapshot()
    assert snap["http_requests_total"] == 100
    assert snap["http_errors_total"] == 50
    assert snap["availability"] == pytest.approx(0.5)
    assert snap["latency_count"] == 100
    assert snap["latency_sum"] == pytest.approx(5050.0)
    assert snap["latency_p95"] == pytest.approx(95.0)
    assert snap["approval_latency_p95"] is None  # unfed: no data, not zero


def test_snapshot_empty_is_no_data():
    snap = M.snapshot()
    assert snap["http_requests_total"] == 0
    assert snap["availability"] is None
    assert snap["latency_p95"] is None
    assert snap["policy"] == {"ALLOW": 0, "ESCALATE": 0, "DENY": 0}


def test_reset_isolation():
    _feed()
    assert M.snapshot()["http_requests_total"] == 3
    M.reset()
    snap = M.snapshot()
    assert snap["http_requests_total"] == 0
    assert snap["approvals_issued"] == 0
    assert snap["budget_exceeded"] == 0
    assert snap["llm_calls"] == {} and snap["tool_calls"] == {}
    body = M.render_prometheus()  # still valid exposition after reset
    assert "approvals_issued_total 0" in body
    assert "budget_exceeded_total 0" in body


def test_thread_safety_counts_exact():
    def _work() -> None:
        for _ in range(100):
            M.observe_http("/t", 200, 0.001)
            M.llm_call("triage")

    threads = [threading.Thread(target=_work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    M.render_prometheus()  # render mid-state must never raise; run once more
    snap = M.snapshot()
    assert snap["http_requests_total"] == 800
    assert snap["llm_calls"] == {"triage": 800}


# ---------------------------------------------------------------------------
# SLO loader: valid file + fail-closed malformed
# ---------------------------------------------------------------------------

def test_slo_loads_versioned_four_objectives():
    slo = M.load_slo()
    assert slo["version"] == "v1"
    names = [o["name"] for o in slo["objectives"]]
    assert names == ["api-availability", "api-p95-latency",
                     "approval-decision-latency", "readiness"]
    by_name = {o["name"]: o for o in slo["objectives"]}
    assert by_name["api-availability"]["op"] == "gte"
    assert by_name["api-p95-latency"]["op"] == "lte"
    assert by_name["readiness"]["op"] == "is_true"
    for obj in slo["objectives"]:
        assert obj["owner"] and obj["window"]
        assert len(obj["burn_rate_alerts"]) >= 1


def _write_tmp(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "slo.yaml"
    path.write_text(text, encoding="utf-8")
    return path


_GOOD_OBJ = """- name: o1
  kind: availability
  metric: availability
  op: gte
  target: 0.99
  window: 30d
  owner: sre
  burn_rate_alerts:
    - severity: critical
      burn_rate: 14.4
      long_window: 1h
      short_window: 5m
"""


def _doc(extra: str) -> str:
    return 'version: "v1"\nobjectives:\n' + extra


@pytest.mark.parametrize("text", [
    'version: "v9"\nobjectives:\n' + _GOOD_OBJ,  # wrong version
    'version: "v1"\nobjectives: []\n',  # empty objectives
    'version: "v1"\n',  # missing objectives
    "- just\n- a\n- list\n",  # non-mapping
    _doc(_GOOD_OBJ + _GOOD_OBJ.replace("o1", "o1")),  # duplicate name
    _doc(_GOOD_OBJ.replace("kind: availability", "kind: vibes")),
    _doc(_GOOD_OBJ.replace("op: gte", "op: approx")),
    _doc(_GOOD_OBJ.replace("target: 0.99", "target: high")),
    _doc(_GOOD_OBJ.replace("target: 0.99", "target: NaN")),
    _doc(_GOOD_OBJ.replace("window: 30d", "window: 30x")),
    _doc(_GOOD_OBJ.replace("owner: sre", "owner: ''")),
    _doc(_GOOD_OBJ.replace("metric: availability", "metric: ''")),
    _doc(_GOOD_OBJ.split("  burn_rate_alerts:")[0]),  # no burns
    _doc(_GOOD_OBJ.replace("burn_rate: 14.4", "burn_rate: 0")),
    _doc(_GOOD_OBJ.replace("long_window: 1h", "long_window: soon")),
    _doc(_GOOD_OBJ.replace("op: gte\n  target: 0.99",
                           "op: is_true\n  target: 0.99")),
])
def test_slo_malformed_fail_closed(tmp_path, text):
    with pytest.raises(M.MetricsError):
        M.load_slo(_write_tmp(tmp_path, text))


def test_slo_missing_file_fail_closed(tmp_path):
    with pytest.raises(M.MetricsError):
        M.load_slo(tmp_path / "nope.yaml")


def test_slo_is_true_takes_no_target(tmp_path):
    doc = _doc(_GOOD_OBJ.replace(
        "  kind: availability\n  metric: availability\n"
        "  op: gte\n  target: 0.99\n", "  kind: readiness\n"
        "  metric: ready\n  op: is_true\n").replace("  window: 30d",
                                                   "  window: 5m"))
    slo = M.load_slo(_write_tmp(tmp_path, doc))
    assert slo["objectives"][0]["target"] is None


# ---------------------------------------------------------------------------
# Alert evaluation: fires + clears on crafted snapshots
# ---------------------------------------------------------------------------

def _states(slo: dict, snap: dict) -> dict[str, M.SloAlert]:
    return {a.name: a for a in M.evaluate_alerts(snap, slo)}


def test_alerts_fire_and_clear():
    slo = M.load_slo()
    fired = _states(slo, {"availability": 0.5, "latency_p95": 5.0,
                          "approval_latency_p95": 900.0, "ready": False})
    assert fired["api-availability"].state == "firing"
    assert fired["api-p95-latency"].state == "firing"
    assert fired["approval-decision-latency"].state == "firing"
    assert fired["readiness"].state == "firing"
    assert all(a.severity == "critical" for a in fired.values())
    cleared = _states(slo, {"availability": 0.9999, "latency_p95": 0.1,
                            "approval_latency_p95": 10.0, "ready": True})
    assert all(a.state == "ok" for a in cleared.values())
    assert all(a.severity == "none" for a in cleared.values())


def test_alerts_boundary_exact_target_is_ok():
    slo = M.load_slo()
    states = _states(slo, {"availability": 0.999, "latency_p95": 1.0,
                           "approval_latency_p95": 600.0, "ready": True})
    assert all(a.state == "ok" for a in states.values())


def test_alerts_missing_keys_are_ok_no_data():
    slo = M.load_slo()
    states = _states(slo, {})
    assert all(a.state == "ok" for a in states.values())
    assert all(a.observed is None and "no data" in a.note
               for a in states.values())


def test_alerts_live_snapshot_starts_quiet():
    # Fresh registry: no traffic -> availability None -> ok/no-data, and the
    # unwired router counters must never page (documented future work).
    slo = M.load_slo()
    states = _states(slo, M.snapshot())
    assert all(a.state == "ok" for a in states.values())


def test_alerts_reject_malformed():
    slo = M.load_slo()
    with pytest.raises(M.MetricsError):
        M.evaluate_alerts({"x": 1}, {"nope": True})
    with pytest.raises(M.MetricsError):
        M.evaluate_alerts({"x": 1}, {"objectives": []})
    with pytest.raises(M.MetricsError):
        M.evaluate_alerts(["not", "a", "mapping"], slo)  # type: ignore[arg-type]
    with pytest.raises(M.MetricsError):  # wrong-typed observed
        M.evaluate_alerts({"availability": "high"}, slo)


def test_alert_to_dict_json_roundtrip():
    slo = M.load_slo()
    alerts = M.evaluate_alerts({"availability": 0.5}, slo)
    blob = json.dumps([a.to_dict() for a in alerts])
    loaded = json.loads(blob)
    assert loaded[0]["name"] == "api-availability"
    assert loaded[0]["state"] == "firing"


# ---------------------------------------------------------------------------
# Wiring pins (structural, host-safe): main.py additive-only
# ---------------------------------------------------------------------------

def _main_tree() -> ast.AST:
    return ast.parse(MAIN_SRC.read_text(encoding="utf-8"))


def test_main_defines_middleware_calling_registry():
    tree = _main_tree()
    fns = [n for n in ast.walk(tree)
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    mw = [f for f in fns if f.name == "metrics_middleware"]
    assert mw, "main.py must define metrics_middleware"
    assert any(isinstance(d, ast.Call)
               and isinstance(d.func, ast.Attribute)
               and d.func.attr == "middleware"
               for d in mw[0].decorator_list), "must use @app.middleware"
    src = ast.get_source_segment(MAIN_SRC.read_text(encoding="utf-8"),
                                 mw[0]) or ""
    assert "observe_http" in src


def test_main_defines_metrics_and_alerts_routes():
    src = MAIN_SRC.read_text(encoding="utf-8")
    assert '@app.get("/metrics")' in src
    assert '@app.get("/alerts")' in src
    assert "render_prometheus" in src
    assert "SLO configuration unavailable" in src  # static 500, no traces
    assert "status_code=500" in src


def test_main_alerts_handler_leaks_no_trace():
    src = MAIN_SRC.read_text(encoding="utf-8")
    segment = src.split("def alerts_endpoint", 1)[1]
    assert "traceback" not in segment
    assert "str(exc" not in segment and "str(e)" not in segment


def test_main_stream_guard_both_orders():
    tree = _main_tree()
    handlers = [n for n in ast.walk(tree)
                if isinstance(n, ast.ExceptHandler)]
    assert any(n.type is not None and getattr(n.type, "id", "") == "ImportError"
               for n in handlers), "stream include needs ImportError guard"
    assert "stream" in MAIN_SRC.read_text(encoding="utf-8")


def test_main_healthz_body_untouched():
    src = MAIN_SRC.read_text(encoding="utf-8")
    assert 'return {"status": "ok", "service": "proofops-api", ' \
        '"spec": "PS03_FINAL_SPEC_V2"}' in src


def test_metrics_module_stdlib_only_no_fake_paging():
    tree = ast.parse(METRICS_SRC.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    allowed = {"__future__", "math", "re", "threading", "collections",
               "dataclasses", "pathlib", "typing", "yaml"}
    assert roots <= allowed, f"non-stdlib imports: {roots - allowed}"
    src = METRICS_SRC.read_text(encoding="utf-8")
    assert "prometheus_client" not in src  # no client lib by scope
    # No fake paging *implementation* (naming an external webhook as future
    # work in prose is allowed; building one here is not).
    for marker in ("send_page", "notify(", "webhook.post", "httpx", "urlopen",
                   "requests.post", "smtp"):
        assert marker not in src.lower(), f"paging marker: {marker}"
