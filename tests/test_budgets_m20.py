"""M20 performance: ledger + latency + cost + caches + routing + parallel.

Single-commit M20 lane (M20.1-M20.7): pure measurement and allowed
optimizations only. Nothing here weakens safety; caches key exact inputs,
parallelism preserves order, money is table-driven.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services import budgets as B  # noqa: E402 (M20 budgets)

ROOT = Path(__file__).resolve().parents[1]


def _ledger():
    ledger = B.Ledger(incident_id="inc-1")
    ledger.add_io("q" * 400, "a" * 400)
    ledger.record_stage("triage", 2.0)
    ledger.record_retrieval(False)
    ledger.record_retrieval(True)
    ledger.record_retrieval(True)
    ledger.observe_ctx(6000)
    return ledger


# ---------------------------------------------------------------------------
# M20.1 token ledger
# ---------------------------------------------------------------------------

def test_estimate_tokens():
    assert B.estimate_tokens("") == 0
    assert B.estimate_tokens("q" * 400) == 100
    assert B.estimate_tokens("caf\u00e9") == 1  # multibyte counts bytes
    with pytest.raises(B.BudgetError):
        B.estimate_tokens(123)  # type: ignore[arg-type]


def test_ledger_io_and_totals():
    ledger = B.Ledger(incident_id="inc-1")
    ledger.add_io("q" * 400, "a" * 800)
    assert (ledger.tokens_in, ledger.tokens_out, ledger.tokens,
            ledger.llm_calls) == (100, 200, 300, 1)


def test_ledger_rejects_bad_state():
    with pytest.raises(B.BudgetError):
        B.Ledger(incident_id="  ")
    ledger = B.Ledger(incident_id="inc-1")
    with pytest.raises(B.BudgetError):
        ledger.record_stage("", 1.0)
    with pytest.raises(B.BudgetError):
        ledger.record_stage("triage", -1.0)
    with pytest.raises(B.BudgetError):
        ledger.observe_ctx(-5)


def test_assert_budgets_pass_and_notes():
    verdict = B.assert_budgets(_ledger())
    assert verdict["passed"] is True
    assert set(verdict["checks"]) == {"tokens", "calls", "ctx", "cache"}


def test_assert_budgets_strict_bounds():
    ledger = _ledger()
    ledger.tokens_in = 79999
    assert B.assert_budgets(ledger)["checks"]["tokens"] is False
    ledger = _ledger()
    for _ in range(11):
        ledger.add_io("q", "a")
    assert ledger.llm_calls == 12
    # Spec bound is inclusive (<=12 permitted): exactly 12 passes (P1 fix).
    assert B.assert_budgets(ledger)["checks"]["calls"] is True
    ledger.add_io("q", "a")
    assert ledger.llm_calls == 13
    assert B.assert_budgets(ledger)["checks"]["calls"] is False


def test_cache_skipped_when_no_retrieval():
    ledger = B.Ledger(incident_id="inc-1")
    verdict = B.assert_budgets(ledger)
    assert "skipped" in verdict["notes"]["cache"]
    assert verdict["passed"] is True
    assert B.assert_budgets(ledger)["checks"].get("cache", True) is True


def test_assert_rejects_non_ledger():
    with pytest.raises(B.BudgetError):
        B.assert_budgets({"tokens": 1})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# M20.2 latency percentiles
# ---------------------------------------------------------------------------

def test_percentile_exact():
    samples = list(range(1, 101))
    assert B.percentile(samples, 50) == 50.0
    assert B.percentile(samples, 95) == 95.0
    assert B.percentile([5.0], 99) == 5.0


def test_percentile_rejects():
    with pytest.raises(B.BudgetError):
        B.percentile([], 50)
    with pytest.raises(B.BudgetError):
        B.percentile([1.0], 0)
    with pytest.raises(B.BudgetError):
        B.percentile([1.0], 100)
    with pytest.raises(B.BudgetError):
        B.percentile([-1.0], 50)


def test_stage_summary():
    ledger = _ledger()
    ledger.record_stage("triage", 4.0)
    summary = ledger.summary()
    assert summary["stages"]["triage"] == {"n": 2, "p50": 2.0, "p95": 4.0,
                                           "max": 4.0}
    assert summary["cache_rate"] == pytest.approx(2 / 3)


# ---------------------------------------------------------------------------
# M20.3 cost from the table only
# ---------------------------------------------------------------------------

def test_pricing_load_and_shape():
    from agents import MODEL_TIERS as _TIERS
    table = B.load_pricing()
    assert table["version"] == "v1"
    assert set(table["tiers"]) == set(_TIERS.values())


def test_cost_math_exact():
    table = B.load_pricing()
    assert B.cost_of(1000, 1000, "small", table) == pytest.approx(0.0035)
    assert B.cost_of(0, 0, "large", table) == 0.0


def test_cost_is_table_driven():
    table = B.load_pricing()
    table["tiers"]["small"]["per_1k_in"] = 99.0
    assert B.cost_of(1000, 0, "small", table) == pytest.approx(99.0)
    with pytest.raises(B.BudgetError):
        B.cost_of(100, 100, "huge", table)
    with pytest.raises(B.BudgetError):
        B.cost_of(-1, 0, "small", table)


def test_pricing_rejects_bad_file(tmp_path):
    bad = tmp_path / "pricing.yaml"
    bad.write_text("version: v9\ntiers: {}\n", encoding="utf-8")
    with pytest.raises(B.BudgetError):
        B.load_pricing(bad)
    with pytest.raises(B.BudgetError):
        B.load_pricing(tmp_path / "missing.yaml")


def test_no_currency_literals_in_code():
    src = (ROOT / "backend" / "app" / "services" / "budgets.py").read_text(
        encoding="utf-8")
    assert "$" not in src


# ---------------------------------------------------------------------------
# M20.5 model routing
# ---------------------------------------------------------------------------

def test_routing_table():
    assert B.route("triage") == "small"
    assert B.route("diagnostic") == "large"
    assert B.route("planner") == "medium"
    assert B.route("reporter") == "economical"
    with pytest.raises(B.BudgetError):
        B.route("manager")


def test_routing_cost_ordering():
    table = B.load_pricing()
    small = B.cost_of(10000, 5000, B.route("triage"), table)
    large = B.cost_of(10000, 5000, B.route("diagnostic"), table)
    assert small < large


# ---------------------------------------------------------------------------
# M20.6 static cache (decorator pattern, M11 untouched)
# ---------------------------------------------------------------------------

def test_static_cache_hits():
    from app.services.runbooks import load_runbook
    cache = B.StaticCache()
    first = cache.get_or_compute("bad-deploy-rollback@1.2.0",
                                 lambda: load_runbook("bad-deploy-rollback"))
    second = cache.get_or_compute("bad-deploy-rollback@1.2.0",
                                  lambda: load_runbook("bad-deploy-rollback"))
    assert first == second
    assert (cache.hits, cache.misses) == (1, 1)
    assert cache.rate == 0.5
    cache.clear()
    assert (cache.hits, cache.misses, cache.rate) == (0, 0, None)


def test_static_cache_rejects_blank_key():
    with pytest.raises(B.BudgetError):
        B.StaticCache().get_or_compute("", lambda: 1)


# ---------------------------------------------------------------------------
# M20.4 cached retrieval (correctness + hit counting)
# ---------------------------------------------------------------------------

def _corpus():
    from app.services.retrieval import index_runbooks
    from app.services.runbooks import load_runbook
    return index_runbooks([load_runbook(name) for name in
                           ("bad-deploy-rollback", "crashloop-oom",
                            "db-pool-saturation", "net-dep-failover",
                            "injection-quarantine")])


def test_cached_retrieval_identical_and_counted():
    from app.services import retrieval as R
    docs = _corpus()
    cache = B.StaticCache()
    query = "web prod http_5xx_spike"
    direct = R.retrieve(query, docs)
    hits, cached = B.cached_retrieve(query, docs, cache)
    assert cached is False
    assert [h.doc_id for h in hits] == [h.doc_id for h in direct]
    hits2, cached2 = B.cached_retrieve(query, docs, cache)
    assert cached2 is True
    assert [h.doc_id for h in hits2] == [h.doc_id for h in hits]


def test_cache_key_binds_filters():
    docs = _corpus()
    cache = B.StaticCache()
    _, first_cached = B.cached_retrieve("web prod spike", docs, cache,
                                        filters={"service": "web"})
    _, second_cached = B.cached_retrieve("web prod spike", docs, cache,
                                         filters={"service": "api"})
    assert first_cached is False and second_cached is False


def test_threshold_respected_through_cache():
    docs = _corpus()
    cache = B.StaticCache()
    hits, _ = B.cached_retrieve("zebra quantum telescope", docs, cache)
    assert hits == []


# ---------------------------------------------------------------------------
# M20.7 parallel fan-out (order + equality + timing + errors)
# ---------------------------------------------------------------------------

def test_parallel_matches_serial():
    import time as _time

    def _work(n):
        _time.sleep(0.01)
        return n * n

    items = list(range(10))
    serial = [_work(i) for i in items]
    out = B.parallel_map(_work, items, max_workers=4)
    assert out["results"] == serial
    assert len(out["ms_per_item"]) == 10
    assert all(ms >= 0 for ms in out["ms_per_item"])
    assert out["total_ms"] >= 0


def test_parallel_empty_and_validation():
    assert B.parallel_map(lambda x: x, [])["results"] == []
    with pytest.raises(B.BudgetError):
        B.parallel_map(lambda x: x, [1], max_workers=0)


def test_parallel_errors_propagate():
    def _boom(n):
        if n == 2:
            raise RuntimeError("worker failed")
        return n

    with pytest.raises(RuntimeError):
        B.parallel_map(_boom, [1, 2, 3])
