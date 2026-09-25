"""M20 performance: metering (ledger/latency/cost) + allowed optimizations.

Ownership: M20 owns THIS FILE (``backend/app/services/budgets.py``) and
``policies/pricing.yaml``. Nothing here weakens safety (spec S49): caches
key on exact inputs (no stale reads), routing only selects size tiers,
parallelism preserves order and propagates errors, and every optimization
is measured (hit rates, timings) rather than claimed.

Token counting: estimate_tokens() = UTF-8 bytes // 4, the same documented
heuristic as M05 pack estimates. Raw tokens are primary; money comes ONLY
from the editable pricing table (no currency literals in this file --
asserted by test). Latencies are caller-measured milliseconds (clock-
injected, no wall-clock reads inside); percentiles use nearest-rank.

Wiring note: the ledger is fed EXPLICITLY by callers (control plane M21
wires sessions/clients/retrieval into it). This module never monkey-patches
or rewrites other modules' code to collect numbers.
"""
from __future__ import annotations

import math
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agents import MODEL_TIERS  # noqa: E402 (M13 routing tiers, dep-free)
from app.contracts.values import canonical_json  # noqa: E402 (stable keys)

TOKENS_LT = 80000
CALLS_LT = 12
CTX_LT = 12000
CACHE_HIT_GT = 0.5
PRICING_VERSION = "v1"


class BudgetError(Exception):
    """Malformed ledger/pricing input or unmeasured claim (fail-closed)."""


def estimate_tokens(text: str) -> int:
    """Raw-token estimate: UTF-8 bytes // 4 (documented heuristic)."""
    if not isinstance(text, str):
        raise BudgetError(f"text must be str, got {type(text).__name__}")
    return len(text.encode("utf-8")) // 4


def percentile(samples: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile (deterministic, M20.2)."""
    values = list(samples)
    if not values:
        raise BudgetError("percentile needs a non-empty sample")
    if isinstance(pct, bool) or not isinstance(pct, (int, float)) or \
            not 0 < float(pct) < 100:
        raise BudgetError("pct must be in (0, 100)")
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or not math.isfinite(float(value)) or float(value) < 0:
            raise BudgetError("samples must be finite non-negative numbers")
    ordered = sorted(float(v) for v in values)
    rank = max(1, math.ceil(float(pct) / 100.0 * len(ordered)))
    return ordered[rank - 1]


@dataclass
class Ledger:
    """Per-incident budget ledger (M20.1): explicit feeds, measured totals."""

    incident_id: str
    tokens_in: int = 0
    tokens_out: int = 0
    llm_calls: int = 0
    stages: dict[str, list[float]] = field(default_factory=dict)
    retrieval_calls: int = 0
    retrieval_hits: int = 0
    ctx_max: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.incident_id, str) or \
                not self.incident_id.strip():
            raise BudgetError("incident_id must be a non-empty string")

    @staticmethod
    def _count(value: int, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) \
                or value < 0:
            raise BudgetError(f"{name} must be a non-negative int")
        return value

    def add_io(self, in_text: str, out_text: str) -> None:
        """Record one LLM round-trip (tokens estimated, call counted)."""
        self.tokens_in += estimate_tokens(in_text)
        self.tokens_out += estimate_tokens(out_text)
        self.llm_calls += 1

    def record_stage(self, stage: str, ms: float) -> None:
        if not isinstance(stage, str) or not stage.strip():
            raise BudgetError("stage must be a non-empty string")
        if isinstance(ms, bool) or not isinstance(ms, (int, float)) or \
                not math.isfinite(float(ms)) or float(ms) < 0:
            raise BudgetError("stage ms must be a finite non-negative number")
        self.stages.setdefault(stage, []).append(float(ms))

    def record_retrieval(self, cached: bool) -> None:
        self.retrieval_calls += 1
        if cached:
            self.retrieval_hits += 1

    def observe_ctx(self, tokens: int) -> None:
        tokens = self._count(tokens, "ctx tokens")
        self.ctx_max = max(self.ctx_max, tokens)

    @property
    def tokens(self) -> int:
        return self.tokens_in + self.tokens_out

    @property
    def cache_rate(self) -> float | None:
        if self.retrieval_calls == 0:
            return None
        return self.retrieval_hits / self.retrieval_calls

    def summary(self) -> dict[str, Any]:
        return {"incident_id": self.incident_id,
                "tokens": self.tokens, "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out, "llm_calls": self.llm_calls,
                "stages": {name: {"n": len(v), "p50": percentile(v, 50),
                                  "p95": percentile(v, 95),
                                  "max": max(v)}
                           for name, v in self.stages.items()},
                "retrieval_calls": self.retrieval_calls,
                "retrieval_hits": self.retrieval_hits,
                "cache_rate": self.cache_rate, "ctx_max": self.ctx_max}


def assert_budgets(ledger: Ledger) -> dict[str, Any]:
    """C4 gate over measured ledger totals (M20.1): spec bounds.

    Bounds are INCLUSIVE (<=): the control plane permits exactly
    TOKENS_LT tokens / CALLS_LT calls / CTX_LT context (P1 off-by-one fix:
    a ledger at exactly the permitted budget passes).
    """
    if not isinstance(ledger, Ledger):
        raise BudgetError("assert_budgets needs a Ledger")
    checks = {"tokens": ledger.tokens <= TOKENS_LT,
              "calls": ledger.llm_calls <= CALLS_LT,
              "ctx": ledger.ctx_max <= CTX_LT}
    notes: dict[str, str] = {
        "tokens": f"{ledger.tokens} <= {TOKENS_LT}",
        "calls": f"{ledger.llm_calls} <= {CALLS_LT}",
        "ctx": f"{ledger.ctx_max} <= {CTX_LT}"}
    rate = ledger.cache_rate
    if rate is None:
        notes["cache"] = "no retrieval calls (skipped, not passed)"
    else:
        checks["cache"] = rate > CACHE_HIT_GT
        notes["cache"] = f"{rate:.3f} > {CACHE_HIT_GT}"
    return {"passed": all(checks.values()), "checks": checks, "notes": notes}


def load_pricing(path: str | Path | None = None) -> dict[str, Any]:
    """Load + validate the editable pricing table (M20.3)."""
    import yaml  # type: ignore[import-untyped]  # same missing-stubs cause
    # as runbooks/policy (types-PyYAML absent); narrow, justified: the table
    # MUST stay editable YAML per scope, and this is its single reader.
    if path is None:
        from app import paths
        path = paths.policies_dir() / "pricing.yaml"
    try:
        with open(path, encoding="utf-8") as handle:
            table = yaml.safe_load(handle)
    except OSError as exc:
        raise BudgetError(f"pricing table unreadable: {exc}") from exc
    if not isinstance(table, dict):
        raise BudgetError("pricing table must be a mapping")
    if str(table.get("version")) != PRICING_VERSION:
        raise BudgetError(
            f"pricing version must be {PRICING_VERSION!r}")
    tiers = table.get("tiers")
    want = sorted(set(MODEL_TIERS.values()))
    if not isinstance(tiers, dict) or sorted(tiers) != want:
        raise BudgetError(
            f"pricing tiers must equal routing tiers {want}")
    for tier, rates in tiers.items():
        if not isinstance(rates, dict):
            raise BudgetError(f"tier {tier!r} must map rates")
        for key in ("per_1k_in", "per_1k_out"):
            value = rates.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not math.isfinite(float(value)) or float(value) < 0:
                raise BudgetError(f"tier {tier!r} {key} must be a "
                                  f"non-negative number")
    return {"version": table["version"],
            "tiers": {t: {"per_1k_in": float(r["per_1k_in"]),
                          "per_1k_out": float(r["per_1k_out"])}
                      for t, r in tiers.items()}}


def cost_of(tokens_in: int, tokens_out: int, tier: str,
            table: Mapping[str, Any]) -> float:
    """Money from the table only (M20.3): never hardcoded, always passed in."""
    for name, value in (("tokens_in", tokens_in),
                        ("tokens_out", tokens_out)):
        if isinstance(value, bool) or not isinstance(value, int) \
                or value < 0:
            raise BudgetError(f"{name} must be a non-negative int")
    try:
        rates = table["tiers"][tier]
        total = tokens_in / 1000.0 * float(rates["per_1k_in"]) + \
            tokens_out / 1000.0 * float(rates["per_1k_out"])
    except (KeyError, TypeError) as exc:
        raise BudgetError(f"unknown tier or bad table: {exc}") from exc
    return round(total, 6)


def route(agent: str) -> str:
    """Model tier for an agent (M20.5): the pinned routing table."""
    try:
        return MODEL_TIERS[agent]
    except KeyError as exc:
        raise BudgetError(f"unknown agent: {agent!r}") from exc


class StaticCache:
    """Immutable-input cache with hit stats (M20.6).

    Keys are caller-chosen strings (e.g. runbook id@version); values must be
    immutable snapshots. No TTL needed: cached content never changes under
    its key (new versions get new keys). Wraps functions WITHOUT modifying
    them (decorator pattern over M11 loader proven in tests).
    """

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}
        self.hits = 0
        self.misses = 0

    def get_or_compute(self, key: str, fn: Callable[[], Any]) -> Any:
        if not isinstance(key, str) or not key:
            raise BudgetError("cache key must be a non-empty string")
        if key in self._store:
            self.hits += 1
            return self._store[key]
        self.misses += 1
        value = fn()
        self._store[key] = value
        return value

    def clear(self) -> None:
        self._store.clear()
        self.hits = 0
        self.misses = 0

    @property
    def rate(self) -> float | None:
        total = self.hits + self.misses
        return self.hits / total if total else None


def cached_retrieve(query_text: str, docs: Sequence[Any], cache: StaticCache,
                    **kwargs: Any) -> tuple[list[Any], bool]:
    """Exact-input retrieval cache (M20.4): identical hits, counted.

    Cache key binds query + filters + threshold + top_k + corpus identity,
    so a cached hit can never serve a different question (no stale reads).
    """
    from app.services import retrieval as retrieval_svc
    fingerprint = canonical_json({
        "query": query_text,
        "filters": dict(kwargs.get("filters") or {}),
        "threshold": kwargs.get("threshold", retrieval_svc.SCORE_THRESHOLD),
        "top_k": kwargs.get("top_k", retrieval_svc.TOP_K),
        "corpus": sorted(d.doc_id for d in docs)})
    key = "retrieval:" + fingerprint
    hits_before = cache.hits
    hits = cache.get_or_compute(
        key, lambda: retrieval_svc.retrieve(query_text, docs, **kwargs))
    return list(hits), cache.hits == hits_before + 1


def parallel_map(fn: Callable[[Any], Any], items: Sequence[Any],
                 max_workers: int = 4) -> dict[str, Any]:
    """Order-preserving parallel fan-out with timings (M20.7).

    Results equal serial execution (asserted by test); exceptions propagate
    (fail-closed, never swallowed); functions must be pure (documented --
    shared mutable state across workers is a caller bug).
    """
    if not isinstance(max_workers, int) or isinstance(max_workers, bool) \
            or max_workers < 1:
        raise BudgetError("max_workers must be a positive int")
    items = list(items)
    if not items:
        return {"results": [], "ms_per_item": [], "total_ms": 0.0}
    start = time.perf_counter()
    per_item: list[float] = [0.0] * len(items)
    results: list[Any] = [None] * len(items)

    def _one(index: int, item: Any) -> None:
        begun = time.perf_counter()
        results[index] = fn(item)
        per_item[index] = (time.perf_counter() - begun) * 1000.0

    with ThreadPoolExecutor(max_workers=min(max_workers,
                                            len(items))) as pool:
        futures = [pool.submit(_one, index, item)
                   for index, item in enumerate(items)]
        for future in futures:
            future.result()
    return {"results": results, "ms_per_item": per_item,
            "total_ms": (time.perf_counter() - start) * 1000.0}
