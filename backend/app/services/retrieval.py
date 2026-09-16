"""Deterministic retrieval: local KB + filters + MMR rerank + Evidence Pack (M12).

Ownership: M12 owns THIS FILE (``backend/app/services/retrieval.py``).
Shape validation is M01.4/M01.6 (Evidence/Runbook contracts); capture and
packing primitives are M05 (``evidence``/``predigest``); runbook intake is
M11 (loader). This module owns ONLY: in-memory corpus builders, lexical
scoring, metadata/temporal filtering, MMR rerank, the retrieve() pipeline,
Evidence Pack assembly under a token budget, and pure retrieval metrics.

Label: CUSTOM-DETERMINISTIC stand-in. There is no live Lyzr call here and
nothing here may be labeled LYZR-NATIVE: Classic KB client wiring (session,
chat, RAI, trace) is M13's job, which consumes this module's corpus shape +
threshold/top-k behavior. NO pgvector (frozen decision, spec G05): scoring
is a deterministic coverage-weighted lexical score over token sets -- no
embeddings, no network,
no LLM, no wall-clock.

Trust boundary: retrieval proposes CANDIDATES. It never authorizes, never
executes, never verifies. Telemetry text is DATA: matched substrings are
quoted as counts/refs, never interpreted as instructions. The current
incident's ground truth (cause / expected RCA / allowed-forbidden lists)
never enters a query: build_query() takes ONLY observable fields
(service/env/signature/top errors) -- there is no parameter that could
carry an answer, so leakage is structurally impossible. Indexed runbook
text is descriptive ONLY (title/trigger/steps/preconditions); action-scope
fields (allowed/forbidden/rollback/approval) are policy-owned (M06) and
deliberately excluded, so injection tokens like "delete namespace" match
nothing.
"""
from __future__ import annotations

import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.services import evidence as evidence_svc  # noqa: E402 (M05 primitives)
from app.services import predigest as predigest_svc  # noqa: E402 (M05.5 pack)

# Spec ``22`` frozen retrieval design (start values, revised after runs).
SCORE_THRESHOLD = 0.7
TOP_K = 5
MMR_LAMBDA = 0.5
# Spec ``23`` Evidence Pack budget (chars//4 estimate, ``[PROVISIONAL]``).
PACK_TOKEN_BUDGET = 6000
# Temporal behavior mirrors the M05 freshness bound (15m) and the deploy
# correlation window (+-15m, spec ``24``).
TEMPORAL_HALF_LIFE_S = 900.0
TEMPORAL_WINDOW_S = 900.0

ALLOWED_FILTER_KEYS = ("service", "env", "source_type")

_TOKEN_RE = re.compile(r"[a-z0-9]+")


# ---------------------------------------------------------------------------
# Corpus documents
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Doc:
    """One retrievable unit: descriptive text + routing metadata.

    ``service`` ``""`` (or ``envs`` ``()``) means universal: the doc applies
    to any service (or env) and always passes that filter dimension.
    ``ts`` ``None`` means timeless (runbooks, standing procedures): temporal
    filtering never drops it and decay never penalizes it.
    """

    doc_id: str
    text: str
    source_type: str = "history"
    service: str = ""
    envs: tuple[str, ...] = ()
    ts: float | None = None
    ref: str = ""


@dataclass(frozen=True)
class Hit:
    """One ranked retrieval result: identity + combined relevance score."""

    doc_id: str
    score: float
    source_type: str = ""
    service: str = ""
    ref: str = ""


def _plain(mapping: Any) -> dict[str, Any]:
    """Best-effort Mapping (incl. FrozenDict) -> plain dict."""
    to_plain = getattr(mapping, "to_plain", None)
    if callable(to_plain):
        result = to_plain()
        return dict(result) if not isinstance(result, dict) else result
    return dict(mapping)


def index_runbooks(runbooks: Iterable[Any]) -> list[Doc]:
    """Index descriptive runbook text (M12.1): title/trigger/steps only.

    Action-scope fields (allowed/forbidden/rollback/approval) are excluded
    by design (see module docstring): they are policy-owned and must never
    become lexical match surface for injected instructions.
    """
    docs: list[Doc] = []
    for rb in runbooks:
        trigger = _plain(rb.trigger)
        scope = tuple(str(e) for e in (rb.scope or ()))
        text = " ".join([
            str(rb.title),
            str(trigger.get("alert_regex", "")),
            str(trigger.get("service", "")),
            *list(scope),
            *list(rb.preconditions),
            *list(rb.diagnostic_steps),
        ])
        docs.append(Doc(
            doc_id=f"{rb.runbook_id}@{rb.version}",
            text=text,
            source_type="runbook",
            service=str(trigger.get("service", "")),
            envs=scope,
            ts=None,
            ref=f"runbooks/{rb.runbook_id}.yaml#{rb.version}",
        ))
    return docs


def index_history(items: Iterable[Mapping[str, Any]]) -> list[Doc]:
    """Index past-incident summaries (M12.1): explicit fields, fail-closed."""
    known = {"doc_id", "text", "source_type", "service", "envs", "env",
             "ts", "ref"}
    docs: list[Doc] = []
    for item in items:
        unknown = set(item) - known
        if unknown:
            raise ValueError(f"unknown history fields: {sorted(unknown)}")
        doc_id = item.get("doc_id", "")
        text = item.get("text", "")
        if not isinstance(doc_id, str) or not doc_id.strip():
            raise ValueError("history doc_id must be a non-empty string")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("history text must be a non-empty string")
        envs = item.get("envs", ())
        if "env" in item and "envs" not in item:
            envs = (item["env"],)
        envs = tuple(str(e) for e in (envs or ()))
        ts = item.get("ts")
        if ts is not None and (isinstance(ts, bool) or not isinstance(ts, (int, float))):
            raise ValueError("history ts must be epoch seconds or None")
        docs.append(Doc(
            doc_id=doc_id,
            text=text,
            source_type=str(item.get("source_type", "history")),
            service=str(item.get("service", "")),
            envs=envs,
            ts=None if ts is None else float(ts),
            ref=str(item.get("ref", "")),
        ))
    return docs


# ---------------------------------------------------------------------------
# Scoring (M12.1 lexical core, deterministic, no embeddings)
# ---------------------------------------------------------------------------

def tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokens; single characters carry no signal."""
    if not isinstance(text, str):
        raise ValueError(f"text must be str, got {type(text).__name__}")
    return [t for t in _TOKEN_RE.findall(text.lower()) if len(t) > 1]


def lexical_score(query_text: str, doc_text: str) -> float:
    """Coverage-weighted lexical score in [0,1] (M12.1).

    ``0.7 * query_coverage + 0.3 * jaccard``: incident queries are short
    (service/env/signature) while procedure docs are long, so pure F1 would
    bury every true match below the 0.7 gate. Coverage answers "is everything
    asked about present"; Jaccard answers "is the doc ABOUT the query".
    1.0 identical, 0.0 disjoint or empty input. Deterministic, no embeddings.
    """
    q, d = set(tokenize(query_text)), set(tokenize(doc_text))
    if not q or not d:
        return 0.0
    inter = len(q & d)
    if inter == 0:
        return 0.0
    coverage = inter / len(q)
    return 0.7 * coverage + 0.3 * (inter / len(q | d))


def jaccard(a_tokens: Iterable[str], b_tokens: Iterable[str]) -> float:
    """Token-set Jaccard in [0,1] (MMR diversity term)."""
    a, b = set(a_tokens), set(b_tokens)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ---------------------------------------------------------------------------
# Filtering (M12.2 metadata, M12.3 temporal)
# ---------------------------------------------------------------------------

def _check_filters(filters: Mapping[str, str] | None) -> dict[str, str]:
    """Validate filter dimensions (fail-closed on unknown keys)."""
    if filters is None:
        return {}
    unknown = set(filters) - set(ALLOWED_FILTER_KEYS)
    if unknown:
        raise ValueError(f"unknown filter keys: {sorted(unknown)}")
    return dict(filters)


def apply_metadata_filter(
    docs: Iterable[Doc], filters: Mapping[str, str] | None
) -> list[Doc]:
    """Exact service/env/source_type match (M12.2).

    Universal docs (``service == ""`` / ``envs == ()``) always pass their
    dimension: a runbook scoped to every env must not be filtered out by an
    env query.
    """
    wanted = _check_filters(filters)
    if not wanted:
        return list(docs)
    kept: list[Doc] = []
    for doc in docs:
        if "service" in wanted and wanted["service"] not in ("", doc.service):
            if doc.service != "":
                continue
        if "env" in wanted and doc.envs and wanted["env"] not in doc.envs:
            continue
        if "source_type" in wanted and doc.source_type != wanted["source_type"]:
            continue
        kept.append(doc)
    return kept


def temporal_decay(
    doc_ts: float | None, now_ts: float, half_life_s: float = TEMPORAL_HALF_LIFE_S
) -> float:
    """Exponential freshness weight in (0,1] (M12.3).

    Timeless docs (``None``) and future timestamps (clock skew, fail-closed)
    score 1.0 -- decay only ever down-weights the past, never crashes.
    """
    if half_life_s <= 0:
        raise ValueError("half_life_s must be positive")
    if doc_ts is None:
        return 1.0
    age = now_ts - float(doc_ts)
    if age <= 0:
        return 1.0
    return 0.5 ** (age / half_life_s)


def apply_temporal_filter(
    docs: Iterable[Doc], now_ts: float, window_s: float = TEMPORAL_WINDOW_S
) -> list[Doc]:
    """Keep timeless docs plus observations within +-window (M12.3)."""
    if window_s <= 0:
        raise ValueError("window_s must be positive")
    kept: list[Doc] = []
    for doc in docs:
        if doc.ts is None or abs(now_ts - doc.ts) <= window_s:
            kept.append(doc)
    return kept


# ---------------------------------------------------------------------------
# Query construction (observable fields only -- ground-truth isolation)
# ---------------------------------------------------------------------------

def build_query(
    service: str, env: str, error_signature: str,
    top_errors: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the retrieval query from OBSERVABLES only (M12.4).

    There is deliberately no parameter for cause/expected/allowed/forbidden:
    the current incident's answer cannot leak into model-visible context
    because the function has nowhere to receive it.
    """
    for name, value in (("service", service), ("env", env),
                        ("error_signature", error_signature)):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    errors = [str(e) for e in top_errors]
    text = " ".join([service, env, error_signature, *errors])
    return {"text": text, "service": service, "env": env}


# ---------------------------------------------------------------------------
# Ranking: threshold gate + MMR rerank (M12.6)
# ---------------------------------------------------------------------------

def _check_threshold(threshold: float) -> float:
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("threshold must be a number in [0,1]")
    if not 0.0 <= float(threshold) <= 1.0:
        raise ValueError("threshold must be in [0,1]")
    return float(threshold)


def _check_top_k(top_k: int) -> int:
    if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k < 1:
        raise ValueError("top_k must be a positive int")
    return top_k


def _check_lambda(lambda_mult: float) -> float:
    if (isinstance(lambda_mult, bool) or not isinstance(lambda_mult, (int, float))
            or not 0.0 <= float(lambda_mult) <= 1.0):
        raise ValueError("lambda_mult must be a number in [0,1]")
    return float(lambda_mult)


def mmr_rank(
    query_text: str,
    scored: list[tuple[Doc, float]],
    top_k: int = TOP_K,
    lambda_mult: float = MMR_LAMBDA,
) -> list[Doc]:
    """Maximal-marginal-relevance rerank (M12.6): relevance minus redundancy.

    ``scored`` carries (doc, combined-relevance). Each round picks the doc
    maximizing ``L*relevance - (1-L)*max_similarity_to_selected``; ties break
    by ``doc_id`` so reruns are byte-identical. Returns at most ``top_k``.
    """
    top_k = _check_top_k(top_k)
    lam = _check_lambda(lambda_mult)
    if not scored:
        return []
    q_tokens = tokenize(query_text)
    doc_tokens = {doc.doc_id: tokenize(doc.text) for doc, _ in scored}
    remaining = sorted(scored, key=lambda pair: (-pair[1], pair[0].doc_id))
    selected: list[Doc] = []
    while remaining and len(selected) < top_k:
        best: tuple[Doc, float] | None = None
        for doc, rel in remaining:
            redundancy = 0.0
            for chosen in selected:
                redundancy = max(redundancy, jaccard(
                    doc_tokens[doc.doc_id], doc_tokens[chosen.doc_id]))
            value = lam * rel - (1.0 - lam) * redundancy
            if best is None or value > best[1] or (
                    value == best[1] and doc.doc_id < best[0].doc_id):
                best = (doc, value)
        assert best is not None
        selected.append(best[0])
        remaining = [(d, r) for d, r in remaining if d.doc_id != best[0].doc_id]
    _ = q_tokens  # lexical content already folded into relevance scores
    return selected


def retrieve(
    query_text: str,
    docs: Iterable[Doc],
    *,
    filters: Mapping[str, str] | None = None,
    now_ts: float | None = None,
    window_s: float = TEMPORAL_WINDOW_S,
    threshold: float = SCORE_THRESHOLD,
    top_k: int = TOP_K,
    lambda_mult: float = MMR_LAMBDA,
) -> list[Hit]:
    """Full retrieval pipeline (M12.1/12.2/12.3/12.6).

    metadata filter -> temporal filter (when ``now_ts`` given) -> lexical
    score -> topicality threshold gate -> freshness-weighted MMR -> top-k.
    Empty queries match nothing (never the whole corpus). Deterministic:
    same inputs yield identical hit order.
    """
    threshold = _check_threshold(threshold)
    top_k = _check_top_k(top_k)
    lam = _check_lambda(lambda_mult)
    if not isinstance(query_text, str) or not query_text.strip():
        return []
    pool = apply_metadata_filter(docs, filters)
    if now_ts is not None:
        pool = apply_temporal_filter(pool, now_ts, window_s)
    scored: list[tuple[Doc, float]] = []
    for doc in pool:
        lexical = lexical_score(query_text, doc.text)
        if lexical < threshold:
            continue
        decay = temporal_decay(doc.ts, now_ts) if now_ts is not None else 1.0
        scored.append((doc, lexical * decay))
    ordered = mmr_rank(query_text, scored, top_k=top_k, lambda_mult=lam)
    by_id = {doc.doc_id: rel for doc, rel in scored}
    return [Hit(doc_id=doc.doc_id, score=round(by_id[doc.doc_id], 4),
                source_type=doc.source_type, service=doc.service, ref=doc.ref)
            for doc in ordered]


# ---------------------------------------------------------------------------
# Evidence Pack assembly under the token budget (M12.5)
# ---------------------------------------------------------------------------

def assemble_pack(
    incident_id: str,
    tele: Mapping[str, Any],
    hits: Iterable[Hit] = (),
    max_tokens: int = PACK_TOKEN_BUDGET,
) -> dict[str, Any]:
    """Pre-digested Evidence Pack + retrieval refs within budget (M12.5).

    Reuses the M05 pre-digester (raw blobs never embedded), attaches hit
    references, then sheds lowest-relevance evidence (then lowest-score hits)
    until the pack fits ``max_tokens``. Never raises for budget pressure:
    an over-budget core is returned with ``budget_ok=False`` so the caller
    (future M13/M14) can escalate instead of crashing.
    """
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise ValueError("incident_id must be a non-empty string")
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
        raise ValueError("max_tokens must be a positive int")
    base = predigest_svc.build_evidence_pack(incident_id, dict(tele))
    # Best-first order (deterministic tie-breaks); shedding pops the tail.
    evidence_items = sorted(
        base.get("evidence", []),
        key=lambda e: (-float(e.get("relevance", 0.0)),
                       str(e.get("ref", "")), str(e.get("source_id", ""))))
    hit_dicts = [{"doc_id": h.doc_id, "score": h.score,
                  "source_type": h.source_type, "ref": h.ref}
                 for h in sorted(hits, key=lambda h: (-h.score, h.doc_id))]
    dropped_evidence = 0
    dropped_hits = 0
    pack: dict[str, Any] = dict(base)
    pack["evidence"] = list(evidence_items)
    pack["retrieval_hits"] = list(hit_dicts)
    estimate = evidence_svc.pack_size_tokens_estimate(pack)
    while estimate > max_tokens and pack["evidence"]:
        pack["evidence"].pop()
        dropped_evidence += 1
        estimate = evidence_svc.pack_size_tokens_estimate(pack)
    while estimate > max_tokens and pack["retrieval_hits"]:
        pack["retrieval_hits"].pop()
        dropped_hits += 1
        estimate = evidence_svc.pack_size_tokens_estimate(pack)
    pack["tokens_estimate"] = estimate
    pack["budget_ok"] = estimate <= max_tokens
    pack["dropped_evidence"] = dropped_evidence
    pack["dropped_hits"] = dropped_hits
    return pack


# ---------------------------------------------------------------------------
# Retrieval metrics (M12.7): pure functions over ranked id lists
# ---------------------------------------------------------------------------

def _check_k(k: int) -> int:
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise ValueError("k must be a positive int")
    return k


def precision_at_k(ranked_ids: list[str], relevant_ids: set[str] | frozenset[str],
                   k: int = TOP_K) -> float:
    """Share of the top-k that is relevant (0.0 when nothing ranked)."""
    k = _check_k(k)
    top = ranked_ids[:k]
    if not top:
        return 0.0
    return sum(1 for i in top if i in relevant_ids) / len(top)


def recall_at_k(ranked_ids: list[str], relevant_ids: set[str] | frozenset[str],
                k: int = TOP_K) -> float:
    """Share of relevant ids recovered in the top-k (0.0 when none exist)."""
    k = _check_k(k)
    if not relevant_ids:
        return 0.0
    return sum(1 for i in ranked_ids[:k] if i in relevant_ids) / len(relevant_ids)


def reciprocal_rank(ranked_ids: list[str],
                    relevant_ids: set[str] | frozenset[str]) -> float:
    """1/rank of the first relevant hit; 0.0 when unranked."""
    for rank, doc_id in enumerate(ranked_ids, start=1):
        if doc_id in relevant_ids:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(ranked_ids: list[str], relevant_ids: set[str] | frozenset[str],
              k: int = TOP_K) -> float:
    """Binary nDCG@k: DCG over ideal DCG; 0.0 when nothing relevant ranks."""
    k = _check_k(k)
    top = ranked_ids[:k]
    dcg = sum(1.0 / math.log2(rank + 2) for rank, doc_id in enumerate(top)
              if doc_id in relevant_ids)
    if dcg == 0.0:
        return 0.0
    ideal_hits = min(len(relevant_ids), len(top))
    idcg = sum(1.0 / math.log2(rank + 2) for rank in range(ideal_hits))
    return dcg / idcg


def irrelevant_ratio(ranked_ids: list[str],
                     relevant_ids: set[str] | frozenset[str]) -> float:
    """Share of ranked ids that is NOT relevant (0.0 when nothing ranked)."""
    if not ranked_ids:
        return 0.0
    return sum(1 for i in ranked_ids if i not in relevant_ids) / len(ranked_ids)


def compare_runs(baseline_ranked: list[str], optimized_ranked: list[str],
                 relevant_ids: set[str] | frozenset[str],
                 k: int = TOP_K) -> dict[str, float]:
    """Baseline-vs-optimized deltas (optimized minus baseline, M12.7).

    Positive precision/recall/MRR/nDCG deltas mean the optimized run ranks
    better; for ``d_irrelevant`` a NEGATIVE delta is the improvement (less
    junk in context). Every number derives from the two ranked lists --
    nothing is estimated or invented.
    """
    k = _check_k(k)
    return {
        "d_precision": precision_at_k(optimized_ranked, relevant_ids, k)
        - precision_at_k(baseline_ranked, relevant_ids, k),
        "d_recall": recall_at_k(optimized_ranked, relevant_ids, k)
        - recall_at_k(baseline_ranked, relevant_ids, k),
        "d_mrr": reciprocal_rank(optimized_ranked, relevant_ids)
        - reciprocal_rank(baseline_ranked, relevant_ids),
        "d_ndcg": ndcg_at_k(optimized_ranked, relevant_ids, k)
        - ndcg_at_k(baseline_ranked, relevant_ids, k),
        "d_irrelevant": irrelevant_ratio(optimized_ranked, relevant_ids)
        - irrelevant_ratio(baseline_ranked, relevant_ids),
    }
