"""M13.9 KB links: runbooks-v* + history collections over M12 retrieval.

The Studio-side Knowledge Base attachment is asserted live (verify_lyzr
KB_TEST: runbooks-v* attached). Here the collection NAMES and the
threshold/top-k contract are pinned so agent queries behave identically
against the local deterministic index: same threshold (0.7), same top-k (5),
same corpus builders. Agents never invent runbooks; they SELECT from hits.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app import paths  # noqa: E402
from app.services.retrieval import (  # noqa: E402 (M12 retrieval)
    TOP_K,
    Doc,
    Hit,
    SCORE_THRESHOLD,
    index_history,
    index_runbooks,
    retrieve,
)
from app.services.runbooks import load_runbook  # noqa: E402 (M11 loader)

KB_COLLECTIONS = {"runbooks": "runbooks-v*", "history": "history"}

DEFAULT_SEEDS = ["bad-deploy-rollback", "crashloop-oom", "db-pool-saturation",
                 "net-dep-failover", "injection-quarantine"]


def collections() -> dict[str, str]:
    """Pinned collection names agents may query (M13.9)."""
    return dict(KB_COLLECTIONS)


def build_index(runbook_ids: Iterable[str] | None = None,
                history_items: Iterable[Mapping[str, Any]] = ()) -> list[Doc]:
    """Index pinned runbooks (+ optional history) for agent queries."""
    ids = list(DEFAULT_SEEDS if runbook_ids is None else runbook_ids)
    if not ids:
        raise ValueError("runbook_ids must be non-empty")
    docs = index_runbooks([
        load_runbook(runbook_id, directory=paths.runbooks_dir())
        for runbook_id in ids
    ])
    docs.extend(index_history(history_items))
    return docs


def kb_query(query_text: str, index: list[Doc], *,
             service: str | None = None, env: str | None = None,
             threshold: float = SCORE_THRESHOLD,
             top_k: int = TOP_K) -> list[Hit]:
    """Threshold-gated, top-k retrieval over the agent KB index (M13.9)."""
    if not isinstance(query_text, str) or not query_text.strip():
        raise ValueError("query_text must be a non-empty string")
    filters: dict[str, str] = {}
    if service is not None:
        filters["service"] = service
    if env is not None:
        filters["env"] = env
    return retrieve(query_text, index, filters=filters or None,
                      threshold=threshold, top_k=top_k)
