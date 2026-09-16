"""M13.10 memory: bounded working memory + honest Cognis interface.

Modes: LOCAL (deterministic in-memory facts, this module -- the only mode
that exists today) vs FUTURE Cognis/Global-Context (not wired; reported as
such, never faked). Incident FACT store is capped (50, oldest dropped);
recall() ranks by the M12 lexical score (deterministic, no embeddings).
GLOBAL_CONTEXT compliance text is injected into every agent prompt.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents.schemas import MEMORY_FACTS_CAP  # noqa: E402 (M13.6 budgets)
from app.services.retrieval import lexical_score  # noqa: E402 (M12 scoring)

GLOBAL_CONTEXT = ("PS03 governed operations: evidence-first; policy decides; "
                  "verify everything; no claim without proof.")

MAX_FACT_CHARS = 1024


@dataclass
class Fact:
    text: str
    source: str


@dataclass
class WorkingMemory:
    incident_id: str
    facts: list[Fact] = field(default_factory=list)

    def add(self, text: str, source: str) -> None:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("fact text must be a non-empty string")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("fact source must be a non-empty string")
        if len(text) > MAX_FACT_CHARS:
            raise ValueError(f"fact text exceeds {MAX_FACT_CHARS} chars")
        self.facts.append(Fact(text=text, source=source))
        while len(self.facts) > MEMORY_FACTS_CAP:
            self.facts.pop(0)

    def recall(self, query: str, k: int = 5) -> list[Fact]:
        """Top-k facts by lexical score (0-score facts excluded)."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be a non-empty string")
        if not isinstance(k, int) or isinstance(k, bool) or k < 1:
            raise ValueError("k must be a positive int")
        scored = [(fact, lexical_score(query, fact.text)) for fact in self.facts]
        scored = [(f, s) for f, s in scored if s > 0.0]
        scored.sort(key=lambda pair: (-pair[1], pair[0].text))
        return [fact for fact, _ in scored[:k]]


class CognisInterface:
    """Memory facade: LOCAL working memory today, Cognis when wired (M13.10)."""

    def __init__(self, incident_id: str) -> None:
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("incident_id must be a non-empty string")
        self.memory = WorkingMemory(incident_id=incident_id)

    @property
    def mode(self) -> str:
        return "local"

    def attach(self) -> dict[str, Any]:
        return {"cognis": self.mode, "global_context": True,
                "facts": len(self.memory.facts),
                "cap": MEMORY_FACTS_CAP}

    def recall(self, query: str, k: int = 5) -> list[Fact]:
        return self.memory.recall(query, k)
