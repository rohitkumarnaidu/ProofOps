"""M13.7 sessions: session_id = incident_id binding, bounded window, resume.

Local deterministic store (memory, optional JSON file). The 10-message
window compacts extractively -- oldest messages collapse into a counted
marker, never an LLM summary (no invented content). LLM-call budgets
(<=12/incident) are enforced here: record_call() raises BudgetExceeded
instead of allowing an unbounded agent loop. Live Lyzr sessions ride along
via the client's session_id passthrough; this store is the accountable copy.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents import AGENTS  # noqa: E402 (M13 workforce map)
from agents.schemas import (  # noqa: E402 (M13.6 budgets)
    MAX_LLM_CALLS_PER_INCIDENT,
    SESSION_WINDOW,
    BudgetExceeded,
)

Role = Literal["system", "user", "assistant"]
MAX_CONTENT_CHARS = 12000


@dataclass
class SessionMessage:
    role: str
    content: str


@dataclass
class Session:
    incident_id: str
    agent: str
    messages: list[SessionMessage] = field(default_factory=list)
    llm_calls: int = 0
    compacted: int = 0
    compacted_head: str = ""

    @property
    def session_id(self) -> str:
        """Binding rule (spec): session_id IS the incident_id."""
        return self.incident_id

    def record_call(self) -> int:
        if self.llm_calls >= MAX_LLM_CALLS_PER_INCIDENT:
            raise BudgetExceeded(
                f"LLM call budget exhausted ({MAX_LLM_CALLS_PER_INCIDENT}/incident)")
        self.llm_calls += 1
        return self.llm_calls

    def append(self, role: str, content: str) -> None:
        if role not in ("system", "user", "assistant"):
            raise ValueError(f"unknown role: {role!r}")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("content must be a non-empty string")
        if len(content) > MAX_CONTENT_CHARS:
            raise ValueError(f"content exceeds {MAX_CONTENT_CHARS} chars")
        self.messages.append(SessionMessage(role=role, content=content))
        self._enforce_window()

    @staticmethod
    def _is_marker(message: SessionMessage) -> bool:
        return (message.role == "system"
                and message.content.startswith("[compacted "))

    def _real_count(self) -> int:
        return sum(1 for m in self.messages if not self._is_marker(m))

    def _enforce_window(self) -> None:
        """Collapse oldest substantive messages into a counted marker.

        The marker is metadata OUTSIDE the window: the model always sees the
        latest SESSION_WINDOW substantive messages plus one compaction
        notice. No LLM summarization -- collapsed content is counted, and
        only the oldest snippet is retained as an anchor.
        """
        while self._real_count() > SESSION_WINDOW:
            idx = next(i for i, m in enumerate(self.messages)
                       if not self._is_marker(m))
            oldest = self.messages.pop(idx)
            self.compacted += 1
            if not self.compacted_head:
                self.compacted_head = oldest.content[:40]
            marker = SessionMessage(
                role="system",
                content=(f"[compacted {self.compacted} earlier message(s); "
                         f"oldest: {self.compacted_head}]"))
            if self.messages and self._is_marker(self.messages[0]):
                self.messages[0] = marker
            else:
                self.messages.insert(0, marker)


class SessionStore:
    """Per-incident sessions with JSON resume (fail-closed on corruption)."""

    def __init__(self) -> None:
        self._sessions: dict[tuple[str, str], Session] = {}

    def get_or_create(self, incident_id: str, agent: str) -> Session:
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("incident_id must be a non-empty string")
        if agent not in AGENTS:
            raise ValueError(f"unknown agent: {agent!r}")
        key = (incident_id, agent)
        if key not in self._sessions:
            self._sessions[key] = Session(incident_id=incident_id, agent=agent)
        return self._sessions[key]

    def get(self, incident_id: str, agent: str) -> Session | None:
        return self._sessions.get((incident_id, agent))

    def reset(self) -> None:
        self._sessions.clear()

    def save_json(self, path: str | Path) -> Path:
        out = Path(path)
        blob = {"sessions": [
            {"incident_id": s.incident_id, "agent": s.agent,
             "messages": [{"role": m.role, "content": m.content}
                          for m in s.messages],
             "llm_calls": s.llm_calls, "compacted": s.compacted,
             "compacted_head": s.compacted_head}
            for s in self._sessions.values()]}
        out.write_text(json.dumps(blob, indent=2), encoding="utf-8")
        return out

    def load_json(self, path: str | Path) -> int:
        try:
            blob = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"session file unreadable: {exc}") from exc
        if not isinstance(blob, dict) or not isinstance(blob.get("sessions"), list):
            raise ValueError("session file must hold {sessions: [...]}")
        count = 0
        for item in blob["sessions"]:
            try:
                incident_id = item["incident_id"]
                agent = item["agent"]
                messages = item.get("messages", [])
                llm_calls = int(item.get("llm_calls", 0))
                compacted = int(item.get("compacted", 0))
                compacted_head = str(item.get("compacted_head", ""))
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"malformed session entry: {exc}") from exc
            session = self.get_or_create(incident_id, agent)
            session.messages = [SessionMessage(role=m["role"], content=m["content"])
                                for m in messages]
            if any(m.role not in ("system", "user", "assistant") for m in session.messages):
                raise ValueError("malformed session entry: bad role")
            if llm_calls < 0 or compacted < 0:
                raise ValueError("malformed session entry: negative counter")
            session.llm_calls = llm_calls
            session.compacted = compacted
            session.compacted_head = compacted_head
            count += 1
        return count

    def to_plain(self) -> dict[str, Any]:
        return {f"{i}/{a}": {"messages": len(s.messages),
                             "llm_calls": s.llm_calls,
                             "compacted": s.compacted}
                for (i, a), s in self._sessions.items()}
