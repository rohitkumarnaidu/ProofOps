"""Persisted per-incident agent conversation threads (M19c agent surface).

Why a store at all
------------------
An agent you cannot follow a thread with is a search box. `session_id =
incident_id` is already the convention the four agents use internally
(`agents/session.py`), so the thread store follows the same key rather than
inventing a parallel notion of "conversation". The practical effect is that an
operator can ask "why did you conclude that?" and get the earlier reasoning
back, which is the whole difference between interrogating an agent and
re-prompting a black box.

Durability, deliberately simple
-------------------------------
JSON files under the resolved state dir, one per incident, written
atomically. No database, no migration, no new dependency. The state dir is
already the sanctioned place for runtime state (`app.paths`), so this inherits
the container's `api_state` volume and the `appuser` ownership that Lane B
provisioned. Adding a table here would mean a migration path for a feature
whose entire data model is a list of messages.

Bounding, because an unbounded thread is a memory leak with a timer
------------------------------------------------------------------
`MAX_TURNS` caps the retained history per incident, keeping the most recent
turns and dropping the oldest. The dropped count is reported rather than
silently swallowed, because a thread that quietly forgets is worse than one
that admits it. This is the same class of guard as the agent loop bounds in
AGENTS.md (hypotheses <= 3, replans <= 2, tools <= 5, calls <= 12) applied to
the surface a human drives.

Grounding is a property of the thread, not of the caller
--------------------------------------------------------
A stored turn keeps the evidence ids its claims cited. Replaying a thread
therefore replays the citations with it, so a claim cannot outlive the
evidence that supported it and then be quoted as though it were still
supported. Callers that re-render history get the grounding for free.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

#: Retained turns per incident thread. Generous enough for a real investigation
#: and small enough that a pathological client cannot grow the state dir.
MAX_TURNS = 40

ROLE = Literal["operator", "agent"]

_LOCK = threading.Lock()


@dataclass
class Turn:
    """One exchange in a thread.

    `citations` and `trace` are the grounding. A turn with an answer but no
    citations is a turn that asserted something without evidence, and
    `routers/agents.py` refuses to write one.
    """

    role: ROLE
    text: str
    at: float
    citations: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    proposed_action: dict[str, Any] | None = None
    reasoning_mode: str = ""
    verdict: str = ""
    dropped: int = 0

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "Turn":
        allowed = {f for f in cls.__dataclass_fields__}  # noqa: SLF001
        return cls(**{k: v for k, v in raw.items() if k in allowed})


def _thread_dir() -> Path:
    from app import paths
    return Path(paths.state_dir()) / "threads"


def _thread_path(incident_id: str) -> Path:
    # Defend the filesystem: an incident id arrives from a URL, and `..` must
    # never escape the thread directory.
    safe = "".join(ch for ch in str(incident_id)
                   if ch.isalnum() or ch in "-_.")[:128]
    if not safe or safe in (".", ".."):
        safe = "unknown"
    return _thread_dir() / f"{safe}.json"


def read_thread(incident_id: str) -> list[Turn]:
    """Retained turns, oldest first. A missing or corrupt thread reads empty."""
    path = _thread_path(incident_id)
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A truncated thread must not take the agent surface down with it. The
        # operator loses history, not availability.
        return []
    turns = raw.get("turns") if isinstance(raw, dict) else None
    if not isinstance(turns, list):
        return []
    out: list[Turn] = []
    for item in turns:
        if isinstance(item, dict):
            try:
                out.append(Turn.from_json(item))
            except TypeError:
                continue
    return out


def append_turn(incident_id: str, turn: Turn) -> int:
    """Append one turn, trim to MAX_TURNS, persist atomically. Returns dropped.

    Atomic because a half-written thread is exactly the corruption `read_thread`
    has to recover from, and it is much cheaper not to create it.
    """
    with _LOCK:
        turns = read_thread(incident_id)
        turns.append(turn)
        dropped = 0
        if len(turns) > MAX_TURNS:
            dropped = len(turns) - MAX_TURNS
            turns = turns[-MAX_TURNS:]
        directory = _thread_dir()
        directory.mkdir(parents=True, exist_ok=True)
        path = _thread_path(incident_id)
        payload = {
            "incident_id": str(incident_id),
            "session_id": str(incident_id),
            "updated_at": time.time(),
            "max_turns": MAX_TURNS,
            "dropped": dropped,
            "turns": [t.to_json() for t in turns],
        }
        handle, temp_name = tempfile.mkstemp(
            dir=str(directory), prefix=".thread-", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, default=str)
            os.replace(temp_name, path)
        except Exception:
            # Never leave a temp file behind on failure.
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
    return dropped


def clear_thread(incident_id: str) -> bool:
    path = _thread_path(incident_id)
    with _LOCK:
        if not path.is_file():
            return False
        try:
            path.unlink()
            return True
        except OSError:
            return False


def thread_summary(incident_id: str) -> dict[str, Any]:
    """Cheap shape for a list view: counts and the latest turn, not the lot."""
    turns = read_thread(incident_id)
    latest = turns[-1] if turns else None
    return {
        "incident_id": str(incident_id),
        "session_id": str(incident_id),
        "turns": len(turns),
        "max_turns": MAX_TURNS,
        "last_at": latest.at if latest else None,
        "last_verdict": latest.verdict if latest else "",
        "last_reasoning_mode": latest.reasoning_mode if latest else "",
    }
