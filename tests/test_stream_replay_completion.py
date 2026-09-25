"""A completed replay is not a stream failure.

Found by browser QA, not by review. On every incident view the UI showed a red
"Event stream update failed: incident event stream disconnected" and flipped the
live-region state to `offline` -- while the backend was healthy, in MOCK mode,
having just delivered its full audit backlog correctly.

Cause: the stream is replay-only. The server sends the backlog and closes, and
the browser's EventSource reports that close through `onerror`, which is
byte-for-byte indistinguishable from a genuine mid-flight drop. The client's
onerror handler therefore reported failure on every *successful* replay.

This is a truthfulness defect in the direction that matters for this project:
the UI overstated a failure. The fix is a named `replay-complete` sentinel from
the server (backend/app/routers/stream.py) that makes normal termination
observable instead of inferred. These tests pin both halves of that contract so
the sentinel cannot be dropped on one side without the other going deaf.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.routers import stream as stream_router  # noqa: E402

SSE_TS = ROOT / "frontend" / "src" / "sse.ts"


def _source() -> str:
    return SSE_TS.read_text(encoding="utf-8")


def _strip_comments(source: str) -> str:
    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(source):
        ch = source[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(source):
                out.append(source[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(source) and source[i + 1] == "/":
            while i < len(source) and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < len(source) and source[i + 1] == "*":
            end = source.find("*/", i + 2)
            i = len(source) if end == -1 else end + 2
            out.append("\n")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------

def test_server_emits_a_named_replay_complete_sentinel():
    assert stream_router.REPLAY_COMPLETE_EVENT == "replay-complete"
    frame = stream_router.format_replay_complete(1)
    # Named, so the browser routes it to a dedicated listener instead of the
    # default onmessage handler that parses audit records.
    assert frame.split("\n", 1)[0] == "event: replay-complete"


def test_every_replay_terminates_explicitly_even_when_empty():
    for items in ([], [{"audit_event_id": "ev-1"}]):
        body = stream_router.build_sse_body(items)
        assert body.count("event: replay-complete") == 1, (
            "every replay must end with the sentinel so the client can tell "
            "completion from failure"
        )


# ---------------------------------------------------------------------------
# Client side
# ---------------------------------------------------------------------------

def test_client_sentinel_name_matches_the_server():
    """A typo here silently reintroduces the false-failure bug."""
    source = _source()
    match = re.search(r'const REPLAY_COMPLETE_EVENT\s*=\s*"([^"]+)"', source)
    assert match is not None, "the client must declare REPLAY_COMPLETE_EVENT"
    assert match.group(1) == stream_router.REPLAY_COMPLETE_EVENT, (
        f"client sentinel {match.group(1)!r} does not match server "
        f"{stream_router.REPLAY_COMPLETE_EVENT!r}; the client would never see it"
    )


def test_client_listens_for_the_sentinel_on_the_eventsource():
    source = _strip_comments(_source())
    assert "addEventListener(REPLAY_COMPLETE_EVENT" in source, (
        "the client must subscribe to the sentinel; a named SSE event does not "
        "reach onmessage, so this listener is the only way to observe it"
    )
    assert "replayCompleted = true" in source


def test_replay_state_exists_and_is_distinct_from_offline():
    source = _strip_comments(_source())
    states = re.search(r"export type StreamConnectionState =(.*?);", source, re.DOTALL)
    assert states is not None
    literals = set(re.findall(r'"([a-z]+)"', states.group(1)))
    assert "replay" in literals, (
        "a completed replay needs its own state so the UI can say so, rather "
        "than reusing 'offline' (a lie) or 'stream' (no longer true)"
    )
    assert "offline" in literals


def test_normal_termination_does_not_raise_an_error_or_report_offline():
    """The core invariant, asserted on the branch itself.

    `replayCompleted` must gate BOTH the error report and the OFFLINE mode
    switch. Gating only one leaves the UI still claiming an outage (or still
    silencing a real one).
    """
    source = _strip_comments(_source())
    idx = source.index("source.onerror")
    branch = source[idx : idx + 1400]
    guard = branch.index("if (replayCompleted)")
    # Everything the normal path must NOT do lives before it.
    early = branch[:guard]
    assert 'handlers.onError?.(new Error("incident event stream disconnected"))' not in early, (
        "the disconnect error must be raised only after the replayCompleted "
        "check, or a completed replay is reported as a failure"
    )
    assert 'handlers.onMode("OFFLINE")' not in early, (
        "OFFLINE must not be reported before the replayCompleted check; a "
        "backend that just answered is not offline"
    )
    # And the normal path must not fabricate an error of its own. The branch
    # ends at its `return`, so slice to that rather than by a fixed width --
    # a fixed window silently reaches into the failure path and makes this
    # assertion look like it fails when the code is correct.
    guard = branch.index("if (replayCompleted)")
    end = branch.index("return;", guard)
    normal = branch[guard:end]
    assert "onError" not in normal, (
        "the completed-replay path must not raise any error"
    )
    assert 'onMode("OFFLINE")' not in normal, (
        "the completed-replay path must not claim the backend went offline"
    )
    # It still keeps the fallback machinery, because new events can appear
    # after the replay window closes.
    assert "startPolling()" in normal
    assert "scheduleReconnect(" in normal


def test_a_genuine_drop_is_still_reported():
    """Over-correcting into silence would be its own dishonesty.

    A stream that never delivered a sentinel did fail, and the UI must still
    say so rather than quietly showing a stale state.
    """
    source = _strip_comments(_source())
    assert 'handlers.onError?.(new Error("incident event stream disconnected"))' in source
    assert 'handlers.onState?.("offline")' in source
