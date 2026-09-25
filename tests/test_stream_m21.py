"""M21 stream router: SSE replay over the audit chain (host-safe).

The crippled host cannot run starlette TestClient, so the replay contract
is tested at the pure layer (framing, cursor filtering, 404/400 paths);
FastAPI wiring is asserted structurally (AST over stream.py).
"""
import ast
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.routers import audit as audit_router  # noqa: E402 (M15 chain)
from app.routers import runs as runs_router  # noqa: E402 (M14b runs)
from app.routers import stream as stream_router  # noqa: E402 (M21 stream)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clean():
    audit_router.reset_demo_state()
    runs_router.reset_demo_state()
    yield
    audit_router.reset_demo_state()
    runs_router.reset_demo_state()


def _emit(incident, event_type="transition", **over):
    chain = audit_router.get_or_create_chain(incident)
    kwargs = {"actor": "test", "result": "NEW->TRIAGING"}
    kwargs.update(over)
    return chain.emit(event_type, **kwargs)


# ---------------------------------------------------------------------------
# Pure framing
# ---------------------------------------------------------------------------

def test_to_stream_item_carries_audit_event_id():
    item = stream_router.to_stream_item({"event_id": "ev-1", "seq": 1})
    assert item["audit_event_id"] == "ev-1"
    assert item["event_id"] == "ev-1" and item["seq"] == 1


def test_format_sse_frame_shape():
    item = {"event_id": "ev-1", "audit_event_id": "ev-1", "seq": 1}
    frame = stream_router.format_sse(item)
    assert frame.startswith("id: ev-1\ndata: ")
    assert frame.endswith("\n\n")
    payload = json.loads(frame.split("data: ", 1)[1])
    assert payload["audit_event_id"] == "ev-1"


def test_build_sse_body_concatenates_frames_then_terminates():
    """The body is the event frames followed by the completion sentinel.

    The sentinel is load-bearing, not decoration. This stream is replay-only:
    the server sends the backlog and closes, and EventSource reports that close
    via onerror -- indistinguishable from a real network drop. Without an
    explicit terminator the client cannot tell a successful replay from a
    failure, and the UI duly reported every healthy replay as a disconnect.
    """
    items = [{"audit_event_id": f"ev-{i}", "seq": i} for i in range(2)]
    body = stream_router.build_sse_body(items)
    assert "id: ev-0" in body and "id: ev-1" in body
    # Two audit frames plus exactly one terminator.
    assert body.count(f"event: {stream_router.REPLAY_COMPLETE_EVENT}") == 1
    assert body.count("data: ") == 3
    assert body.endswith("\n\n")


def test_replay_complete_sentinel_reports_the_delivered_count():
    frame = stream_router.format_replay_complete(3)
    assert frame.startswith(f"event: {stream_router.REPLAY_COMPLETE_EVENT}\n")
    assert frame.endswith("\n\n")
    payload = json.loads(frame.split("data: ", 1)[1])
    assert payload == {"delivered": 3}


def test_replay_complete_sentinel_is_terminally_named():
    """It must be a NAMED event.

    A named SSE event does not fire the default `onmessage` handler. If this
    were an unnamed `data:` frame the client would parse it as an audit record
    and it would appear in the audit chain UI as a phantom event.
    """
    frame = stream_router.format_replay_complete(0)
    assert not frame.startswith("data:")
    assert "event:" in frame.split("\n", 1)[0]
    # An empty replay still terminates explicitly rather than closing silently.
    assert stream_router.build_sse_body([]).count(
        f"event: {stream_router.REPLAY_COMPLETE_EVENT}"
    ) == 1


def test_audit_frames_are_unchanged_by_the_sentinel():
    """The sentinel must not alter the shape of a real audit frame."""
    item = {"event_id": "ev-1", "audit_event_id": "ev-1", "seq": 1}
    frame = stream_router.format_sse(item)
    assert frame.startswith("id: ev-1\ndata: ")
    assert "event:" not in frame.split("\n", 1)[0]


# ---------------------------------------------------------------------------
# Cursor filtering
# ---------------------------------------------------------------------------

def _items(*ids):
    return [{"event_id": i, "audit_event_id": i} for i in ids]


def test_filter_after_none_replays_all():
    assert stream_router.filter_after(_items("a", "b"), None) \
        == _items("a", "b")
    assert stream_router.filter_after(_items("a", "b"), "  ") \
        == _items("a", "b")


def test_filter_after_returns_only_newer():
    assert stream_router.filter_after(_items("a", "b", "c"), "a") \
        == _items("b", "c")
    assert stream_router.filter_after(_items("a", "b"), "b") == []


def test_filter_after_unknown_cursor_400():
    with pytest.raises(stream_router.StreamCursorUnknown):
        stream_router.filter_after(_items("a"), "nope")
    assert stream_router.http_status(
        stream_router.StreamCursorUnknown("x")) == 400


# ---------------------------------------------------------------------------
# Replay paths (404 / 400 / replay)
# ---------------------------------------------------------------------------

def test_unknown_incident_404():
    with pytest.raises(stream_router.StreamMissing):
        stream_router.list_stream_items("inc-stream-nope-xyz")
    assert stream_router.http_status(
        stream_router.StreamMissing("x")) == 404
    assert stream_router.http_status(Exception("x")) == 500


def test_replay_open_run_empty_then_events():
    runs_router.create_run("inc-stream-1", now=1700000000.0)
    assert stream_router.list_stream_items("inc-stream-1") == []
    first = _emit("inc-stream-1")
    second = _emit("inc-stream-1", result="TRIAGING->CORRELATED")
    items = stream_router.list_stream_items("inc-stream-1")
    assert [i["audit_event_id"] for i in items] \
        == [first.event_id, second.event_id]
    tail = stream_router.list_stream_items("inc-stream-1",
                                           since=first.event_id)
    assert [i["audit_event_id"] for i in tail] == [second.event_id]
    with pytest.raises(stream_router.StreamCursorUnknown):
        stream_router.list_stream_items("inc-stream-1", since="bogus")


def test_chain_without_run_still_replays():
    event = _emit("inc-stream-2")
    items = stream_router.list_stream_items("inc-stream-2")
    assert [i["audit_event_id"] for i in items] == [event.event_id]


# ---------------------------------------------------------------------------
# Wiring pins (structural, host-safe)
# ---------------------------------------------------------------------------

def test_stream_router_contract():
    src = (ROOT / "backend" / "app" / "routers" / "stream.py").read_text(
        encoding="utf-8")
    tree = ast.parse(src)
    # None-tolerant router exposure (main.py includes it with one guarded
    # line, owned by another lane): FastAPI import probe + router=None.
    assert "router = None" in src
    assert "get_or_create_chain" in src  # import, never a local chain copy
    assert "text/event-stream" in src
    assert "/stream/incidents/{incident_id}" in src
    assert "since" in src
    # READ-only OPEN views by documented choice (matches audit.http_view):
    # no key gate on this route.
    assert "guard_http" not in src and "X-API-Key" not in src
    gets = [n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and getattr(n.func, "attr", "") == "get"]
    assert any("/stream/incidents/{incident_id}" in ast.dump(n)
               for n in gets), "stream.py must register the SSE GET route"
