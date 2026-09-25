"""M21 stream router: SSE replay over the audit chain (thin translation).

Ownership: Lane 3 owns THIS ROUTER. Chain storage/verification stays M15
(``app.services.audit``); chain access stays the audit router
(``get_or_create_chain`` -- imported, never duplicated here). This router
owns ONLY: cursor filtering (``?since=`` event id), SSE framing (each frame
carries ``audit_event_id`` untouched for the ``frontend/src/sse.ts``
subscriber), and typed HTTP mapping (unknown incident 404, unknown cursor
400).

READ-only, OPEN views (deliberate, documented choice): this matches
``audit.http_view`` / ``http_verify`` / ``http_export`` and ``runs.http_get``,
which carry no key gate -- the audit chain is incident evidence, and this
endpoint cannot mutate anything (no emit/approve/execute path exists here).
Mutating handlers (``audit.http_emit``, approvals, runs advance) stay behind
the M21 API-key matrix. If the matrix later gates reads, gate this
route identically to ``audit.http_view``.

Pure functions carry all logic and are unit-tested without HTTP; the
``@router`` registration is guarded for the host starlette drift and
asserted via AST (same pattern as routers/runs.py). Exposes ``router``
(None-tolerant) so ``main.py`` inclusion stays one guarded line.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

try:  # pragma: no cover - container path (pinned deps)
    from fastapi import APIRouter as _APIRouter
    from fastapi import Header as _Header
    from fastapi import HTTPException as _HTTPException
    from fastapi.responses import StreamingResponse as _StreamingResponse
    _APIRouter(prefix="/__probe__")  # host starlette v1.x breaks construction
    router = _APIRouter(tags=["stream"])
    HTTPException = _HTTPException
    Header = _Header
    StreamingResponse = _StreamingResponse
except Exception:  # host-only drift (AGENTS.md S13.2)
    router = None  # type: ignore[assignment]

    def Header(default: object = None, **kwargs: object) -> object:  # type: ignore[no-redef]
        return default

    class HTTPException(Exception):  # type: ignore[no-redef]
        def __init__(self, status_code: int = 500, detail: str = "") -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class StreamingResponse:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("streaming unavailable on host")


class StreamMissing(Exception):
    """Unknown incident id (HTTP 404)."""


class StreamCursorUnknown(Exception):
    """Unknown ?since= event id (HTTP 400)."""


def http_status(exc: Exception) -> int:
    """Fail-closed error mapping (spec S40 typed errors)."""
    if isinstance(exc, StreamMissing):
        return 404
    if isinstance(exc, StreamCursorUnknown):
        return 400
    return 500


def to_stream_item(event: Mapping[str, Any]) -> dict[str, Any]:
    """Project one audit event dict into a stream item.

    Copies the event verbatim and surfaces its cursor as ``audit_event_id``
    (the contract field is ``event_id``; the ``frontend/src/sse.ts``
    subscriber tracks ``audit_event_id``). No data invented.
    """
    item = dict(event)
    item["audit_event_id"] = event.get("event_id", "")
    return item


def filter_after(items: Sequence[Mapping[str, Any]],
                 since: str | None) -> list[dict[str, Any]]:
    """Return items newer than the ``?since=`` cursor (fail-closed).

    ``None`` (or blank) replays the whole chain. Otherwise the cursor must
    match an ``event_id``/``audit_event_id`` in the chain; the match itself
    is excluded (only NEWER events replay). Unknown ids raise
    ``StreamCursorUnknown`` (HTTP 400) -- never silently restart.
    """
    ordered = [dict(item) for item in items]
    if since is None or (isinstance(since, str) and not since.strip()):
        return ordered
    if not isinstance(since, str):
        raise StreamCursorUnknown("since cursor must be an event id string")
    for index, item in enumerate(ordered):
        if item.get("event_id") == since \
                or item.get("audit_event_id") == since:
            return ordered[index + 1:]
    raise StreamCursorUnknown(f"unknown stream cursor: {since!r}")


def _seq_of(item: Mapping[str, Any]) -> int:
    """The chain's own ordinal for a stream item (0 when absent/unparseable).

    This is the only sound way to order live events: `audit_event_id` is a
    content hash, so its lexicographic order has nothing to do with the order
    the events were appended in.
    """
    try:
        return int(item.get("seq", 0) or 0)
    except (TypeError, ValueError):
        return 0


def format_sse(item: Mapping[str, Any]) -> str:
    """Frame one stream item as a single SSE event (pure, testable)."""
    cursor = str(item.get("audit_event_id", ""))
    data = json.dumps(dict(item), sort_keys=True, default=str)
    if cursor:
        return f"id: {cursor}\ndata: {data}\n\n"
    return f"data: {data}\n\n"


#: Named sentinel frame emitted after the last replayed event.
#:
#: This stream is replay-only: the server sends the backlog and closes. The
#: browser's EventSource reports that close through `onerror`, which is
#: indistinguishable from a genuine mid-flight network drop -- so the client
#: used to treat every SUCCESSFUL replay as a failure, flipping the
#: operating-mode badge to OFFLINE and raising a red "stream disconnected"
#: alert while the backend was perfectly healthy.
#:
#: An explicit terminator makes the normal end of a replay observable instead of
#: inferred. It is a *named* SSE event, so it does not fire the default
#: `onmessage` handler and cannot be mistaken for an audit record.
REPLAY_COMPLETE_EVENT = "replay-complete"


def format_replay_complete(delivered: int) -> str:
    """Terminal frame for one replay: the backlog is fully delivered."""
    payload = json.dumps({"delivered": delivered}, sort_keys=True)
    return f"event: {REPLAY_COMPLETE_EVENT}\ndata: {payload}\n\n"


def build_sse_body(items: Sequence[Mapping[str, Any]]) -> str:
    """Concatenate frames for one replay, terminated by the sentinel (pure)."""
    return "".join(_sse_frames(items))


def _sse_frames(items: Sequence[Mapping[str, Any]]) -> Iterator[str]:
    for item in items:
        yield format_sse(item)
    yield format_replay_complete(len(items))


def list_stream_items(incident_id: str,
                      since: str | None = None) -> list[dict[str, Any]]:
    """Replay one incident's audit chain as stream items (pure over routers).

    Reads through the audit router's ``get_or_create_chain`` (never a local
    chain copy). Unknown incidents raise ``StreamMissing`` (HTTP 404): known
    means a live chain, a persisted chain file, or an open run -- an empty
    chain for an open run replays as ``[]`` (honest empty, not 404).
    """
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise StreamMissing(f"unknown incident: {incident_id!r}")
    from app.routers import audit as audit_router
    known = incident_id in audit_router.CHAINS
    if not known:
        try:
            from app.routers import runs as runs_router
            try:
                runs_router.get_run(incident_id)
                known = True
            except Exception:
                known = False
        except Exception:
            known = False
    if not known:
        path = audit_router._chain_path(incident_id)
        if path is not None and path.is_file():
            known = True
    if not known:
        raise StreamMissing(f"unknown incident: {incident_id}")
    chain = audit_router.get_or_create_chain(incident_id)
    items = [to_stream_item(event.model_dump(mode="json"))
             for event in chain.events]
    return filter_after(items, since)


def _guarded(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except (StreamMissing, StreamCursorUnknown) as exc:
        raise HTTPException(status_code=http_status(exc),
                            detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


#: Comment frame cadence. Proxies and load balancers close an idle connection,
#: and a client cannot tell "quiet" from "dead" without a heartbeat. This is
#: well under the common 30-60s idle timeouts and keeps the connection warm.
KEEPALIVE_SECONDS = 15.0

#: Upper bound on one connection's lifetime. A browser tab left open for days
#: should not pin a task forever; the client reconnects with Last-Event-ID and
#: loses nothing, because the chain is replayable from any cursor.
MAX_CONNECTION_SECONDS = 3600.0


def _live_frames(incident_id: str, since: str | None) -> Any:
    """Replay the backlog, then hold the connection open and push live events.

    A plain function returning an async generator, NOT an `async def`: the
    StreamingResponse needs the generator itself, and awaiting a coroutine here
    would hand it a coroutine instead.

    The two halves matter and are ordered deliberately:

    1. Subscribe FIRST, then read the backlog. The reverse order has a real
       race -- an event emitted between the backlog read and the subscribe
       would be lost, and the client would never learn it missed one. Reading
       the backlog after subscribing means any overlap is de-duplicated by the
       seq check below rather than dropped.
    2. De-duplicate on the chain's `seq`, because that overlap is expected and
       harmless once filtered.
    3. Then stream, with periodic keepalive comments, until the client goes
       away or MAX_CONNECTION_SECONDS is reached.
    """
    from app.services import eventbus

    async def _generate() -> Any:
        # Inside the generator, so this runs on the event loop.
        loop = asyncio.get_running_loop()
        subscription = eventbus.BUS.subscribe(incident_id, loop)
        last_seq = 0
        try:
            # Validate existence/cursor exactly as the replay-only path did, so
            # a 404/400 still happens before any streaming begins.
            backlog = _guarded(list_stream_items, incident_id, since)
            for item in backlog:
                last_seq = max(last_seq, _seq_of(item))
                yield format_sse(item)
            yield format_replay_complete(len(backlog))

            deadline = loop.time() + MAX_CONNECTION_SECONDS
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    # Clean close; the client reconnects with its cursor.
                    return
                try:
                    raw = await asyncio.wait_for(
                        subscription.get(), timeout=min(KEEPALIVE_SECONDS, remaining))
                except (asyncio.TimeoutError, TimeoutError):
                    # Comment frame: keeps proxies and the client's own
                    # liveness check happy without inventing an event.
                    yield ": keepalive\n\n"
                    continue
                item = to_stream_item(raw)
                # Order by the chain's own `seq`, NEVER by comparing event ids.
                # Ids are content hashes: lexicographic order is unrelated to
                # emission order, so an id comparison would silently drop live
                # events whose hash happens to sort lower.
                seq = _seq_of(item)
                if seq and seq <= last_seq:
                    continue  # already delivered in the backlog
                last_seq = max(last_seq, seq)
                yield format_sse(item)
        finally:
            eventbus.BUS.unsubscribe(subscription)

    return _generate()


def http_stream(incident_id: str,
                since: str | None = None) -> Any:
    """SSE: ``GET /stream/incidents/{id}[?since=event_id]`` (live, open).

    Replays the backlog, emits a ``replay-complete`` sentinel, then HOLDS the
    connection open and pushes each new audit event as it is appended. Unknown
    incidents 404, unknown cursors 400. A client that reconnects passes its last
    seen ``audit_event_id`` and resumes with no gap and no duplicate.
    """
    return StreamingResponse(
        _live_frames(incident_id, since),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            # Tell nginx not to buffer and not to time the connection out early;
            # the long read timeout here must match the keepalive cadence.
            "Connection": "keep-alive",
        })


if router is not None:  # container path; host asserts wiring via AST
    router.get("/stream/incidents/{incident_id}")(http_stream)
