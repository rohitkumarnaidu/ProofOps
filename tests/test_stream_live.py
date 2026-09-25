"""The audit stream is LIVE, not replay-and-close.

The stream used to send its whole backlog and return, closing the connection.
That is not a small limitation: it made the product structurally incapable of
showing an operator anything as it happened, so every visible transition was
one they had triggered by hand. The UI was not "slow", it was static by
construction.

These tests pin the live behaviour, and they test it the way it actually runs:
by holding a real connection open and emitting into it from another context,
exactly as the orchestrator will.

What is asserted:
  * the backlog is replayed, then a `replay-complete` sentinel, then the
    connection STAYS OPEN;
  * an event emitted after the replay reaches the open client;
  * keepalive comments flow while nothing happens, so a quiet stream is
    distinguishable from a dead one;
  * no duplicate and no gap across the replay/live boundary (the subscribe-
    before-replay ordering that prevents a real race);
  * ordering is by the chain's `seq`, never by comparing content hashes;
  * unsubscribing actually stops delivery (no listener leak across incidents).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.routers import audit as audit_router  # noqa: E402
from app.routers import stream as stream_router  # noqa: E402
from app.services import eventbus  # noqa: E402
from app.services import audit as audit_svc  # noqa: E402

INCIDENT = "live-stream-test"


@pytest.fixture(autouse=True)
def _clean():
    audit_router.CHAINS.pop(INCIDENT, None)
    yield
    audit_router.CHAINS.pop(INCIDENT, None)


def _chain() -> object:
    return audit_router.get_or_create_chain(INCIDENT)


async def _drain(gen, *, want: int, timeout: float = 5.0) -> list[str]:
    """Pull frames until `want` have arrived, or fail loudly."""
    out: list[str] = []
    deadline = asyncio.get_running_loop().time() + timeout
    while len(out) < want:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise AssertionError(f"only got {len(out)}/{want} frames: {out!r}")
        out.append(await asyncio.wait_for(gen.__anext__(), timeout=remaining))
    return out


async def _open_stream(incident: str, *, seed: bool = True):
    """Open a live stream past its replay phase.

    Seeds one event first so the backlog is a known 1 frame + 1 sentinel = 2.
    Counting frames by hand is how this file's first bug happened: an EMPTY
    chain yields only the sentinel, so "drain 2" would block forever waiting
    for a frame that legitimately does not exist yet.
    """
    if seed:
        _chain().emit("run.create", actor="test", result="seeded")
    gen = stream_router._live_frames(incident, None)
    frames = await _drain(gen, want=2)
    assert "data:" in frames[0]
    assert frames[1].startswith("event: replay-complete")
    return gen


def test_backlog_then_sentinel_then_the_connection_stays_open():
    """The core regression: a closed stream is a static product."""

    async def scenario():
        gen = await _open_stream(INCIDENT)
        try:
            # THE assertion. Before the fix this raised StopAsyncIteration here,
            # because the generator returned after the backlog.
            with pytest.raises((asyncio.TimeoutError, TimeoutError)):
                await asyncio.wait_for(gen.__anext__(), timeout=0.4)
        finally:
            await gen.aclose()

    asyncio.run(scenario())


def test_an_event_emitted_after_replay_reaches_the_open_client():
    async def scenario():
        gen = await _open_stream(INCIDENT)
        try:
            # Emit from outside the generator, the way the worker thread will.
            # action_id is required by the audit contract for policy.decision --
            # the contract rejecting an under-specified event is the correct
            # behaviour, not an obstacle to work around.
            _chain().emit("policy.decision", actor="control-plane",
                          action_id="act-live-1",
                          policy={"version": "v1", "rule": "r", "result": "ALLOW"},
                          result="ALLOW: allowed")
            frame = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
            assert "policy.decision" in frame
            assert "ALLOW" in frame
        finally:
            await gen.aclose()

    asyncio.run(scenario())


def test_no_duplicate_across_the_replay_live_boundary():
    """Subscribe-before-replay means overlap is possible; it must be filtered.

    The event below is emitted after the subscription is registered but before
    the backlog is read, so it legitimately arrives twice: once in the backlog
    and once live. Exactly one copy may reach the client -- a duplicate would
    make the client re-apply a transition, and a dropped one would leave it
    permanently behind with no way to notice.
    """
    async def scenario():
        gen = stream_router._live_frames(INCIDENT, None)
        try:
            _chain().emit("run.create", actor="test", result="created")
            first = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
            assert "run.create" in first
            sentinel = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
            assert sentinel.startswith("event: replay-complete")
            # A duplicate would arrive here as a live data frame.
            with pytest.raises((asyncio.TimeoutError, TimeoutError)):
                await asyncio.wait_for(gen.__anext__(), timeout=0.5)
        finally:
            await gen.aclose()

    asyncio.run(scenario())


def test_keepalive_flows_while_nothing_happens():
    """A quiet stream must be distinguishable from a dead one."""
    stream_router.KEEPALIVE_SECONDS = 0.2  # keep the test fast

    async def scenario():
        gen = await _open_stream(INCIDENT)
        try:
            frame = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
            assert frame.startswith(":"), f"expected a keepalive comment, got {frame!r}"
        finally:
            await gen.aclose()
            stream_router.KEEPALIVE_SECONDS = 15.0

    asyncio.run(scenario())


def test_live_ordering_uses_seq_not_the_hash_id():
    """Regression guard for a real bug caught while writing this.

    Event ids are content hashes. Ordering live events by comparing id strings
    would drop any event whose hash happens to sort below the previous one --
    silently, intermittently, and only under load. Ordering must use `seq`.
    """
    assert stream_router._seq_of({"seq": 7}) == 7
    assert stream_router._seq_of({"seq": "9"}) == 9
    assert stream_router._seq_of({}) == 0
    assert stream_router._seq_of({"seq": None}) == 0
    assert stream_router._seq_of({"seq": "not-a-number"}) == 0

    # Two ids whose lexicographic order is the REVERSE of their seq order.
    early = {"seq": 1, "audit_event_id": "ffff"}
    late = {"seq": 2, "audit_event_id": "0000"}
    assert early["audit_event_id"] > late["audit_event_id"]
    assert stream_router._seq_of(early) < stream_router._seq_of(late), (
        "seq must be the ordering key; id comparison inverts these two"
    )


def test_unsubscribe_stops_delivery_and_leaks_nothing():
    async def scenario():
        bus = eventbus.EventBus()
        loop = asyncio.get_running_loop()
        sub = bus.subscribe(INCIDENT, loop)
        assert bus.subscriber_count(INCIDENT) == 1
        bus.publish(INCIDENT, {"seq": 1})
        await asyncio.sleep(0)  # let the scheduled put_nowait run
        assert sub.queue.qsize() == 1

        bus.unsubscribe(sub)
        assert bus.subscriber_count(INCIDENT) == 0
        bus.publish(INCIDENT, {"seq": 2})
        await asyncio.sleep(0)
        assert sub.queue.qsize() == 1, "a removed subscriber must receive nothing more"

    asyncio.run(scenario())


def test_a_slow_subscriber_drops_oldest_and_keeps_the_newest():
    """Back-pressure policy, asserted because it is a deliberate trade.

    An unbounded queue lets one wedged reader grow the process's memory; a
    newest-drop policy would strand a reader on stale state forever. Dropping
    the oldest is correct for an audit feed, and the hash-linked chain makes
    any gap self-evident rather than silently believed.
    """
    async def scenario():
        bus = eventbus.EventBus()
        loop = asyncio.get_running_loop()
        sub = bus.subscribe(INCIDENT, loop, maxsize=3)
        for i in range(1, 8):
            bus.publish(INCIDENT, {"seq": i})
            await asyncio.sleep(0)
        assert sub.queue.qsize() == 3
        assert sub.dropped == 4
        newest = [sub.queue.get_nowait()["seq"] for _ in range(3)]
        assert newest == [5, 6, 7], f"must keep the newest, got {newest}"
        bus.unsubscribe(sub)

    asyncio.run(scenario())


def test_publish_is_safe_from_a_worker_thread():
    """The orchestrator runs the pipeline in a thread; this must not explode.

    Publishing touches an asyncio queue, so it goes through
    call_soon_threadsafe. A plain call would corrupt the loop or raise.
    """
    import threading

    async def scenario():
        bus = eventbus.EventBus()
        loop = asyncio.get_running_loop()
        sub = bus.subscribe(INCIDENT, loop)
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                for i in range(5):
                    bus.publish(INCIDENT, {"seq": i})
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        while thread.is_alive():
            await asyncio.sleep(0.01)
        thread.join()
        for _ in range(10):
            await asyncio.sleep(0.01)

        assert not errors, f"cross-thread publish raised: {errors}"
        assert sub.queue.qsize() == 5
        bus.unsubscribe(sub)

    asyncio.run(scenario())


def test_audit_emit_publishes_to_the_bus():
    """The wiring: emitting on the chain is what makes the stream live."""
    bus = eventbus.EventBus()
    original = eventbus.BUS
    eventbus.BUS = bus
    try:
        chain = audit_svc.AuditChain(incident_id=INCIDENT)
        chain.emit("run.create", actor="test", result="created")
        assert bus.subscriber_count(INCIDENT) == 0  # nobody listening
        # And with a listener attached, the event is delivered.
        async def scenario():
            sub = bus.subscribe(INCIDENT, asyncio.get_running_loop())
            chain.emit("run.create", actor="test", result="second")
            await asyncio.sleep(0.01)
            assert sub.queue.qsize() == 1
            bus.unsubscribe(sub)

        asyncio.run(scenario())
    finally:
        eventbus.BUS = original
