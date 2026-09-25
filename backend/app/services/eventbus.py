"""Live audit event fan-out (M19b real-time path).

Why this exists
---------------
The product's whole thesis is that the hash-chained audit log is the proof of
what the control plane did. Until now the only way to read that proof was to
open a stream, receive the entire backlog, and watch the connection close --
so the UI was structurally incapable of showing anything *as it happened*, and
an operator watching an incident saw a frozen page. Every visible transition
was one they had triggered by hand.

This module is the missing half: a thread-safe broker between the audit chain
(the single source of truth) and any number of live subscribers.

Threading, which is the whole difficulty
----------------------------------------
Producers and consumers run on different threads, deliberately:

* the HTTP layer and the SSE handlers live on the asyncio event loop;
* the orchestrator runs the pipeline in a worker thread (via
  `asyncio.to_thread`) precisely so a slow or blocking pipeline cannot stall
  every other request in the process.

So `publish` is called from a worker thread while the subscriber queues belong
to the loop. Every push therefore goes through `loop.call_soon_threadsafe`,
which is the only safe way to touch an asyncio primitive from another thread.
Publishing from the loop thread itself is equally fine -- the call is simply a
no-throw schedule.

Back-pressure, because an unbounded queue is a slowloris
--------------------------------------------------------
A subscriber that stops reading must not be able to grow the server's memory
without limit, and it must not be allowed to stall the producer. Each
subscription owns a bounded queue and drops its OLDEST unread item on overflow.
Dropping the oldest is the right trade for an audit feed: the newest state is
what an operator needs, and any gap is detectable because the chain is
hash-linked -- the client's cursor simply will not match and it re-replays.
Dropping the newest instead would strand a reader on stale state forever.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from typing import Any, Iterator

#: Per-subscriber backlog. Deep enough to absorb a burst of transitions
#: between polls, shallow enough that a wedged reader cannot hoard memory.
DEFAULT_QUEUE_SIZE = 256


@dataclass
class Subscription:
    """One live reader of one incident's audit chain."""

    incident_id: str
    loop: asyncio.AbstractEventLoop
    maxsize: int = DEFAULT_QUEUE_SIZE
    queue: asyncio.Queue = field(init=False)

    def __post_init__(self) -> None:
        self.queue = asyncio.Queue(maxsize=self.maxsize)

    @property
    def dropped(self) -> int:
        """How many items were discarded because this reader fell behind."""
        return self._dropped

    _dropped: int = 0

    def offer(self, payload: Any) -> None:
        """Enqueue from ANY thread. Never blocks, never raises.

        `call_soon_threadsafe` raises only if the loop is closed, which happens
        during shutdown; a subscriber going away mid-publish is normal and must
        not take the producer down with it.
        """
        try:
            self.loop.call_soon_threadsafe(self._put, payload)
        except RuntimeError:
            # Loop closed (shutdown). The reader is gone; nothing to do.
            return

    def _put(self, payload: Any) -> None:
        try:
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            # Drop the OLDEST so the newest state always survives. The chain is
            # hash-linked, so a gap is self-evident to the client rather than
            # silently believed.
            try:
                self.queue.get_nowait()
                self._dropped += 1
                self.queue.put_nowait(payload)
            except (asyncio.QueueEmpty, asyncio.QueueFull):  # pragma: no cover
                self._dropped += 1

    async def get(self) -> Any:
        return await self.queue.get()


class EventBus:
    """Process-wide fan-out from audit chains to live subscribers."""

    def __init__(self) -> None:
        # A plain dict guarded by a lock: subscribe/publish are rare and cheap,
        # and this keeps the hot path (offer) free of async locking.
        self._subs: dict[str, list[Subscription]] = {}
        self._lock = threading.Lock()

    def subscribe(
        self,
        incident_id: str,
        loop: asyncio.AbstractEventLoop,
        maxsize: int = DEFAULT_QUEUE_SIZE,
    ) -> Subscription:
        sub = Subscription(incident_id=incident_id, loop=loop, maxsize=maxsize)
        with self._lock:
            self._subs.setdefault(incident_id, []).append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            bucket = self._subs.get(sub.incident_id)
            if not bucket:
                return
            try:
                bucket.remove(sub)
            except ValueError:
                return
            if not bucket:
                self._subs.pop(sub.incident_id, None)

    def publish(self, incident_id: str, payload: Any) -> int:
        """Fan out one event. Returns the number of subscribers reached.

        Safe from any thread, and a no-op when nobody is listening -- which is
        the normal case for tests and for headless API use.
        """
        with self._lock:
            targets = list(self._subs.get(incident_id, ()))
        for sub in targets:
            sub.offer(payload)
        return len(targets)

    def subscriber_count(self, incident_id: str | None = None) -> int:
        with self._lock:
            if incident_id is None:
                return sum(len(v) for v in self._subs.values())
            return len(self._subs.get(incident_id, ()))

    def incidents_with_subscribers(self) -> Iterator[str]:
        with self._lock:
            return iter(tuple(self._subs))


#: Module-level singleton. Deliberately a singleton: audit chains are created
#: in many places (HTTP layer, pipeline, scripts) and they all have to reach the
#: same subscribers without threading a bus through every constructor.
BUS = EventBus()


def publish(incident_id: str, payload: Any) -> int:
    return BUS.publish(incident_id, payload)
