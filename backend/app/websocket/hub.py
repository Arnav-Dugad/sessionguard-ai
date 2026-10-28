"""In-process pub/sub for live security events.

Events are produced from synchronous request handlers running in the threadpool, so
publishing hops onto the event loop with ``call_soon_threadsafe``.
"""
from __future__ import annotations

import asyncio
import json
import threading
from typing import Any


class EventHub:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=500)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        with self._lock:
            self._subscribers.discard(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def _deliver(self, message: str) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            if q.full():
                try:
                    q.get_nowait()  # drop the oldest frame for slow consumers
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(message)

    def publish(self, kind: str, data: dict[str, Any]) -> None:
        if self._loop is None or not self._subscribers:
            return
        message = json.dumps({"type": kind, "data": data}, default=str)
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            self._deliver(message)
        else:
            self._loop.call_soon_threadsafe(self._deliver, message)


hub = EventHub()
