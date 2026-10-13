# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""In-process fan-out of live-sync notifications to SSE streams (docs/sync.md).

Publishers are request handlers running in the thread pool; subscribers are async generators on
the event loop. `publish` is thread-safe: it hands each event to the subscriber's loop with
`call_soon_threadsafe`. Events are notifications only (a version number, never data), so a full
queue simply drops one: the stream's periodic database re-check catches up.
"""

import asyncio
import contextlib
import json
import logging
import threading
from dataclasses import dataclass, field

log = logging.getLogger(__name__)
QUEUE_SIZE = 64


@dataclass(frozen=True)
class Event:
    name: str
    data: dict[str, object]
    event_id: str | None = None

    def encode(self) -> str:
        lines = [f"event: {self.name}"]
        if self.event_id is not None:
            lines.append(f"id: {self.event_id}")
        lines.append("data: " + json.dumps(self.data, separators=(",", ":")))
        return "\n".join(lines) + "\n\n"


@dataclass(eq=False)
class Subscription:
    account_id: str
    device_id: str
    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue[Event] = field(default_factory=lambda: asyncio.Queue(QUEUE_SIZE))


def _put(queue: asyncio.Queue[Event], event: Event) -> None:
    with contextlib.suppress(asyncio.QueueFull):
        queue.put_nowait(event)


class Broker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: set[Subscription] = set()

    def subscribe(self, account_id: str, device_id: str) -> Subscription:
        sub = Subscription(account_id, device_id, asyncio.get_running_loop())
        with self._lock:
            self._subs.add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            self._subs.discard(sub)

    def count(self, device_id: str | None = None) -> int:
        with self._lock:
            if device_id is None:
                return len(self._subs)
            return sum(1 for s in self._subs if s.device_id == device_id)

    def publish(self, account_id: str, event: Event, device_id: str | None = None) -> None:
        """To every stream of the account, or only to `device_id`'s streams."""
        with self._lock:
            targets = [
                s
                for s in self._subs
                if s.account_id == account_id and (device_id is None or s.device_id == device_id)
            ]
        for sub in targets:
            try:
                sub.loop.call_soon_threadsafe(_put, sub.queue, event)
            except RuntimeError:
                # The loop is closed: the stream is gone and will unsubscribe itself.
                log.debug("dropped an event for a closed stream")
