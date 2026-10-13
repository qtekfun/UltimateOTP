# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Temporary blocking of clients that keep failing, with a growing back-off (docs/deploy.md §6).

On top of the per-route token buckets and the per-account SRP lockout, every failed or abusive
attempt is counted per anonymized client across all routes: wrong SRP proofs, wrong email codes,
unknown-account probes, signature failures, locked-account hits, refused heads and rate-limit
hits. `block_threshold` of them within `block_window_s` block the client for the first length of
`block_durations_s` (15 min), the next block for the second (1 h), then the last (24 h). A client
that stays quiet for `block_decay_s` after its block ended starts again at the first length.
A successful login does not erase a block or a count: a guesser that finds the password is not
rewarded, and a block is not a thing the blocked party can lift.

Counts live in memory. Blocks are mirrored to the `client_blocks` table when `block_persist` is on,
so a restart does not wipe a 24 h block, and the admin CLI can list and clear them (the api
re-reads the table every few seconds while it holds a block). The LAN of the owner is exempt.
State is keyed by the anonymized client id of the UTC day; a block or a level carries over
midnight through the previous day's id (see anon.py), nothing older is linked.

`BlockGuard` answers 429 `client_blocked` for blocked clients before routing.
"""

import logging
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Receive, Scope, Send

from ultimateotp import errors
from ultimateotp.anon import SCOPE_KEY, ClientContext
from ultimateotp.clock import Clock
from ultimateotp.db import Database
from ultimateotp.metrics import Metrics
from ultimateotp.settings import Settings

# Security events that count as a failed or abusive attempt (each weighs one).
ABUSE_EVENTS = frozenset(
    {
        "auth.failure",  # unknown device, bad signature, replay, bad token
        "ratelimit.hit",
        "srp.failure",  # wrong proof, expired or unknown handshake
        "srp.locked",  # knocking on a locked account
        "email.code_failure",
        "login.unknown_account",
        "vault.head_rejected",
        "enroll.denied_network",
    }
)
RESYNC_EVERY_S = 5
MAX_STATES = 50_000
SWEEP_EVERY = 512
API_PREFIX = "/otp/v1"


@dataclass
class _State:
    failures: int = 0
    window_start: int = 0
    level: int = 0
    blocked_until: int = 0
    last_event: int = 0
    reason: str = ""


@dataclass
class BlockInfo:
    client_id: str
    level: int
    blocked_until: int
    last_event_at: int
    reason: str
    remaining_s: int = 0


@dataclass
class Blocker:
    settings: Settings
    clock: Clock
    metrics: Metrics
    db: Database | None = None
    # Called as emit(event_name, **fields): the service's security-event writer.
    emit: Callable[..., None] | None = None
    notify: Callable[[str, str], None] | None = None
    _states: dict[str, _State] = field(default_factory=dict)
    _blocked: set[str] = field(default_factory=set)
    _dirty: dict[str, tuple[int, int, int, str]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _calls: int = 0
    _last_resync: float = 0.0

    def __post_init__(self) -> None:
        self.metrics.gauge("uotp_blocked_clients", self._blocked_count)
        if self._persist:
            self._load()

    @property
    def enabled(self) -> bool:
        return self.settings.block_enabled

    @property
    def _persist(self) -> bool:
        return self.db is not None and self.settings.block_persist

    # ------------------------------------------------------------------ queries

    def _blocked_count(self) -> float:
        now = self.clock.now()
        with self._lock:
            return float(sum(1 for key in self._blocked if self._states[key].blocked_until > now))

    def check(self, context: ClientContext) -> int | None:
        """Seconds the client must wait, or None. LAN clients and a disabled blocker: None."""
        if not self.enabled or context.exempt:
            return None
        now = self.clock.now()
        with self._lock:
            if self._blocked:
                self._resync(now)
            wait = 0
            for key in (context.client_id, context.previous_id):
                state = self._states.get(key)
                if state is not None and state.blocked_until > now:
                    wait = max(wait, state.blocked_until - now)
        return wait or None

    # ------------------------------------------------------------------ counting

    def record(self, context: ClientContext | None, reason: str) -> None:
        """One failed or abusive attempt. May start a block (and emit `client.blocked`)."""
        if context is None or not self.enabled or context.exempt or context.counted:
            return
        context.counted.append(reason)
        now = self.clock.now()
        started: tuple[int, int] | None = None
        with self._lock:
            self._calls += 1
            if self._calls % SWEEP_EVERY == 0 or len(self._states) > MAX_STATES:
                self._sweep(now)
            state = self._state_for(context)
            self._decay(state, now)
            if state.blocked_until > now:
                return  # blocked clients are refused before they get here; do not stack up
            if state.failures == 0 or now - state.window_start > self.settings.block_window_s:
                state.failures, state.window_start = 0, now
            state.failures += 1
            state.last_event = now
            state.reason = reason
            if state.failures >= self.settings.block_threshold:
                durations = self.settings.block_duration_list
                state.level = min(state.level + 1, len(durations))
                length = durations[state.level - 1]
                state.blocked_until = now + length
                state.failures = 0
                self._blocked.add(context.client_id)
                self._write(context.client_id, state)
                started = (state.level, length)
        if started is not None:
            self._announce(context.client_id, reason, *started)

    def _announce(self, client_id: str, reason: str, level: int, length: int) -> None:
        self.metrics.inc("uotp_blocks_total")
        if self.emit is not None:
            self.emit(
                "client.blocked",
                level=logging.WARNING,
                client_id=client_id,
                block_level=level,
                duration_s=length,
                reason=reason,
            )
        if self.notify is not None and level >= len(self.settings.block_duration_list):
            self.notify(
                "UltimateOTP: a client keeps getting blocked",
                f"Client {client_id} reached the longest block ({length} s)."
                f" Last reason: {reason}.",
            )

    def _state_for(self, context: ClientContext) -> _State:
        state = self._states.get(context.client_id)
        if state is None:
            state = _State()
            previous = self._states.get(context.previous_id)
            if previous is not None and previous.level > 0:
                # The back-off memory crosses midnight through yesterday's id, once.
                state.level = previous.level
                state.blocked_until = previous.blocked_until
                state.last_event = previous.last_event
                state.reason = previous.reason
                if state.blocked_until > self.clock.now():
                    self._blocked.add(context.client_id)
            self._states[context.client_id] = state
        return state

    def _decay(self, state: _State, now: int) -> None:
        quiet_since = max(state.last_event, state.blocked_until)
        if (
            state.level
            and state.blocked_until <= now
            and now - quiet_since >= self.settings.block_decay_s
        ):
            state.level = 0
            state.failures = 0

    def _sweep(self, now: int) -> None:
        window, decay = self.settings.block_window_s, self.settings.block_decay_s
        for key in [
            k
            for k, s in self._states.items()
            if s.blocked_until <= now
            and now - max(s.last_event, s.blocked_until) > (decay if s.level else window)
        ]:
            del self._states[key]
            self._blocked.discard(key)

    # ------------------------------------------------------------------ persistence

    def _load(self) -> None:
        if self.db is None:
            return
        now = self.clock.now()
        try:
            with self.db.read() as conn:
                rows = conn.execute("SELECT * FROM client_blocks").fetchall()
        except sqlite3.OperationalError:
            return  # not migrated yet
        for row in rows:
            if (
                row["blocked_until"] <= now
                and now - row["blocked_until"] >= self.settings.block_decay_s
            ):
                continue
            self._states[row["client_id"]] = _State(
                level=row["level"],
                blocked_until=row["blocked_until"],
                last_event=row["last_event_at"],
                reason=row["reason"],
            )
            if row["blocked_until"] > now:
                self._blocked.add(row["client_id"])

    def _write(self, client_id: str, state: _State) -> None:
        """Queues the row. `record` may run inside a caller's write transaction (SQLite has one
        writer): the table is written by `flush`, from the guard after the request, or the
        maintenance task."""
        if self._persist:
            self._dirty[client_id] = (
                state.level,
                state.blocked_until,
                state.last_event,
                state.reason,
            )

    @property
    def has_dirty(self) -> bool:
        return bool(self._dirty)

    def flush(self) -> None:
        if self.db is None:
            return
        with self._lock:
            rows = dict(self._dirty)
        if not rows:
            return
        with self.db.write() as conn:
            conn.executemany(
                "INSERT INTO client_blocks (client_id, level, blocked_until, last_event_at, reason)"
                " VALUES (?, ?, ?, ?, ?) ON CONFLICT (client_id) DO UPDATE SET"
                " level = excluded.level, blocked_until = excluded.blocked_until,"
                " last_event_at = excluded.last_event_at, reason = excluded.reason",
                [(cid, *values) for cid, values in rows.items()],
            )
        with self._lock:
            # Only now (committed) are they forgotten, so a re-sync never sees a block that is
            # in neither the queue nor the table.
            for cid, values in rows.items():
                if self._dirty.get(cid) == values:
                    del self._dirty[cid]

    def _resync(self, now: int) -> None:
        """Honours a `blocks clear` made by the CLI process: a block whose row is gone ends."""
        if not self._persist or self.db is None:
            return
        monotonic = self.clock.monotonic()
        if monotonic - self._last_resync < RESYNC_EVERY_S:
            return
        self._last_resync = monotonic
        with self.db.read() as conn:
            rows = {r[0] for r in conn.execute("SELECT client_id FROM client_blocks")}
        for key in list(self._blocked):
            state = self._states.get(key)
            if state is None or state.blocked_until <= now:
                self._blocked.discard(key)
            elif key not in rows and key not in self._dirty:
                self._states[key] = _State()
                self._blocked.discard(key)

    def prune(self) -> int:
        """Drops table rows whose block ended more than `block_decay_s` ago. Returns the count."""
        if not self._persist or self.db is None:
            return 0
        self.flush()
        now = self.clock.now()
        with self._lock:
            self._sweep(now)
        with self.db.write() as conn:
            return conn.execute(
                "DELETE FROM client_blocks WHERE blocked_until < ?",
                (now - self.settings.block_decay_s,),
            ).rowcount

    # ------------------------------------------------------------------ admin

    def listing(self) -> list[BlockInfo]:
        """Active blocks from the table (what the CLI shows), longest remaining first."""
        if self.db is None:
            return []
        now = self.clock.now()
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT * FROM client_blocks WHERE blocked_until > ? ORDER BY blocked_until DESC",
                (now,),
            ).fetchall()
        return [
            BlockInfo(
                r["client_id"],
                r["level"],
                r["blocked_until"],
                r["last_event_at"],
                r["reason"],
                r["blocked_until"] - now,
            )
            for r in rows
        ]

    def clear(self, client_id: str | None = None) -> int:
        """Removes one block (or all of them with None). Returns how many rows went."""
        if self.db is None:
            return 0
        with self._lock:
            if client_id is None:
                self._dirty.clear()
            else:
                self._dirty.pop(client_id, None)
        with self.db.write() as conn:
            if client_id is None:
                count = conn.execute("DELETE FROM client_blocks").rowcount
            else:
                count = conn.execute(
                    "DELETE FROM client_blocks WHERE client_id = ?", (client_id,)
                ).rowcount
        with self._lock:
            for key in [client_id] if client_id else list(self._states):
                if key in self._states:
                    self._states[key] = _State()
                    self._blocked.discard(key)
        return count


class BlockGuard:
    """Plain ASGI middleware, inside the access log: a blocked client's `/otp/v1` requests are
    answered 429 `client_blocked` with `Retry-After` before any routing or body reading."""

    def __init__(self, app: ASGIApp, blocker: Blocker, metrics: Metrics) -> None:
        self._app = app
        self._blocker = blocker
        self._metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and str(scope.get("path", "")).startswith(API_PREFIX):
            context = scope.get(SCOPE_KEY)
            wait = self._blocker.check(context) if isinstance(context, ClientContext) else None
            if wait is not None:
                self._metrics.inc("uotp_problems_total", "client_blocked")
                response = errors.problem_response(
                    429,
                    "client_blocked",
                    "too many failed attempts; try again later",
                    str(scope.get("path", "")),
                    retry_after=wait,
                )
                await response(scope, receive, send)
                return
        try:
            await self._app(scope, receive, send)
        finally:
            if self._blocker.has_dirty:
                await run_in_threadpool(self._blocker.flush)
