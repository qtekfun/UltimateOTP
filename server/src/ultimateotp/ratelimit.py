# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Rate-limit hooks.

The edge (Traefik) already limits per client address and route (docs/deploy.md). These hooks
are the application's own layer, keyed by what only the api knows (the device, the resolved
client behind the proxy, the kind of route). `RateLimiter` is the interface: the in-memory token
bucket fits the single api process; a shared store (Redis) could implement it later.
"""

import threading
from dataclasses import dataclass
from typing import Protocol

from ultimateotp.clock import Clock

# Buckets idle longer than this are forgotten (bounded memory).
_IDLE_S = 3600.0
_SWEEP_EVERY = 1024


@dataclass(frozen=True)
class Limit:
    rate_per_s: float
    burst: int


class RateLimiter(Protocol):
    def hit(self, bucket: str, key: str) -> float | None:
        """Takes one token from `bucket` for `key`. None when allowed, else seconds to wait."""
        ...


class NoRateLimit:
    def hit(self, bucket: str, key: str) -> float | None:
        return None


class TokenBucketLimiter:
    def __init__(self, limits: dict[str, Limit], clock: Clock) -> None:
        self._limits = limits
        self._clock = clock
        self._state: dict[tuple[str, str], tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._calls = 0

    def hit(self, bucket: str, key: str) -> float | None:
        limit = self._limits.get(bucket)
        if limit is None:
            return None
        now = self._clock.monotonic()
        with self._lock:
            self._calls += 1
            if self._calls % _SWEEP_EVERY == 0:
                self._sweep(now)
            tokens, last = self._state.get((bucket, key), (float(limit.burst), now))
            tokens = min(float(limit.burst), tokens + (now - last) * limit.rate_per_s)
            if tokens >= 1.0:
                self._state[(bucket, key)] = (tokens - 1.0, now)
                return None
            self._state[(bucket, key)] = (tokens, now)
            return (1.0 - tokens) / limit.rate_per_s

    def _sweep(self, now: float) -> None:
        for name in [k for k, (_, last) in self._state.items() if now - last > _IDLE_S]:
            del self._state[name]
