# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Injectable clock: every stored time and every signature window goes through it."""

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> int:
        """Unix seconds."""
        ...

    def monotonic(self) -> float: ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())

    def monotonic(self) -> float:
        return time.monotonic()
