# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""A few Prometheus counters, written in the text exposition format without a dependency.

Labels are fixed, low-cardinality strings (event names, problem codes): never ids or addresses.
"""

import threading
from collections import defaultdict
from collections.abc import Callable

_HELP = {
    "uotp_events_total": "Security and sync events by name",
    "uotp_problems_total": "Problem responses by code",
    "uotp_sse_streams": "Open live-sync streams",
}


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, str], int] = defaultdict(int)
        self._gauges: dict[str, Callable[[], float]] = {}

    def inc(self, name: str, label: str) -> None:
        with self._lock:
            self._counters[(name, label)] += 1

    def value(self, name: str, label: str) -> int:
        with self._lock:
            return self._counters.get((name, label), 0)

    def gauge(self, name: str, read: Callable[[], float]) -> None:
        self._gauges[name] = read

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
        lines: list[str] = []
        label_name = {"uotp_events_total": "event", "uotp_problems_total": "code"}
        for name in sorted({n for n, _ in counters}):
            lines.append(f"# HELP {name} {_HELP.get(name, name)}")
            lines.append(f"# TYPE {name} counter")
            for (n, label), value in sorted(counters.items()):
                if n == name:
                    lines.append(f'{name}{{{label_name.get(name, "label")}="{label}"}} {value}')
        for name, read in sorted(self._gauges.items()):
            lines.append(f"# HELP {name} {_HELP.get(name, name)}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {read()}")
        return "\n".join(lines) + "\n"
