# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prometheus metrics in the text exposition format, without a dependency.

Labels are fixed, low-cardinality strings (event names, problem codes, route templates, result
names): never an account, a device, an address or a client id. docs/monitoring/ has the Grafana
dashboard and the alert rules built on these names.
"""

import threading
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Final

LabelSet = tuple[tuple[str, str], ...]

# Seconds. Commits and logins (Argon2 is client side; SRP math is ~tens of ms) fit in these.
LATENCY_BUCKETS: Final = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_HELP = {
    "uotp_events_total": "Security and sync events by name",
    "uotp_problems_total": "Problem responses by code",
    "uotp_signups_total": "Accounts created from the app",
    "uotp_logins_total": "Logins by result (success, srp_failure, email_code_failure, locked)",
    "uotp_blocks_total": "Temporary client blocks started, by back-off level",
    "uotp_lockouts_total": "Per-account SRP lockouts started",
    "uotp_commits_total": "Vault commits accepted",
    "uotp_rotations_total": "Vault key rotations accepted",
    "uotp_conflicts_total": "Vault commits refused as conflicts, by reason",
    "uotp_sse_connections_total": "Live-sync streams opened",
    "uotp_emails_total": "Emails handed to the relay, by result (sent, failed)",
    "uotp_notifications_total": "ntfy notifications, by result (sent, failed)",
    "uotp_account_actions_total": "Account management actions by name",
    "uotp_http_request_duration_seconds": "Request latency by method, route and status class",
    "uotp_sse_streams": "Open live-sync streams",
    "uotp_blocked_clients": "Clients blocked right now",
    "uotp_accounts": "Accounts",
    "uotp_devices_active": "Active (not revoked) devices",
    "uotp_vault_items": "Live vault items, all accounts",
    "uotp_history_versions": "Retained previous vault versions, all accounts",
    "uotp_history_items": "Retained previous item blobs, all accounts",
    "uotp_history_bytes": "Bytes of retained previous item blobs",
    "uotp_database_bytes": "Size of the SQLite database file plus its WAL",
    "uotp_build_info": "Server version (value 1)",
}
_LABEL_NAME = {"uotp_events_total": "event", "uotp_problems_total": "code"}

# Series that exist from the first scrape, so rate() and increase() see a 0 baseline.
_DECLARED: dict[str, list[dict[str, str]]] = {
    "uotp_signups_total": [{}],
    "uotp_blocks_total": [{}],
    "uotp_lockouts_total": [{}],
    "uotp_commits_total": [{}],
    "uotp_rotations_total": [{}],
    "uotp_sse_connections_total": [{}],
    "uotp_logins_total": [
        {"result": r} for r in ("success", "srp_failure", "email_code_failure", "locked")
    ],
    "uotp_conflicts_total": [{"reason": r} for r in ("version", "key_epoch")],
    "uotp_emails_total": [{"result": r} for r in ("sent", "failed")],
    "uotp_notifications_total": [{"result": r} for r in ("sent", "failed")],
}


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format(labels: Iterable[tuple[str, str]]) -> str:
    pairs = [f'{name}="{_escape(value)}"' for name, value in labels]
    return "{" + ",".join(pairs) + "}" if pairs else ""


class _Histogram:
    __slots__ = ("buckets", "count", "total")

    def __init__(self) -> None:
        self.buckets = [0] * len(LATENCY_BUCKETS)
        self.count = 0
        self.total = 0.0

    def observe(self, value: float) -> None:
        self.count += 1
        self.total += value
        for index, bound in enumerate(LATENCY_BUCKETS):
            if value <= bound:
                self.buckets[index] += 1


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, LabelSet], int] = defaultdict(int)
        self._histograms: dict[tuple[str, LabelSet], _Histogram] = {}
        self._gauges: dict[tuple[str, LabelSet], Callable[[], float]] = {}
        for name, series in _DECLARED.items():
            for labels in series:
                self._counters[(name, tuple(sorted(labels.items())))] += 0

    def inc(self, name: str, label: str | None = None, *, amount: int = 1, **labels: str) -> None:
        """`inc("uotp_events_total", "srp.success")` or `inc("uotp_logins_total", result="x")`."""
        if label is not None:
            labels[_LABEL_NAME.get(name, "label")] = label
        with self._lock:
            self._counters[(name, tuple(sorted(labels.items())))] += amount

    def value(self, name: str, label: str | None = None, **labels: str) -> int:
        if label is not None:
            labels[_LABEL_NAME.get(name, "label")] = label
        with self._lock:
            return self._counters.get((name, tuple(sorted(labels.items()))), 0)

    def observe(self, name: str, seconds: float, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            histogram = self._histograms.get(key)
            if histogram is None:
                histogram = self._histograms[key] = _Histogram()
            histogram.observe(seconds)

    def gauge(self, name: str, read: Callable[[], float], **labels: str) -> None:
        self._gauges[(name, tuple(sorted(labels.items())))] = read

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            histograms = {
                key: (list(h.buckets), h.count, h.total) for key, h in self._histograms.items()
            }
        lines: list[str] = []
        for name in sorted({n for n, _ in counters}):
            lines.append(f"# HELP {name} {_HELP.get(name, name)}")
            lines.append(f"# TYPE {name} counter")
            for (n, labels), value in sorted(counters.items()):
                if n == name:
                    lines.append(f"{name}{_format(labels)} {value}")
        for name in sorted({n for n, _ in histograms}):
            lines.append(f"# HELP {name} {_HELP.get(name, name)}")
            lines.append(f"# TYPE {name} histogram")
            for (n, labels), (buckets, count, total) in sorted(histograms.items()):
                if n != name:
                    continue
                for bound, cumulative in zip(LATENCY_BUCKETS, buckets, strict=True):
                    lines.append(
                        f"{name}_bucket{_format((*labels, ('le', f'{bound:g}')))} {cumulative}"
                    )
                lines.append(f"{name}_bucket{_format((*labels, ('le', '+Inf')))} {count}")
                lines.append(f"{name}_sum{_format(labels)} {total:.6f}")
                lines.append(f"{name}_count{_format(labels)} {count}")
        gauge_names = sorted({n for n, _ in self._gauges})
        for name in gauge_names:
            lines.append(f"# HELP {name} {_HELP.get(name, name)}")
            lines.append(f"# TYPE {name} gauge")
            for (n, labels), read in sorted(self._gauges.items()):
                if n == name:
                    lines.append(f"{name}{_format(labels)} {read()}")
        return "\n".join(lines) + "\n"
