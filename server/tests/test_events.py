# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Live sync over SSE (docs/sync.md), against a real uvicorn server on a loopback port."""

import json
import queue
import secrets
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import uvicorn

from tests.client import Device, Vault, new_item_id
from tests.conftest import MIGRATIONS, PASSWORD
from ultimateotp import db
from ultimateotp.app import create_app
from ultimateotp.clock import SystemClock
from ultimateotp.events import Broker
from ultimateotp.metrics import Metrics
from ultimateotp.service import Service
from ultimateotp.settings import Settings

DEADLINE_S = 2.0


@dataclass
class Live:
    url: str
    settings: Settings
    service: Service


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture
def live(tmp_path: Any) -> Iterator[Callable[..., Live]]:
    servers: list[tuple[uvicorn.Server, threading.Thread]] = []

    def start(**overrides: Any) -> Live:
        # A short keepalive lets test readers notice they should stop (the default is 15 s).
        values: dict[str, Any] = {"sse_keepalive_s": 0.2, **overrides}
        settings = Settings(
            data_dir=tmp_path, migrations_dir=MIGRATIONS, ratelimit_enabled=False, **values
        )
        db.migrate(settings.database_file, settings.migrations_dir)
        app = create_app(settings)
        port = _free_port()
        config = uvicorn.Config(
            app, host="127.0.0.1", port=port, log_config=None, timeout_graceful_shutdown=1
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        while not server.started:
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.02)
        servers.append((server, thread))
        return Live(f"http://127.0.0.1:{port}", settings, app.fastapi.state.service)  # type: ignore[attr-defined]

    yield start
    for server, thread in servers:
        server.should_exit = True
        thread.join(timeout=5)


class Stream:
    """Reads one SSE stream in a background thread and queues parsed events."""

    def __init__(self, url: str, headers: dict[str, str]) -> None:
        self.events: queue.Queue[tuple[str, dict[str, Any], str | None]] = queue.Queue()
        self.status: int | None = None
        self.closed = threading.Event()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._client = httpx.Client(timeout=httpx.Timeout(10.0, read=30.0))
        self._thread = threading.Thread(target=self._run, args=(url, headers), daemon=True)
        self._thread.start()
        assert self._ready.wait(5)

    def _run(self, url: str, headers: dict[str, str]) -> None:
        try:
            with self._client.stream("GET", url, headers=headers) as response:
                self.status = response.status_code
                self._ready.set()
                if response.status_code != 200:
                    return
                name, data, event_id = "message", "", None
                for line in response.iter_lines():
                    if self._stop.is_set():
                        return
                    if line.startswith("event: "):
                        name = line[7:]
                    elif line.startswith("data: "):
                        data = line[6:]
                    elif line.startswith("id: "):
                        event_id = line[4:]
                    elif line == "" and data:
                        self.events.put((name, json.loads(data), event_id))
                        name, data, event_id = "message", "", None
        except httpx.HTTPError:
            pass
        finally:
            self._ready.set()
            self.closed.set()

    def next(self, name: str, timeout: float = DEADLINE_S) -> tuple[dict[str, Any], str | None]:
        """The next event called `name` (earlier ones of other kinds are skipped)."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"no {name!r} event within {timeout}s")
            try:
                got, data, event_id = self.events.get(timeout=remaining)
            except queue.Empty:
                continue
            if got == name:
                return data, event_id

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._client.close()


@contextmanager
def streams(live: Live, *devices: Device) -> Iterator[list[Stream]]:
    opened = [
        Stream(live.url + "/otp/v1/events", d.headers("GET", "/otp/v1/events", b""))
        for d in devices
    ]
    try:
        yield opened
    finally:
        for stream in opened:
            stream.close()


def _bootstrap(live: Live, client: httpx.Client, count: int) -> tuple[list[Device], Vault]:
    account_id, token, _ = live.service.create_account()
    vault = Vault(account_id=account_id)
    first = Device(client, "A")
    assert (
        first.enroll(token, vault.key_bundle(PASSWORD, secrets.token_bytes(32))).status_code == 201
    )
    devices = [first]
    for n in range(count - 1):
        tok, _ = live.service.create_token(account_id)
        dev = Device(client, f"D{n}")
        assert dev.enroll(tok).status_code == 201
        devices.append(dev)
    return devices, vault


def test_commit_reaches_other_devices(live: Callable[..., Live]) -> None:
    # A 3 s tick: an event seen well before it was pushed in-process, not caught up from the db.
    server = live(sse_keepalive_s=3.0)
    with httpx.Client(base_url=server.url) as client:
        (a, b, c), vault = _bootstrap(server, client, 3)
        with streams(server, a, b) as (sa, sb):
            for stream in (sa, sb):
                hello, _ = stream.next("hello")
                assert hello == {
                    "version": 0,
                    "key_epoch": 1,
                    "devices_revision": 3,
                    "rotation_required": False,
                }
            started = time.monotonic()
            assert c.commit(vault, {new_item_id(): {"issuer": "x"}}).status_code == 200
            for stream in (sa, sb):
                data, event_id = stream.next("vault")
                assert data == {"version": 1, "key_epoch": 1, "signed_by": c.device_id}
                assert event_id == "1"
            assert time.monotonic() - started < 1.0
            # The notified devices pull the change.
            assert b.get("/otp/v1/vault?since=0").json()["head"]["version"] == 1


def test_events_stay_within_the_account(live: Callable[..., Live]) -> None:
    server = live()
    with httpx.Client(base_url=server.url) as client:
        (a,), vault_a = _bootstrap(server, client, 1)
        (x,), _ = _bootstrap(server, client, 1)
        with streams(server, x) as (sx,):
            sx.next("hello")
            a.commit(vault_a, {new_item_id(): {"issuer": "x"}})
            with pytest.raises(AssertionError, match="no 'vault' event"):
                sx.next("vault", timeout=0.5)


def test_revoked_device_gets_revoked_and_the_stream_closes(live: Callable[..., Live]) -> None:
    server = live()
    with httpx.Client(base_url=server.url) as client:
        (a, b), _ = _bootstrap(server, client, 2)
        with streams(server, a, b) as (sa, sb):
            sa.next("hello")
            sb.next("hello")
            assert a.post(f"/otp/v1/devices/{b.device_id}/revoke").status_code == 200
            data, _ = sb.next("revoked")
            assert data == {"device_id": b.device_id}
            assert sb.closed.wait(DEADLINE_S)
            devices, _ = sa.next("devices")
            assert devices == {"devices_revision": 3}


def test_changes_from_outside_the_process_arrive_on_the_next_tick(
    live: Callable[..., Live],
) -> None:
    """The admin CLI is another process: streams catch up by re-reading the database."""
    server = live(sse_keepalive_s=0.3)  # the catch-up tick
    cli = Service(
        db.Database(server.settings.database_file),
        server.settings,
        SystemClock(),
        Broker(),
        Metrics(),
    )
    with httpx.Client(base_url=server.url) as client:
        (a, b), _ = _bootstrap(server, client, 2)
        with streams(server, a, b) as (sa, sb):
            sa.next("hello")
            sb.next("hello")
            assert b.device_id is not None
            cli.revoke_device(b.device_id, None)
            assert sa.next("devices")[0] == {"devices_revision": 3}
            sb.next("revoked")
            assert sb.closed.wait(DEADLINE_S)


def test_pairing_join_notifies_the_creator(live: Callable[..., Live]) -> None:
    server = live()
    with httpx.Client(base_url=server.url) as client:
        (a,), _ = _bootstrap(server, client, 1)
        with streams(server, a) as (sa,):
            sa.next("hello")
            pairing = a.post("/otp/v1/pairings").json()
            joiner = Device(client)
            joiner.post(
                f"/otp/v1/pairings/{pairing['pairing_id']}/join",
                {
                    "ed25519_public_key": joiner.ed25519,
                    "x25519_public_key": joiner.x25519,
                    "label": "B",
                },
                bearer=pairing["secret"],
            )
            data, _ = sa.next("pairing")
            assert data == {"pairing_id": pairing["pairing_id"], "status": "joined"}


def test_stream_limits_and_auth(live: Callable[..., Live]) -> None:
    server = live(sse_max_streams_per_device=1)
    with httpx.Client(base_url=server.url) as client:
        (a,), _ = _bootstrap(server, client, 1)
        assert client.get("/otp/v1/events").status_code == 401
        with streams(server, a) as (first,):
            first.next("hello")
            with streams(server, a) as (second,):
                assert second.status == 429


def test_stream_ends_after_max_age(live: Callable[..., Live]) -> None:
    server = live(sse_max_age_s=0.5, sse_keepalive_s=0.2)
    with httpx.Client(base_url=server.url) as client:
        (a,), _ = _bootstrap(server, client, 1)
        with streams(server, a) as (sa,):
            sa.next("hello")
            assert sa.closed.wait(DEADLINE_S)
        assert server.service.broker.count() == 0
