# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Temporary blocking with a growing back-off (docs/deploy.md §6): counting across routes,
15 min / 1 h / 24 h, decay, persistence, the LAN exemption, the off switch and the CLI."""

import io
import json
import logging
import secrets
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.client import Device
from tests.conftest import LAN_CLIENT, PASSWORD, PUBLIC_CLIENT, Bootstrapped, FakeClock, Server
from tests.fakes import SMTP_PASSWORD, SMTP_USER, smtp_relay
from tests.test_login import EMAIL, _account
from ultimateotp import b64, cli, srp
from ultimateotp.logging import JsonFormatter, RedactingFilter
from ultimateotp.settings import Settings

THRESHOLD = 5
PUBLIC = ("203.0.113.7", 51000)
OTHER = ("198.51.100.9", 51000)


def _settings(make_settings: Callable[..., Settings], **overrides: Any) -> Settings:
    return make_settings(block_threshold=THRESHOLD, srp_lockout_threshold=100, **overrides)


def _probe(client: TestClient, n: int = 1) -> None:
    """`n` unknown-account probes: an SRP handshake for an address nobody has."""
    big_a = b64.encode(srp.GROUP_4096.pad(srp.client_public(srp.GROUP_4096, srp.new_ephemeral())))
    for index in range(n):
        client.post(
            "/otp/v1/srp/session", json={"email": f"nobody{index}@example.org", "srp_a": big_a}
        )


def _status(client: TestClient) -> Any:
    return client.get("/otp/v1/server-info")


def _wait(response: Any) -> int:
    """The Retry-After of a block, rounded to the nearest 10 s (the fake clock follows real
    seconds, so a test can straddle a second boundary)."""
    assert response.status_code == 429, response.text
    assert response.json()["code"] == "client_blocked"
    return int(round(response.json()["retry_after"], -1))


def _trip(client: TestClient) -> Any:
    _probe(client, THRESHOLD)
    return _status(client)


def test_a_client_that_keeps_failing_is_blocked_with_retry_after(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(_settings(make_settings))
    with server.client(PUBLIC) as client:
        _probe(client, THRESHOLD - 1)
        assert _status(client).status_code == 200
        _probe(client)
        blocked = _status(client)
        assert blocked.status_code == 429
        assert blocked.headers["retry-after"] in ("899", "900")
        body = blocked.json()
        assert body["code"] == "client_blocked"
        assert body["retry_after"] in (899, 900)
        assert blocked.headers["content-type"] == "application/problem+json"
        # Every /otp/v1 route is closed to it, not only the one it abused.
        assert (
            client.post("/otp/v1/srp/attributes", json={"email": "a@example.org"}).status_code
            == 429
        )
        # Others, and the probes, are not.
        with server.client(OTHER) as other:
            assert _status(other).status_code == 200
        assert client.get("/healthz").status_code == 200
    assert server.service.metrics.value("uotp_blocks_total") == 1
    assert server.service.metrics.value("uotp_problems_total", "client_blocked") >= 2


def test_backoff_grows_15_min_1_h_24_h_and_caps(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    server = make_server(_settings(make_settings))
    waits = []
    with server.client(PUBLIC) as client:
        for _ in range(4):
            waits.append(_wait(_trip(client)))
            clock.advance(waits[-1] + 11)
            assert _status(client).status_code == 200
    assert waits == [900, 3600, 86400, 86400]


def test_block_decays_after_a_quiet_period(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    server = make_server(_settings(make_settings, block_decay_s=7200))
    with server.client(PUBLIC) as client:
        assert _wait(_trip(client)) == 900
        clock.advance(901)
        assert _wait(_trip(client)) == 3600
        clock.advance(3601 + 7200)  # block over, then quiet for the whole decay
        assert _wait(_trip(client)) == 900


def test_failures_expire_with_the_window(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    server = make_server(_settings(make_settings, block_window_s=60))
    with server.client(PUBLIC) as client:
        _probe(client, THRESHOLD - 1)
        clock.advance(61)
        _probe(client, THRESHOLD - 1)
        assert _status(client).status_code == 200


@pytest.mark.parametrize("source", ["srp_proof", "signature", "unknown_account", "rate_limit"])
def test_every_kind_of_failure_counts(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    source: str,
) -> None:
    server = make_server(
        _settings(make_settings, ratelimit_enabled=source == "rate_limit", srp_burst=2)
    )
    with server.client(LAN_CLIENT) as lan:
        _account(server, lan)
    with server.client(PUBLIC) as client:
        for _ in range(THRESHOLD if source == "srp_proof" else THRESHOLD + 2):
            if source == "srp_proof":
                Device(client).srp_login(EMAIL, "wrong password")
            elif source == "signature":
                client.get(
                    "/otp/v1/devices",
                    headers={
                        "X-UOTP-Device": "dev_" + "A" * 22,
                        "X-UOTP-Timestamp": str(int(time.time())),
                        "X-UOTP-Nonce": b64.encode(secrets.token_bytes(16)),
                        "X-UOTP-Signature": "A" * 86,
                    },
                )
            elif source == "unknown_account":
                _probe(client)
            else:  # srp_burst=2: the handshakes beyond the bucket are rate-limit hits
                _probe(client)
        assert _status(client).status_code == 429
        assert _status(client).json()["code"] == "client_blocked"


def test_wrong_email_codes_count(
    tmp_path: Path,
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
) -> None:
    with smtp_relay(tmp_path) as (_, port, cert):
        server = make_server(
            _settings(
                make_settings,
                email_verification="enabled",
                smtp_host="127.0.0.1",
                smtp_port=port,
                smtp_user=SMTP_USER,
                smtp_from="UltimateOTP <otp@example.org>",
                smtp_password=SMTP_PASSWORD,
                smtp_ca_file=cert,
                email_code_max_attempts=20,
            )
        )
        server.service.create_account(EMAIL)
        big_a = b64.encode(
            srp.GROUP_4096.pad(srp.client_public(srp.GROUP_4096, srp.new_ephemeral()))
        )
        with server.client(PUBLIC) as client:
            for _ in range(THRESHOLD):
                wrong = client.post(
                    "/otp/v1/srp/session",
                    json={"email": EMAIL, "srp_a": big_a, "email_code": "000000"},
                )
                assert wrong.json()["code"] == "invalid_email_code"
            assert _status(client).status_code == 429
        assert server.service.metrics.value("uotp_logins_total", result="email_code_failure") == 5
        server.service.alerts.flush()


def test_a_successful_login_does_not_erase_a_block_or_a_count(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    server = make_server(_settings(make_settings))
    with server.client(LAN_CLIENT) as lan:
        _account(server, lan)
    with server.client(PUBLIC) as client:
        _probe(client, THRESHOLD - 1)
        ok = Device(client, "Mine").srp_login(EMAIL, PASSWORD)
        assert ok.status_code == 201  # the owner logs in fine meanwhile ...
        _probe(client)
        # ... and the count was not reset by it.
        assert _status(client).status_code == 429
        # Blocked now: even the right password is refused until the block ends.
        late = client.post("/otp/v1/srp/attributes", json={"email": EMAIL})
        assert late.status_code == 429
        assert late.json()["code"] == "client_blocked"
        clock.advance(901)
        again = Device(client, "Again")
        again.clock_offset = clock.offset
        assert again.srp_login(EMAIL, PASSWORD).status_code == 201


def test_the_lan_is_exempt(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(_settings(make_settings))
    with server.client(LAN_CLIENT) as lan:
        _probe(lan, THRESHOLD * 3)
        assert _status(lan).status_code == 200
    assert server.service.metrics.value("uotp_blocks_total") == 0
    # Not in the LAN list (or denied): the same behaviour as a stranger.
    strict = make_server(
        _settings(make_settings, lan_networks="192.168.1.0/24", denied_networks="192.168.1.10/32")
    )
    with strict.client(LAN_CLIENT) as denied:
        assert _trip(denied).status_code == 429


def test_forwarded_clients_are_not_exempt(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(_settings(make_settings, trusted_proxies="10.213.49.2/32"))
    with server.client(("10.213.49.2", 1)) as proxy:
        headers = {"X-Forwarded-For": "203.0.113.7"}
        big_a = b64.encode(
            srp.GROUP_4096.pad(srp.client_public(srp.GROUP_4096, srp.new_ephemeral()))
        )
        for index in range(THRESHOLD):
            proxy.post(
                "/otp/v1/srp/session",
                json={"email": f"n{index}@example.org", "srp_a": big_a},
                headers=headers,
            )
        assert proxy.get("/otp/v1/server-info", headers=headers).status_code == 429
        # Another client behind the same proxy is fine.
        other = {"X-Forwarded-For": "198.51.100.9"}
        assert proxy.get("/otp/v1/server-info", headers=other).status_code == 200


def test_off_switch(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(_settings(make_settings, block_enabled=False))
    with server.client(PUBLIC) as client:
        _probe(client, THRESHOLD * 3)
        assert _status(client).status_code == 200


def test_blocked_requests_do_not_extend_the_block(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    server = make_server(_settings(make_settings))
    with server.client(PUBLIC) as client:
        assert _wait(_trip(client)) == 900
        for _ in range(THRESHOLD * 4):  # hammering a blocked route
            _status(client)
        clock.advance(901)
        assert _status(client).status_code == 200


# ---------------------------------------------------------------- persistence and the CLI


def test_active_block_survives_a_restart(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    settings = _settings(make_settings)
    first = make_server(settings)
    with first.client(PUBLIC) as client:
        assert _trip(client).status_code == 429
    with closing(sqlite3.connect(settings.database_file)) as conn:
        rows = conn.execute("SELECT client_id, level FROM client_blocks").fetchall()
    assert len(rows) == 1
    assert rows[0][0].startswith("c_")
    assert "203.0.113.7" not in str(rows)
    restarted = make_server(settings)
    with restarted.client(PUBLIC) as client:
        assert _status(client).status_code == 429
        clock.advance(901)
        assert _status(client).status_code == 200
        # The level came back too: the next block is the second length.
        assert _wait(_trip(client)) == 3600


def test_without_persistence_a_restart_wipes_blocks(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    settings = _settings(make_settings, block_persist=False)
    with make_server(settings).client(PUBLIC) as client:
        assert _trip(client).status_code == 429
    with closing(sqlite3.connect(settings.database_file)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM client_blocks").fetchone()[0] == 0
    with make_server(settings).client(PUBLIC) as client:
        assert _status(client).status_code == 200


def test_block_carries_over_midnight_and_the_level_with_it(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    """Ids rotate at 00:00 UTC; a block set at 23:50 must still hold at 00:01, and the
    back-off level crosses midnight with it (through yesterday's id, once)."""
    now = int(time.time())
    midnight = now - now % 86_400 + 86_400
    clock.offset = midnight - 600 - now  # 23:50 UTC
    server = make_server(_settings(make_settings, block_decay_s=7 * 86_400))
    with server.client(PUBLIC) as client:
        assert _wait(_trip(client)) == 900  # until 00:05
        clock.advance(700)  # 00:01:40, another day, another id
        carried = _status(client)
        assert carried.status_code == 429
        clock.advance(300)  # 00:06:40: the block is over
        assert _status(client).status_code == 200
        assert _wait(_trip(client)) == 3600


def test_client_blocked_event_has_the_anonymized_id_only(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        server = make_server(_settings(make_settings))
        with server.client(PUBLIC) as client:
            _trip(client)
    finally:
        root.removeHandler(handler)
    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    blocked = [e for e in events if e.get("event") == "client.blocked"]
    assert len(blocked) == 1
    event = blocked[0]
    assert event["client_id"].startswith("c_")
    assert event["duration_s"] == 900
    assert event["block_level"] == 1
    assert event["reason"] == "login.unknown_account"
    assert event["level"] == "WARNING"
    assert event["logger"] == "ultimateotp.security"
    assert "203.0.113.7" not in stream.getvalue()
    assert "ip" not in {k for k in event if k.endswith("_ip")}


def _cli(capsys: pytest.CaptureFixture[str], *args: str) -> Any:
    assert cli.main(list(args)) == 0
    out = capsys.readouterr().out
    return json.loads(out)


def test_cli_lists_and_clears_blocks_and_the_api_honours_it(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    clock: FakeClock,
) -> None:
    settings = _settings(make_settings)
    server = make_server(settings)
    for key, value in {
        "UOTP_DATA_DIR": str(settings.data_dir),
        "UOTP_MIGRATIONS_DIR": str(settings.migrations_dir),
        "UOTP_EMAIL_VERIFICATION": "disabled",
        "UOTP_RATELIMIT_ENABLED": "false",
        "UOTP_BLOCK_THRESHOLD": str(THRESHOLD),
    }.items():
        monkeypatch.setenv(key, value)
    with server.client(PUBLIC) as client, server.client(OTHER) as other:
        assert _trip(client).status_code == 429
        assert _trip(other).status_code == 429
        listing = _cli(capsys, "blocks", "list")
        assert len(listing) == 2
        assert all(row["client_id"].startswith("c_") and row["remaining_s"] > 0 for row in listing)
        target = listing[0]["client_id"]
        assert _cli(capsys, "blocks", "clear", target) == {"cleared": 1}
        assert len(_cli(capsys, "blocks", "list")) == 1
        # The api re-reads the table every few seconds while it holds blocks.
        clock.advance(6)
        statuses = {_status(client).status_code, _status(other).status_code}
        assert statuses == {200, 429}
        assert _cli(capsys, "blocks", "clear", "c_000000000000") == {"cleared": 0}
        assert _cli(capsys, "blocks", "clear", "--all") == {"cleared": 1}
        clock.advance(6)
        assert _status(client).status_code == 200
        assert _status(other).status_code == 200
    # Misuse is refused.
    assert cli.main(["blocks", "clear"]) == 1


def test_a_cleared_client_starts_from_the_first_length_again(
    make_settings: Callable[..., Settings],
    make_server: Callable[[Settings], Server],
    clock: FakeClock,
) -> None:
    settings = _settings(make_settings)
    server = make_server(settings)
    with server.client(PUBLIC) as client:
        assert _wait(_trip(client)) == 900
        assert server.service.blocker.clear() == 1
        assert _status(client).status_code == 200
        assert _wait(_trip(client)) == 900


def test_blocked_clients_gauge_and_unmigrated_database(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(_settings(make_settings))
    assert "uotp_blocked_clients 0.0" in server.service.metrics.render()
    with server.client(PUBLIC) as client:
        _trip(client)
    assert "uotp_blocked_clients 1.0" in server.service.metrics.render()


def test_bootstrapped_owner_is_unaffected_by_strangers(
    server: Server, bootstrapped: Bootstrapped
) -> None:
    with server.client(PUBLIC_CLIENT) as stranger:
        _probe(stranger, 50)
    assert bootstrapped.device.get("/otp/v1/devices").status_code == 200
