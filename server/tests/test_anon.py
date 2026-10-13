# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Anonymized client addresses: a client IP never reaches a log line, a notice, a metric label,
the database or a rate-limit key (owner decision of 2026-10-13, docs/deploy.md §6)."""

import io
import json
import logging
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path

import pytest

from tests.client import Device, Vault, new_item_id
from tests.conftest import PASSWORD, Bootstrapped, FakeClock, Server
from tests.fakes import SMTP_PASSWORD, SMTP_USER, ntfy_server, smtp_relay
from ultimateotp.anon import ClientIds, mask
from ultimateotp.logging import JsonFormatter, RedactingFilter, scrub_addresses
from ultimateotp.settings import Settings

SECRET = b"s" * 32
EMAIL = "owner@example.org"
PROXY = "10.213.49.2"


def _ids(clock: FakeClock, secret: bytes = SECRET) -> ClientIds:
    return ClientIds(secret, clock)


# ---------------------------------------------------------------- the id


def test_id_shape_and_stability_within_a_day(clock: FakeClock) -> None:
    ids = _ids(clock)
    first = ids.client_id("203.0.113.7")
    assert re.fullmatch(r"c_[0-9a-f]{12}", first)
    assert ids.client_id("203.0.113.7") == first
    assert ids.client_id("203.0.113.8") != first
    # Not derivable from the address alone: another secret, another id.
    assert _ids(clock, b"t" * 32).client_id("203.0.113.7") != first
    # An address is never part of the id.
    assert "203" not in first


def test_id_rotates_daily_and_days_do_not_link(clock: FakeClock) -> None:
    ids = _ids(clock)
    today = ids.client_id("203.0.113.7")
    # What yesterday's id was, as seen from today (the block carry-over).
    yesterday = ids.previous_id("203.0.113.7")
    assert yesterday != today
    clock.advance(86_400)
    tomorrow = ids.client_id("203.0.113.7")
    assert tomorrow not in (today, yesterday)
    # Tomorrow's "previous" is today's id: the one-day carry-over, nothing older.
    assert ids.previous_id("203.0.113.7") == today
    clock.advance(86_400)
    assert ids.previous_id("203.0.113.7") == tomorrow


def test_only_todays_salt_is_kept(clock: FakeClock) -> None:
    ids = _ids(clock)
    ids.client_id("203.0.113.7")
    ids.previous_id("203.0.113.7")
    assert ids._cached is not None
    cached_day = ids._cached[0]
    clock.advance(3 * 86_400)
    ids.client_id("203.0.113.7")
    assert ids._cached[0] > cached_day


def test_ipv6_is_masked_to_its_64(clock: FakeClock) -> None:
    ids = _ids(clock)
    one = ids.client_id("2001:db8:abcd:12::1")
    assert ids.client_id("2001:db8:abcd:12:aaaa:bbbb:cccc:dddd") == one
    assert ids.client_id("2001:DB8:ABCD:12:0:0:0:99") == one
    assert ids.client_id("2001:db8:abcd:13::1") != one
    assert mask("2001:db8:abcd:12::1") == "2001:db8:abcd:12::/64"


def test_mapped_ipv4_and_garbage(clock: FakeClock) -> None:
    ids = _ids(clock)
    assert ids.client_id("::ffff:203.0.113.7") == ids.client_id("203.0.113.7")
    assert ids.client_id(None) == ids.client_id("unknown") == ids.client_id("not an address")
    assert ids.client_id("unknown") != ids.client_id("203.0.113.7")


def test_secret_must_be_long_enough(clock: FakeClock) -> None:
    with pytest.raises(ValueError, match="too short"):
        ClientIds(b"short", clock)


def test_secret_survives_restarts_and_is_not_a_log_field(
    make_server: Callable[[Settings], Server], settings: Settings, clock: FakeClock
) -> None:
    first = make_server(settings)
    with first.client(("203.0.113.7", 1)) as client:
        a = client.get("/otp/v1/server-info")
    with closing(sqlite3.connect(settings.database_file)) as conn:
        row = conn.execute(
            "SELECT secret FROM server_secrets WHERE name = 'client-id-secret'"
        ).fetchone()
    assert row is not None
    assert a.status_code == 200
    # A restart (a second app on the same database) loads the same secret, so a block or a
    # count keyed by an id survives it.
    from ultimateotp import anon  # noqa: PLC0415
    from ultimateotp.db import Database  # noqa: PLC0415

    again = anon.load_secret(Database(settings.database_file), settings, clock)
    assert again == bytes.fromhex(row[0])
    assert make_server(settings) is not None


def test_configured_secret_wins_over_the_database(
    make_server: Callable[[Settings], Server], make_settings: Callable[..., Settings]
) -> None:
    server = make_server(make_settings(ip_secret="x" * 40))
    with closing(sqlite3.connect(server.settings.database_file)) as conn:
        assert (
            conn.execute("SELECT 1 FROM server_secrets WHERE name = 'client-id-secret'").fetchone()
            is None
        )


# ---------------------------------------------------------------- the log scrubber


@pytest.mark.parametrize(
    "text",
    [
        "from 203.0.113.7 now",
        "peer=('198.51.100.23', 5000)",
        "client 2001:db8:abcd:12::77 failed",
        "client 2001:db8:abcd:12:aaaa:bbbb:cccc:dddd failed",
        "via [::1]:8080",
        "::ffff:192.0.2.9",
    ],
)
def test_scrubber_removes_addresses(text: str) -> None:
    out = scrub_addresses(text)
    assert not re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", out)
    assert "2001:db8" not in out
    assert "[ip]" in out


@pytest.mark.parametrize(
    "text",
    [
        "Uvicorn running on http://0.0.0.0:8047",
        "version 1.2.0 api 1.2.0",
        "at 12:30:45 UTC",
        "c_0123456789ab acc_AAAAAAAAAAAAAAAAAAAAAA",
        "Foo::bar and module::attr are python",
        "2026-10-13T10:11:12+00:00",
    ],
)
def test_scrubber_leaves_innocent_text(text: str) -> None:
    assert scrub_addresses(text) == text


# ---------------------------------------------------------------- the whole flow


@contextmanager
def _capture() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    old = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield stream
    finally:
        root.removeHandler(handler)
        root.setLevel(old)


ADDRESSES = ["203.0.113.7", "198.51.100.23", "2001:db8:abcd:12::77", "192.0.2.55"]


def test_no_raw_ip_in_logs_notices_metrics_database_or_mail(
    tmp_path: Path, make_settings: Callable[..., Settings], make_server: Callable[..., Server]
) -> None:
    """A full flow from several addresses (direct, behind a trusted proxy, IPv6, a LAN one):
    sign-up, password login, wrong passwords, rate-limit hits, signature failures, blocks,
    commits, account management. Everything the server writes or sends is scanned."""
    smtp = smtp_relay(tmp_path)
    box, port, cert = smtp.__enter__()
    ntfy = ntfy_server()
    inbox, url = ntfy.__enter__()
    try:
        settings = make_settings(
            email_verification="enabled",
            smtp_host="127.0.0.1",
            smtp_port=port,
            smtp_user=SMTP_USER,
            smtp_from="UltimateOTP <otp@example.org>",
            smtp_password=SMTP_PASSWORD,
            smtp_ca_file=cert,
            ntfy_url=url,
            signup="enabled",
            trusted_proxies=f"{PROXY}/32",
            ratelimit_enabled=True,
            srp_burst=4,
            block_threshold=6,
            srp_lockout_threshold=3,
        )
        server = make_server(settings)
        with _capture() as stream:
            _flow(server, box)
            assert server.service.alerts.flush()
        logs = stream.getvalue()
        assert logs.count("\n") > 20, "the flow should have logged plenty"
        ntfy_text = json.dumps(inbox.posts)
        mails = "\n".join(
            m.get_payload(decode=True).decode() + str(m["Subject"]) for m in box.messages
        )
        with closing(sqlite3.connect(settings.database_file)) as conn:
            database = "\n".join(
                str(row)
                for table in ("devices", "client_blocks", "server_secrets", "accounts")
                for row in conn.execute(f"SELECT * FROM {table}")  # noqa: S608
            )
        metrics = server.service.metrics.render()
        assert all((logs, ntfy_text, mails, database, metrics))
        for blob_name, blob in (
            ("logs", logs),
            ("ntfy", ntfy_text),
            ("mail", mails),
            ("database", database),
            ("metrics", metrics),
        ):
            for address in [*ADDRESSES, "2001:db8:abcd:12", "2001:db8:abcd"]:
                assert address not in blob, f"{address} found in {blob_name}"
        assert "client_id" in logs
        assert "c_" in ntfy_text
    finally:
        ntfy.__exit__(None, None, None)
        smtp.__exit__(None, None, None)


def _flow(server: Server, box: object) -> None:
    flush = server.service.alerts.flush
    # Sign-up from a public IPv4 address behind the trusted proxy (the address is in XFF).
    with server.client((PROXY, 4000)) as proxied:
        headers = {"X-Forwarded-For": "198.51.100.23"}
        assert (
            proxied.post(
                "/otp/v1/login/email-code", json={"email": EMAIL}, headers=headers
            ).status_code
            == 202
        )
        flush()
        code = box.code_for(EMAIL)  # type: ignore[attr-defined]
        vault = Vault(account_id="")
        device = Device(proxied, "Phone")
        keys = vault.key_bundle(PASSWORD, secrets.token_bytes(32))
        response = device.post(
            "/otp/v1/signup",
            {
                "email": EMAIL,
                "email_code": code,
                "device": {
                    "ed25519_public_key": device.ed25519,
                    "x25519_public_key": device.x25519,
                    "label": "Phone",
                },
                "keys": keys,
            },
            extra_headers=headers,
        )
        assert response.status_code == 201, response.text
        device.device_id = response.json()["device"]["device_id"]
        vault.account_id = response.json()["account_id"]
        assert device.commit(vault, {new_item_id(): {"issuer": "x"}}).status_code == 200
    # IPv6 client: a login with the right password, then wrong ones until the lockout.
    with server.client(("2001:db8:abcd:12::77", 4000)) as v6:
        v6.post("/otp/v1/login/email-code", json={"email": EMAIL})
        flush()
        good = Device(v6, "Laptop").srp_login(EMAIL, PASSWORD, box.code_for(EMAIL))  # type: ignore[attr-defined]
        assert good.status_code == 201, good.text
    with server.client(("203.0.113.7", 4000)) as public:
        for _ in range(8):  # wrong proofs, unknown accounts, rate-limit hits, then a block
            public.post(
                "/otp/v1/login/email-code", json={"email": f"x{secrets.token_hex(3)}@e.org"}
            )
            public.get("/otp/v1/devices", headers={"X-UOTP-Device": "dev_" + "A" * 22})
            public.post("/otp/v1/srp/attributes", json={"email": "nobody@example.org"})
        assert public.get("/otp/v1/server-info").status_code == 429
    # A malformed chain: unknown client, still no address.
    with server.client((PROXY, 4000)) as proxied:
        proxied.get("/otp/v1/server-info", headers={"X-Forwarded-For": "not-an-ip, 192.0.2.55"})
        assert proxied.get("/healthz").status_code == 200
    # The metrics endpoint answers loopback.
    with server.client(("127.0.0.1", 4000)) as local:
        assert local.get("/metrics").status_code == 200


def test_rate_limit_keys_are_client_ids(server: Server) -> None:
    class Spy:
        keys: list[str] = []  # noqa: RUF012

        def hit(self, bucket: str, key: str) -> float | None:
            self.keys.append(key)
            return None

    spy = Spy()
    server.asgi.fastapi.state.limiter = spy
    with server.client(("203.0.113.7", 1)) as client:
        client.post("/otp/v1/srp/attributes", json={"email": "a@example.org"})
    assert spy.keys
    assert all(re.fullmatch(r"c_[0-9a-f]{12}", key) for key in spy.keys)


def test_session_metadata_is_the_daily_id_and_old_addresses_are_scrubbed(
    server: Server, bootstrapped: Bootstrapped
) -> None:
    sessions = bootstrapped.device.get("/otp/v1/sessions").json()["sessions"]
    assert re.fullmatch(r"c_[0-9a-f]{12}", sessions[0]["last_ip"])
    with closing(sqlite3.connect(server.settings.database_file)) as conn:
        rows = conn.execute("SELECT last_ip FROM devices").fetchall()
    assert all(re.fullmatch(r"c_[0-9a-f]{12}", r[0]) for r in rows)


def test_ntfy_notice_names_the_client_id_not_the_address(
    make_settings: Callable[..., Settings], make_server: Callable[..., Server], tmp_path: Path
) -> None:
    with ntfy_server() as (inbox, url):
        server = make_server(make_settings(ntfy_url=url))
        account_id, token, _ = server.service.create_account()
        with server.client(("192.168.1.10", 1)) as client:
            device = Device(client, "Phone")
            keys = Vault(account_id=account_id).key_bundle(PASSWORD, secrets.token_bytes(32))
            assert device.enroll(token, keys).status_code == 201
        assert server.service.alerts.flush()
        body = " ".join(b for _, b in inbox.posts)
        assert "192.168.1.10" not in body
        assert re.search(r"client c_[0-9a-f]{12}", body)
