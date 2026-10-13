# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Versioned blobs: optimistic concurrency, signed heads and rollback protection."""

import copy
import secrets
import sqlite3
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.client import Device, RollbackError, Vault, apply_changes, new_item_id
from tests.conftest import Bootstrapped, Server, second_device
from ultimateotp import b64
from ultimateotp.settings import Settings

ITEM = {"type": "totp", "issuer": "Example", "secret_b32": "JBSWY3DPEHPK3PXP"}


def _shared_vault(boot: Bootstrapped) -> Vault:
    """A second device's view of the same vault (same key, nothing pulled yet)."""
    return Vault(account_id=boot.account_id, vault_key=boot.vault.vault_key)


def _trusted(*devices: Device) -> dict[str, str]:
    return {d.device_id: d.ed25519 for d in devices if d.device_id}


# ---------------------------------------------------------------- commits and pulls


def test_commit_pull_update_delete(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    a, vault_a = bootstrapped.device, bootstrapped.vault
    b = second_device(server, lan, bootstrapped)
    vault_b = _shared_vault(bootstrapped)
    one, two = new_item_id(), new_item_id()
    assert a.commit(vault_a, {one: ITEM, two: {**ITEM, "issuer": "Other"}}).status_code == 200
    b.pull(vault_b, _trusted(a, b))
    assert vault_b.version == 1
    assert vault_b.plaintext[one]["issuer"] == "Example"

    assert b.commit(vault_b, {one: {**ITEM, "issuer": "Renamed"}}).status_code == 200
    assert b.commit(vault_b, deletes=[two]).status_code == 200
    a.pull(vault_a, _trusted(a, b))
    assert vault_a.version == 3
    assert set(vault_a.plaintext) == {one}
    assert vault_a.plaintext[one]["issuer"] == "Renamed"

    changes = a.get("/otp/v1/vault?since=1").json()["items"]
    assert [(i["item_id"], i["version"], i["deleted"]) for i in changes] == [
        (one, 2, False),
        (two, 3, True),
    ]
    assert changes[1]["blob"] is None


def test_concurrent_commits_conflict(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    a, vault_a = bootstrapped.device, bootstrapped.vault
    b = second_device(server, lan, bootstrapped)
    vault_b = _shared_vault(bootstrapped)
    assert a.commit(vault_a, {new_item_id(): ITEM}).status_code == 200
    # B still believes the vault is at version 0.
    stale = b.commit(vault_b, {new_item_id(): ITEM})
    assert stale.status_code == 409
    problem = stale.json()
    assert problem["code"] == "version_conflict"
    assert problem["head"]["version"] == 1
    assert problem["head"]["signed_by"] == a.device_id
    # Pull, merge, retry: accepted on top of A's commit.
    b.pull(vault_b, _trusted(a, b))
    retry = b.commit(vault_b, {new_item_id(): ITEM})
    assert retry.status_code == 200
    assert retry.json()["version"] == 2
    assert len(vault_b.plaintext) == 2


def test_only_one_of_many_racing_commits_wins(server: Server, bootstrapped: Bootstrapped) -> None:
    """Eight clients commit on the same base at the same time, each on its own connection:
    BEGIN IMMEDIATE serializes them and exactly one wins."""
    base = copy.deepcopy(bootstrapped.vault)
    barrier = threading.Barrier(8)

    def attempt(_: int) -> int:
        with server.client() as client:
            dev = copy.copy(bootstrapped.device)
            dev.http = client
            barrier.wait()
            return dev.commit(copy.deepcopy(base), {new_item_id(): ITEM}).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = sorted(pool.map(attempt, range(8)))
    assert codes == [200] + [409] * 7


def test_key_epoch_must_match(bootstrapped: Bootstrapped) -> None:
    vault = copy.deepcopy(bootstrapped.vault)
    vault.key_epoch = 2
    response = bootstrapped.device.commit(vault, {new_item_id(): ITEM})
    assert response.status_code == 409
    assert response.json()["code"] == "key_epoch_conflict"


def _raw_commit(dev: Device, vault: Vault, **overrides: Any) -> Any:
    item = new_item_id()
    blob = vault.encrypt_item(item, ITEM, vault.version + 1)
    live = {**vault.blobs, item: (vault.version + 1, blob)}
    payload: dict[str, Any] = {
        "base_version": vault.version,
        "key_epoch": vault.key_epoch,
        "head": {
            "version": vault.version + 1,
            "signature": dev.head_signature(vault, vault.version + 1, vault.key_epoch, live),
        },
        "upserts": [{"item_id": item, "blob": b64.encode(blob)}],
        "deletes": [],
    }
    payload.update(overrides)
    return dev.post("/otp/v1/vault/commit", payload)


def test_version_must_be_base_plus_one(bootstrapped: Bootstrapped) -> None:
    dev, vault = bootstrapped.device, bootstrapped.vault
    response = _raw_commit(dev, vault, head={"version": 5, "signature": "A" * 86})
    assert response.status_code == 400
    assert response.json()["code"] == "bad_version"


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"upserts": [], "deletes": []}, "empty_commit"),
        ({"deletes": ["00000000-0000-4000-8000-000000000000"]}, "unknown_item"),
        ({"upserts": [{"item_id": "not-a-uuid", "blob": "AAAA"}]}, "invalid_request"),
        (
            {"upserts": [{"item_id": "00000000-0000-4000-8000-000000000000", "blob": "AA=="}]},
            "invalid_request",
        ),
    ],
)
def test_bad_change_sets(bootstrapped: Bootstrapped, change: dict[str, Any], code: str) -> None:
    response = _raw_commit(bootstrapped.device, bootstrapped.vault, **change)
    assert response.status_code == 400
    assert response.json()["code"] == code


def test_duplicate_items_are_refused(bootstrapped: Bootstrapped) -> None:
    item = new_item_id()
    upsert = {"item_id": item, "blob": "AAAA"}
    response = _raw_commit(
        bootstrapped.device, bootstrapped.vault, upserts=[upsert], deletes=[item]
    )
    assert response.json()["code"] == "duplicate_item"


def test_blob_size_limit(bootstrapped: Bootstrapped) -> None:
    big = b64.encode(secrets.token_bytes(64 * 1024 + 1))
    upsert = {"item_id": new_item_id(), "blob": big}
    response = _raw_commit(bootstrapped.device, bootstrapped.vault, upserts=[upsert])
    assert response.status_code == 400


def test_item_count_limit(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(max_items=2))
    account_id, token, _ = server.service.create_account()
    with server.client() as client:
        dev = Device(client)
        vault = Vault(account_id=account_id)
        dev.enroll(token, vault.key_bundle("pw", secrets.token_bytes(32)))
        assert dev.commit(vault, {new_item_id(): ITEM, new_item_id(): ITEM}).status_code == 200
        over = dev.commit(vault, {new_item_id(): ITEM})
    assert over.json()["code"] == "too_many_items"


def test_body_size_limit(
    make_settings: Callable[..., Settings], make_server: Callable[[Settings], Server]
) -> None:
    server = make_server(make_settings(max_body_bytes=64 * 1024))
    with server.client() as client:
        response = client.post("/otp/v1/vault/commit", content=b"x" * (65 * 1024))
    assert response.status_code == 413
    assert response.json()["code"] == "body_too_large"


# ---------------------------------------------------------------- signed heads


def test_head_signed_over_a_wrong_manifest_is_refused(bootstrapped: Bootstrapped) -> None:
    dev, vault = bootstrapped.device, bootstrapped.vault
    assert dev.commit(vault, {new_item_id(): ITEM}).status_code == 200
    # Sign a manifest that omits the existing item (as if the device wanted to hide it).
    item = new_item_id()
    blob = vault.encrypt_item(item, ITEM, 2)
    sig = dev.head_signature(vault, 2, 1, {item: (2, blob)})
    response = _raw_commit(
        dev,
        vault,
        head={"version": 2, "signature": sig},
        upserts=[{"item_id": item, "blob": b64.encode(blob)}],
    )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_head_signature"


def test_head_signed_by_another_device_is_refused(
    server: Server, lan: TestClient, bootstrapped: Bootstrapped
) -> None:
    a, vault = bootstrapped.device, bootstrapped.vault
    b = second_device(server, lan, bootstrapped)
    item = new_item_id()
    blob = vault.encrypt_item(item, ITEM, 1)
    sig_by_a = a.head_signature(vault, 1, 1, {item: (1, blob)})
    response = _raw_commit(
        b,
        vault,
        head={"version": 1, "signature": sig_by_a},
        upserts=[{"item_id": item, "blob": b64.encode(blob)}],
    )
    assert response.json()["code"] == "invalid_head_signature"


def test_server_stores_the_signed_head(bootstrapped: Bootstrapped) -> None:
    dev, vault = bootstrapped.device, bootstrapped.vault
    dev.commit(vault, {new_item_id(): ITEM})
    head = dev.get("/otp/v1/vault").json()["head"]
    assert head["version"] == 1
    assert head["signed_by"] == dev.device_id
    assert len(b64.decode(head["signature"])) == 64


# ---------------------------------------------------------------- rollback protection


def test_server_never_moves_backwards(bootstrapped: Bootstrapped) -> None:
    """A captured old commit, re-signed, cannot rewind the vault: it is a conflict."""
    dev, vault = bootstrapped.device, bootstrapped.vault
    old = copy.deepcopy(vault)
    for _ in range(3):
        assert dev.commit(vault, {new_item_id(): ITEM}).status_code == 200
    rewind = dev.commit(old, {new_item_id(): ITEM})
    assert rewind.status_code == 409
    assert dev.get("/otp/v1/vault").json()["head"]["version"] == 3


def test_client_refuses_an_older_head(bootstrapped: Bootstrapped) -> None:
    """A malicious server (or a restored backup) serving an old, validly signed state."""
    dev, vault = bootstrapped.device, bootstrapped.vault
    dev.commit(vault, {new_item_id(): ITEM})
    old_state = dev.get("/otp/v1/vault?since=0").json()
    dev.commit(vault, {new_item_id(): ITEM})
    assert vault.version == 2
    with pytest.raises(RollbackError, match="older"):
        apply_changes(vault, old_state, bootstrapped.trusted)


def test_client_refuses_a_head_from_an_unknown_signer(bootstrapped: Bootstrapped) -> None:
    dev, vault = bootstrapped.device, bootstrapped.vault
    dev.commit(vault, {new_item_id(): ITEM})
    fresh = Vault(account_id=vault.account_id, vault_key=vault.vault_key)
    state = dev.get("/otp/v1/vault?since=0").json()
    with pytest.raises(RollbackError, match="trusted"):
        apply_changes(fresh, state, trusted={})
    apply_changes(fresh, state, bootstrapped.trusted)
    assert fresh.version == 1


def test_client_detects_a_dropped_or_swapped_item(
    server: Server, bootstrapped: Bootstrapped
) -> None:
    """The server withholds an item, or serves an older blob of it: the manifest no longer
    matches the signed head."""
    dev, vault = bootstrapped.device, bootstrapped.vault
    one, two = new_item_id(), new_item_id()
    dev.commit(vault, {one: ITEM, two: ITEM})
    state = dev.get("/otp/v1/vault?since=0").json()

    dropped = copy.deepcopy(state)
    dropped["items"] = [i for i in dropped["items"] if i["item_id"] != two]
    with pytest.raises(RollbackError, match="manifest"):
        apply_changes(
            Vault(account_id=vault.account_id, vault_key=vault.vault_key),
            dropped,
            bootstrapped.trusted,
        )

    swapped = copy.deepcopy(state)
    swapped["items"][0]["blob"] = b64.encode(vault.encrypt_item(one, ITEM, 1))
    with pytest.raises(RollbackError, match="manifest"):
        apply_changes(
            Vault(account_id=vault.account_id, vault_key=vault.vault_key),
            swapped,
            bootstrapped.trusted,
        )


def test_tampered_database_row_is_detected_by_clients(
    server: Server, bootstrapped: Bootstrapped
) -> None:
    """Someone with write access to the SQLite file rewinds the head row."""
    dev, vault = bootstrapped.device, bootstrapped.vault
    dev.commit(vault, {new_item_id(): ITEM})
    dev.commit(vault, {new_item_id(): ITEM})
    with closing(sqlite3.connect(server.settings.database_file)) as conn, conn:
        conn.execute("UPDATE accounts SET vault_version = 1")
    state = dev.get("/otp/v1/vault?since=0").json()
    with pytest.raises(RollbackError):
        apply_changes(vault, state, bootstrapped.trusted)
