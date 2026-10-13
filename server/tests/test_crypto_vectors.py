# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Interoperability with docs/crypto-format.md v1 (branch feat/android).

`vectors/crypto-v1.json` is a verbatim copy of `docs/crypto-vectors/vectors.json` at feat/android
commit 6f05a51 (crypto-format v1.1). The server's signed statements (`signing.py`), its size
checks (`formats.py`), its SRP (`srp.py`) and the test client's crypto must all reproduce or
accept them.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from tests import client
from ultimateotp import b64, formats, signing

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors" / "crypto-v1.json").read_text(encoding="utf-8")
)


def _sign_key(device: str) -> bytes:
    seed = bytes.fromhex(VECTORS["devices"][device]["sign_seed_hex"])
    return bytes(SigningKey(seed).verify_key)


def test_device_keys_match_the_seeds() -> None:
    for name in ("a", "b"):
        assert b64.encode(_sign_key(name)) == VECTORS["devices"][name]["ed25519_b64u"]


def test_request_signature() -> None:
    v = VECTORS["request_signature"]
    message = signing.request_message(
        v["method"], v["target"], v["device"], v["timestamp"], v["nonce"], v["body"].encode()
    )
    assert message.decode() == v["message"]
    assert signing.verify(b64.encode(_sign_key("a")), message, v["signature_by_a_b64u"])


def test_head_manifest_message_and_signature() -> None:
    v = VECTORS["head"]
    live = [
        (i["item_id"], i["version"], signing.sha256_b64(b64.decode(i["blob_b64u"])))
        for i in v["live_items"]
    ]
    manifest = signing.manifest(live)
    assert manifest.decode() == v["manifest"]
    assert signing.sha256_b64(signing.manifest([])) == v["empty_manifest_sha256_b64u"]
    message = signing.head_message(
        v["account_id"], v["version"], v["key_epoch"], v["signed_by"], manifest
    )
    assert message.decode() == v["message"]
    assert signing.verify(b64.encode(_sign_key("a")), message, v["signature_by_a_b64u"])
    for item in v["live_items"]:
        assert formats.valid_blob_size(len(b64.decode(item["blob_b64u"])))


def test_device_certificate() -> None:
    v = VECTORS["devices"]
    b = v["b"]
    message = signing.device_message(
        v["account_id"], b["device_id"], b["ed25519_b64u"], b["x25519_b64u"]
    )
    assert message.decode() == v["device_certificate_b"]["message"]
    assert signing.verify(
        b64.encode(_sign_key("a")), message, v["device_certificate_b"]["signature_by_a_b64u"]
    )


def test_sealed_vault_key() -> None:
    v = VECTORS["sealed_vault_key"]
    devices = VECTORS["devices"]
    sealed = b64.decode(v["sealed_b64u"])
    assert len(sealed) in formats.SEALED_VAULT_KEY_BYTES
    message = signing.seal_message(devices["account_id"], 1, devices["b"]["device_id"], sealed)
    assert message.decode() == v["message"]
    assert signing.verify(b64.encode(_sign_key("a")), message, v["signature_by_a_b64u"])
    box_b = PrivateKey(bytes.fromhex(devices["b"]["x25519_sk_hex"]))
    vk = bytes.fromhex(VECTORS["wraps"]["vk_hex"])
    assert client.open_grant(box_b, sealed, devices["account_id"], 1) == vk
    assert client.grant_plaintext(devices["account_id"], 1, vk).hex() == v["plaintext_hex"]


def test_wraps_and_their_api_sizes() -> None:
    v = VECTORS["wraps"]
    vk = bytes.fromhex(v["vk_hex"])
    params = b64.decode(v["password_kdf_b64u"])
    password_wrap = b64.decode(v["api_password_wrap_b64u"])
    recovery_wrap = b64.decode(v["recovery_wrap"]["api_b64u"])
    assert len(params) in formats.KDF_PARAMS_BYTES
    assert len(password_wrap) in formats.PASSWORD_WRAP_BYTES
    assert len(recovery_wrap) in formats.RECOVERY_WRAP_BYTES
    kek_pw = bytes.fromhex(v["kek_pw_hex"])
    assert client.unwrap(1, kek_pw, password_wrap[:73], v["key_epoch"], params) == vk
    kek_rk = client.kdf(bytes.fromhex(v["recovery_key_hex"]), 1, "uotprcvy")
    assert kek_rk.hex() == v["kek_rk_hex"]
    assert client.unwrap(2, kek_rk, recovery_wrap, v["key_epoch"], b"") == vk
    assert client.unwrap(3, kek_pw, password_wrap[73:], 0, params) == kek_rk


def test_item_blob() -> None:
    v = VECTORS["item"]
    vault = client.Vault(account_id=v["account_id"], vault_key=bytes.fromhex(v["vk_hex"]))
    assert client.kdf(vault.vault_key, 1, "uotpitem").hex() == v["k_item_hex"]
    ad = vault.item_ad(v["item_id"], v["item_version"], v["key_epoch"])
    assert ad.hex() == v["ad_hex"]
    blob = bytes.fromhex(v["blob_hex"])
    assert formats.valid_blob_size(len(blob))
    assert vault.decrypt_item(v["item_id"], blob, v["item_version"]) == json.loads(v["plaintext"])


@pytest.mark.parametrize(
    ("size", "ok"),
    [(45, False), (45 + 256, True), (45 + 256 * 240, True), (45 + 256 * 241, False), (300, False)],
)
def test_blob_size_rule(size: int, ok: bool) -> None:
    assert formats.valid_blob_size(size) is ok


def test_srp_against_the_android_vector() -> None:
    """crypto-format §4.4 (v1.1): login subkey, verifier, A, B, u, S, K, M1 and M2."""
    from ultimateotp import srp  # noqa: PLC0415

    v = VECTORS["srp"]
    group = srp.GROUP_4096
    kek = bytes.fromhex(v["kek_pw_hex"])
    subkey = client.login_key(kek)
    assert subkey.hex() == v["login_subkey_hex"]
    identity, salt = v["srp_user_id"].encode(), bytes.fromhex(v["srp_salt_hex"])
    verifier = srp.verifier(group, salt, identity, subkey)
    assert b64.encode(group.pad(verifier)) == v["verifier_b64u"]
    a, b = int(v["a_hex"], 16), int(v["b_hex"], 16)
    big_a, big_b = srp.client_public(group, a), srp.server_public(group, verifier, b)
    assert b64.encode(group.pad(big_a)) == v["A_b64u"]
    assert b64.encode(group.pad(big_b)) == v["B_b64u"]
    assert group.Hint(group.pad(big_a), group.pad(big_b)) == int(v["u_hex"], 16)
    premaster = srp.premaster_secret(group, verifier, big_a, b, big_b)
    assert premaster == int(v["S_hex"], 16)
    m1, key = srp.client_session(group, salt, identity, subkey, a, big_b)
    assert key.hex() == v["K_hex"]
    assert b64.encode(m1) == v["M1_b64u"]
    m2 = srp.server_verify(group, identity, salt, verifier, big_a, b, m1)
    assert m2 is not None
    assert b64.encode(m2) == v["M2_b64u"]
    rfc = v["rfc5054_appendix_b"]
    assert int(rfc["N"], 16) == srp.RFC5054_TEST_GROUP.N
