# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""A reference client for the tests: device keys, request signing, signed heads, and the
client-side crypto of docs/crypto-format.md v1 (branch feat/android, v1.1 at commit 6f05a51): wraps
(§4), item blobs (§6), sealed vault keys (§5.3). `tests/test_crypto_vectors.py` checks this code
against that document's vectors, so the server tests run on real v1 ciphertext.
"""

import hashlib
import json
import secrets
import struct
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
from nacl import pwhash
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    sodium_pad,
    sodium_unpad,
)
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from ultimateotp import b64, signing, srp

PAD_BUCKET = 256
ALG_ARGON2ID13 = 2
# Cheap Argon2id for tests, inside the reader limits of §4.1 (real clients use 4 / 1 GiB).
TEST_OPSLIMIT = 1
TEST_MEMLIMIT = 8192
WRAP_BYTES = 73


# ---------------------------------------------------------------- client-side crypto (§2-§6)


def kdf(master: bytes, subkey_id: int, context: str) -> bytes:
    """crypto_kdf_derive_from_key (BLAKE2b keyed, salt = LE64(id), personal = ctx)."""
    salt = struct.pack("<Q", subkey_id) + bytes(8)
    person = context.encode() + bytes(8)
    return hashlib.blake2b(b"", digest_size=32, key=master, salt=salt, person=person).digest()


def aead(key: bytes, nonce: bytes, message: bytes, ad: bytes) -> bytes:
    return crypto_aead_xchacha20poly1305_ietf_encrypt(message, ad, nonce, key)


def params_block(opslimit: int, memlimit: int, salt: bytes) -> bytes:
    return bytes([ALG_ARGON2ID13]) + struct.pack(">IQ", opslimit, memlimit) + salt


def derive_kek(password: str, block: bytes) -> bytes:
    opslimit, memlimit = struct.unpack(">IQ", block[1:13])
    data = unicodedata.normalize("NFC", password).encode()
    return pwhash.argon2id.kdf(32, data, block[13:29], opslimit=opslimit, memlimit=memlimit)


def wrap(kind: int, key: bytes, payload: bytes, key_epoch: int, params: bytes) -> bytes:
    nonce = secrets.token_bytes(24)
    ad = b"UOTP-WRAP-v1" + bytes([kind]) + struct.pack(">I", key_epoch) + params
    return b"\x01" + nonce + aead(key, nonce, payload, ad)


def unwrap(kind: int, key: bytes, blob: bytes, key_epoch: int, params: bytes) -> bytes:
    ad = b"UOTP-WRAP-v1" + bytes([kind]) + struct.pack(">I", key_epoch) + params
    return crypto_aead_xchacha20poly1305_ietf_decrypt(blob[25:], ad, blob[1:25], key)


@dataclass
class Vault:
    """What a client holds: the vault key, items in plaintext, the highest version accepted."""

    account_id: str = ""
    vault_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    key_epoch: int = 1
    version: int = 0
    plaintext: dict[str, dict[str, Any]] = field(default_factory=dict)
    blobs: dict[str, tuple[int, bytes]] = field(default_factory=dict)

    def item_ad(self, item_id: str, version: int, key_epoch: int) -> bytes:
        account = self.account_id.encode()
        return (
            b"UOTP-ITEM-v1"
            + bytes([len(account)])
            + account
            + uuid.UUID(item_id).bytes
            + struct.pack(">QI", version, key_epoch)
        )

    def encrypt_item(self, item_id: str, item: dict[str, Any], version: int) -> bytes:
        padded = sodium_pad(json.dumps(item, sort_keys=True).encode(), PAD_BUCKET)
        nonce = secrets.token_bytes(24)
        k_item = kdf(self.vault_key, 1, "uotpitem")
        ad = self.item_ad(item_id, version, self.key_epoch)
        return b"\x01" + struct.pack(">I", self.key_epoch) + nonce + aead(k_item, nonce, padded, ad)

    def decrypt_item(self, item_id: str, blob: bytes, version: int) -> dict[str, Any]:
        assert blob[0] == 1
        (key_epoch,) = struct.unpack(">I", blob[1:5])
        k_item = kdf(self.vault_key, 1, "uotpitem")
        padded = crypto_aead_xchacha20poly1305_ietf_decrypt(
            blob[29:], self.item_ad(item_id, version, key_epoch), blob[5:29], k_item
        )
        result: dict[str, Any] = json.loads(sodium_unpad(padded, PAD_BUCKET))
        return result

    def key_bundle(
        self, password: str, recovery_key: bytes, *, with_srp: bool = True
    ) -> dict[str, Any]:
        """`KeyBundle` of the contract as §4.2 maps it, with the SRP login record."""
        params = params_block(TEST_OPSLIMIT, TEST_MEMLIMIT, secrets.token_bytes(16))
        kek_pw = derive_kek(password, params)
        kek_rk = kdf(recovery_key, 1, "uotprcvy")
        extra: dict[str, Any] = {"srp": srp_setup(kek_pw)} if with_srp else {}
        return {
            **extra,
            "password_kdf": b64.encode(params),
            "password_wrap": b64.encode(
                wrap(1, kek_pw, self.vault_key, self.key_epoch, params)
                + wrap(3, kek_pw, kek_rk, 0, params)
            ),
            "recovery_wrap": b64.encode(wrap(2, kek_rk, self.vault_key, self.key_epoch, b"")),
        }


def login_key(kek_pw: bytes) -> bytes:
    """The SRP password: a subkey of KEK_pw, never the KEK (crypto-format v1.1 §4.4, Ente's
    construction: the first 16 bytes of KDF(KEK_pw, 1, "loginctx"))."""
    return kdf(kek_pw, 1, "loginctx")[:16]


def srp_setup(kek_pw: bytes) -> dict[str, str]:
    user_id = str(uuid.uuid4())
    salt = secrets.token_bytes(16)
    v = srp.verifier(srp.GROUP_4096, salt, user_id.encode(), login_key(kek_pw))
    return {
        "srp_user_id": user_id,
        "srp_salt": b64.encode(salt),
        "srp_verifier": b64.encode(srp.GROUP_4096.pad(v)),
    }


def unwrap_with_password(bundle: dict[str, Any], password: str) -> bytes:
    params = b64.decode(bundle["password_kdf"])
    kind1 = b64.decode(bundle["password_wrap"])[:WRAP_BYTES]
    return unwrap(1, derive_kek(password, params), kind1, bundle["key_epoch"], params)


def grant_plaintext(account_id: str, key_epoch: int, vault_key: bytes) -> bytes:
    return b"UOTP-GRANT-v1" + struct.pack(">I", key_epoch) + vault_key + account_id.encode()


def seal_for(
    recipient_x25519_b64: str, vault_key: bytes, account_id: str = "", key_epoch: int = 1
) -> bytes:
    """§5.3 sealed vault key (123 bytes)."""
    plaintext = grant_plaintext(account_id, key_epoch, vault_key)
    return SealedBox(PublicKey(b64.decode(recipient_x25519_b64))).encrypt(plaintext)


def open_grant(box_key: PrivateKey, sealed: bytes, account_id: str, key_epoch: int) -> bytes:
    plaintext = SealedBox(box_key).decrypt(sealed)
    prefix = b"UOTP-GRANT-v1" + struct.pack(">I", key_epoch)
    assert plaintext.startswith(prefix)
    assert plaintext[len(prefix) + 32 :] == account_id.encode()
    return plaintext[len(prefix) : len(prefix) + 32]


# ---------------------------------------------------------------- device and signing


class Device:
    """A device's keys and an HTTP client that signs every request."""

    def __init__(self, http: httpx.Client | Any, label: str = "Test phone") -> None:
        self.http = http
        self.label = label
        self.signing_key = SigningKey.generate()
        self.box_key = PrivateKey.generate()
        self.device_id: str | None = None
        self.account_id: str | None = None
        self.clock_offset = 0

    @property
    def ed25519(self) -> str:
        return b64.encode(bytes(self.signing_key.verify_key))

    @property
    def x25519(self) -> str:
        return b64.encode(bytes(self.box_key.public_key))

    def sign(self, message: bytes) -> str:
        return b64.encode(self.signing_key.sign(message).signature)

    def headers(
        self,
        method: str,
        target: str,
        body: bytes,
        *,
        device: str | None = None,
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> dict[str, str]:
        device = device or self.device_id or "pending"
        ts = str(timestamp if timestamp is not None else int(time.time()) + self.clock_offset)
        nonce = nonce or b64.encode(secrets.token_bytes(16))
        message = signing.request_message(method, target, device, ts, nonce, body)
        return {
            "X-UOTP-Device": device,
            "X-UOTP-Timestamp": ts,
            "X-UOTP-Nonce": nonce,
            "X-UOTP-Signature": self.sign(message),
        }

    def request(
        self,
        method: str,
        target: str,
        payload: Any = None,
        *,
        bearer: str | None = None,
        extra_headers: dict[str, str] | None = None,
        **sign_args: Any,
    ) -> httpx.Response:
        body = b"" if payload is None else json.dumps(payload).encode()
        headers = self.headers(method, target, body, **sign_args)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        headers.update(extra_headers or {})
        response: httpx.Response = self.http.request(method, target, content=body, headers=headers)
        return response

    def get(self, target: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", target, **kwargs)

    def post(self, target: str, payload: Any = None, **kwargs: Any) -> httpx.Response:
        return self.request("POST", target, payload, **kwargs)

    def put(self, target: str, payload: Any = None, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", target, payload, **kwargs)

    # ------------------------------------------------------------ flows

    def enroll(self, token: str, keys: dict[str, str] | None = None) -> httpx.Response:
        payload: dict[str, Any] = {
            "ed25519_public_key": self.ed25519,
            "x25519_public_key": self.x25519,
            "label": self.label,
        }
        if keys is not None:
            payload["keys"] = keys
        response = self.post("/otp/v1/enroll", payload, bearer=token)
        if response.status_code == 201:
            self.device_id = response.json()["device"]["device_id"]
            self.account_id = response.json()["account_id"]
        return response

    def srp_login(
        self,
        email: str,
        password: str,
        code: str | None = None,
        *,
        tamper: bool = False,
        retry_stale: bool = False,
        stale_first: bool = False,
    ) -> httpx.Response:
        """The whole password login of the contract: attributes, session, verify.

        `stale_first` sends the verify request with a clock an hour ahead and expects
        `stale_request`; the request is then repeated with the right time, as the Android client
        does (`UotpApi.call`, one retry on skew). `retry_stale` instead corrects the clock from the
        `server_time` of a `stale_request` answer and resends the same body.
        """
        group = srp.GROUP_4096
        attributes = self.http.post("/otp/v1/srp/attributes", json={"email": email}).json()
        kek = derive_kek(password, b64.decode(attributes["password_kdf"]))
        a = srp.new_ephemeral()
        payload: dict[str, Any] = {
            "email": email,
            "srp_a": b64.encode(group.pad(srp.client_public(group, a))),
        }
        if code is not None:
            payload["email_code"] = code
        session = self.http.post("/otp/v1/srp/session", json=payload)
        if session.status_code != 200:
            return session
        big_b = int.from_bytes(b64.decode(session.json()["srp_b"]), "big")
        identity = attributes["srp_user_id"].encode()
        m1, key = srp.client_session(
            group, b64.decode(attributes["srp_salt"]), identity, login_key(kek), a, big_b
        )
        if tamper:
            m1 = bytes(32)
        payload = {
            "session_id": session.json()["session_id"],
            "srp_m1": b64.encode(m1),
            "device": {
                "ed25519_public_key": self.ed25519,
                "x25519_public_key": self.x25519,
                "label": self.label,
                "app_version": "1.0.0-test",
            },
        }
        if stale_first:
            first = self.post("/otp/v1/srp/verify", payload, timestamp=int(time.time()) + 3600)
            assert first.json()["code"] == "stale_request"
        response = self.post("/otp/v1/srp/verify", payload)
        if (
            retry_stale
            and response.status_code == 401
            and response.json().get("code") == "stale_request"
        ):
            # What the app does: correct the clock from `server_time` and resend the same body.
            self.clock_offset = int(response.json()["server_time"]) - int(time.time())
            response = self.post("/otp/v1/srp/verify", payload)
        if response.status_code == 201:
            data = response.json()
            big_a = srp.client_public(group, a)
            assert b64.decode(data["srp_m2"]) == srp.server_proof(group, big_a, m1, key)
            self.device_id = data["device"]["device_id"]
            self.account_id = data["account_id"]
        return response

    def reauth_srp(
        self, password: str, *, tamper: bool = False
    ) -> tuple[httpx.Response, dict[str, str] | None]:
        """Step-up by password for the dangerous account actions: the handshake and the proof
        to put in `reauth.srp`."""
        group = srp.GROUP_4096
        a = srp.new_ephemeral()
        start = self.post(
            "/otp/v1/account/reauth/srp",
            {"srp_a": b64.encode(group.pad(srp.client_public(group, a)))},
        )
        if start.status_code != 200:
            return start, None
        data = start.json()
        kek = derive_kek(password, b64.decode(data["password_kdf"]))
        big_b = int.from_bytes(b64.decode(data["srp_b"]), "big")
        m1, _ = srp.client_session(
            group,
            b64.decode(data["srp_salt"]),
            data["srp_user_id"].encode(),
            login_key(kek),
            a,
            big_b,
        )
        if tamper:
            m1 = bytes(32)
        return start, {"session_id": data["session_id"], "srp_m1": b64.encode(m1)}

    def head_signature(
        self, vault: Vault, version: int, key_epoch: int, live: dict[str, tuple[int, bytes]]
    ) -> str:
        manifest = signing.manifest(
            (item_id, v, signing.sha256_b64(blob)) for item_id, (v, blob) in live.items()
        )
        assert self.device_id is not None
        return self.sign(
            signing.head_message(vault.account_id, version, key_epoch, self.device_id, manifest)
        )

    def commit(
        self,
        vault: Vault,
        upserts: dict[str, dict[str, Any]] | None = None,
        deletes: list[str] | None = None,
        *,
        base_version: int | None = None,
    ) -> httpx.Response:
        """Encrypts, signs the new head over the resulting manifest and commits."""
        upserts = upserts or {}
        deletes = deletes or []
        base = vault.version if base_version is None else base_version
        new_version = base + 1
        live = dict(vault.blobs)
        payload_upserts = []
        for item_id, item in upserts.items():
            blob = vault.encrypt_item(item_id, item, new_version)
            live[item_id] = (new_version, blob)
            payload_upserts.append({"item_id": item_id, "blob": b64.encode(blob)})
        for item_id in deletes:
            live.pop(item_id, None)
        payload = {
            "base_version": base,
            "key_epoch": vault.key_epoch,
            "head": {
                "version": new_version,
                "signature": self.head_signature(vault, new_version, vault.key_epoch, live),
            },
            "upserts": payload_upserts,
            "deletes": deletes,
        }
        response = self.post("/otp/v1/vault/commit", payload)
        if response.status_code == 200:
            vault.version = new_version
            vault.blobs = live
            vault.plaintext.update(upserts)
            for item_id in deletes:
                vault.plaintext.pop(item_id, None)
        return response

    def pull(self, vault: Vault, trusted: dict[str, str]) -> None:
        """Pulls changes and applies the client-side anti-rollback rules (design §4.4)."""
        response = self.get(f"/otp/v1/vault?since={vault.version}")
        assert response.status_code == 200, response.text
        data = response.json()
        apply_changes(vault, data, trusted)


class RollbackError(Exception):
    pass


def apply_changes(vault: Vault, data: dict[str, Any], trusted: dict[str, str]) -> None:
    """Accepts a head only if it is not older than what the client holds, is signed by a
    trusted device, and its manifest matches the resulting items."""
    head = data["head"]
    if head["version"] < vault.version:
        raise RollbackError("head older than the highest version seen")
    if head["version"] == vault.version:
        return
    signer = trusted.get(head["signed_by"] or "")
    if signer is None:
        raise RollbackError("head not signed by a trusted device")
    live = dict(vault.blobs)
    for item in data["items"]:
        if item["deleted"]:
            live.pop(item["item_id"], None)
        else:
            live[item["item_id"]] = (item["version"], b64.decode(item["blob"]))
    manifest = signing.manifest(
        (item_id, v, signing.sha256_b64(blob)) for item_id, (v, blob) in live.items()
    )
    message = signing.head_message(
        head["account_id"], head["version"], head["key_epoch"], head["signed_by"], manifest
    )
    try:
        VerifyKey(b64.decode(signer)).verify(message, b64.decode(head["signature"]))
    except Exception as exc:
        raise RollbackError("bad head signature or manifest mismatch") from exc
    vault.version = head["version"]
    vault.key_epoch = head["key_epoch"]
    vault.blobs = live
    vault.plaintext = {i: vault.decrypt_item(i, blob, v) for i, (v, blob) in live.items()}


def new_item_id() -> str:
    return str(uuid.uuid4())
