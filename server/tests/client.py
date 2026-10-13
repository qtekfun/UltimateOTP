# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""A reference client for the tests: device keys, request signing, signed heads, and the
client-side crypto (vault key, wraps, item encryption).

The crypto here follows docs/design.md §3 (Argon2id, XChaCha20-Poly1305, sealed boxes) with
libsodium through PyNaCl. It stands in for `docs/crypto-format.md` (owned by the Android work)
until that document exists: the server treats all of it as opaque bytes either way.
"""

import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
from nacl import pwhash
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.public import PrivateKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from ultimateotp import b64, signing

PAD_BUCKET = 256


# ---------------------------------------------------------------- client-side crypto


def aead_encrypt(key: bytes, plaintext: bytes, ad: bytes) -> bytes:
    nonce = secrets.token_bytes(24)
    return b"\x01" + nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)


def aead_decrypt(key: bytes, blob: bytes, ad: bytes) -> bytes:
    assert blob[0] == 1
    return crypto_aead_xchacha20poly1305_ietf_decrypt(blob[25:], ad, blob[1:25], key)


def derive_kek(password: str, salt: bytes) -> bytes:
    # Minimum limits keep the tests fast; real clients use MODERATE or more (design §3.1).
    return pwhash.argon2id.kdf(
        32,
        password.encode(),
        salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MIN,
        memlimit=pwhash.argon2id.MEMLIMIT_MIN,
    )


def pad(data: bytes) -> bytes:
    size = (len(data) // PAD_BUCKET + 1) * PAD_BUCKET
    return data + b"\x80" + b"\x00" * (size - len(data) - 1)


def unpad(data: bytes) -> bytes:
    return data[: data.rindex(b"\x80")]


@dataclass
class Vault:
    """What a client holds: the vault key, items in plaintext, the highest version accepted."""

    account_id: str = ""
    vault_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    key_epoch: int = 1
    version: int = 0
    plaintext: dict[str, dict[str, Any]] = field(default_factory=dict)
    blobs: dict[str, tuple[int, bytes]] = field(default_factory=dict)

    def item_ad(self, item_id: str, version: int) -> bytes:
        return f"UOTP-ITEM-v1\n{self.account_id}\n{item_id}\n{version}".encode()

    def encrypt_item(self, item_id: str, item: dict[str, Any], version: int) -> bytes:
        plaintext = pad(json.dumps(item, sort_keys=True).encode())
        return aead_encrypt(self.vault_key, plaintext, self.item_ad(item_id, version))

    def decrypt_item(self, item_id: str, blob: bytes, version: int) -> dict[str, Any]:
        data = aead_decrypt(self.vault_key, blob, self.item_ad(item_id, version))
        result: dict[str, Any] = json.loads(unpad(data))
        return result

    def key_bundle(self, password: str, recovery_key: bytes) -> dict[str, str]:
        salt = secrets.token_bytes(16)
        kek = derive_kek(password, salt)
        params = json.dumps({"alg": "argon2id", "salt": b64.encode(salt), "ops": 1}).encode()
        return {
            "password_wrap": b64.encode(aead_encrypt(kek, self.vault_key, b"UOTP-WRAP-pw")),
            "password_kdf": b64.encode(params),
            "recovery_wrap": b64.encode(
                aead_encrypt(recovery_key, self.vault_key, b"UOTP-WRAP-rk")
            ),
        }


def unwrap_with_password(bundle: dict[str, Any], password: str) -> bytes:
    params = json.loads(b64.decode(bundle["password_kdf"]))
    kek = derive_kek(password, b64.decode(params["salt"]))
    return aead_decrypt(kek, b64.decode(bundle["password_wrap"]), b"UOTP-WRAP-pw")


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


def seal_for(recipient_x25519_b64: str, vault_key: bytes) -> bytes:
    from nacl.public import PublicKey  # noqa: PLC0415

    return SealedBox(PublicKey(b64.decode(recipient_x25519_b64))).encrypt(vault_key)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
