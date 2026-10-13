# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Canonical messages of the contract and Ed25519 verification (PyNaCl / libsodium).

The server only ever *verifies*: it holds no private key and decrypts nothing. Every message is
a fixed list of lines joined by `\\n`, starting with a versioned domain tag, so a signature made
for one purpose can never be replayed as another.
"""

import hashlib
from collections.abc import Iterable

from nacl.exceptions import BadSignatureError, CryptoError
from nacl.signing import VerifyKey

from ultimateotp import b64

REQUEST_TAG = "UOTP-REQ-v1"
HEAD_TAG = "UOTP-HEAD-v1"
SEAL_TAG = "UOTP-SEAL-v1"
DEVICE_TAG = "UOTP-DEVICE-v1"

PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64
NONCE_MIN_BYTES = 16
NONCE_MAX_BYTES = 32


def sha256_b64(data: bytes) -> str:
    return b64.encode(hashlib.sha256(data).digest())


def _lines(*parts: object) -> bytes:
    return "\n".join(str(p) for p in parts).encode("utf-8")


def request_message(
    method: str, target: str, device: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    """`target` is the path as sent plus `?query` when there is one."""
    return _lines(REQUEST_TAG, method.upper(), target, device, timestamp, nonce, sha256_b64(body))


def manifest(live_items: Iterable[tuple[str, int, str]]) -> bytes:
    """`(item_id, version, blob_sha256_b64)` of every live item, in any order."""
    return "".join(f"{i}:{v}:{h}\n" for i, v, h in sorted(live_items)).encode("ascii")


def head_message(
    account_id: str, version: int, key_epoch: int, signed_by: str, manifest_bytes: bytes
) -> bytes:
    return _lines(HEAD_TAG, account_id, version, key_epoch, signed_by, sha256_b64(manifest_bytes))


def seal_message(account_id: str, key_epoch: int, recipient: str, sealed: bytes) -> bytes:
    return _lines(SEAL_TAG, account_id, key_epoch, recipient, sha256_b64(sealed))


def device_message(account_id: str, device_id: str, ed25519_pub: str, x25519_pub: str) -> bytes:
    return _lines(DEVICE_TAG, account_id, device_id, ed25519_pub, x25519_pub)


def verify(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """True only for a valid Ed25519 signature; any malformed input is simply False."""
    try:
        key = b64.decode(public_key_b64)
        signature = b64.decode(signature_b64)
        if len(key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
            return False
        VerifyKey(key).verify(message, signature)
    except (b64.InvalidBase64Error, BadSignatureError, CryptoError, ValueError):
        return False
    return True
