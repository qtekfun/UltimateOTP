# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sizes of the opaque values, from docs/crypto-format.md v1 §12 (branch feat/android).

The server never looks inside these values; checking their length catches client bugs and keeps
garbage out of the database. A new client format version changes this module only.
"""

KDF_PARAMS_BYTES = (29,)
# A kind 1 wrap alone, or kind 1 followed by kind 3 (crypto-format §4.2).
PASSWORD_WRAP_BYTES = (73, 146)
RECOVERY_WRAP_BYTES = (73,)
SEALED_VAULT_KEY_BYTES = (123,)
# u8 version || u32be key_epoch || nonce[24] || AEAD of 256-byte buckets (16-byte tag).
BLOB_OVERHEAD = 1 + 4 + 24 + 16
BLOB_BUCKET = 256
BLOB_MAX_BUCKETS = 240


def valid_blob_size(size: int) -> bool:
    buckets, remainder = divmod(size - BLOB_OVERHEAD, BLOB_BUCKET)
    return remainder == 0 and 1 <= buckets <= BLOB_MAX_BUCKETS
