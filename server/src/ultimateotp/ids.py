# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Random identifiers and secrets (contract: "Conventions")."""

import hashlib
import re
import secrets

from ultimateotp import b64

ACCOUNT_PREFIX = "acc_"
DEVICE_PREFIX = "dev_"
PAIRING_PREFIX = "pair_"
ENROLLMENT_TOKEN_PREFIX = "uoe_"  # noqa: S105 - a public prefix, not a secret
PAIRING_SECRET_PREFIX = "uop_"  # noqa: S105 - a public prefix, not a secret

ACCOUNT_ID = re.compile(r"^acc_[A-Za-z0-9_-]{22}$")
DEVICE_ID = re.compile(r"^dev_[A-Za-z0-9_-]{22}$")
PAIRING_ID = re.compile(r"^pair_[A-Za-z0-9_-]{22}$")
ENROLLMENT_TOKEN = re.compile(r"^uoe_[A-Za-z0-9_-]{43}$")
PAIRING_SECRET = re.compile(r"^uop_[A-Za-z0-9_-]{43}$")
ITEM_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _random(prefix: str, size: int) -> str:
    return prefix + b64.encode(secrets.token_bytes(size))


def new_account_id() -> str:
    return _random(ACCOUNT_PREFIX, 16)


def new_device_id() -> str:
    return _random(DEVICE_PREFIX, 16)


def new_pairing_id() -> str:
    return _random(PAIRING_PREFIX, 16)


def new_enrollment_token() -> str:
    return _random(ENROLLMENT_TOKEN_PREFIX, 32)


def new_pairing_secret() -> str:
    return _random(PAIRING_SECRET_PREFIX, 32)


def secret_hash(secret: str) -> str:
    """What the database keeps of a token or pairing secret (256-bit random: no KDF needed)."""
    return hashlib.sha256(secret.encode("ascii")).hexdigest()
