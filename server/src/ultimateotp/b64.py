# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict base64url without padding (RFC 4648 §5), the only binary encoding of the API."""

import base64
import binascii
import re

_ALPHABET = re.compile(r"^[A-Za-z0-9_-]*$")


class InvalidBase64Error(ValueError):
    """Not canonical unpadded base64url."""


def encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode(text: str) -> bytes:
    """Decodes canonical unpadded base64url; anything else (padding, other alphabets, non-zero
    trailing bits) is refused, so one byte string has exactly one accepted encoding."""
    if not _ALPHABET.match(text) or len(text) % 4 == 1:
        raise InvalidBase64Error("not base64url without padding")
    try:
        data = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise InvalidBase64Error("not base64url without padding") from exc
    if encode(data) != text:
        raise InvalidBase64Error("not canonical base64url")
    return data
