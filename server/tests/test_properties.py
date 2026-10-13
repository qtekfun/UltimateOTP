# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Properties of the signed statements and the strict encodings (Hypothesis).

The example-based tests (`test_crypto_vectors.py`) pin the bytes of one message each. These tests
state what must hold for *every* input: a statement is injective in its fields (two different
requests never share the signed bytes), the manifest does not depend on item order, a signature
only verifies for the exact message and key, and `verify` never raises on hostile input.
"""

import re

from hypothesis import given, settings
from hypothesis import strategies as st
from nacl.signing import SigningKey

from tests.client import params_block
from ultimateotp import b64, formats, signing

# Header-safe and path-safe values: no line break (the statements are newline-joined, so a
# value containing one would be ambiguous, which is why the request parser never produces them).
line = st.text(
    alphabet=st.characters(blacklist_characters="\n\r", blacklist_categories=("Cs",)),
    max_size=40,
)
token = st.from_regex(r"[A-Za-z0-9_-]{1,40}", fullmatch=True)
body = st.binary(max_size=512)
sha = st.binary(min_size=32, max_size=32).map(b64.encode)
item = st.tuples(token, st.integers(min_value=1, max_value=2**31), sha)

REQUEST_FIELDS = st.tuples(
    st.sampled_from(["GET", "POST", "PUT", "DELETE"]), line, token, token, token, body
)


@given(REQUEST_FIELDS)
def test_request_message_is_deterministic_and_tagged(fields: tuple) -> None:
    method, target, device, ts, nonce, payload = fields
    message = signing.request_message(method, target, device, ts, nonce, payload)
    assert message == signing.request_message(method, target, device, ts, nonce, payload)
    lines = message.decode().split("\n")
    assert lines[0] == signing.REQUEST_TAG
    assert len(lines) == 7  # tag, method, target, device, timestamp, nonce, body hash
    assert lines[-1] == signing.sha256_b64(payload)


@given(REQUEST_FIELDS, REQUEST_FIELDS)
def test_request_message_is_injective_in_its_fields(a: tuple, b: tuple) -> None:
    ma = signing.request_message(*a)
    mb = signing.request_message(*b)
    same_fields = (a[0].upper(), *a[1:]) == (b[0].upper(), *b[1:])
    assert (ma == mb) == same_fields


@given(REQUEST_FIELDS, st.binary(min_size=1, max_size=8))
def test_request_message_binds_the_body(fields: tuple, extra: bytes) -> None:
    method, target, device, ts, nonce, payload = fields
    assert signing.request_message(method, target, device, ts, nonce, payload) != (
        signing.request_message(method, target, device, ts, nonce, payload + extra)
    )


@given(st.lists(item, max_size=30, unique_by=lambda i: i[0]), st.randoms(use_true_random=False))
def test_manifest_ignores_order_and_is_one_line_per_item(items: list, rnd: object) -> None:
    shuffled = list(items)
    rnd.shuffle(shuffled)  # type: ignore[attr-defined]
    manifest = signing.manifest(items)
    assert manifest == signing.manifest(shuffled)
    assert manifest.count(b"\n") == len(items)
    assert manifest == b"" or manifest.endswith(b"\n")


@given(
    st.lists(item, max_size=10, unique_by=lambda i: i[0]),
    st.lists(item, max_size=10, unique_by=lambda i: i[0]),
)
def test_manifest_distinguishes_item_sets(a: list, b: list) -> None:
    assert (signing.manifest(a) == signing.manifest(b)) == (sorted(a) == sorted(b))


@given(
    token,
    st.integers(0, 2**31),
    st.integers(1, 2**31),
    token,
    st.lists(item, max_size=5, unique_by=lambda i: i[0]),
)
def test_head_message_binds_every_field(
    account: str, version: int, epoch: int, signer: str, items: list
) -> None:
    manifest = signing.manifest(items)
    base = signing.head_message(account, version, epoch, signer, manifest)
    assert base != signing.head_message(account + "x", version, epoch, signer, manifest)
    assert base != signing.head_message(account, version + 1, epoch, signer, manifest)
    assert base != signing.head_message(account, version, epoch + 1, signer, manifest)
    assert base != signing.head_message(account, version, epoch, signer + "x", manifest)
    other = signing.manifest([*items, ("zzz-extra", 1, signing.sha256_b64(b"x"))])
    assert base != signing.head_message(account, version, epoch, signer, other)


@given(st.binary(min_size=32, max_size=32), st.binary(max_size=200), st.data())
@settings(max_examples=60)
def test_signature_verifies_only_for_the_exact_message_and_key(
    seed: bytes, message: bytes, data: st.DataObject
) -> None:
    key = SigningKey(seed)
    public = b64.encode(bytes(key.verify_key))
    signature = b64.encode(key.sign(message).signature)
    assert signing.verify(public, message, signature)

    # Any single flipped bit of the message, the signature or the key is refused.
    flip = data.draw(st.integers(0, 7))
    if message:
        at = data.draw(st.integers(0, len(message) - 1))
        tampered = bytearray(message)
        tampered[at] ^= 1 << flip
        assert not signing.verify(public, bytes(tampered), signature)
    raw_signature = bytearray(b64.decode(signature))
    raw_signature[data.draw(st.integers(0, 63))] ^= 1 << flip
    assert not signing.verify(public, message, b64.encode(bytes(raw_signature)))
    raw_key = bytearray(b64.decode(public))
    raw_key[data.draw(st.integers(0, 31))] ^= 1 << flip
    assert not signing.verify(b64.encode(bytes(raw_key)), message, signature)


@given(st.text(max_size=120), st.text(max_size=120), st.binary(max_size=64))
def test_verify_never_raises_on_hostile_input(key: str, signature: str, message: bytes) -> None:
    assert signing.verify(key, message, signature) is False


@given(st.binary(max_size=300))
def test_base64url_round_trip_is_canonical(data: bytes) -> None:
    text = b64.encode(data)
    assert re.fullmatch(r"[A-Za-z0-9_-]*", text)
    assert b64.decode(text) == data


@given(st.text(max_size=60))
def test_base64url_accepts_only_the_canonical_encoding(text: str) -> None:
    try:
        data = b64.decode(text)
    except b64.InvalidBase64Error:
        return
    assert b64.encode(data) == text  # one byte string, exactly one accepted spelling


@given(st.integers(min_value=-10, max_value=100_000))
def test_blob_size_rule_matches_its_definition(size: int) -> None:
    expected = any(
        size == formats.BLOB_OVERHEAD + n * formats.BLOB_BUCKET
        for n in range(1, formats.BLOB_MAX_BUCKETS + 1)
    )
    assert formats.valid_blob_size(size) == expected


@given(st.integers(1, 4096), st.integers(8192, 1 << 30), st.binary(min_size=16, max_size=16))
def test_any_password_kdf_inside_the_reader_limits_is_a_29_byte_block(
    ops: int, mem: int, salt: bytes
) -> None:
    """What `PasswordKdf` writes (Kotlin, any rung of the ladder) is what `password_kdf` carries."""
    block = params_block(ops, mem, salt)
    assert len(block) in formats.KDF_PARAMS_BYTES
    assert block[0] == 2  # crypto_pwhash_ALG_ARGON2ID13
    assert int.from_bytes(block[1:5], "big") == ops
    assert int.from_bytes(block[5:13], "big") == mem
