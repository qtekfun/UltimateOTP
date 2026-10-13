# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reference implementation of docs/crypto-format.md and generator of its test vectors.

Uses PyNaCl (the reference libsodium) only, so the vectors come from a different binding than the
Android client's. Run from this directory:

    uv run --no-project --with pynacl==1.6.2 python generate_vectors.py > vectors.json

Everything that libsodium randomizes internally (secretstream headers, sealed-box ephemeral keys)
differs on each run; those vectors are "decrypt-only": a conforming implementation must open them.
Everything else is deterministic and must be reproduced byte for byte.
"""

import base64
import hashlib
import json
import struct
import unicodedata
import uuid

import nacl.bindings as b
import nacl.public
import nacl.pwhash
import nacl.signing

ALG_ARGON2ID13 = 2  # crypto_pwhash_ALG_ARGON2ID13


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def h(data: bytes) -> str:
    return data.hex()


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def u64(n: int) -> bytes:
    return struct.pack(">Q", n)


def generichash(data: bytes, key: bytes = b"", size: int = 32) -> bytes:
    return hashlib.blake2b(data, digest_size=size, key=key).digest()


def kdf(master: bytes, subkey_id: int, context: str, size: int = 32) -> bytes:
    """crypto_kdf_derive_from_key (BLAKE2b): salt = LE64(id) || 0^8, personal = ctx || 0^8."""
    ctx = context.encode()
    assert len(ctx) == 8
    salt = struct.pack("<Q", subkey_id) + bytes(8)
    return hashlib.blake2b(b"", digest_size=size, key=master, salt=salt, person=ctx + bytes(8)).digest()


def password_bytes(password: str) -> bytes:
    return unicodedata.normalize("NFC", password).encode("utf-8")


def pwhash(password: str, salt: bytes, ops: int, mem: int) -> bytes:
    return nacl.pwhash.argon2id.kdf(32, password_bytes(password), salt, opslimit=ops, memlimit=mem)


def aead(key: bytes, nonce: bytes, msg: bytes, ad: bytes) -> bytes:
    return b.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, ad, nonce, key)


def kdf_params_block(ops: int, mem: int, salt: bytes) -> bytes:
    return bytes([ALG_ARGON2ID13]) + u32(ops) + u64(mem) + salt


def wrap(kind: int, key: bytes, nonce: bytes, payload: bytes, vault_id: bytes, epoch: int,
         params: bytes) -> bytes:
    ad = b"uotp/wrap/v1" + bytes([kind]) + vault_id + u32(epoch) + params
    return bytes([1]) + nonce + aead(key, nonce, payload, ad)


def bip39_words(entropy: bytes, wordlist: list[str]) -> list[str]:
    checksum_bits = len(entropy) * 8 // 32
    bits = int.from_bytes(entropy, "big")
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    total = (bits << checksum_bits) | checksum
    n_words = (len(entropy) * 8 + checksum_bits) // 11
    return [wordlist[(total >> (11 * (n_words - 1 - i))) & 0x7FF] for i in range(n_words)]


def sas_words(fpr_a: bytes, fpr_b: bytes, wordlist: list[str]) -> list[str]:
    digest = generichash(b"uotp/sas/v1" + fpr_a + fpr_b)
    bits = int.from_bytes(digest[:9], "big") >> 6  # first 66 bits
    return [wordlist[(bits >> (11 * (5 - i))) & 0x7FF] for i in range(6)]


def device_fpr(sign_pk: bytes, box_pk: bytes) -> bytes:
    return generichash(b"uotp/device/v1" + sign_pk + box_pk)


def item_ad(vault_id: bytes, item_id: bytes, item_version: int, epoch: int) -> bytes:
    return b"uotp/item/v1" + vault_id + item_id + u64(item_version) + u32(epoch)


def items_digest(entries: list[tuple[bytes, int, bytes | None]]) -> bytes:
    acc = b""
    for item_id, version, blob in sorted(entries, key=lambda e: e[0]):
        if blob is None:
            acc += item_id + u64(version) + bytes([1]) + bytes(32)
        else:
            acc += item_id + u64(version) + bytes([0]) + generichash(blob)
    return generichash(acc)


def secretstream_encrypt(key: bytes, chunks: list[bytes], ad: bytes) -> tuple[bytes, bytes]:
    state = b.crypto_secretstream_xchacha20poly1305_state()
    header = b.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    out = b""
    for i, chunk in enumerate(chunks):
        tag = (b.crypto_secretstream_xchacha20poly1305_TAG_FINAL if i == len(chunks) - 1
               else b.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
        out += b.crypto_secretstream_xchacha20poly1305_push(state, chunk, ad, tag)
    return header, out


def main() -> None:
    with open("bip39-english.txt", encoding="utf-8") as f:
        wordlist = [w.strip() for w in f if w.strip()]
    assert len(wordlist) == 2048

    vault_id = uuid.UUID("0f3c8a52-6d1e-4c7b-9a35-2b8e4f6d7c10").bytes
    vk = bytes(range(0x40, 0x60))  # 32 bytes
    epoch = 1
    vectors: dict = {"format": "uotp-crypto-vectors", "version": 1,
                     "libsodium": "PyNaCl " + __import__("nacl").__version__}

    # 1. Password KDF (cheap parameters so tests stay fast; real ones are in crypto-format.md).
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    kdf_cases = []
    for pw in ["correct horse battery staple", "Contraseña € \U0001F511 café"]:
        kdf_cases.append({"password": pw, "password_nfc_utf8_hex": h(password_bytes(pw)),
                          "salt_hex": h(salt), "opslimit": 2, "memlimit": 16 * 1024 * 1024,
                          "kek_hex": h(pwhash(pw, salt, 2, 16 * 1024 * 1024))})
    vectors["password_kdf"] = kdf_cases

    # 2. Key wraps.
    kek_pw = bytes.fromhex(kdf_cases[1]["kek_hex"])
    params = kdf_params_block(2, 16 * 1024 * 1024, salt)
    recovery_key = bytes(range(0xA0, 0xC0))
    kek_rk = kdf(recovery_key, 1, "uotprcvy")
    n1, n2, n3 = (bytes([i]) * 24 for i in (0x11, 0x22, 0x33))
    vectors["wraps"] = {
        "vault_id": str(uuid.UUID(bytes=vault_id)), "vault_id_hex": h(vault_id),
        "vk_hex": h(vk), "key_epoch": epoch, "kek_pw_hex": h(kek_pw),
        "kdf_params_block_hex": h(params),
        "password_wrap": {"kind": 1, "nonce_hex": h(n1),
                          "wrap_hex": h(wrap(1, kek_pw, n1, vk, vault_id, epoch, params))},
        "recovery_key_hex": h(recovery_key),
        "recovery_words": bip39_words(recovery_key, wordlist),
        "kek_rk_hex": h(kek_rk),
        "recovery_wrap": {"kind": 2, "nonce_hex": h(n2),
                          "wrap_hex": h(wrap(2, kek_rk, n2, vk, vault_id, epoch, b""))},
        "recovery_kek_wrap": {"kind": 3, "nonce_hex": h(n3),
                              "wrap_hex": h(wrap(3, kek_pw, n3, kek_rk, vault_id, 0, params))},
    }

    # 3. Subkeys.
    k_item = kdf(vk, 1, "uotpitem")
    k_cert = kdf(vk, 2, "uotpcert")
    vectors["subkeys"] = {"vk_hex": h(vk), "k_item_hex": h(k_item), "k_cert_hex": h(k_cert)}

    # 4. Item blob.
    item_id = uuid.UUID("7d444840-9dc0-11d1-b245-5ffdce74fad2").bytes
    plaintext = json.dumps({
        "v": 1, "type": "totp", "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "algorithm": "SHA1",
        "digits": 6, "period": 30, "issuer": "Example", "label": "alice@example.com",
        "tags": [], "notes": "", "favorite": False, "created": 1760000000000,
        "updated": 1760000000000, "updated_by": "AAAAAAAAAAAAAAAAAAAAAA"},
        separators=(",", ":"), sort_keys=True).encode()
    padded = b.sodium_pad(plaintext, 256)
    nonce = bytes([0x5A]) * 24
    ad = item_ad(vault_id, item_id, 3, epoch)
    blob = bytes([1]) + u32(epoch) + nonce + aead(k_item, nonce, padded, ad)
    vectors["item"] = {"vault_id_hex": h(vault_id), "item_id": str(uuid.UUID(bytes=item_id)),
                       "item_id_hex": h(item_id), "item_version": 3, "key_epoch": epoch,
                       "k_item_hex": h(k_item), "plaintext": plaintext.decode(),
                       "padded_len": len(padded), "nonce_hex": h(nonce), "ad_hex": h(ad),
                       "blob_hex": h(blob), "blob_b64u": b64u(blob)}

    # 5. Devices, certificates, head signature, request signature.
    sign_a = nacl.signing.SigningKey(bytes([0x01]) * 32)
    box_a = nacl.public.PrivateKey(bytes([0x02]) * 32)
    sign_b = nacl.signing.SigningKey(bytes([0x03]) * 32)
    box_b = nacl.public.PrivateKey(bytes([0x04]) * 32)
    fpr_a = device_fpr(bytes(sign_a.verify_key), bytes(box_a.public_key))
    fpr_b = device_fpr(bytes(sign_b.verify_key), bytes(box_b.public_key))
    created = 1760000000
    cert_body = (b"uotp/devcert/v1" + vault_id + bytes(sign_b.verify_key)
                 + bytes(box_b.public_key) + u64(created))
    vectors["devices"] = {
        "a": {"sign_seed_hex": "01" * 32, "sign_pk_hex": h(bytes(sign_a.verify_key)),
              "box_sk_hex": "02" * 32, "box_pk_hex": h(bytes(box_a.public_key)),
              "fpr_hex": h(fpr_a), "device_id": b64u(fpr_a[:16])},
        "b": {"sign_seed_hex": "03" * 32, "sign_pk_hex": h(bytes(sign_b.verify_key)),
              "box_sk_hex": "04" * 32, "box_pk_hex": h(bytes(box_b.public_key)),
              "fpr_hex": h(fpr_b), "device_id": b64u(fpr_b[:16])},
        "sas_words_a_then_b": sas_words(fpr_a, fpr_b, wordlist),
        "cert_b": {"created": created, "body_hex": h(cert_body),
                   "self_sig_hex": h(sign_b.sign(cert_body).signature),
                   "vk_mac_epoch1_hex": h(generichash(u32(1) + cert_body, key=k_cert))},
    }

    tomb_id = uuid.UUID("00000000-0000-4000-8000-000000000001").bytes
    digest = items_digest([(item_id, 3, blob), (tomb_id, 2, None)])
    head_body = b"uotp/head/v1" + vault_id + u64(42) + u32(epoch) + digest
    vectors["head"] = {"entries": [{"item_id": str(uuid.UUID(bytes=item_id)), "item_version": 3,
                                    "blob_hex": h(blob)},
                                   {"item_id": str(uuid.UUID(bytes=tomb_id)), "item_version": 2,
                                    "deleted": True}],
                       "empty_digest_hex": h(items_digest([])),
                       "items_digest_hex": h(digest), "head_version": 42, "key_epoch": epoch,
                       "body_hex": h(head_body),
                       "sig_by_a_hex": h(sign_a.sign(head_body).signature)}

    body = b'{"base_version":41}'
    to_sign = ("uotp/req/v1\nPOST\n/otp/v1/vault/commit?x=1\n1760000000\nAAECAwQFBgcICQoLDA0ODw\n"
               + hashlib.sha256(body).hexdigest()).encode()
    vectors["request_signature"] = {"method": "POST", "path_and_query": "/otp/v1/vault/commit?x=1",
                                    "timestamp": 1760000000, "nonce": "AAECAwQFBgcICQoLDA0ODw",
                                    "body": body.decode(), "string_to_sign": to_sign.decode(),
                                    "sig_by_a_b64u": b64u(sign_a.sign(to_sign).signature)}

    # 6. Device key grant (sealed box: decrypt-only) and its signature.
    grant_plain = b"uotp/grant/v1" + vault_id + u32(epoch) + vk
    sealed = nacl.public.SealedBox(box_b.public_key).encrypt(grant_plain)
    vectors["grant"] = {"plaintext_hex": h(grant_plain), "sealed_to_b_hex": h(sealed),
                        "sig_by_a_hex": h(sign_a.sign(b"uotp/grantsig/v1" + fpr_b + sealed).signature)}

    # 7. Pairing bundle (sealed to b, signed by a).
    bundle = json.dumps({"v": 1, "vault_id": str(uuid.UUID(bytes=vault_id)), "key_epoch": epoch,
                         "vk": b64u(vk), "head_version": 42, "items_digest": b64u(digest)},
                        separators=(",", ":"), sort_keys=True).encode()
    sealed_bundle = nacl.public.SealedBox(box_b.public_key).encrypt(b"uotp/pair/v1" + bundle)
    session_id = "sess-123"
    vectors["pairing"] = {"session_id": session_id, "bundle_json": bundle.decode(),
                          "sealed_to_b_hex": h(sealed_bundle),
                          "sig_by_a_hex": h(sign_a.sign(b"uotp/pairsig/v1" + session_id.encode()
                                                        + fpr_b + sealed_bundle).signature)}

    # 8. Export file (cheap Argon2id parameters; two chunks to exercise framing).
    export_pw = "export été"
    export_salt = bytes([0x77]) * 16
    export_key = pwhash(export_pw, export_salt, 2, 16 * 1024 * 1024)
    export_plain = json.dumps({"format": "uotp-export", "version": 1, "items": [
        json.loads(plaintext)]}, separators=(",", ":"), sort_keys=True).encode()
    chunk = 64
    chunks = [export_plain[i:i + chunk] for i in range(0, len(export_plain), chunk)] or [b""]
    prefix = b"UOTPEXP1" + bytes([ALG_ARGON2ID13]) + u32(2) + u64(16 * 1024 * 1024) + export_salt
    state = b.crypto_secretstream_xchacha20poly1305_state()
    header = b.crypto_secretstream_xchacha20poly1305_init_push(state, export_key)
    file_header = prefix + u32(chunk) + header
    body_ct = b""
    for i, c in enumerate(chunks):
        tag = (b.crypto_secretstream_xchacha20poly1305_TAG_FINAL if i == len(chunks) - 1
               else b.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
        body_ct += b.crypto_secretstream_xchacha20poly1305_push(state, c, file_header, tag)
    vectors["export"] = {"password": export_pw, "chunk_size": chunk, "plaintext": export_plain.decode(),
                         "key_hex": h(export_key), "file_b64": base64.b64encode(file_header + body_ct).decode()}

    # 9. Ente Auth encrypted export (format of Ente's export_widget.dart; decrypt-only).
    ente_pw = "ente pass"
    ente_salt = bytes([0x42]) * 16
    ente_key = nacl.pwhash.argon2id.kdf(32, ente_pw.encode(), ente_salt, opslimit=2,
                                         memlimit=16 * 1024 * 1024)
    ente_plain = ("otpauth://totp/Example:alice@example.com?algorithm=SHA1&digits=6&issuer=Example"
                  "&period=30&secret=JBSWY3DPEHPK3PXP\n"
                  "otpauth://hotp/Bank:bob?algorithm=SHA256&digits=8&issuer=Bank&period=30"
                  "&secret=GEZDGNBVGY3TQOJQ&counter=7\n").encode()
    ente_header, ente_ct = secretstream_encrypt(ente_key, [ente_plain], b"")
    vectors["ente_encrypted_export"] = {
        "password": ente_pw, "plaintext": ente_plain.decode(),
        "file": json.dumps({"version": 1, "kdfParams": {"memLimit": 16 * 1024 * 1024, "opsLimit": 2,
                                                         "salt": base64.b64encode(ente_salt).decode()},
                            "encryptedData": base64.b64encode(ente_ct).decode(),
                            "encryptionNonce": base64.b64encode(ente_header).decode()})}

    print(json.dumps(vectors, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
