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


def wrap(kind: int, key: bytes, nonce: bytes, payload: bytes, epoch: int, params: bytes) -> bytes:
    ad = b"UOTP-WRAP-v1" + bytes([kind]) + u32(epoch) + params
    return bytes([1]) + nonce + aead(key, nonce, payload, ad)


def bip39_words(entropy: bytes, wordlist: list[str]) -> list[str]:
    checksum_bits = len(entropy) * 8 // 32
    bits = int.from_bytes(entropy, "big")
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    total = (bits << checksum_bits) | checksum
    n_words = (len(entropy) * 8 + checksum_bits) // 11
    return [wordlist[(total >> (11 * (n_words - 1 - i))) & 0x7FF] for i in range(n_words)]


def sas_words(a_ed: bytes, b_ed: bytes, b_x: bytes, wordlist: list[str]) -> list[str]:
    digest = generichash(b"UOTP-SAS-v1" + a_ed + b_ed + b_x)
    bits = int.from_bytes(digest[:9], "big") >> 6  # first 66 bits
    return [wordlist[(bits >> (11 * (5 - i))) & 0x7FF] for i in range(6)]


def item_ad(account_id: str, item_id: bytes, item_version: int, epoch: int) -> bytes:
    acc = account_id.encode()
    return b"UOTP-ITEM-v1" + bytes([len(acc)]) + acc + item_id + u64(item_version) + u32(epoch)


def sha256_b64u(data: bytes) -> str:
    return b64u(hashlib.sha256(data).digest())


def lines(*parts: object) -> bytes:
    """The contract's signed statements: lines joined by \\n, no trailing newline."""
    return "\n".join(str(p) for p in parts).encode()


def manifest(live: list[tuple[str, int, bytes]]) -> bytes:
    return "".join(f"{i}:{v}:{sha256_b64u(blob)}\n" for i, v, blob in sorted(live)).encode()


# ---- SRP-6a (RFC 5054 group arithmetic; proofs as Ente's server) -----------------------------

def srp_pad(n: int, size: int) -> bytes:
    return n.to_bytes(size, "big")


def srp_session(N: int, g: int, H, I: bytes, P: bytes, s: bytes, a: int, b: int) -> dict:
    size = (N.bit_length() + 7) // 8
    h = lambda *parts: H(b"".join(parts)).digest()
    k = int.from_bytes(h(srp_pad(N, size), srp_pad(g, size)), "big")
    x = int.from_bytes(h(s, h(I + b":" + P)), "big")
    v = pow(g, x, N)
    A = pow(g, a, N)
    B = (k * v + pow(g, b, N)) % N
    u = int.from_bytes(h(srp_pad(A, size), srp_pad(B, size)), "big")
    S_client = pow((B - k * v) % N, a + u * x, N)
    S_server = pow(A * pow(v, u, N) % N, b, N)
    assert S_client == S_server
    M1 = h(srp_pad(A, size), srp_pad(B, size), srp_pad(S_client, size))
    M2 = h(srp_pad(A, size), M1, srp_pad(S_client, size))
    return {"k": k, "x": x, "v": v, "A": A, "B": B, "u": u, "S": S_client, "M1": M1, "M2": M2, "size": size}


def check_rfc5054(rfc: dict) -> None:
    t = rfc["rfc5054_appendix_b"]
    r = srp_session(int(t["N"], 16), t["g"], hashlib.sha1, t["I"].encode(), t["P"].encode(),
                    bytes.fromhex(t["s"]), int(t["a"], 16), int(t["b"], 16))
    for name, key in [("k", "k"), ("x", "x"), ("v", "v"), ("A", "A"), ("B", "B"), ("u", "u"), ("S", "premaster")]:
        assert r[name] == int(t[key], 16), name


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

    account_id = "acc_AAECAwQFBgcICQoLDA0ODw"
    vk = bytes(range(0x40, 0x60))  # 32 bytes
    epoch = 1
    vectors: dict = {"format": "uotp-crypto-vectors", "version": 2,
                     "libsodium": "PyNaCl " + __import__("nacl").__version__}

    # 1. Password KDF (cheap parameters so tests stay fast; real ones are in crypto-format.md).
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    kdf_cases = []
    for pw in ["correct horse battery staple", "Contrase\u00f1a \u20ac \U0001F511 cafe\u0301"]:
        kdf_cases.append({"password": pw, "password_nfc_utf8_hex": h(password_bytes(pw)),
                          "salt_hex": h(salt), "opslimit": 2, "memlimit": 16 * 1024 * 1024,
                          "kek_hex": h(pwhash(pw, salt, 2, 16 * 1024 * 1024))})
    vectors["password_kdf"] = kdf_cases

    # 2. Key wraps (API: password_wrap = kind 1 || kind 3, password_kdf = params, recovery_wrap = kind 2).
    kek_pw = bytes.fromhex(kdf_cases[1]["kek_hex"])
    params = kdf_params_block(2, 16 * 1024 * 1024, salt)
    recovery_key = bytes(range(0xA0, 0xC0))
    kek_rk = kdf(recovery_key, 1, "uotprcvy")
    n1, n2, n3 = (bytes([i]) * 24 for i in (0x11, 0x22, 0x33))
    w1 = wrap(1, kek_pw, n1, vk, epoch, params)
    w2 = wrap(2, kek_rk, n2, vk, epoch, b"")
    w3 = wrap(3, kek_pw, n3, kek_rk, 0, params)
    vectors["wraps"] = {
        "vk_hex": h(vk), "key_epoch": epoch, "kek_pw_hex": h(kek_pw),
        "password_kdf_b64u": b64u(params),
        "password_wrap": {"nonce_hex": h(n1), "wrap_hex": h(w1)},
        "recovery_key_hex": h(recovery_key),
        "recovery_words": bip39_words(recovery_key, wordlist),
        "kek_rk_hex": h(kek_rk),
        "recovery_wrap": {"nonce_hex": h(n2), "wrap_hex": h(w2), "api_b64u": b64u(w2)},
        "recovery_kek_wrap": {"nonce_hex": h(n3), "wrap_hex": h(w3)},
        "api_password_wrap_b64u": b64u(w1 + w3),
    }

    # 3. Item blob.
    k_item = kdf(vk, 1, "uotpitem")
    item_uuid = uuid.UUID("7d444840-9dc0-11d1-b245-5ffdce74fad2")
    plaintext = json.dumps({
        "v": 1, "type": "totp", "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "algorithm": "SHA1",
        "digits": 6, "period": 30, "issuer": "Example", "label": "alice@example.com",
        "tags": [], "notes": "", "favorite": False, "created": 1760000000000,
        "updated": 1760000000000, "updated_by": "dev_AAAAAAAAAAAAAAAAAAAAAA"},
        separators=(",", ":"), sort_keys=True).encode()
    padded = b.sodium_pad(plaintext, 256)
    nonce = bytes([0x5A]) * 24
    ad = item_ad(account_id, item_uuid.bytes, 3, epoch)
    blob = bytes([1]) + u32(epoch) + nonce + aead(k_item, nonce, padded, ad)
    local_ad = item_ad("", item_uuid.bytes, 0, epoch)
    vectors["item"] = {"account_id": account_id, "item_id": str(item_uuid), "item_version": 3,
                       "key_epoch": epoch, "vk_hex": h(vk), "k_item_hex": h(k_item),
                       "plaintext": plaintext.decode(), "padded_len": len(padded),
                       "nonce_hex": h(nonce), "ad_hex": h(ad), "blob_hex": h(blob),
                       "blob_b64u": b64u(blob), "local_ad_hex": h(local_ad)}

    # 4. Devices, signed statements of the contract, SAS.
    sign_a = nacl.signing.SigningKey(bytes([0x01]) * 32)
    box_a = nacl.public.PrivateKey(bytes([0x02]) * 32)
    sign_b = nacl.signing.SigningKey(bytes([0x03]) * 32)
    box_b = nacl.public.PrivateKey(bytes([0x04]) * 32)
    a_ed, a_x = bytes(sign_a.verify_key), bytes(box_a.public_key)
    b_ed, b_x = bytes(sign_b.verify_key), bytes(box_b.public_key)
    dev_a, dev_b = "dev_AAAAAAAAAAAAAAAAAAAAAA", "dev_BBBBBBBBBBBBBBBBBBBBBB"
    cert_b = lines("UOTP-DEVICE-v1", account_id, dev_b, b64u(b_ed), b64u(b_x))
    vectors["devices"] = {
        "account_id": account_id,
        "a": {"device_id": dev_a, "sign_seed_hex": "01" * 32, "ed25519_b64u": b64u(a_ed),
              "x25519_sk_hex": "02" * 32, "x25519_b64u": b64u(a_x)},
        "b": {"device_id": dev_b, "sign_seed_hex": "03" * 32, "ed25519_b64u": b64u(b_ed),
              "x25519_sk_hex": "04" * 32, "x25519_b64u": b64u(b_x)},
        "sas_words": sas_words(a_ed, b_ed, b_x, wordlist),
        "device_certificate_b": {"message": cert_b.decode(),
                                 "signature_by_a_b64u": b64u(sign_a.sign(cert_b).signature)},
    }

    tomb = "00000000-0000-4000-8000-000000000001"
    other = "ffffffff-0000-4000-8000-000000000002"
    other_blob = bytes([1]) + u32(epoch) + bytes(24) + bytes(16 + 256)
    man = manifest([(str(item_uuid), 3, blob), (other, 41, other_blob)])
    head_msg = lines("UOTP-HEAD-v1", account_id, 42, epoch, dev_a, sha256_b64u(man))
    vectors["head"] = {"account_id": account_id, "version": 42, "key_epoch": epoch, "signed_by": dev_a,
                       "live_items": [{"item_id": str(item_uuid), "version": 3, "blob_b64u": b64u(blob)},
                                      {"item_id": other, "version": 41, "blob_b64u": b64u(other_blob)}],
                       "tombstones": [{"item_id": tomb, "version": 40}],
                       "manifest": man.decode(), "empty_manifest_sha256_b64u": sha256_b64u(b""),
                       "message": head_msg.decode(),
                       "signature_by_a_b64u": b64u(sign_a.sign(head_msg).signature)}

    body = b'{"base_version":41}'
    req = lines("UOTP-REQ-v1", "POST", "/otp/v1/vault/commit?x=1", dev_a, "1760000000",
                "AAECAwQFBgcICQoLDA0ODw", sha256_b64u(body))
    vectors["request_signature"] = {"method": "POST", "target": "/otp/v1/vault/commit?x=1",
                                    "device": dev_a, "timestamp": "1760000000",
                                    "nonce": "AAECAwQFBgcICQoLDA0ODw", "body": body.decode(),
                                    "message": req.decode(),
                                    "signature_by_a_b64u": b64u(sign_a.sign(req).signature)}

    # 5. Sealed vault key for b (decrypt-only) and the seal signature by a.
    grant_plain = b"UOTP-GRANT-v1" + u32(epoch) + vk + account_id.encode()
    sealed = nacl.public.SealedBox(box_b.public_key).encrypt(grant_plain)
    seal_msg = lines("UOTP-SEAL-v1", account_id, epoch, dev_b, sha256_b64u(sealed))
    vectors["sealed_vault_key"] = {"plaintext_hex": h(grant_plain), "sealed_b64u": b64u(sealed),
                                   "message": seal_msg.decode(),
                                   "signature_by_a_b64u": b64u(sign_a.sign(seal_msg).signature)}

    # 6. Export file (cheap Argon2id parameters; several chunks to exercise framing).
    export_pw = "export \u00e9t\u00e9"
    export_salt = bytes([0x77]) * 16
    export_key = pwhash(export_pw, export_salt, 2, 16 * 1024 * 1024)
    export_plain = json.dumps({"format": "uotp-export", "version": 1, "exported_at": 1760000000000,
                               "items": [json.loads(plaintext)]},
                              separators=(",", ":"), sort_keys=True).encode()
    chunk = 64
    chunks = [export_plain[i:i + chunk] for i in range(0, len(export_plain), chunk)]
    if len(export_plain) % chunk == 0:
        chunks.append(b"")
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

    # 7. Ente Auth encrypted export (format of Ente's export_widget.dart; decrypt-only).
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

    # 8. SRP login (crypto-format.md §4.4): RFC 5054 Appendix B checks the arithmetic, then the
    #    UltimateOTP parameters (4096-bit group, g = 5, SHA-256) with fixed private values.
    with open("rfc5054.json", encoding="utf-8") as f:
        rfc = json.load(f)
    check_rfc5054(rfc)
    login_subkey = kdf(kek_pw, 1, "loginctx")[:16]
    srp_salt = bytes([0x5C]) * 16
    identity = "3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8"
    a_priv = int.from_bytes(bytes([0xA1]) * 64, "big")
    b_priv = int.from_bytes(bytes([0xB2]) * 64, "big")
    r = srp_session(int(rfc["n4096"], 16), 5, hashlib.sha256, identity.encode(), login_subkey, srp_salt,
                    a_priv, b_priv)
    size = r["size"]
    vectors["srp"] = {
        "rfc5054_appendix_b": rfc["rfc5054_appendix_b"],
        "kek_pw_hex": h(kek_pw), "login_subkey_hex": h(login_subkey), "srp_user_id": identity,
        "srp_salt_hex": h(srp_salt), "a_hex": h(srp_pad(a_priv, 64)), "b_hex": h(srp_pad(b_priv, 64)),
        "verifier_b64u": b64u(srp_pad(r["v"], size)), "A_b64u": b64u(srp_pad(r["A"], size)),
        "B_b64u": b64u(srp_pad(r["B"], size)), "u_hex": h(r["u"].to_bytes(32, "big")),
        "S_hex": h(srp_pad(r["S"], size)), "M1_b64u": b64u(r["M1"]), "M2_b64u": b64u(r["M2"]),
    }

    print(json.dumps(vectors, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
