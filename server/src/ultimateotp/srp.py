# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""SRP-6a (RFC 5054 arithmetic), server side, plus the client side the tests need.

Why our own ~100 lines and not a library: the server needs only modular exponentiation (Python
integers) and SHA-256 (stdlib); a dependency would add a C extension or global configuration for
that. The arithmetic is checked against the RFC 5054 Appendix B test vectors
(`tests/test_srp.py`), and the group is the RFC 5054 4096-bit group (the RFC 3526 prime, g = 5),
with SHA-256, as Ente uses. Every value is a plain integer or bytes: nothing here is stored.

Definitions (contract, "SRP login"). `PAD(x)` = big-endian, left-padded to the byte length of N.

    k  = H(N || PAD(g))
    x  = H(s || H(I || ":" || P))          client only; P = the login subkey bytes
    v  = g^x mod N                         uploaded by the client, stored by the server
    B  = (k*v + g^b) mod N                 b: 256 random bits, kept 5 minutes server side
    u  = H(PAD(A) || PAD(B))               refused when 0
    S  = (A * v^u)^b mod N                 refused when A mod N == 0
    K  = H(PAD(S))
    M1 = H((H(N) xor H(PAD(g))) || H(I) || s || PAD(A) || PAD(B) || K)
    M2 = H(PAD(A) || M1 || K)
"""

import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass

HashFn = Callable[[bytes], bytes]


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sha1(data: bytes) -> bytes:
    return hashlib.sha1(data, usedforsecurity=False).digest()


@dataclass(frozen=True)
class Group:
    N: int
    g: int
    hash: HashFn

    @property
    def size(self) -> int:
        return (self.N.bit_length() + 7) // 8

    def pad(self, value: int) -> bytes:
        return value.to_bytes(self.size, "big")

    def H(self, *parts: bytes) -> bytes:  # noqa: N802 - the RFC's name
        return self.hash(b"".join(parts))

    def Hint(self, *parts: bytes) -> int:  # noqa: N802
        return int.from_bytes(self.H(*parts), "big")

    @property
    def k(self) -> int:
        return self.Hint(self.pad(self.N), self.pad(self.g))


_N_4096 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
    16,
)
# RFC 5054 Appendix A 1024-bit group: only for the RFC's own test vectors (SHA-1).
_N_1024 = int(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576"
    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1"
    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC"
    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
    16,
)

GROUP_4096 = Group(_N_4096, 5, _sha256)
RFC5054_TEST_GROUP = Group(_N_1024, 2, _sha1)
EPHEMERAL_BITS = 256


# ---------------------------------------------------------------- client side (tests, CLI)


def private_key(group: Group, salt: bytes, identity: bytes, password: bytes) -> int:
    return group.Hint(salt, group.H(identity + b":" + password))


def verifier(group: Group, salt: bytes, identity: bytes, password: bytes) -> int:
    return pow(group.g, private_key(group, salt, identity, password), group.N)


def client_public(group: Group, a: int) -> int:
    return pow(group.g, a, group.N)


def client_session(  # noqa: PLR0913, PLR0917 - the protocol's inputs
    group: Group, salt: bytes, identity: bytes, password: bytes, a: int, server_b: int
) -> tuple[bytes, bytes]:
    """(M1, K) for the client."""
    big_a = client_public(group, a)
    u = group.Hint(group.pad(big_a), group.pad(server_b))
    x = private_key(group, salt, identity, password)
    base = (server_b - group.k * pow(group.g, x, group.N)) % group.N
    premaster = pow(base, a + u * x, group.N)
    key = group.H(group.pad(premaster))
    return proof(group, identity, salt, big_a, server_b, key), key


# ---------------------------------------------------------------- shared and server side


def proof(  # noqa: PLR0913, PLR0917 - the protocol's inputs
    group: Group, identity: bytes, salt: bytes, big_a: int, big_b: int, key: bytes
) -> bytes:
    hn, hg = group.H(group.pad(group.N)), group.H(group.pad(group.g))
    xor = bytes(x ^ y for x, y in zip(hn, hg, strict=True))
    return group.H(xor, group.H(identity), salt, group.pad(big_a), group.pad(big_b), key)


def server_proof(group: Group, big_a: int, m1: bytes, key: bytes) -> bytes:
    return group.H(group.pad(big_a), m1, key)


def new_ephemeral() -> int:
    return secrets.randbits(EPHEMERAL_BITS) | 1


def server_public(group: Group, v: int, b: int) -> int:
    return (group.k * v + pow(group.g, b, group.N)) % group.N


def premaster_secret(group: Group, v: int, big_a: int, b: int, big_b: int) -> int:
    u = group.Hint(group.pad(big_a), group.pad(big_b))
    if u == 0:
        raise ValueError("u is zero")
    return pow(big_a * pow(v, u, group.N) % group.N, b, group.N)


def valid_public(group: Group, value: int) -> bool:
    return 0 < value < group.N and value % group.N != 0


def server_verify(  # noqa: PLR0913, PLR0917 - the protocol's inputs
    group: Group, identity: bytes, salt: bytes, v: int, big_a: int, b: int, m1: bytes
) -> bytes | None:
    """M2 when the client's M1 proves the password, else None (constant-time compare)."""
    if not valid_public(group, big_a):
        return None
    big_b = server_public(group, v, b)
    try:
        premaster = premaster_secret(group, v, big_a, b, big_b)
    except ValueError:
        return None
    key = group.H(group.pad(premaster))
    expected = proof(group, identity, salt, big_a, big_b, key)
    if not hmac.compare_digest(expected, m1):
        return None
    return server_proof(group, big_a, m1, key)
