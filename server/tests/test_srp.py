# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""SRP-6a arithmetic: RFC 5054 Appendix B test vectors, and a 4096-bit SHA-256 round trip."""

import secrets

from ultimateotp import srp


def h(text: str) -> int:
    return int("".join(text.split()), 16)


IDENTITY, PASSWORD = b"alice", b"password123"
S_SALT = bytes.fromhex("BEB25379D1A8581EB5A727673A2441EE")
A_PRIV = h("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")
B_PRIV = h("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20")


def test_rfc5054_appendix_b() -> None:
    g = srp.RFC5054_TEST_GROUP
    assert g.k == h("7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")
    assert srp.private_key(g, S_SALT, IDENTITY, PASSWORD) == h(
        "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124"
    )
    v = srp.verifier(g, S_SALT, IDENTITY, PASSWORD)
    assert v == h(
        "7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 9BADA1F1"
        "822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A"
        "48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04"
        "E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB"
    )
    big_a = srp.client_public(g, A_PRIV)
    assert big_a == h(
        "61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 4352E890"
        "3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E"
        "42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261"
        "EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B"
    )
    big_b = srp.server_public(g, v, B_PRIV)
    assert big_b == h(
        "BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 BAF38964"
        "DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610"
        "D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A"
        "00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58"
    )
    assert g.Hint(g.pad(big_a), g.pad(big_b)) == h("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019")
    premaster = h(
        "B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D 233861E3"
        "59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C 41BB59B6 D5979B5C"
        "00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F 3499B200 210DCC1F 10EB3394"
        "3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D C346D7E4 74B29EDE 8A469FFE CA686E5A"
    )
    assert srp.premaster_secret(g, v, big_a, B_PRIV, big_b) == premaster
    m1, key = srp.client_session(g, S_SALT, IDENTITY, PASSWORD, A_PRIV, big_b)
    assert key == g.H(g.pad(premaster))
    m2 = srp.server_verify(g, IDENTITY, S_SALT, v, big_a, B_PRIV, m1)
    assert m2 == srp.server_proof(g, big_a, m1, key)


def test_group_4096_is_the_rfc_prime() -> None:
    g = srp.GROUP_4096
    assert g.N.bit_length() == 4096
    assert g.g == 5
    # Fermat check with a few bases (the prime is the RFC 3526 4096-bit MODP prime).
    assert all(pow(base, g.N - 1, g.N) == 1 for base in (2, 3, 5, 7))


def test_round_trip_4096_sha256() -> None:
    g = srp.GROUP_4096
    salt, identity, password = secrets.token_bytes(16), b"user-id", secrets.token_bytes(32)
    v = srp.verifier(g, salt, identity, password)
    a, b = srp.new_ephemeral(), srp.new_ephemeral()
    big_b = srp.server_public(g, v, b)
    m1, key = srp.client_session(g, salt, identity, password, a, big_b)
    big_a = srp.client_public(g, a)
    assert srp.server_verify(g, identity, salt, v, big_a, b, m1) == srp.server_proof(
        g, big_a, m1, key
    )
    wrong, _ = srp.client_session(g, salt, identity, b"wrong", a, big_b)
    assert srp.server_verify(g, identity, salt, v, big_a, b, wrong) is None


def test_bad_client_public_values_are_refused() -> None:
    g = srp.GROUP_4096
    v = srp.verifier(g, b"s", b"i", b"p")
    for bad in (0, g.N, 2 * g.N):
        assert srp.server_verify(g, b"i", b"s", v, bad, 12345, b"x" * 32) is None
