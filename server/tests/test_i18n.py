# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Localized emails: es and en from plain template files, with a fallback to en."""

import re
import secrets
import string
from email.header import decode_header, make_header
from importlib import resources
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.client import Device, Vault
from tests.conftest import PASSWORD, PUBLIC_CLIENT, Mail
from ultimateotp import i18n

EMAIL = "owner@example.org"


# ---------------------------------------------------------------- negotiation


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("es", "es"),
        ("es-ES,es;q=0.9,en;q=0.8", "es"),
        ("en-US,en;q=0.9,es;q=0.8", "en"),
        ("fr-FR,fr;q=0.9,es;q=0.5", "es"),
        ("de, es;q=0.4, en;q=0.6", "en"),
        ("ES-mx", "es"),
        ("es;q=0", None),
        ("es;q=0, en", "en"),
        ("fr, de, ja", None),
        ("*", None),
        ("", None),
        (None, None),
        ("es;q=banana", None),
        ("es;q=1.5", None),
        ("x" * 1000, None),
        ("a" * 5 + "-" * 3, None),
        ("<script>", None),
    ],
)
def test_accept_language(header: str | None, expected: str | None) -> None:
    assert i18n.from_accept_language(header) == expected


def test_pick_order_is_explicit_then_header_then_stored_then_english() -> None:
    assert i18n.pick("es", "en", "en") == "es"
    assert i18n.pick(None, "es", "en") == "es"
    assert i18n.pick(None, None, "es") == "es"
    assert i18n.pick(None, None, None) == "en"
    assert i18n.pick("klingon", "xx", "yy") == "en"
    # A malformed explicit tag is ignored, not an error.
    assert i18n.pick("e", "es", None) == "es"


# ---------------------------------------------------------------- the template files


def _placeholders(text: str) -> set[str]:
    return {m.group("named") for m in string.Template.pattern.finditer(text) if m.group("named")}


def test_every_template_exists_in_both_languages_with_the_same_placeholders() -> None:
    root = resources.files("ultimateotp").joinpath("templates")
    names = {
        lang: {p.name for p in root.joinpath(lang).iterdir() if p.name.endswith(".txt")}
        for lang in i18n.SUPPORTED
    }
    assert names["en"] == names["es"]
    assert names["en"], "no templates"
    for name in sorted(names["en"]):
        texts = {lang: root.joinpath(lang, name).read_text(encoding="utf-8") for lang in names}
        for lang, text in texts.items():
            assert text.startswith("Subject: "), (lang, name)
            assert "\n\n" in text
            assert "$$" not in text
        assert _placeholders(texts["en"]) == _placeholders(texts["es"]), name


def test_spanish_reads_as_tu_not_usted_or_voseo() -> None:
    root = resources.files("ultimateotp").joinpath("templates", "es")
    for item in root.iterdir():
        text = item.read_text(encoding="utf-8").lower()
        for banned in (
            " usted",
            " su cuenta",
            " su contraseña",
            "vosotros",
            "tenés",
            "podés",
            "tu cuenta,",
        ):
            assert banned not in text, (item.name, banned)
    subject, body = i18n.render("es", "login_code", code="123456", minutes=10)
    assert subject == "Tu código de acceso de UltimateOTP"
    assert "Tu código de UltimateOTP es 123456." in body
    assert "10 minutos" in body


def test_render_falls_back_to_english_and_substitutes() -> None:
    subject, body = i18n.render("fr", "login_code", code="654321", minutes=5)
    assert subject == "Your UltimateOTP login code"
    assert "654321" in body
    assert "5 minutes" in body
    # A device label with template syntax is data, not a template.
    _, notice = i18n.render("en", "data_exported", device="$secret ${x}")
    assert '"$secret ${x}"' in notice
    with pytest.raises(KeyError):
        i18n.render("en", "login_code", code="1")


# ---------------------------------------------------------------- end to end with the relay


def _ask(client: TestClient, mail: Mail, **kwargs: Any) -> Any:
    assert client.post("/otp/v1/login/email-code", **kwargs).status_code == 202
    mail.flush()
    return mail.box.messages[-1]


def _text(message: Any) -> str:
    payload = message.get_payload(decode=True).decode()
    subject = str(make_header(decode_header(message["Subject"])))
    return f"{subject}\n{payload}"


def test_login_code_language_from_the_field_the_header_and_the_fallback(mail: Mail) -> None:
    mail.server.service.create_account(EMAIL)
    mail.flush()
    mail.box.messages.clear()
    with mail.server.client(PUBLIC_CLIENT) as client:
        body = {"email": EMAIL}
        english = _ask(client, mail, json=body)
        assert "Your UltimateOTP login code" in _text(english)
        explicit = _ask(client, mail, json={**body, "lang": "es"})
        assert "Tu código de acceso de UltimateOTP" in _text(explicit)
        header = _ask(client, mail, json=body, headers={"Accept-Language": "es-MX,es;q=0.9"})
        assert "Tu código de UltimateOTP es" in _text(header)
        # The explicit field wins over the header.
        both = _ask(client, mail, json={**body, "lang": "en"}, headers={"Accept-Language": "es"})
        assert "Your UltimateOTP code is" in _text(both)
        # An unsupported language falls back to English, as do garbage and q=0.
        for headers in ({"Accept-Language": "fr-FR,fr;q=0.9"}, {"Accept-Language": "es;q=0"}):
            assert "Your UltimateOTP code is" in _text(
                _ask(client, mail, json=body, headers=headers)
            )
        unsupported = _ask(client, mail, json={**body, "lang": "fr"})
        assert "Your UltimateOTP code is" in _text(unsupported)
        # Not a language tag at all: the request is refused like any bad body.
        bad = client.post("/otp/v1/login/email-code", json={**body, "lang": "es; DROP"})
        assert bad.status_code == 400
        # The code itself is intact in every language.
        for message in mail.box.messages:
            assert re.search(r"\b\d{6}\b", message.get_payload(decode=True).decode())


def test_signup_sends_in_the_requested_language_and_remembers_it(make_mail: Any) -> None:
    mail: Mail = make_mail(signup="enabled")
    with mail.server.client(PUBLIC_CLIENT) as client:
        message = _ask(client, mail, json={"email": EMAIL, "lang": "es"})
        assert "Tu código" in _text(message)
        code = mail.box.code_for(EMAIL)
        vault = Vault(account_id="")
        device = Device(client, "Móvil")
        response = device.post(
            "/otp/v1/signup",
            {
                "email": EMAIL,
                "email_code": code,
                "lang": "es",
                "device": {
                    "ed25519_public_key": device.ed25519,
                    "x25519_public_key": device.x25519,
                    "label": "Móvil",
                },
                "keys": vault.key_bundle(PASSWORD, secrets.token_bytes(32)),
            },
        )
        assert response.status_code == 201, response.text
    assert mail.server.service.accounts is not None
    with mail.server.service.db.read() as conn:
        assert conn.execute("SELECT lang FROM accounts").fetchone()[0] == "es"
    # Later codes for that account follow the stored language when the request names none.
    with mail.server.client(PUBLIC_CLIENT) as client:
        assert "Tu código" in _text(_ask(client, mail, json={"email": EMAIL}))


def test_notices_follow_the_language_of_the_signed_device(mail: Mail) -> None:
    """A key rotation notice goes out in the language the device asks with."""
    from tests.test_email import _bootstrap  # noqa: PLC0415

    with mail.server.client() as lan:
        boot = _bootstrap(mail, lan)
        mail.box.messages.clear()
        # Any signed request carrying Accept-Language teaches the server the account's language.
        boot.device.get("/otp/v1/devices", extra_headers={"Accept-Language": "es-ES,es;q=0.9"})
        mail.server.service.accounts  # noqa: B018 - the manager exists
        token, _ = mail.server.service.create_token(boot.account_id)
        recovery = lan.get("/otp/v1/recovery/keys", headers={"Authorization": f"Bearer {token}"})
        assert recovery.status_code == 200
        mail.flush()
        notice = _text(mail.box.messages[-1])
        assert "UltimateOTP: se han descargado tus datos de recuperación" in notice
        assert "Si no has sido tú" in notice
        # And back to English when the device starts asking in English.
        boot.device.get("/otp/v1/devices", extra_headers={"Accept-Language": "en"})
        token, _ = mail.server.service.create_token(boot.account_id)
        lan.get("/otp/v1/recovery/keys", headers={"Authorization": f"Bearer {token}"})
        mail.flush()
        assert "UltimateOTP: recovery data fetched" in _text(mail.box.messages[-1])


def test_cli_created_account_gets_its_code_in_the_chosen_language(mail: Mail) -> None:
    mail.server.service.create_account(EMAIL, lang="es")
    mail.flush()
    assert "Tu código de acceso" in _text(mail.box.messages[-1])
    mail.server.service.create_account("other@example.org")
    mail.flush()
    assert "Your UltimateOTP login code" in _text(mail.box.messages[-1])


def test_unauthenticated_header_cannot_change_a_stored_language(mail: Mail) -> None:
    """Only a signed request updates the account's language: a stranger asking for a code with
    another language changes that one email, not the account."""
    mail.server.service.create_account(EMAIL, lang="en")
    mail.flush()
    with mail.server.client(PUBLIC_CLIENT) as client:
        _ask(client, mail, json={"email": EMAIL}, headers={"Accept-Language": "es"})
    with mail.server.service.db.read() as conn:
        assert conn.execute("SELECT lang FROM accounts").fetchone()[0] == "en"
