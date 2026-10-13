# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Localized emails from plain template files, no dependency (contract 1.2.0).

`templates/<lang>/<name>.txt` is `Subject: ...`, a blank line, then the body, with `$name`
placeholders (`string.Template`). The language is the first of `es`, `en` that the request asks
for: the explicit `lang` field, else `Accept-Language` by quality, else the language last used by
the account, else `en`. Only the emails are localized; API problems and ntfy notices stay English.
"""

import re
from functools import lru_cache
from importlib import resources
from string import Template

SUPPORTED = ("en", "es")
DEFAULT = "en"
_TAG = re.compile(r"^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$")
_QUALITY = re.compile(r"^\s*(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)\s*$")
MAX_HEADER_CHARS = 256
MAX_RANGES = 16


def from_tag(tag: str | None) -> str | None:
    """`es-MX` -> `es`; None when the tag is malformed or not a supported language."""
    if not tag or not _TAG.match(tag):
        return None
    primary = re.split(r"[-_]", tag, maxsplit=1)[0].lower()
    return primary if primary in SUPPORTED else None


def from_accept_language(header: str | None) -> str | None:
    """The supported language the header prefers (highest q, then order); None when it names
    none (`*` is not a preference). `q=0` excludes a language."""
    if not header:
        return None
    ranked: list[tuple[float, int, str]] = []
    for index, part in enumerate(header[:MAX_HEADER_CHARS].split(",")[:MAX_RANGES]):
        tag, _, params = part.strip().partition(";")
        quality = 1.0
        params = params.strip()
        if params:
            name, _, value = params.partition("=")
            if name.strip().lower() != "q" or not _QUALITY.match(value):
                continue
            quality = float(value)
        language = from_tag(tag.strip())
        if language is not None and quality > 0:
            ranked.append((-quality, index, language))
    return min(ranked)[2] if ranked else None


def pick(explicit: str | None, header: str | None, stored: str | None = None) -> str:
    return from_tag(explicit) or from_accept_language(header) or from_tag(stored) or DEFAULT


@lru_cache(maxsize=128)
def _load(lang: str, name: str) -> tuple[str, Template]:
    root = resources.files("ultimateotp").joinpath("templates", lang, f"{name}.txt")
    text = root.read_text(encoding="utf-8")
    head, _, body = text.partition("\n\n")
    if not head.startswith("Subject: "):
        raise ValueError(f"template {lang}/{name}: the first line must be 'Subject: ...'")
    return head.removeprefix("Subject: ").strip(), Template(body.rstrip("\n") + "\n")


def render(lang: str, name: str, **params: str | int) -> tuple[str, str]:
    """(subject, body) of template `name` in `lang` (falls back to English)."""
    language = lang if lang in SUPPORTED else DEFAULT
    subject, body = _load(language, name)
    values = {key: str(value) for key, value in params.items()}
    return Template(subject).substitute(values), body.substitute(values)


def template_names() -> list[str]:
    root = resources.files("ultimateotp").joinpath("templates", DEFAULT)
    return sorted(
        item.name.removesuffix(".txt") for item in root.iterdir() if item.name.endswith(".txt")
    )
