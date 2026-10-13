# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Request bodies of `contracts/openapi.yaml`. Responses are plain dicts built by the service.

Shapes only: lengths after decoding (blob, wrap) are checked by the service against the
settings, and nothing here ever looks inside a blob.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

B64_PATTERN = r"^[A-Za-z0-9_-]+$"
# Contract caps (64 KiB blob, 4 KiB wrap, in base64url characters); settings may lower them.
BLOB_MAX_CHARS = 87382
WRAP_MAX_CHARS = 5462

Ed25519Key = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]
X25519Key = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]
Signature = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{86}$")]
DeviceId = Annotated[str, StringConstraints(pattern=r"^dev_[A-Za-z0-9_-]{22}$")]
ItemId = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
]
ItemBlob = Annotated[str, StringConstraints(pattern=B64_PATTERN, max_length=BLOB_MAX_CHARS)]
WrapBlob = Annotated[str, StringConstraints(pattern=B64_PATTERN, max_length=WRAP_MAX_CHARS)]
# Printable, no control characters (it ends up in a terminal through the admin CLI).
Label = Annotated[str, StringConstraints(pattern=r"^[^\x00-\x1f\x7f]{1,64}$")]

MAX_CHANGES = 2000


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class KeyBundle(_Body):
    password_wrap: WrapBlob | None = None
    password_kdf: WrapBlob | None = None
    recovery_wrap: WrapBlob


class EnrollRequest(_Body):
    ed25519_public_key: Ed25519Key
    x25519_public_key: X25519Key
    label: Label
    keys: KeyBundle | None = None


class PutKeysRequest(_Body):
    base_revision: int = Field(ge=1)
    key_epoch: int = Field(ge=1)
    password_wrap: WrapBlob | None = None
    password_kdf: WrapBlob | None = None
    recovery_wrap: WrapBlob


class JoinRequest(_Body):
    ed25519_public_key: Ed25519Key
    x25519_public_key: X25519Key
    label: Label


class ApproveRequest(_Body):
    device_id: DeviceId
    device_signature: Signature
    sealed_vault_key: WrapBlob
    seal_signature: Signature


class HeadInput(_Body):
    version: int = Field(ge=1)
    signature: Signature


class Upsert(_Body):
    item_id: ItemId
    blob: ItemBlob


class CommitRequest(_Body):
    base_version: int = Field(ge=0)
    key_epoch: int = Field(ge=1)
    head: HeadInput
    upserts: list[Upsert] = Field(default_factory=list, max_length=MAX_CHANGES)
    deletes: list[ItemId] = Field(default_factory=list, max_length=MAX_CHANGES)


class DeviceKeyInput(_Body):
    device_id: DeviceId
    sealed_vault_key: WrapBlob
    seal_signature: Signature


class RotateRequest(_Body):
    base_version: int = Field(ge=0)
    new_key_epoch: int = Field(ge=2)
    head: HeadInput
    upserts: list[Upsert] = Field(default_factory=list, max_length=MAX_CHANGES)
    deletes: list[ItemId] = Field(default_factory=list, max_length=MAX_CHANGES)
    keys: KeyBundle
    device_keys: list[DeviceKeyInput] = Field(min_length=1, max_length=MAX_CHANGES)
