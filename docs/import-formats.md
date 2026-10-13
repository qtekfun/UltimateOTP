# Importing from other authenticator apps

Settings > Import file reads the export of another app, finds out which one it is from the
file's structure, asks for a password if the file is encrypted, and adds the accounts. The code is
in `android/core/importers`; every format has fixtures and tests there.

What every importer guarantees:

- A file it cannot read fails with one fixed sentence (never the file's content, never a secret),
  not with a crash and not with half-read garbage.
- An entry it cannot use (unknown type, bad secret, unsupported algorithm) is counted as rejected;
  the others are imported.
- Nothing is logged. Secrets live in memory only while the file is being converted.
- Existing entries are not duplicated: an account with the same issuer, account name and secret
  (names compared without case and surrounding spaces) is skipped; if the match is in the trash it is
  restored.
- Size limit 16 MiB; KDF parameters read from a file are bounded (scrypt at most 256 MiB,
  andOTP iterations at most 10 million) so a hostile file cannot stall the phone.

| App | File | Encrypted | Reads | Does not read |
|---|---|---|---|---|
| Aegis | `.json` vault | password slot (scrypt, AES-256-GCM) | TOTP, HOTP, Steam, notes, favorites, groups as tags | MOTP, Yandex; vaults with only biometric/raw slots; vault version newer than 1 / content version newer than 3 |
| 2FAS | `.2fas` / `.json` backup | `servicesEncrypted` (PBKDF2-SHA256 10 000, AES-GCM) | TOTP, HOTP, Steam, groups as tags | schema newer than 4; other token types |
| andOTP | `.json`, `.json.aes`/`.bin` | password: PBKDF2-SHA1 (0.6.3+) and SHA-256 (older) with AES-GCM | TOTP, HOTP, Steam, tags | MOTP; OpenPGP-encrypted backups (decrypt with OpenKeychain/gpg first) |
| Raivo OTP | `.json`, unencrypted `.zip` | not read | TOTP, HOTP, Steam | password-protected zips (extract them first) |
| Bitwarden | `.json`, `.csv` export | not read ("encrypted JSON" is refused with an explanation) | TOTP field as `otpauth://`, `steam://` or a bare secret; name, username, notes, favorite | logins without a TOTP value are skipped |
| Proton Authenticator | `.json` export | password: Argon2id (19 MiB, 2 passes), AES-256-GCM | `otpauth://`, `steam://`, note | other versions than 1 |

## Formats and sources

The layouts were checked against the importers and format documents of other open-source
projects, and against their own test files (real exports with invented accounts, kept in
`core/importers/src/test/resources/fixtures`, GPL-3.0-or-later, from Aegis Authenticator's
importer tests). Files that the real apps could not give us are built by
`FixtureBuilders.kt` from the documented layout (fixed salts and nonces).

1. **Aegis** — `docs/vault.md` of https://github.com/beemdevelopment/Aegis. `{version:1, header:{slots,
   params}, db}`. `slots` null and `db` an object = plain. Otherwise `db` is base64 AES-256-GCM
   ciphertext (nonce and tag in `header.params`, hex) under a random master key; each password slot
   (`type 1`) holds that key encrypted (`key`, `key_params`) under `scrypt(password, salt, n, r, p)`
   (32 bytes; Aegis uses N=32768, r=8, p=1). Entries: `type`, `name`, `issuer`, `note`,
   `favorite`, `info{secret, algo, digits, period|counter}`, `groups`.
2. **2FAS** — `TwoFASImporter` of Aegis, which documents the backup format. `services` (plain) or
   `servicesEncrypted` = `b64(ciphertext+tag):b64(salt):b64(iv)`; key = PBKDF2-HMAC-SHA256 of the
   password, 10 000 iterations, 256 bits; the plaintext is the JSON `services` array. Service:
   `name`, `secret`, `otp{account, issuer, digits, period, algorithm, tokenType, counter}`, `groupId`.
3. **andOTP** — `AndOtpImporter` of Aegis and andOTP's `EncryptionHelper`. Plain: JSON array
   (`secret`, `issuer`, `label`, `digits`, `type`, `algorithm`, `period`, `counter`, `tags`);
   labels of old versions are `Issuer - account` or `Issuer:account`. Encrypted new:
   `u32be iterations || salt[12] || nonce[12] || AES-256-GCM(ciphertext||tag)`, key =
   PBKDF2-HMAC-SHA1(password, salt, iterations). Encrypted old: `nonce[12] ||
   ciphertext||tag`, key = SHA-256(password). The old one is tried first (one hash).
4. **Raivo OTP** — export JSON array of string-valued objects: `kind` (TOTP/HOTP), `issuer`,
   `account`, `secret`, `algorithm`, `digits`, `timer`, `counter`.
5. **Bitwarden** — "Export vault" `.json` (`items[].login.totp`, `items[].name`,
   `login.username`) and `.csv` (`login_totp`, `name`, `login_username`).
6. **Proton Authenticator** — export `{version:1, entries:[{content:{uri, entry_type, name},
   note}]}`; encrypted: `{version:1, salt, content}` with `content = nonce[12] ||
   AES-256-GCM(json)`, key = Argon2id(password, salt, t=2, m=19 MiB, p=1), AAD
   `proton.authenticator.export.v1`.

## Known limits

- A wrong password and a damaged file cannot be told apart (the authentication tag fails in
  both cases); the app says "wrong password".
- A binary file that is not an andOTP backup (for example an OpenPGP file that is not armored)
  is offered as an andOTP file and ends as "wrong password".
- Icons and per-app settings (sorting, colours) are not imported.
- Not verified on a device: the file picker path, and the speed of scrypt (32 MiB) and Argon2id
  on low-end phones.
