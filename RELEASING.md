# Releasing UltimateOTP

Releases are built and signed by GitHub Actions (`.github/workflows/release.yml`) when a `v*` tag is pushed. Nobody builds release APKs by hand.

## Signing (one time, by the author)

1. Create the key and back up the file and its password (if it is lost, users must uninstall to update). It lives in `~/keys` like the other projects' keys. Claude never handles key material.
   ```sh
   keytool -genkeypair -v -keystore ~/keys/ultimateotp-release.jks -alias ultimateotp \
     -keyalg RSA -keysize 4096 -validity 10000
   chmod 600 ~/keys/ultimateotp-release.jks
   ```
   keytool creates a PKCS12 store: the key password is the store password.
2. Repository secrets. `gh secret set` reads hidden input when no `--body` is given:
   ```sh
   base64 -w0 ~/keys/ultimateotp-release.jks | gh secret set UOTP_KEYSTORE_BASE64 -R qtekfun/UltimateOTP
   gh secret set UOTP_KEYSTORE_PASSWORD -R qtekfun/UltimateOTP
   gh secret set UOTP_KEY_PASSWORD -R qtekfun/UltimateOTP      # same value as the store password
   gh secret set UOTP_KEY_ALIAS -R qtekfun/UltimateOTP --body ultimateotp
   ```

Without the `UOTP_*` variables, `./gradlew assembleRelease` builds an unsigned APK. Local signed builds use the same four variables, with `UOTP_KEYSTORE_FILE` pointing at the `.jks`.

## Versions

- `versionName` is SemVer: `X.Y.Z`, or `X.Y.Z-rc.N` for a release candidate. Before 1.0.0 it is `0.x`.
- `versionCode` is a plain integer that **goes up by exactly one with every tag, release candidates
  included**, and is never reused or lowered (so far 1, 2, 3; 0.1.3 is 4). Both live in
  `android/app/build.gradle.kts`. F-Droid and Android compare only `versionCode`; the workflow compares
  the tag with `versionName`.
- Never move or delete a pushed tag. If a release is wrong, fix it and tag the next version: F-Droid
  and the signature check of reproducible builds identify a release by its tag and commit.

## Making a release

1. In `CHANGELOG.md`, move the `[Unreleased]` notes under `## [X.Y.Z] - YYYY-MM-DD` and fix the compare
   links at the bottom.
2. Set `versionName` and `versionCode` in `android/app/build.gradle.kts`.
3. Changelog files per versionCode (what F-Droid shows under "What's new"): add
   `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt` and the same in `es-ES/`. Plain
   text, at most 500 bytes, user-facing (not the commit log). The file name is the **versionCode**, not
   the version name. Check store texts against [docs/store-checklist.md](docs/store-checklist.md).
4. If dependencies changed, `android/gradle/verification-metadata.xml` must be up to date
   (see [docs/reproducible-builds.md](docs/reproducible-builds.md)).
5. Commit to `master` (`chore: release X.Y.Z`) and wait for the checks to pass.
6. Tag exactly `v<versionName>` on that commit and push the tag:
   ```sh
   git tag -a v0.1.3 -m "UltimateOTP 0.1.3" && git push origin v0.1.3
   ```
7. The Release workflow checks that the tag matches `versionName`, runs `./gradlew check assembleRelease`,
   verifies the signature and version, pushes the server image `ghcr.io/qtekfun/ultimateotp-server:<version>`
   (amd64 + arm64), and publishes the GitHub Release with `UltimateOTP-<version>.apk` and its SHA-256.
   0.x versions and `-rc` tags are published as pre-releases.
8. F-Droid notices the tag by itself (`UpdateCheckMode: Tags`) and, after its own build matches the
   APK published on GitHub, ships the project's signed APK (see below).

A manual run of the workflow (Actions → Release → Run workflow) is a dry run: it builds and checks everything and publishes nothing.

The GHCR package `ultimateotp-server` is created private on its first push; make it public once (GitHub → Packages → ultimateotp-server → Package settings → Change visibility) so hosts can pull it without logging in.

## F-Droid

The recipe lives in `docs/fdroid/com.qtekfun.ultimateotp.yml` (a draft; the file F-Droid uses is
`metadata/com.qtekfun.ultimateotp.yml` in [fdroiddata](https://gitlab.com/fdroid/fdroiddata)). Details,
the anti-feature analysis and the native libraries question are in [docs/fdroid/README.md](docs/fdroid/README.md).

- F-Droid builds the tag from source with its own Gradle and no signing key, then compares the result with
  `Binaries` (the GitHub Release APK) and publishes **our signed APK** if they match. That is why the
  build must be reproducible ([docs/reproducible-builds.md](docs/reproducible-builds.md)) and why
  `AllowedAPKSigningKeys` holds the SHA-256 of the release certificate:
  ```sh
  keytool -list -v -keystore ~/keys/ultimateotp-release.jks -alias ultimateotp | grep 'SHA256:'
  # lower case, without the colons
  ```
- After the recipe is merged, new tags need no recipe change (`AutoUpdateMode: Version`): the
  checkupdates bot adds the build entry. The asset name must stay `UltimateOTP-<version>.apk` and the
  tag `v<version>`.
- Fastlane texts and changelogs are read from the tag, so a store text fix ships with the next tag.
- Do not publish a tag whose APK differs from what the tag builds (for example by building on a
  machine with other tools): F-Droid would then refuse or fall back to its own signature.
