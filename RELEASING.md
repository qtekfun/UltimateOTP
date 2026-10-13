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

## Making a release

1. Set `versionName` (and bump `versionCode`) in `android/app/build.gradle.kts`, then commit to `master`. Wait for the CI workflow (`.github/workflows/ci.yml`) to be green on that commit: the release workflow runs `./gradlew check` but not the contract test or the emulator suite (docs/testing.md).
2. Tag exactly `v<versionName>` and push the tag:
   ```sh
   git tag -a v0.1.0 -m "UltimateOTP 0.1.0" && git push origin v0.1.0
   ```
3. The Release workflow checks that the tag matches `versionName`, runs `./gradlew check assembleRelease`, verifies the signature and version, pushes the server image `ghcr.io/qtekfun/ultimateotp-server:<version>` (amd64 + arm64), and publishes the GitHub Release with `UltimateOTP-<version>.apk` and its SHA-256. 0.x versions and `-rc` tags are published as pre-releases.

A manual run of the workflow (Actions → Release → Run workflow) is a dry run: it builds and checks everything and publishes nothing.

The GHCR package `ultimateotp-server` is created private on its first push; make it public once (GitHub → Packages → ultimateotp-server → Package settings → Change visibility) so hosts can pull it without logging in.
