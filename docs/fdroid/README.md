<!--
SPDX-FileCopyrightText: 2026 UltimateOTP contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# F-Droid

`com.qtekfun.ultimateotp.yml` is a **draft** of the recipe for
[fdroiddata](https://gitlab.com/fdroid/fdroiddata) (`metadata/com.qtekfun.ultimateotp.yml`). It is modelled on
the owner's `com.qtekfun.ultimatedeck.yml` and on the drafts of UltimatePhone and UltimateKeys. It is not
submitted, and two values are deliberate placeholders (`deadbeef...`):

- `commit:` the full hash of the release tag to build (first submission: the 0.2.0 tag).
- `AllowedAPKSigningKeys:` the SHA-256 of the release certificate (RELEASING.md, "F-Droid").

Nothing here was pushed to the local fdroiddata clone or to GitLab.

## Fields

| Field | Value | Why |
|---|---|---|
| `Categories` | `Password & 2FA` | The category exists in fdroiddata's `config/categories.yml` ("authenticators, OTP, TOTP, HOTP"). |
| `Binaries` | `.../releases/download/v%v/UltimateOTP-%v.apk` | The release workflow names the asset `UltimateOTP-<versionName>.apk`. With `AllowedAPKSigningKeys`, F-Droid ships that signed APK when its own build is bit-identical. |
| `subdir` | `android/app` | The Gradle build lives under `android/`; the application module is `app`. The Gradle wrapper properties are found one level up (`gradlew-fdroid` looks in `.`, `..` and `../..`). |
| `sudo` | `openjdk-21-jdk-headless` | The build needs JDK 21 (AGP 9, Gradle 9.8). Same lines as the owner's other recipes. |
| `gradle: yes` | | Runs `assembleRelease` with no flavours. The signing config in `app/build.gradle.kts` only exists when `UOTP_KEYSTORE_FILE` is set, and F-Droid removes signing blocks anyway, so its APK is unsigned. |
| `ndk` | not set | No native code is compiled; the native libraries come prebuilt from Maven (below). |
| `prebuild`, `srclibs` | none | Nothing has to be generated or fetched before the build. |
| `AutoUpdateMode: Version` | | New tags become builds without editing the recipe. |
| `UpdateCheckMode: Tags ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$` | | Tags are `vX.Y.Z` or `vX.Y.Z-rc.N`, like the release workflow. `versionName` and `versionCode` are read from `android/app/build.gradle.kts` at the tag. |

The Gradle version is taken from `android/gradle/wrapper/gradle-wrapper.properties` (9.8.1); F-Droid's
`gradlew-fdroid` verifies the download against its own checksum list or the Gradle transparency log.

## Anti-features

None apply, checked one by one against fdroiddata's `config/antiFeatures.yml`:

| Anti-feature | Applies? | Reason |
|---|---|---|
| `Ads`, `Tracking` | no | No ad or analytics code, no telemetry, no crash reporting. `checkForbiddenDependencies` in the build fails if Play Services, Firebase or analytics libraries appear. |
| `NonFreeNet` | no | The only network use is the sync with a server **the user runs** (free software in this repository). The app works fully offline and the server address is typed by the user. It does not depend on a proprietary service. Email codes are sent by the user's own server through the SMTP relay the user chooses. |
| `TetheredNet` | no | Sync is optional; codes never need a network. |
| `NonFreeDep` | no | Everything is free software (Apache-2.0, ISC, LGPL-2.1+ or Apache-2.0). No Play Services, no Google ML Kit (QR decoding uses ZXing core). |
| `NonFreeAssets`, `NonFreeAdd` | no | No third-party artwork or plugins. Re-check when the redesign's logo lands. |
| `KnownVuln` | not known | Check the scanner's result on each release. |
| `DisabledAlgorithm`, `NoSourceSince` | no | |

If a future version adds push notifications through a hosted service, or a dependency with a
non-free licence, revisit this table.

## Prebuilt native libraries

The app ships two kinds of native code, both prebuilt inside Maven Central artifacts and **not**
compiled by this project or by F-Droid:

| File | In | Source | Licence | Checked |
|---|---|---|---|---|
| `lib/<abi>/libsodium.so` (arm64-v8a, armeabi-v7a, x86, x86_64) | `com.ionspin.kotlin:multiplatform-crypto-libsodium-bindings-android:0.9.5` AAR | [jedisct1/libsodium](https://github.com/jedisct1/libsodium) 1.0.20, built by the ionspin project from its libsodium submodule with libsodium's `dist-build` scripts | ISC (libsodium), Apache-2.0 (bindings) | `sodium_version_string` in the arm64 library reads `1.0.20`; the NDK `.comment` shows Android's clang 19 |
| `lib/<abi>/libjnidispatch.so` | `net.java.dev.jna:jna:5.18.1` AAR | [java-native-access/jna](https://github.com/java-native-access/jna) `native/` | Apache-2.0 or LGPL-2.1+ | |

### What F-Droid's policy requires

Quoted from the [Inclusion Policy](https://f-droid.org/docs/Inclusion_Policy/) (read for this draft):

- "Library dependencies must be built from source or provided in a trusted Maven repo."
- "Applications can download prebuilt FLOSS binaries with specific conditions from trusted Maven
  repositories. Those include Maven Central, Google Maven, OSS Sonatype, OSS JFrog, JitPack.io and Clojars."
- "Those binaries must still be freely licensed, simply being included in one of those repositories is not
  enough."

The policy text does not mention `.so` files separately. The fdroidserver source scanner flags
`.so`, `.aar`, `.jar` and similar files **checked into the source tree**; it does not look inside
resolved Maven dependencies, and it allows only the repositories above. UltimateOTP has none checked
in, the scanner reports no problem on the source tree, and its APK scan (known non-free classes,
extra signing blocks) reports none (see Validation).

### Options

1. **Declare nothing and rely on the trusted-Maven rule (recommended, what the draft does).** Both
   artifacts are on Maven Central and freely licensed; the build resolves them by hash
   (`android/gradle/verification-metadata.xml`), so F-Droid and the maintainer get the same bytes.
   Cost: nothing. Risk: a reviewer may still ask for the libraries to be built from source (I
   did not find a written rule that requires it, and did not survey how fdroiddata handled other apps with
   prebuilt native libraries). The answer to give is the table above and this policy quote.
2. **Build libsodium from source in the recipe.** A `srclibs` entry for libsodium at the tag matching
   1.0.20 and a `prebuild` step running `dist-build/android-*.sh` (needs `ndk:`), then replace the `.so`
   files of the AAR (for example by a local Maven repository or `jniLibs` override that wins over the
   AAR's, which needs a small change in `app/build.gradle.kts`). It changes the APK compared with the one
   the GitHub workflow builds, unless the workflow does the same, so the two builds must be changed in
   lockstep. Likely only worthwhile if F-Droid asks. Same for JNA, which has its own native build in its repository.
3. **Replace the bindings** by libsodium built in-tree with the NDK and a small JNI layer. Largest
   change, touches the crypto module; out of scope for release preparation.

If F-Droid asks for 2, the formats do not change (the vectors pin every call).

## Validation done locally

Tools: `fdroidserver` 2.4.5 installed with `pipx`, run against a scratch directory that contains a copy
of fdroiddata's `config/` (categories, anti-features) and `.yamllint`; Gradle and JDK as in
docs/reproducible-builds.md.

| Check | Result |
|---|---|
| `fdroid lint com.qtekfun.ultimateotp` | no findings |
| `fdroid rewritemeta` | file unchanged (already in canonical form) |
| `yamllint` with fdroiddata's `.yamllint` | no findings |
| `fdroid checkupdates` (read-only, against GitHub) | cloned the repository, found the tags, parsed `android/app/build.gradle.kts` at the latest tag (`versionCode` 3); it reports "current version is newer" only because the draft is 0.1.3 |
| fdroidserver source scanner (`scan_source`) on `git archive HEAD` | 0 problems (it removes the wrapper script and jar first, as F-Droid does) |
| fdroidserver APK scanner (`scan_binary`) on the release APK | 0 problems |
| Signing-config stripping (`remove_signing_keys`), then `assembleRelease` from `android/app` in a Debian OpenJDK 21 container without an NDK | builds; APK identical to two host builds (docs/reproducible-builds.md) |
| Build with Gradle dependency verification, fresh Gradle home, then `--offline` | passes |

Not run: `fdroid build` on F-Droid's real build server image (not available locally), the
`fdroid verify` comparison against a signed APK, and fdroiddata's GitLab CI. The recipe's `commit`
and `AllowedAPKSigningKeys` are placeholders, so `fdroid build` could not run on it anyway.

## What F-Droid will probably ask next

- A tag with the fix: 0.1.2 crashes on sign-up; submit 0.2.0 or later.
- That the app works without a server and what the "server" is: the description says so. They may
  ask for the server's source to be linked: it is in `server/` of the same repository.
- Whether the prebuilt `libsodium.so` / `libjnidispatch.so` can be built from source (see above).
- Icon, feature graphic and screenshots (not required, but the app page is bare without them).
- A reproducible-build confirmation: `Binaries` and `AllowedAPKSigningKeys` are the mechanism.
- Possibly the anti-feature question for the self-hosted server (`NonFreeNet`): the answer is above.
