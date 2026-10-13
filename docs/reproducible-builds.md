<!--
SPDX-FileCopyrightText: 2026 UltimateOTP contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Reproducible builds and dependency verification

Goal: the release APK built by GitHub Actions and the one F-Droid builds from the same tag are
bit-identical (apart from the signature), so F-Droid can publish the project-signed APK and a user
can check what they install. The unsigned APK (`app-release-unsigned.apk`) is the thing compared.

## Result (2026-10-13)

`assembleRelease` of commit `c6160d0` plus `d37766a` (the tree this document ships in), unsigned:

| Build | Where | JDK | NDK in the SDK | Path, time zone | SHA-256 of the APK |
|---|---|---|---|---|---|
| A | host | Temurin 21 | yes | `.../a/UltimateOTP`, UTC | `5aa4b62c8ab3e4a0944e07c2ead1b2163754adff5ccff735b58ff2a85adfdc27` |
| B | host | Temurin 21 | yes | `.../bbbbbbbb/deeper/UltimateOTP-copy`, Pacific/Auckland | `5aa4b62c8ab3e4a0944e07c2ead1b2163754adff5ccff735b58ff2a85adfdc27` |
| C | `debian:trixie` container, fresh Gradle home | Debian OpenJDK 21.0.12.1 | **no** | `/src/UltimateOTP`, Europe/Madrid, built from `android/app` with the signing blocks removed by fdroidserver's `remove_signing_keys`, dependency verification enforced | `5aa4b62c8ab3e4a0944e07c2ead1b2163754adff5ccff735b58ff2a85adfdc27` |

All three are **identical**; `diffoscope` was not needed. Each was built with `--no-build-cache
--no-configuration-cache` (the project's `gradle.properties` enables both, which would hide
non-determinism) and from a separate copy of `git archive HEAD`.

Not covered: a different Gradle distribution than 9.8.1 or AGP than 9.4.1, a different Android
platform or build-tools version than the ones I had (`android-37.0`, build-tools 36.0.0), a different
machine architecture, and F-Droid's own build server. The first real proof is F-Droid's build of a tag.

### The one non-determinism found, and its fix

Building the earlier tree (before `c6160d0`) in the container without an NDK gave an APK of
5 473 321 bytes against 5 276 713 on the host, differing **only** in the native libraries
(`libsodium.so`, `libjnidispatch.so`, `libdatastore_shared_counter.so` in every ABI): AGP strips the
`.so` files with the NDK's `llvm-strip` when the SDK has an NDK, and leaves them untouched when it has
none. So the APK depended on whether the build machine had an NDK installed, and on which version.

Fix, in `android/app/build.gradle.kts`: `packaging { jniLibs.keepDebugSymbols += "**/*.so" }`. The
libraries are then packaged exactly as they come in the AARs (the APK is about 190 KB larger, which
is a size cost accepted for reproducibility). Everything else was already identical: dex, resources,
manifest, `META-INF`, art profiles.

### What the build already did right

- `vcsInfo.include = false` (no commit hash in the APK) and `dependenciesInfo` off (no encrypted
  dependency blob) in `app/build.gradle.kts` and the convention plugin.
- No timestamps, build numbers, `BuildConfig` fields from the clock or the machine, and no
  generated sources that embed paths.
- Dependencies by version (no `+` or `-SNAPSHOT` ranges), checked by hash since `c6160d0`/`d37766a`.
- `jniLibs.useLegacyPackaging = false`: native libraries stored uncompressed and 16 KB aligned.

## How to check a build yourself

```sh
# two copies at different paths, so paths and time zone cannot hide behind each other
git archive v0.1.3 | tar -x -C /tmp/a/UltimateOTP        # mkdir first
git archive v0.1.3 | tar -x -C /tmp/b/deeper/UltimateOTP
export JAVA_HOME=/path/to/jdk-21 ANDROID_HOME=/path/to/Sdk
(cd /tmp/a/UltimateOTP/android && TZ=UTC ./gradlew --no-daemon --no-build-cache --no-configuration-cache :app:assembleRelease)
(cd /tmp/b/deeper/UltimateOTP/android && TZ=Pacific/Auckland ./gradlew --no-daemon --no-build-cache --no-configuration-cache :app:assembleRelease)
sha256sum /tmp/a/UltimateOTP/android/app/build/outputs/apk/release/app-release-unsigned.apk \
          /tmp/b/deeper/UltimateOTP/android/app/build/outputs/apk/release/app-release-unsigned.apk
```

Do not set the `UOTP_*` signing variables (the output would be `app-release.apk`, signed with a key).
If the hashes differ:

```sh
docker run --rm -t -v /tmp:/tmp registry.salsa.debian.org/reproducible-builds/diffoscope \
  /tmp/a/UltimateOTP/android/app/build/outputs/apk/release/app-release-unsigned.apk \
  /tmp/b/deeper/UltimateOTP/android/app/build/outputs/apk/release/app-release-unsigned.apk
```

(A quick first look without diffoscope: `unzip -lv` both and diff the lists; that is how the NDK
difference above was found.)

To compare with the published release: the GitHub APK is signed, so strip the signature first, or
use `apksigcopier` (copy the signature onto your unsigned build, then `cmp` the two APKs), which is
also what F-Droid's verification does.

## F-Droid's side

The recipe (`docs/fdroid/com.qtekfun.ultimateotp.yml`) builds from `android/app` with `gradle: yes`.
F-Droid's `gradlew-fdroid` downloads the Gradle version named in
`android/gradle/wrapper/gradle-wrapper.properties` (9.8.1) and verifies it; the JDK is Debian's
`openjdk-21-jdk-headless`, and the signing blocks of the Gradle files are removed, giving the unsigned
APK that is compared with `Binaries`. Build C above reproduces those conditions except for F-Droid's
own SDK and NDK installation; the NDK is the one difference that mattered, and it is now irrelevant.

If a future change introduces non-determinism, F-Droid reports a mismatch and, depending on the
recipe, either fails the build or publishes its own signed APK (a different signature, so
users cannot update from the GitHub APK). Check with the commands above before tagging.

## Gradle dependency verification

`android/gradle/verification-metadata.xml` holds the SHA-256 of every artifact Gradle resolves: libraries
(`.aar`, `.jar`, `.pom`, `.module`) and Gradle plugins, including AGP's own tool chain and the plugins of
`build-logic`. Gradle enforces it automatically on every build, in CI and in F-Droid's build: an artifact
that is missing from the file, or whose hash differs, fails the build ("Dependency verification
failed"). `verify-signatures` is off: only checksums are checked, which is what pins the build to the
bytes that were reviewed when the entry was added.

What it does not cover: the Gradle distribution itself (pinned by `distributionSha256Sum` in
`gradle-wrapper.properties`), the JDK, the Android SDK and build-tools, and the Maven artifacts that
Robolectric downloads at test runtime (`android-all-*` jars, resolved by Robolectric's own resolver, not
Gradle). Running the unit tests fully offline therefore needs those jars cached in `~/.m2`.

### Updating the verification metadata

When Dependabot or Renovate (or you) change a version in `android/gradle/libs.versions.toml`, the build
fails with a "Dependency verification failed" report for the new artifacts. To update:

1. Check out the PR branch.
2. Regenerate **from an empty Gradle user home**, so that every artifact is downloaded and
   recorded (with a warm cache Gradle skips artifacts it already has, and entries go missing; this was
   hit while preparing the file):
   ```sh
   cd android
   GRADLE_USER_HOME=$(mktemp -d) ./gradlew --no-daemon --no-configuration-cache --no-build-cache \
     --write-verification-metadata sha256 check assembleDebug assembleRelease assembleAndroidTest
   ```
   `--write-verification-metadata sha256 help` alone records almost nothing: it resolves only what
   `help` needs.
3. Review the diff of `verification-metadata.xml`: only the changed dependency's entries (old version
   removed, new added) and its transitive dependencies should move. An unexpected new group or a
   changed hash for an unchanged version is a reason to stop and look, not to commit.
4. Verify without network access to the old cache: `GRADLE_USER_HOME=$(mktemp -d) ./gradlew
   --no-daemon check assembleRelease` must pass. (An offline run, `--offline`, then works from that
   warmed home.)
5. Commit the file with the version bump (`build(deps): ...`).

Entries of versions no longer used stay in the file until the next regeneration; removing them is
optional (regenerate by deleting the file first, then step 2, then review).

Dependabot is configured in `.github/dependabot.yml` for Gradle (the catalog), uv (`server/`), Docker and
GitHub Actions; it does not update this file. There is currently **no CI workflow that runs on pull
requests** (only the Release workflow on tags), so a Dependabot PR is not checked until it is merged and
tagged. Adding a workflow that runs `./gradlew check` on pull requests would make step 4 automatic; this
is listed in the open points of the release preparation.

### Server

`server/uv.lock` pins the Python dependencies with hashes (`uv sync --locked` in the Dockerfile) and the
base images are pinned by digest. The server image is not claimed reproducible; it is published with
provenance and an SBOM by the release workflow.
