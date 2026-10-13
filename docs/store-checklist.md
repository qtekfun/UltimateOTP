<!--
SPDX-FileCopyrightText: 2026 UltimateOTP contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Store checklist (F-Droid and GitHub Releases)

Distribution channels: F-Droid and GitHub Releases only. Not Google Play, not IzzyOnDroid.
Tick the boxes in a release PR or in the first-submission merge request.

## Once, before the first F-Droid submission

- [ ] A tagged release that contains the resource-path fix (0.1.3 or later). Do not submit 0.1.2.
- [ ] Release key exists, is backed up, and the four `UOTP_*` secrets are set (RELEASING.md).
- [ ] `AllowedAPKSigningKeys` filled in with the SHA-256 of the release certificate.
- [ ] `commit:` in the recipe is the full 40-character hash of the release tag.
- [ ] Icon (`fastlane/metadata/android/en-US/images/icon.png`, 512 x 512) and feature graphic
      (`featureGraphic.png`, 1024 x 500) from the redesign are in place; the same in `es-ES/` is optional
      (F-Droid falls back to `en-US`).
- [ ] At least two screenshots in `images/phoneScreenshots/` (`1.png`, `2.png`, ...), taken with invented
      data only (no real issuers or secrets), on the final UI.
- [ ] README, `SECURITY.md` and the status wording ("early development, not audited") are consistent with
      `full_description.txt`.
- [ ] Private vulnerability reporting is enabled on the GitHub repository (Settings, Code security).
- [ ] The repository is public, has the GPL-3.0-or-later `LICENSE`, and every dependency is free software
      (the `licensee` Gradle plugin runs in `./gradlew check`).
- [ ] `fdroid lint` and `fdroid rewritemeta` leave the recipe unchanged, and the source and APK scanners
      report no problems (docs/fdroid/README.md, "Validation").
- [ ] A reproducible build check passes for the tag (docs/reproducible-builds.md).
- [ ] Fork fdroiddata, add `metadata/com.qtekfun.ultimateotp.yml`, run the CI of the merge request, open
      it. Do this from the owner's account; nothing in this repository does it.

## With every release

- [ ] `CHANGELOG.md` updated and dated; compare links fixed.
- [ ] `versionName` and `versionCode` bumped in `android/app/build.gradle.kts`; `versionCode` is exactly
      one higher than the previous tag.
- [ ] `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt` and `es-ES/` exist, at most 500
      bytes each, no emoji, no markup.
- [ ] `title.txt` at most 30 characters, `short_description.txt` at most 80, `full_description.txt` at
      most 4000 (current: 11, 60 and about 2000).
- [ ] The description still matches reality: features that exist, the "not audited" statement, the need
      for your own server for sync.
- [ ] `android/gradle/verification-metadata.xml` updated if any dependency or plugin moved.
- [ ] No new permission, tracker, network endpoint or non-free dependency was added without being
      mentioned in the description and in `docs/fdroid/README.md`.
- [ ] Tag `v<versionName>` pushed; the Release workflow is green; the APK and its `.sha256` are on the
      GitHub Release.
- [ ] After the F-Droid bot's merge request or build: the F-Droid build is verified reproducible (the
      app's page shows the project's signature, not F-Droid's).

## Screenshots and graphics: sizes

| File | Size | Notes |
|---|---|---|
| `images/icon.png` | 512 x 512 px, PNG, under 1 MB | Same artwork as the launcher icon. No transparency tricks that make it unreadable on a dark background. |
| `images/featureGraphic.png` | 1024 x 500 px, PNG or JPG | Shown on the app page header. |
| `images/phoneScreenshots/N.png` | Phone portrait, for example 1080 x 2400 px | Numbered from 1; shown in order. Use the light and the dark theme if both look good. |
| `images/sevenInchScreenshots/`, `tenInchScreenshots/` | Optional | Only if a tablet layout is worth showing. |
| `images/promoGraphic.png`, `tvBanner.png` | Not used | |
