# Issuer icon pack

The codes list shows the logo of the service next to every account. The logos are a curated set of
**172 vector drawables** (`android/app/src/main/res/drawable/si_<slug>.xml`) taken from
[Simple Icons](https://github.com/simple-icons/simple-icons).

| | |
|---|---|
| Source | https://github.com/simple-icons/simple-icons (npm package `simple-icons`) |
| Version | 16.35.0 |
| Licence | CC0 1.0 Universal. No attribution is required; we record it anyway (`NOTICE`). |
| Trademarks | The marks belong to their owners. They are used only to identify a service, never to suggest endorsement. |
| Format | Android `VectorDrawable`, 24x24 viewport, one path, black fill; the app tints it. |

## How an account finds its icon

`ui/icons/IssuerIcons.kt` (plain Kotlin, unit-tested in `IssuerIconsTest`):

1. The item's explicit `icon` key, if the data model carries one.
2. The issuer, then the label's prefix (`GitHub:me@example.org`).
3. Names are reduced to lowercase letters and digits after dropping company suffixes
   (`Inc.`, `LLC`, `GmbH`...), so `Github`, `github.com`, `GitHub Inc.` and `accounts.github.com` match.
   Domains are matched by the service label (`gitlab.mycompany.com` is GitLab).
4. An alias table covers renamed or differently spelled brands (`Twitter` is X, `Meta` is Facebook...).
5. A few brands are no longer in Simple Icons (Microsoft, Amazon, AWS, Azure, LinkedIn, Slack...).
   They get a letter on the brand colour, not their mark.
6. Anything else: a letter on one of 12 colours chosen by an FNV-1a hash of the name, so the colour is
   the same on every device and run.

Icons are referenced as `R.drawable.si_*` in the generated `SimpleIcons.kt`, never looked up by name.
That keeps resource shrinking and R8 correct (0.1.2 crashed on a class-relative resource lookup).

## Adding an icon

1. Check it exists: `icons/<slug>.svg` in the Simple Icons package.
2. Add the slug to `SLUGS` in `tools/icons/build_icon_pack.py`.
3. Download the package and run the script:

   ```sh
   mkdir /tmp/si && cd /tmp/si && npm pack simple-icons@16.35.0 && tar xzf simple-icons-*.tgz
   python3 -I tools/icons/build_icon_pack.py /tmp/si/package android/app
   ```

4. If people spell the name differently, add the squashed spellings to `ALIASES` in `IssuerIcons.kt`.
5. Run `./gradlew :app:testDebugUnitTest`; `IssuerIconsTest` checks every bundled slug resolves to itself.

Never copy artwork that is not CC0 (or equally permissive) into the pack; check the licence first.
