# UI design system

The Android app's look: a dark-first, green-accented Material 3 theme, vector brand icons next to
every account, and screens that adapt from the Pixel 9 Pro Fold's cover display to its inner display.
The code is in `android/app/src/main/kotlin/com/qtekfun/ultimateotp/ui/`.

![Codes](screenshots/phone-dark-codes.png)

## Identity

| | |
|---|---|
| Name | UltimateOTP |
| Mark | A countdown ring with a gap and a hand: the time left on a code. Original artwork. |
| Sources | `docs/branding/logo.svg` (icon with background, 108 x 108), `docs/branding/logo-mark.svg` (mark alone). Store graphics should be generated from these. |
| Launcher icon | Adaptive: `ic_launcher_background`, `ic_launcher_foreground`, `ic_launcher_monochrome` (themed icons). |
| Splash | AndroidX SplashScreen, `Theme.UltimateOTP.Starting`; it stays until the saved theme is read, so there is no light flash in dark mode. |
| In-app logo | `ic_logo.xml` through `UotpLogo`, on onboarding, the lock screen and Settings > About. |

## Palette

Defined in `ui/theme/Color.kt`; one green identity (emerald to mint), neutrals tinted slightly green.

| Role | Dark | Light |
|---|---|---|
| Background | `#0D1210` (`#000000` with "True black") | `#F4F8F5` |
| Card (surfaceContainer) | `#131A16` | `#E8EEEA` |
| Primary | `#5BE08F` on `#00391B` | `#0B7A3E` on white |
| Primary container | `#0F4F2B` | `#C6F2D5` |
| Secondary | `#A9CDB6` | `#3F6350` |
| Warning (ring "soon", callouts) | `#FFC46B` | `#9A5A00` |
| Danger (ring "now", errors) | `#FF8F87` | `#B3261E` |
| Success (synced, copied) | `#7CE9A6` | `#0B7A43` |

Dynamic colour (Android 12+) is a setting, off by default. Colour is never the only signal: the ring
always has the seconds written in it, callouts have icons, the strength meter has words and segments.

## Typography

`ui/theme/Type.kt`. The default face (Roboto) for text, with a clear scale from `headlineLarge` 30 sp
down to `labelSmall` 11 sp. Codes and recovery words use **JetBrains Mono** (OFL 1.1, bundled as
`res/font/jetbrains_mono.ttf`, a variable font) with `tnum`, so every digit has the same width:

| Style | Size | Where |
|---|---|---|
| `CodeStyles.Hero` | 52 sp | the detail pane |
| `CodeStyles.Large` | 30 sp | list cards |
| `CodeStyles.Medium` | 24 sp | grid cards |
| `CodeStyles.Small` | 17 sp | next-code preview, recovery words |

Codes are grouped as `123 456` (`1234 5678` for 8 digits; Steam's 5 characters stay whole).

## Spacing, shapes

`ui/theme/Dimens.kt`: a 4 dp grid (`Space.Xs` 4, `Sm` 8, `Md` 12, `Lg` 16, `Xl` 24, `Xxl` 32, `Huge` 48),
16 dp side gutter, 48 dp minimum touch target, corner radii 6/10/16/22/30 dp. Forms and settings are
at most 640 dp wide and centred.

## Components (`ui/components/`)

| Component | Use |
|---|---|
| `IssuerAvatar` | brand icon on its colour, or a letter on a stable colour |
| `CountdownRing` | animated ring, accent / amber (last third) / red (last five seconds), seconds inside |
| `Callout` | bordered info / warning / error / success card with icon |
| `StrengthMeter` | four-segment bar plus words |
| `RecoveryWordsGrid`, `CopyWordsButton` | the 24 words in a bordered 2 (3 when wide) column grid |
| `FlowScaffold`, `StepProgress`, `StepHeader` | sign-up, log-in and detail screens: top bar, "Step n of m", centred column |
| `SettingsGroup`, `SettingsRow`, `SettingsSwitchRow` | grouped settings with icons |
| `PasswordField` | password with a show/hide eye |
| `UotpLogo` | the mark on its tile |

## Screens

* **Codes** (`ui/codes/`): collapsing large top bar with search, sync state, lock and an overflow menu;
  tag chips and a list/grid toggle; pinned section; cards with logo, name, grouped code and ring; tap
  copies (haptic, in-place check), long press opens the account menu sheet (edit, pin, tags, delete);
  HOTP has a next button; the last five seconds show the next code faded; extended FAB opens the add
  sheet (scan, enter manually, import). Empty state with illustration and two actions.
* **Adaptive**: compact is one column (or a 2-column grid); medium has several columns; expanded
  (>= 840 dp, e.g. the inner display) is a list plus a detail pane for the selected account.
  `WidthClass` is computed from the configuration, so fold/unfold re-lays out without losing state
  (selection, search, dialogs use `rememberSaveable`).
* **Add / Edit / Settings / Sessions / Sync / Sign-up / Log-in / Lock / Welcome**: see
  `docs/screenshots/`.

## Motion, haptics, accessibility

* Ring animates linearly between ticks; colour cross-fades; avatar cross-fades to a check on copy;
  screens slide and fade; predictive back is enabled (`enableOnBackInvokedCallback`).
* Haptics: `LongPress` when the menu opens, `Confirm` on copy.
* Cards are one TalkBack element with a spoken description (digits spaced, seconds left) and named
  click and long-click actions. Targets are at least 48 dp. Text is in sp and the layouts were
  rendered at font scale 1.3 and 2.0.

## Icon pack policy

See [icons.md](icons.md): Simple Icons (CC0), vector only, referenced by `R.drawable`, never by a
name lookup; unknown names get a stable coloured letter.

## Screenshots

`ScreenshotTest` renders the screens on the JVM (Roborazzi, Robolectric native graphics) into
`android/app/build/screenshots/<look>/` for phone, fold cover, fold inner display, light/dark, true
black and large fonts. `docs/screenshots/` holds a curated, downscaled selection. They are a review
aid, not golden files: fonts and anti-aliasing differ per host.
