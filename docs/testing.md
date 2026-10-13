# Testing

What each layer of the test suite proves, what it cannot, how to run it, and what still needs a
real phone. Written after a signed release APK crashed on a Pixel 9 Pro Fold with 284 tests green:
the old suite ran unminified code, on a JVM, against fakes written by the same people as the code,
and never on a phone with a screen lock. The layers below exist to close that distance, and the
last section says how far they get.

Status of each layer is stated plainly: **verified** means it was run on the machine that wrote it;
**unverified** means it is written and compiles, but runs only in GitHub Actions and has not been
seen to pass.

## The layers

| # | Layer | Where | Runs in | Proves | Cannot prove |
|---|---|---|---|---|---|
| 1 | Server tests (pytest) | `server/tests` | `./gradlew`-free: `uv run pytest`; CI `server` | Routes, auth, rate limits, SQLite, migrations, SSE, the contract's schemas, RFC/PyNaCl vectors | That any client speaks the protocol (the test client is the server authors' own) |
| 2 | Server properties (Hypothesis) | `server/tests/test_properties.py` | same | The signed statements are injective in their fields, the manifest is order-free, signatures verify only for the exact message and key, strict base64url | Anything about how clients build them |
| 3 | Server process test | `server/tests/test_process.py` | same | `python -m ultimateotp migrate` and `api` start from `UOTP_*` variables alone, answer, and stop on SIGTERM | Docker image, Traefik, TLS |
| 4 | Android unit tests (JUnit 5) | `android/core/*/src/test` | `./gradlew check`; CI `android` | Crypto against vectors, OTP against RFCs, merge, codec, sync engine against `FakeUotpServer` | Minified code, native libraries of a real ABI, a real server |
| 5 | Android property tests (kotest) | `*PropertiesTest`, `PasswordKdfLadderTest`, `ItemCipherPropertiesTest` | same | The same code over random secrets/times/items; the KDF ladder over every memory figure | Same as 4 |
| 6 | Robolectric Compose tests | `android/app/src/test/.../ui` | same | Screens and view models tapped through with real crypto against the fake server, at the cover (411 dp) and inner (791 dp) window sizes, across a recreate; the lapsed-authentication paths (`ExpiredAuthenticationTest`: prompt, cancel, success, key invalidated, at first run, unlock, sign-up and login) | Real window sizes, real Keystore, R8, a real Activity from the launcher |
| 7 | R8 mapping check | `verifyMinifiedBuild` in `android/app/build.gradle.kts`, part of `check` | same, runs R8 once | Names reached by reflection (JNA, ionspin, Room `_Impl`, activity, application) kept their names; serializers and engine classes were not removed | That the minified app *behaves*: only that those names exist |
| 8 | Contract test | `RealServerContractTest` in `:core:sync` (tag `contract`) | `./gradlew :core:sync:contractTest`; CI `contract` | The Android sync engine against the real Python server over HTTP: sign-up, password login on a second device, live events, revocation, clock skew, lockout, CLI-minted token + recovery words | Production TLS/proxy, a real email relay |
| 9 | Device suite | `android/app/src/androidTest` + `.github/scripts/device-tests.sh` | CI `device` (emulator, KVM) | The **minified release build** starts, signs up against a real server, logs in again from a fresh install, works offline; Argon2id at the maximum step on a real native library | See "Known gaps" |
| 10 | Test guard | `android/config/testguard` | every module's unit tests | No `@Test` method returns a value (JUnit would skip it silently); no test is disabled without `KNOWN BUG` | Tests that pass for the wrong reason in other ways |
| 11 | Coverage floors | Kover (`koverVerify`), coverage.py (`fail_under`) | `check`, CI `server` | Coverage cannot fall below today's | That covered lines are well asserted |

CI (`.github/workflows/ci.yml`) runs on every push and pull request: `server`, `android`,
`contract`, `device`, `actionlint`, `gitleaks`, all independent. Releases stay in `release.yml`,
which still runs `./gradlew check assembleRelease` itself; a tag should only be pushed from a
commit whose CI is green, because `release.yml` does not run layers 8 and 9.

## Running it locally

```sh
# Server (ruff, format, tests with coverage, OpenAPI)
cd server
uv run ruff check . && uv run ruff format --check .
uv run coverage run -m pytest && uv run coverage report      # fail_under in pyproject.toml
uv run openapi-spec-validator ../contracts/openapi.yaml

# Android: everything that needs no device and no uv
cd android
./gradlew check                    # detekt, ktlint, lint, licensee, JVM + Robolectric tests, Kover floors, R8 mapping check
./gradlew koverHtmlReport          # per-module report under */build/reports/kover/html

# The sync engine against the real Python server (needs uv on PATH)
./gradlew :core:sync:contractTest

# Compile the instrumented tests; this needs no device
./gradlew :app:assembleSmoke :app:assembleSmokeAndroidTest
./gradlew -Puotp.testBuildType=debug :app:assembleDebugAndroidTest
```

Property tests use a fixed seed so a red build is reproducible. `UOTP_PBT_SEED=random ./gradlew
:core:otp:test` explores new inputs (Hypothesis on the server does so by itself, keeping failing
examples in `.hypothesis/`).

**Do not run the device suite on a phone you care about.** `connected*AndroidTest` installs the
`smoke` build (package `com.qtekfun.ultimateotp.smoke`, a different package from the real app, so
it cannot replace or wipe it), runs, and uninstalls. It is meant for an emulator. To run it by
hand: start a server on the host
(`UOTP_SIGNUP=enabled UOTP_EMAIL_VERIFICATION=disabled UOTP_RATELIMIT_ENABLED=false uv run
ultimateotp api`, after `migrate`), then `.github/scripts/device-tests.sh` with
`UOTP_SERVER=http://10.0.2.2:8047`.

## Why the device suite is built the way it is

**The build under test.** `testBuildType` of `:app` is `smoke`: `initWith(release)`, so the same R8
configuration (`proguard-android-optimize.txt` + `proguard-rules.pro`), `isMinifyEnabled` and
`isShrinkResources`, signed with the debug key and installed under `.smoke`. Its differences from
the shipped APK are exactly: the signing key, the application id suffix, and
`src/smoke/res/xml/network_security_config.xml` (cleartext to `10.0.2.2`, where CI runs the
server). Everything else is the release build. AGP creates the unit tests for the test build
type only, so the JVM tests also run as `testSmokeUnitTest`; unit tests do not run R8 either way.
`-Puotp.testBuildType=debug` selects the debug build (used once, for the KDF test).

**UI Automator, not Compose test APIs.** The app under test is minified: its classes and
members are renamed, so a test that names them breaks, or worse, tests a different class path than
the user runs. `createComposeRule` also needs `ui-test-manifest`, a debug-only artifact that would
have to be added to the build under test. UI Automator reads the accessibility tree of the installed
app, launches it from the launcher intent and references nothing of the app, which is the interface
a person has. The price: text fields are addressed by order (Compose labels are not the field's
text), and system UI (document picker, lock prompt) is whatever the system image has.

**A real server.** The job starts `ultimateotp api` on the runner with `UOTP_SIGNUP=enabled`
and `UOTP_EMAIL_VERIFICATION=disabled`; the emulator reaches it at `10.0.2.2:8047`. The second
journey is a fresh install that logs in with the first one's email and password (Gradle uninstalls
between runs), so password derivation, the SRP proof and the key unwrap run for real.

**Journeys** (`android/app/src/androidTest/.../smoke`):

| Test | Steps | Blocking |
|---|---|---|
| `OfflineJourneyTest` | start, "Use without a server", add an entry from an `otpauth://` URI (Paste tab), see its grouped code, open settings | yes |
| `SignUpJourneyTest` | "Create account", server + email, code, password (Argon2id), 24 words, confirm, create, codes screen | yes |
| `LoginJourneyTest` | fresh install, "Log in", email, password (SRP), sync, codes screen | yes |
| `KdfMaxStepTest` | debug build: 4 passes / 1 GiB against a PyNaCl key; the step this device would pick, derived and re-read | yes |
| `LockedDeviceSignUpTest` | `locksettings set-pin`, wait out the 30 s Keystore window, tap "Create account": the app must survive | **no**: KB-3 is fixed on the JVM, but the real prompt has never been seen on a device |
| `ExportImportJourneyTest` | encrypted export and re-import through the system document picker | **no**: depends on DocumentsUI selectors, unverified |

Non-blocking steps print a `::warning::` with their result; promote them to blocking (move them to
`blocking` in `device-tests.sh`) once `LockedDeviceSignUpTest` and the picker test have each passed
three times on an emulator. Note that on that test the system prompt is shown now (the app asks the
person to authenticate instead of dying), so the test driver must confirm the PIN to get past it.

## The 32-bit ABI and the key derivation

Password keys are Argon2id with libsodium's *sensitive* limits, 4 passes over 1 GiB, falling back
to 8 x 512 MiB and 16 x 256 MiB (crypto-format.md section 4.1). On Android a failed 1 GiB `mmap` is
not a reliable signal (overcommit lets it succeed and the low-memory killer ends the process), so
the rung is chosen up front from `ActivityManager.MemoryInfo.availMem` (`PasswordKdf.ladderFor`)
with 1.5x headroom.

* `PasswordKdfLadderTest` covers the decision for injected figures: unknown (0), negative,
  below 384 MiB, each boundary, `Long.MAX_VALUE`, monotonicity. Findings it encodes: below 384 MiB
  *and* when memory is unknown the 256 MiB rung is still run (the ladder never refuses), so a device
  that reports almost no free memory is sent into a 256 MiB allocation instead of an error.
* Every rung encodes to the 29-byte `params_block` the server's `password_kdf` accepts, passes the
  reader limits (the first rung is exactly `MAX_MEM`: raising it would make a new account
  unreadable by a client that enforces the limit), and reproduces PyNaCl's key for the same inputs.
  A device whose ladder starts elsewhere opens what another device wrote, because the reader uses
  the stored parameters, never its own ladder.
* **32-bit.** libsodium's `crypto_pwhash` takes `size_t memlimit`. The ionspin bindings pass a
  64-bit integer, which on `armeabi-v7a`/`x86` shifts the following arguments; `PasswordKdf` calls
  the function through JNA with `NativeLong` instead (4 bytes there). The test asserts every rung
  fits a signed 32-bit `NativeLong`, so a ladder edit above 2 GiB fails on the JVM. The APK ships
  all four ABIs. What no test here shows is a 1 GiB allocation inside a 32-bit process's address
  space on a phone; the experimental `x86 / API 30` CI entry runs the same Argon2id test on a
  32-bit emulator image, which is the closest proxy available without an ARM device.
  Status (2026-10-14): that job runs on the `google_apis` x86 API 30 image, because the `default` one
  does not exist on the GitHub runners, and it passes. It is the only evidence of the key derivation
  with a 4-byte `size_t`; real armeabi-v7a hardware is still untested.

## Known bugs the suite found

Each is a test written to the *correct* behaviour, run once to confirm it fails, and then marked
`@Disabled("KNOWN BUG KB-n ...")` (or `xfail(strict=True)` in pytest, which turns red when the bug
is fixed). The guard in layer 10 refuses any other disabled test. When the suite was written
production code was not changed; KB-3 has since been fixed (below) and its tests enabled.

| ID | Where | What | Test |
|---|---|---|---|
| KB-1 | `OtpAuthUri.parse` | A colon in an issuer or an account name corrupts the entry on the `otpauth` round trip: `format` percent-encodes it, `parse` splits the *decoded* label at its first colon. `("a:b","c")` comes back as label `b:c`; `("","x:y")` as issuer `x`, label `y` | `OtpPropertiesTest` |
| ~~KB-2~~ | server `Login.verify` | **Fixed (server 1.2.0).** An SRP login from a phone whose clock was more than 60 s off could never succeed: the session was consumed before the request timestamp was checked. `stale_request` is now answered first and consumes nothing | `RealServerContractTest`, `test_login.py::test_password_login_survives_a_stale_clock_retry`, `test_clock_skew.py` |
| ~~KB-3~~ **closed** | `RootViewModel.create`, `SignupViewModel.go`, `LoginViewModel.go` | `AuthenticationRequiredException` (a Keystore key with `setUserAuthenticationRequired(true)` and a 30 s window, which is every phone with a screen lock) is not an `IOException`, `CryptoException` or `ApiException`, so no handler matches and the coroutine ends the process. It happens when the vault key is first written (tap "Create account") and again at the end of sign-up, after a person has read an email and typed a password for more than 30 s. At that point the server has already created the account (`201`) and the device has not stored its keys: a retry meets `email_taken` | `ExpiredAuthenticationTest` |
| KB-4 | manifest | The app tells the user to enroll on a LAN address (`EnrollmentPolicy` accepts `http://192.168...`), but the manifest has no network security config, and since Android 9 cleartext HTTP is refused for targetSdk 28+: every plain-http LAN URL fails as a network error | `CleartextPolicyTest` |
| KB-5 | sign-up / login / sync screens | Form fields are `remember`, not `rememberSaveable`: unfolding or rotating the phone empties the server address, email and code. The step and the recovery words are kept (they live in the view model) | `SignupUiTest` |

### KB-3, closed: how

* **Preflight.** `SecretStore.checkUsable()` initialises an encrypt cipher on the Keystore key
  (that is where the authentication window is checked) and stores nothing; `SyncStore.ensureWritable()`
  exposes it to the engine. `SyncEngine` calls it before `/signup`, `/enroll` (bootstrap and token
  enrollment), `/srp/verify` and rotation, and again after any slow key derivation that precedes
  the request. `SrpEmailLogin.complete` runs it before it consumes the SRP session, so a declined
  prompt leaves the same session and emailed code for the retry. `EmailSignup.create` no longer
  turns a failing first sync into a failed sign-up (the account exists by then).
* **One gate.** `auth/AuthGate` (singleton). `gate.run { ... }` runs an operation; on
  `AuthenticationRequiredException` it publishes a `Prompt`, the root composable (`AuthHost`, in
  `AppRoot`) shows the existing BiometricPrompt / device-credential flow and answers it, and the
  operation is run again from its start (at most three times, one prompt shared by concurrent
  callers). Declined or failed prompts return `GateResult.Declined` and post a `Notice` (a dialog
  at the root); `KeyInvalidatedException` returns `GateResult.KeyLost` with its own message; any
  other exception propagates to the caller's own mapping, or `gate.attempt` turns it into
  `GateResult.Failed` and a `Notice`. Cancelling returns the screen to where it was: welcome
  screen at first run, the recovery words at the end of sign-up (draft kept), the password step at
  login (session kept), the previous step in the sync screen.
* **No dead process.** The app's background scope has a `CoroutineExceptionHandler`; every
  `viewModelScope.launch` goes through the gate, a catch-all that maps to a failed state
  (`SignupStep.Failed`, `LoginStep.Failed`, `SyncStep.Failed(UNEXPECTED)`, a `Notice`), or
  swallows only what it can safely ignore (a failed device list refresh). `SyncController.syncNow`
  catches any exception and resets `running`.
* **Not verified on a device**: the real BiometricPrompt, the 30 s Keystore timing, and what an
  Activity recreation does to a prompt that is on screen (the prompt is re-issued by
  `LaunchedEffect`; the library's own retention of the fragment is not exercised here).
* **Open**: `KeyInvalidatedException` is reported with a message that points to restoring from
  sync or an import, but there is no in-app way to clear a lost Keystore key's orphaned
  `vault_key` file, so a phone in that state stays on the lock screen. That needs a decision
  (a destructive "start over" action) and was left out on purpose.

KB-3 matched both crash points of the report from the Pixel 9 Pro Fold (first tap on "Create
account", and again after code and password). It was derived from reading the code and
reproduced on the JVM with a store that behaves like the lapsed key; it was *not* observed on a
device, and the device log may show something else (see "Known gaps").

Not bugs, but worth a decision: `Merge.resolve` is not symmetric when two writes carry the same
`updated` and `updatedBy` (the remote side wins whichever is "local"); R8's own keep rules in
`proguard-rules.pro` for JNA and ionspin changed nothing in the mapping when removed, because the
libraries' consumer rules already keep them (the mapping check shows names only, not behaviour).

## Known gaps: what still needs a real phone

* **The device suite is unverified.** None of layer 9 (or the YAML's emulator step) has been run: the
  author's emulator segfaults and phones are off limits. It was validated for what it can be:
  `actionlint` (clean), `shellcheck`, `assembleSmoke`, `assembleSmokeAndroidTest`,
  `assembleDebugAndroidTest`, and the Gradle task graph. Expect first-run fixes in the selectors
  (`AppDriver`) and the picker test.
* **Real hardware keys.** An emulator has a software Keystore (no StrongBox, no TEE). KB-3 depends
  on `isDeviceSecure`; CI sets a PIN with `locksettings`, but the biometric prompt and the
  `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` flow of `MainActivity.authenticate` are not driven by
  any test.
* **Memory pressure.** The emulator has 4 GiB; a phone has other apps and a low-memory killer with
  vendor policies. No test makes a 1 GiB Argon2id compete with real memory pressure, and no ARM
  device runs the `armeabi-v7a` build.
* **Foldable behaviour.** The Robolectric tests use the two window sizes and a recreate; they do not
  run the real hinge, `WindowManager` posture, multi-window, or a process death while folded.
  Compose is not adaptive in this app (single column on both displays); nothing checks that the
  inner display *looks* right, only that it works.
* **The system camera, QR scanner and CameraX** (`QrScanner`) and `ActivityResult` pickers other
  than the one smoke attempt.
* **Production transport.** TLS, Cloudflare, Traefik rate limits, and the real email relay are not
  exercised; the server runs with email verification disabled in every automated flow that uses a
  real process, so the emailed-code path is only tested in-process (pytest and the fake server).
* **Upgrade paths.** No test installs the previous release and upgrades over it (Room migration
  with real data, Keystore key surviving an update).
* **Long-running behaviour.** Event-stream reconnects after the one-hour server cut, the
  foreground/background lifecycle of `SyncController`, and the auto-lock timer have no device test.
* **Accessibility, localisation, backups and `data_extraction_rules`.**

## Numbers

Measured on the machine that wrote this, at the commit that added this file.

| | Before (`d5db3a0`) | After |
|---|---|---|
| Server tests | 170 passed | 184 passed + 1 strict xfail |
| Android JVM tests (`./gradlew check`) | 114 | 191, of which 184 run and 7 are disabled known bugs |
| Contract test (`:core:sync:contractTest`) | none | 8, of which 7 run and 1 is a disabled known bug |
| Instrumented tests (emulator, CI) | none | 6 classes, 7 tests: **never run** |
| Server coverage (lines + branches) | 96 % | 96 % (floor 94 %) |
| Kover line coverage, `app` | 5.8 % | 32.5 % (floor 30) |
| `core:crypto` | 96.5 % | 97.0 % (floor 94) |
| `core:otp` | 97.0 % | 97.0 % (floor 94) |
| `core:sync` | 92.4 %\* | 91.6 % (floor 89) |
| `core:vault` | 61.1 % | 77.1 % (floor 74) |

\* With the contract fake server counted as production code; it is excluded now, which lowers the
figure although the module has more tests. The contract test adds about four points to
`core:sync` when its data is merged (95.4 % was measured once that way); it is deliberately not
counted, because it needs `uv` and `check` must not.

Kover line coverage is the measure used for the floors; branch coverage is lower (`core:sync` 49 %,
`core:vault` 52 %, `app` 25 %) and is in `koverHtmlReport`. A floor says the number cannot fall, not
that the covered lines are well asserted.

After the KB-3 fix (`fix/keystore-auth`, integrated with `feat/show-password`): Android JVM tests 255
(251 run, 4 disabled known bugs: KB-1, KB-4, KB-5 twice for the two window sizes). The fix added 16:
`ExpiredAuthenticationTest` 4 to 15 (its three disabled KB-3 tests now run), `PreflightTest` 4
(engine: no request while secrets cannot be stored), `VaultRepositoryTest` 1. Contract test: 7 run.
