#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The instrumented suite, run by the emulator step of .github/workflows/ci.yml (and by hand against
# an emulator with a real server on the host: see docs/testing.md). Never run it against a phone
# with data: Gradle installs the app, runs the tests and uninstalls it again.
#
# Blocking journeys fail the job. Non-blocking ones (known bug, or brittle system UI) are
# reported as warnings with their result, so they are visible without hiding a real failure.
#
# Environment:
#   UOTP_SERVER   the server as the emulator sees it (default http://10.0.2.2:8047)
#   UOTP_SUITE    "full" (default) or "kdf" (only the Argon2id test, for the 32-bit image)
set -u
cd "$(dirname "$0")/../../android" || exit 1

server="${UOTP_SERVER:-http://10.0.2.2:8047}"
suite="${UOTP_SUITE:-full}"
pkg="com.qtekfun.ultimateotp.smoke"
args=(--console=plain --stacktrace "-Pandroid.testInstrumentationRunnerArguments.server=${server}")
failed=()
warned=()

# run_class <gradle task> <test class> [extra gradle args...]
run_class() {
  local task="$1" class="$2"
  shift 2
  echo "::group::${class}"
  ./gradlew "${task}" "${args[@]}" "$@" \
    "-Pandroid.testInstrumentationRunnerArguments.class=${pkg}.${class}"
  local rc=$?
  echo "::endgroup::"
  return "${rc}"
}

blocking() {
  run_class "$@" || failed+=("$2")
}

advisory() {
  run_class "$@" || warned+=("$2")
}

# Unminified: the largest Argon2id step against a PyNaCl key, on this ABI.
blocking connectedDebugAndroidTest KdfMaxStepTest -Puotp.testBuildType=debug

if [[ "${suite}" == "full" ]]; then
  # The minified release build. Order matters: the login needs the account the sign-up made, and
  # Gradle uninstalls the app after each run, so the second run is a fresh install (a second device).
  blocking connectedSmokeAndroidTest OfflineJourneyTest
  blocking connectedSmokeAndroidTest SignUpJourneyTest
  blocking connectedSmokeAndroidTest LoginJourneyTest
  # Known to fail until the app handles an expired Keystore authentication (docs/testing.md, KB-3),
  # and dependent on the system document picker.
  advisory connectedSmokeAndroidTest LockedDeviceSignUpTest
  advisory connectedSmokeAndroidTest ExportImportJourneyTest
fi

for name in "${warned[@]}"; do
  echo "::warning title=Advisory device test failed::${name} (non-blocking, see docs/testing.md)"
done
if ((${#failed[@]})); then
  for name in "${failed[@]}"; do
    echo "::error title=Device test failed::${name}"
  done
  exit 1
fi
