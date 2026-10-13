# Autofill

UltimateOTP is an Android autofill service (`android.service.autofill.AutofillService`). When a
login form asks for a one-time code it offers the matching entry; picking it fills the code.
Turn it on in Settings > Autofill > Autofill settings, which opens Android's own choice of
autofill service.

## What it does and what it never does

- **Unlock first.** While the vault is locked a request only gets one entry, "Unlock
  UltimateOTP"; picking it shows the biometric / device-credential prompt, and only then are the
  matching entries offered. No entry can be listed without that.
- **Datasets carry no code.** Each offered entry is an authentication-required dataset: the
  response holds only issuer and account for the label. The code is made when the user picks it
  (so it is fresh, and HOTP counters advance only on use), by `AutofillAuthActivity`, which
  checks that the app is unlocked. The activity window is `FLAG_SECURE`.
- **Nothing is stored.** No `SaveInfo` is set, so Android never asks to save; `onSaveRequest` does
  nothing. The service reads field descriptions (hints, ids, labels, input type), never the text a
  user typed. Matching reads no secret: only issuer and the stored associations.
- **The app does not fill itself.**

## How an entry is matched

1. **Explicit association** (Settings > Autofill > Apps and sites per entry): one package name
   (`com.example.app`) or domain (`example.com`, which also covers `login.example.com`) per
   line. Always first.
2. **Issuer guess** for a web form: the issuer equals the registrable label of the domain (issuer
   "GitHub" for `github.com` or `gist.github.com`), or is itself a domain that covers or is covered by
   it (issuer `accounts.google.com`). For an app: the issuer equals a segment of the package name
   (`com.github.android`). Issuers shorter than 3 characters are never guessed from.

For a web form only the web domain is used, not the browser's package. At most 5 entries are
offered.

## How the code field is found

OTP fields are often not annotated. The service picks the best-scoring text field:
explicit hints (`smsOTPCode`, `oneTimeCode`, HTML `autocomplete="one-time-code"`) win; otherwise
field ids, hints, labels (and for web fields `name`, `id`, `aria-label`) are scored for words such
as `otp`, `totp`, `2fa`, `mfa`, `verification code`, `authenticator`, `security code`,
`código`, `verificación`; numeric input and a `maxlength` of 4-10 add to it. Username, email,
phone and ordinary password fields are never chosen.

## Limits, honestly

- **It depends on the app or browser.** Autofill only works where the app exposes the form to the
  framework. Apps that mark fields `importantForAutofill="no"`, custom-drawn fields, games and
  some banking apps give the service nothing.
- **Browsers.** Chrome (with "Autofill using another service" enabled), Firefox, Brave and
  other Chromium browsers expose the web domain; the domain is only known when the browser
  provides it (Android 8+ "compat mode" in some browsers does not). When the domain is missing the
  entry can only match by explicit package association, which is useless for a browser.
- **The code field is a guess** unless the site marks it. A field called `code` or `pin` with
  no other hint is not recognised; the user then copies the code from the app as before.
  Pages that show the code field only after a click may need a second request.
- **Several matches** are all listed (up to 5); there is no learning of which one you use.
- **Split code fields** (six one-digit boxes) are filled with the full code in every box the
  detector recognises; most such pages take the first and distribute it, some do not.
- **Inline suggestions** in the keyboard are not offered, only the dropdown.
- **Password managers fight.** Android allows one autofill service; UltimateOTP replaces yours
  for everything, passwords included, unless your service is the one that is selected. Use it
  together with a keyboard-based or manual password manager, or leave it off.
- **Not verified on a device** at the time of writing: the whole path (the service, the
  authentication activity, the datasets) has unit tests for matching and field detection but was
  not run on a phone or emulator.
