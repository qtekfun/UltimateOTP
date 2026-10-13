# Error log

The app keeps a small log of crashes and handled errors **on the phone only**. It never goes
anywhere by itself; the owner exports it from Settings > Error log (Share, or Save as a text file)
and sends it, or does not.

## What is in it

- A header: app version and version code, build type, **R8 map id**, Android SDK level.
- **Crash records**: the thread name and the redacted stack trace of an uncaught exception, with the
  last 30 events of the ring (below) before it.
- **Error records**: handled problems (for example "server trash unavailable") with the same
  tail.
- The **ring**: the last 200 non-sensitive events (app start, locked, sync finished with counts,
  autofill request seen). It lives in memory only and reaches the file only inside a record.

The file is `files/diagnostics/errors.log` in the app's private storage, 64 KiB at most, rotated
into `errors.1.log` (so at most 128 KiB). No network is used.

## What is never in it

Everything passes through `Redactor` when it is written: `otpauth://` and
`otpauth-migration://` URIs, base32/hex/base64 tokens, 6-8 digit codes, email addresses, ids
(`dev_…`, `acc_…`, `uoe_…`, UUIDs), IPv4 addresses, "password/secret/token" followed by a value, and
the **path, query and credentials of URLs** (the host and port stay, so connection problems can be
read). Callers also pass counts and kinds, not content. Redaction is tested in
`DiagnosticsLogTest`.

## Reading a stack trace of a release build

The release build is minified by R8, so frames look like `at a.b.c.d(r8-map-id-1a2b….java:7)`.

1. The header's `r8 map id` and the frame's `r8-map-id-…` are the same value: they name the
   `mapping.txt` of that build. A GitHub release keeps the `mapping.txt` of its tag (see
   RELEASING.md); the id is in its first lines as `# pg_map_id: …`. If the header says "obfuscated, id
   not embedded", match by version code instead.
2. De-obfuscate with R8's retrace: `retrace mapping.txt trace.txt` (command line tools /
   `r8.jar com.android.tools.r8.retrace.Retrace`) or Android Studio's "Analyze > Stack Trace or
   Thread Dump".
3. A mismatched mapping gives wrong names without an error: check the id first. (This is what
   made the 0.1.2 crash readable.)

## Limits

- Native crashes (libsodium, JNA) and out-of-memory kills do not run the Java handler and
  leave no record.
- The ring is lost with the process; a crash record contains it, a kill does not.
