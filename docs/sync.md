# Live sync: Server-Sent Events

Status: decided for `/otp/v1` (contract `contracts/openapi.yaml` 1.2.0, `GET /otp/v1/events`; 1.2.0 only adds the `account_deleted` event).
Owner decision 1 (docs/decisions.md): changes on one device must reach the other online devices
without a manual step, within seconds.

## Choice: SSE, not WebSocket

The server only ever needs to tell devices "something changed, pull". Writes already go through
signed REST calls (`POST /otp/v1/vault/commit`), which give us optimistic concurrency, request
signatures, body limits and per-route rate limits for free. So the live channel is one-way.

| Concern | SSE (`text/event-stream`) | WebSocket |
|---|---|---|
| Direction we need | server -> client only | both (unused half) |
| Authentication | a normal signed `GET`: the same Ed25519 request signature as every other call | signature on the upgrade request, then a second, framed protocol to secure |
| Through Cloudflare Tunnel + Traefik | plain HTTP/1.1 response; works through both without special config (Traefik `buffering` must not be applied to the route) | needs upgrade support on every hop; Cloudflare supports it, but it is one more thing to break |
| Server code | an async generator in FastAPI, no extra dependency | needs `websockets`/`wsproto` and a message protocol |
| Android client | OkHttp `okhttp-sse` (same OkHttp the app already uses) or a 30-line reader | OkHttp WebSocket, plus our own framing, heartbeats and reconnect |
| Reconnect semantics | built into the format (`retry:`); we resend state in `hello` | all ours |
| Other later clients (CLI, desktop, web) | `EventSource` / any HTTP client | any WS library |

WebSocket would only win if the server needed to receive a high rate of small messages from the
devices. It does not. No FCM or other push service is used (F-Droid, no Google services): the
stream is the "push", and only while the app is in use or a foreground sync runs.

## Protocol

1. The device opens `GET /otp/v1/events` with the usual signature headers (contract,
   "Authentication"). The signature only needs to be valid at open time.
2. The server answers `200 text/event-stream` and writes, in order:
   - `retry: 5000` (reconnect hint for standard clients);
   - `event: hello` with `{"version", "key_epoch", "devices_revision", "rotation_required"}`;
   - then notifications as they happen:

| Event | Sent to | `data` | Client action |
|---|---|---|---|
| `vault` (`id:` = version) | every stream of the account (the committing device too) | `{"version", "key_epoch", "signed_by"}` | if `version` > local, `GET /otp/v1/vault?since=<local>`, verify head, merge |
| `devices` | every stream of the account | `{"devices_revision"}` | `GET /otp/v1/devices` (or `/otp/v1/sessions`), warn on unexpected additions; also sent when a device signs in with the password (SRP) or signs up |
| `pairing` | streams of the device that created the session | `{"pairing_id", "status"}` | `GET /otp/v1/pairings/{id}`, show SAS |
| `revoked` | streams of the revoked device; then the stream closes | `{"device_id"}` | stop syncing, wipe server state |
| `account_deleted` | every stream of the account; then the stream closes | `{}` | the account was deleted from another device: wipe server state |
| `: keepalive` (comment) | every stream, every 15 s | none | none (keeps proxies and NAT from closing the connection) |

3. Events are **notifications, never data**. A missed event costs nothing: on every (re)connect the
   `hello` state is compared with local state and the client pulls what it lacks. So there is no
   `Last-Event-ID` replay buffer on the server.
4. The server closes a stream after `UOTP_SSE_MAX_AGE_S` (1 h) so stale signatures and half-dead
   connections do not live forever; the client reconnects with a fresh signature. Clients back off
   (5 s, then exponential up to 60 s, with jitter) after errors.
5. A device may hold `UOTP_SSE_MAX_STREAMS_PER_DEVICE` (3) streams; more get `429`.

## Latency

A commit publishes the event in-process right after its transaction commits: other online devices
see `vault` within milliseconds, then pull (one round trip). The test
`tests/test_events.py::test_commit_reaches_other_devices` runs a real uvicorn server, opens two
streams, commits from a third device and asserts both receive the event within 2 s.

Changes made outside the api process (the admin CLI revoking a device, run with `docker compose
exec`) reach the streams on the next keepalive tick (at most 15 s): each stream re-reads its
account state from the database on every tick and emits `vault`/`devices`/`revoked` when it moved.

## Limits and scaling

- The fan-out broker lives in the api process. **Run exactly one api process** (one uvicorn worker,
  one replica), which is what `server/compose.yaml` does. That fits the design (single owner, SQLite).
  A multi-replica deployment would need a shared broker (Postgres `LISTEN/NOTIFY` or Redis); the
  database re-check on every keepalive tick already makes it correct, only slower (<= 15 s).
- Each open stream holds one connection; uvicorn's `limit_concurrency` and Traefik's `inflightreq`
  must leave room for them (deploy notes in `docs/deploy.md`).

## Fetching a delta after tombstone compaction

`GET /otp/v1/vault?since=N` answers `full: true` (the complete live set) when `N` is `0` or older
than a tombstone the server compacted (`UOTP_TOMBSTONE_RETENTION_DAYS`, off by default). On a full
answer a client replaces its local set and treats any local item that is not listed as deleted.
Past versions and the trash are not part of the stream: `GET /otp/v1/vault/history`, see
docs/deploy.md §8.
