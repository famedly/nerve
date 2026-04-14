# Cloud-Native Matrix Test Client

A **cloud-native test client** for [Matrix](https://matrix.org/) homeservers. It
continuously logs in as one or more users, creates encrypted DM rooms between
them, sends numbered messages (with optional image attachments), and verifies
that every message arrives intact and in order — all while emitting structured
telemetry via [OpenTelemetry](https://opentelemetry.io/).

The primary use case is **end-to-end black-box testing** of Matrix homeserver
deployments: federation, end-to-end encryption (E2EE), media handling, and
cross-signing — under realistic, sustained load.

---

## Why Cloud-Native?

### Stateless

Every instance starts from scratch. On launch it registers (or re-registers)
its users via the Synapse shared-secret admin API, logs in with a fresh device,
sets up cross-signing and recovery, back-paginates existing rooms to discover
the current message serial, and then begins sending. On shutdown it uploads any
remaining room keys to the server-side backup and logs the device out.

No local database, volume mount, or persistent storage of any kind is required.
The entire cryptographic state is bootstrapped from the server on every start
and cleaned up on every stop.

### Redundant

Multiple instances can run simultaneously for the **same set of users**. Only
one device per user (the "first" device, determined by login time, encoded as
device display name) actively sends messages at any given time. All other
instances sync, receive, verify, and are ready to take over the moment the
primary disappears. When the primary instance shuts down and a new one is
launched (or an existing standby detects it is now first), it seamlessly
resumes sending from the correct serial number.

### OpenTelemetry

All logs and traces are exported via OTLP (gRPC or HTTP). Every message
delivery is recorded as a structured log line / span with fields including:

| Field | Description |
|---|---|
| `delivery_ms` | Wall-clock milliseconds from send timestamp to receipt |
| `serial` | Monotonically increasing message number per room per user |
| `kind` | `text` or `media` |
| `distance` | `same_user`, `same_server`, or `federated` |
| `media_size_bytes` | Size of downloaded media (if applicable) |
| `valid` | Whether the message/media passed validation |
| `room` | Room ID |
| `sender` | Sender MXID |
| `user` | Receiving user MXID |

This makes it straightforward to build dashboards and alerts for message
delivery latency, federation delays, encryption failures, and media integrity
in tools like Grafana, Datadog, or any OTLP-compatible backend.

---

## Caveat: No Dehydrated Device Support

[matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk) does not
currently support
[dehydrated devices](https://github.com/matrix-org/matrix-spec-proposals/pull/3814)
(MSC3814). Because this client is fully stateless and creates a fresh device on
every launch, **encrypted messages can only be received as long as at least one
instance is running per user**. Messages sent while no instance is online for a
given user cannot be decrypted retroactively.

In practice this means: for continuous testing, make sure there is always at
least one instance running for each user. During a rolling restart, the login
stagger (see `LOGIN_INTERVAL`) gives the new instance time to come up before
the old one's device is logged out.

---

## What It Does

For each user defined in the `USERS` variable, the client runs the following
lifecycle:

1. **Authenticate** — one of two modes, selected by environment variable:
   - **Shared Registration** (`SHARED_REGISTRATION_SECRET`): register the user
     via the Synapse shared-secret admin API (idempotent — silently succeeds if
     the user already exists), then log in with `m.login.password`.
   - **STA** (`STA_SECRET`): skip registration entirely and log in with a
     `com.famedly.login.token` JWT signed with the shared secret (HS512). The
     JWT contains `sub` (the user's localpart) and `exp` (1 hour from now).
     Users must already exist on the homeserver. Alternatively, `STA_SEED` can
     be specified so that the `STA_SECRET` is derived automatically.
2. **Log in** with a fresh device using
   [matrix-sdk](https://github.com/matrix-org/matrix-rust-sdk).
3. **Bootstrap E2EE**: enable cross-signing, set up server-side key backup, and
   either enable recovery with a passphrase or import existing secrets from an
   earlier session.
4. **Accept pending invites** from rooms whose server name matches the
   configured `USERS` domains or `ACCEPT_INVITE_DOMAINS` patterns (if any).
5. **Start a background sync loop** that receives events in real time.
6. **Verify rooms**: back-paginate each joined room to validate that all
   historical messages have correct, monotonically increasing serial numbers
   and that any media attachments are valid PNGs.
7. **Send messages**: once a room is verified, send numbered text messages
   (e.g. `Message #42 1719484800000`) or randomly generated 128×128 PNG images
   with the message as a caption.
8. **Create DMs**: for each configured peer that doesn't yet share a DM room
   with the user, create an encrypted direct room.
9. **Shut down gracefully** on SIGINT/SIGTERM: stop syncing, wait for key
   backup upload to complete, then log the device out.

Only the **first device** (by deterministic ordering) for a given user actively
sends messages and creates DMs. Additional devices participate in sync,
verification, and delivery tracking only, providing redundancy without
duplicate messages.

---

## Environment Variables

### Required

| Variable | Description |
|---|---|
| `USERS` | Whitespace-separated list of user entries. Each entry is a comma-separated list of MXIDs: the first is the user, the rest are its peers. Example: `@alice:hs1.example.com,@bob:hs2.example.net @carol:hs1.example.com` |
| `PASSWORD_SECRET` | A shared secret from which each user's login password is deterministically derived (`HMAC-SHA1(secret, mxid)`, base64-encoded). |
| `RECOVERY_SECRET` | A shared secret from which each user's E2EE recovery passphrase is deterministically derived (same scheme as `PASSWORD_SECRET`). |

### Authentication (set exactly one)

| Variable | Description |
|---|---|
| `SHARED_REGISTRATION_SECRET` | The Synapse `registration_shared_secret` used to register accounts via the admin API, then log in with `m.login.password`. |
| `STA_SECRET` | Shared secret for the STA (Secure Token Auth) flow. The client signs a JWT (HS512) with this secret and logs in using the `com.famedly.login.token` login type. No explicit registration is performed — users must already exist or autocreation must be enabled in STA. |
| `STA_SEED` | Derive the `STA_SECRET` automatically for each hostname. |

### Optional

| Variable | Default | Description |
|---|---|---|
| `LOGIN_INTERVAL` | `10` | Seconds between successive user logins (stagger). Accepts a single value (`10`) or a range (`5..15`) for random sampling. |
| `LOOP_INTERVAL` | `2` | Seconds between main-loop ticks (verify / send / DM creation cycle). Accepts a single value or a range. |
| `SYNC_TIMEOUT` | `10` | Timeout in seconds for each `/sync` request to the homeserver. |
| `SYNC_ERROR_DELAY` | `2` | Seconds to wait before retrying after a sync error. Accepts a single value or a range. |
| `MEDIA_PROBABILITY` | `0.0` | Probability (0.0–1.0) that a message is sent as a randomly generated 128×128 PNG image instead of plain text. |
| `ACCEPT_INVITE_DOMAINS` | *(none)* | Comma-separated list of domain patterns. When set, the client auto-accepts room invites whose room ID server name matches one of the patterns. Three syntaxes are supported: `example.com` (exact match), `.example.com` (one or more subdomain levels — matches `a.example.com` and `a.b.example.com` but **not** `example.com` itself), and `*.example.com` (single-level wildcard — matches `a.example.com` but **not** `a.b.example.com` or `example.com`). The domains from the `USERS` MXIDs (including peers) are included automatically (as exact match). Example: `matrix.org,.example.com,*.internal.net` |
| `LEAVE_ON_FAILURE` | *(unset)* | When set to a non-empty value, the client leaves a room if message verification fails (serial mismatch, invalid media, unexpected event types). Otherwise the room is simply disabled for further sending. |

### OpenTelemetry

Standard OTLP environment variables are supported:

| Variable | Default | Description |
|---|---|---|
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` | OTLP transport protocol: `grpc`, `http/json`, or `http/protobuf`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(SDK default)* | Base URL of the OTLP collector (e.g. `http://otel-collector:4317`). |
| `OTEL_EXPORTER_OTLP_HEADERS` | *(none)* | Comma-separated `key=value` pairs sent as headers/metadata on every export request. |
| `OTEL_SERVICE_NAME` | `nerve` | Logical service name reported in telemetry. |
| `RUST_LOG` | `info` | Log level filter ([`tracing_subscriber::EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) syntax). |

---

## Building

```
cargo build --release
```

### Docker

The included multi-stage `Dockerfile` produces a minimal, statically linked
`scratch`-based image:

```
docker build -t cloud-native-matrix-test-client .
```

---

## Example

### Shared Registration mode

```
docker run --rm \
  -e USERS="@alice:matrix.example.com,@bob:matrix.example.com @bob:matrix.example.com,@alice:matrix.example.com" \
  -e SHARED_REGISTRATION_SECRET="synapse-registration-secret" \
  -e PASSWORD_SECRET="my-password-secret" \
  -e RECOVERY_SECRET="my-recovery-secret" \
  -e ACCEPT_INVITE_DOMAINS="matrix.example.com" \
  -e MEDIA_PROBABILITY=0.1 \
  -e LOGIN_INTERVAL=3..8 \
  -e LOOP_INTERVAL=1..3 \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317 \
  cloud-native-matrix-test-client
```

This starts two users — Alice and Bob — each configured as the other's peer.
They will register on `matrix.example.com`, log in, create an encrypted DM
with each other, and continuously exchange numbered messages (10% of which will
be images). All telemetry is exported to the OTLP collector.

### STA mode

```
docker run --rm \
  -e USERS="@alice:matrix.example.com,@bob:matrix.example.com @bob:matrix.example.com,@alice:matrix.example.com" \
  -e STA_SECRET="my-sta-jwt-secret" \
  -e PASSWORD_SECRET="my-password-secret" \
  -e RECOVERY_SECRET="my-recovery-secret" \
  -e ACCEPT_INVITE_DOMAINS="matrix.example.com" \
  -e MEDIA_PROBABILITY=0.1 \
  -e LOGIN_INTERVAL=3..8 \
  -e LOOP_INTERVAL=1..3 \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317 \
  cloud-native-matrix-test-client
```

Same setup, but users must already exist on the homeserver. The client skips
registration and authenticates by presenting a short-lived JWT to the
`com.famedly.login.token` login endpoint.

### Log in for manual debugging

Pass the `--print` flag to print either the derived passwords or STA secrets,
as well as the recovery passphrases for all users and exit immediately.
Useful for debugging or manual login. Use gedisa-login-stub if you want to
log in manually with STA.
