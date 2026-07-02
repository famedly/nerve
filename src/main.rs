mod auth;
mod datapoint;
mod image;
mod registration;
mod telemetry;

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::Ipv6Addr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use matrix_sdk::{
    Client, Room, ServerName,
    attachment::{AttachmentConfig, AttachmentInfo, BaseImageInfo},
    config::SyncSettings,
    deserialized_responses::TimelineEventKind,
    encryption::{EncryptionSettings, recovery::RecoveryState},
    media::{MediaFormat, MediaRequestParameters},
    room::MessagesOptions,
    ruma::{
        OwnedDeviceId, OwnedRoomId, OwnedUserId, UInt, UserId,
        api::client::{keys::get_keys, uiaa},
        events::{
            AnySyncMessageLikeEvent, AnySyncTimelineEvent,
            room::{
                member::StrippedRoomMemberEvent,
                message::{
                    MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent,
                    TextMessageEventContent,
                },
            },
        },
        uint,
    },
};
use rand::{Rng, random};
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    signal,
    sync::{Mutex as TokioMutex, Notify, watch},
    time::sleep,
};
use tracing::Instrument;

use crate::registration::RegistrationError;

/// Classifies the relationship between the local user and the sender of a
/// received message, used as a structured field on delivery-time log lines.
#[derive(Debug, Clone, Copy)]
enum Distance {
    /// The sender is the same account (echo of our own message).
    SameUser,
    /// A different user whose MXID shares the same homeserver.
    SameServer,
    /// A user on a different homeserver (federation).
    Federated,
}

impl Distance {
    /// Derive the distance from two MXIDs (`@user:server`).
    fn from_mxids(our_user_id: &UserId, sender_user_id: &UserId) -> Self {
        if our_user_id == sender_user_id {
            Self::SameUser
        } else if our_user_id.server_name() == sender_user_id.server_name() {
            Self::SameServer
        } else {
            Self::Federated
        }
    }
}

impl fmt::Display for Distance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameUser => write!(f, "same_user"),
            Self::SameServer => write!(f, "same_server"),
            Self::Federated => write!(f, "federated"),
        }
    }
}

/// Shared map tracking the highest serial seen per (room_id, user_id) from
/// live sync events.  The event handler writes to it; the main loop reads
/// from it to keep `next_serial` up to date.
type LiveSerials = Arc<TokioMutex<HashMap<(OwnedRoomId, OwnedUserId), u64>>>;

// ── Parsed user specification ───────────────────────────────────────────

/// A single entry from the `USERS` environment variable.
///
/// Format: `@user:server,@peer1:server,@peer2:server`
///
/// The first MXID is the user to log in as; the remaining (comma-separated)
/// MXIDs are its peers.
#[derive(Debug, Clone)]
struct UserSpec {
    mxid: OwnedUserId,
    /// Homeserver URL derived from the server part of the MXID
    /// (always `https://<server>`).
    homeserver_url: String,
    /// The `localpart` of the MXID (everything between `@` and `:`).
    username: String,
    /// Peers this user should create DMs with.
    peers: Vec<OwnedUserId>,
}

/// Parse the `USERS` environment variable.
///
/// `USERS` is a **whitespace-separated** list of entries.  Each entry is a
/// **comma-separated** list of MXIDs where the first one is the user and the
/// rest are its peers.
///
/// Example:
/// ```text
/// USERS="@alice:hs1.example.com,@bob:hs2.example.net @carol:hs1.example.com"
/// ```
impl FromStr for UserSpec {
    type Err = String;
    fn from_str(entry: &str) -> Result<UserSpec, String> {
        let mut mxids = entry.split(',').map(str::trim).filter(|s| !s.is_empty());
        let mxid_str = mxids.next().ok_or("Empty entry in USERS")?;

        let mxid: OwnedUserId = <&UserId>::try_from(mxid_str)
            .map_err(|e| format!("Invalid MXID in USERS: {mxid_str:?}: {e}"))?
            .to_owned();

        // Derive homeserver URL and username from the MXID.
        let server_name = mxid.server_name().as_str().to_owned();
        let homeserver_url = format!("https://{server_name}");
        let username = mxid.localpart().to_owned();

        let peers: Vec<OwnedUserId> = mxids
            .map(|s| {
                <&UserId>::try_from(s)
                    .map_err(|e| {
                        format!("Invalid peer MXID in USERS entry for {mxid_str}: {s:?}: {e}")
                    })
                    .map(ToOwned::to_owned)
            })
            .collect::<Result<_, String>>()?;

        Ok(UserSpec {
            mxid,
            homeserver_url,
            username,
            peers,
        })
    }
}

// ── Interval range ──────────────────────────────────────────────────────

/// A closed `[lo, hi]` range of seconds.  Each call to [`sample`] picks a
/// value uniformly at random from the range and returns it as a [`Duration`].
///
/// Parsed from strings of the form `"10..20"` (range) or `"10"` (point).
#[derive(Debug, Clone, Copy)]
struct IntervalRange {
    lo: u64,
    hi: u64,
}

impl FromStr for IntervalRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((a, b)) = s.split_once("..") {
            let lo = a
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("bad lower bound: {e}"))?;
            let hi = b
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("bad upper bound: {e}"))?;
            Ok(Self {
                lo: lo.min(hi),
                hi: lo.max(hi),
            })
        } else {
            let v = s
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("bad interval value: {e}"))?;
            Ok(Self { lo: v, hi: v })
        }
    }
}

impl IntervalRange {
    /// Return a random [`Duration`] sampled uniformly from `[lo, hi]`.
    fn sample(self) -> Duration {
        if self.lo == self.hi {
            Duration::from_secs(self.lo)
        } else {
            let secs = rand::rng().random_range(self.lo..=self.hi);
            Duration::from_secs(secs)
        }
    }
}

// ── Invite domain patterns ──────────────────────────────────────────────

/// A pattern that matches the server-name part of a room ID to decide
/// whether to auto-accept an invite.
///
/// Parsed from individual entries in the `ACCEPT_INVITE_DOMAINS` env var:
///
/// | Syntax | Meaning |
/// |---|---|
/// | `example.com` | Exact match only |
/// | `.example.com` | One or more sub-domain levels (matches `a.example.com`, `a.b.example.com`, but **not** `example.com` itself) |
/// | `*.example.com` | Exactly one sub-domain level (matches `a.example.com` but **not** `a.b.example.com` or `example.com`) |
#[derive(Debug, Clone)]
enum InviteDomainPattern {
    /// Exact match: the server name must equal `domain`.
    Exact(String),
    /// One-or-more subdomain levels: the server name must end with
    /// `.<domain>` (the leading dot is stored in `suffix`).
    DotSubdomain(String),
    /// Single-level wildcard (`*.domain`): there must be exactly one label
    /// before `.<domain>`.
    WildcardSubdomain(String),
}

impl From<&ServerName> for InviteDomainPattern {
    fn from(value: &ServerName) -> Self {
        Self::Exact(value.to_string())
    }
}

impl FromStr for InviteDomainPattern {
    type Err = String;
    /// Parse a single pattern string.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err(String::new());
        }
        if let Some(rest) = s.strip_prefix("*.") {
            if rest.is_empty() {
                return Err(String::new());
            }
            // Store as ".<domain>" so matching is a simple suffix check
            // after verifying there is exactly one label before it.
            Ok(Self::WildcardSubdomain(format!(".{rest}")))
        } else if let Some(rest) = s.strip_prefix('.') {
            if rest.is_empty() {
                return Err(String::new());
            }
            // Store as ".<domain>" — any server name ending with this suffix
            // matches (one or more sub-domain levels).
            Ok(Self::DotSubdomain(format!(".{rest}")))
        } else {
            Ok(Self::Exact(s.to_owned()))
        }
    }
}

impl InviteDomainPattern {
    /// Test whether `server_name` matches this pattern.
    fn matches(&self, server_name: &str) -> bool {
        match self {
            Self::Exact(domain) => server_name == domain,
            Self::DotSubdomain(suffix) => server_name.ends_with(suffix),
            Self::WildcardSubdomain(suffix) => {
                // `suffix` is ".<domain>".  The server name must end with it
                // and the prefix (the part before it) must be a single DNS
                // label, i.e. non-empty and containing no dots.
                if let Some(prefix) = server_name.strip_suffix(suffix.as_str()) {
                    !prefix.is_empty() && !prefix.contains('.')
                } else {
                    false
                }
            }
        }
    }
}

/// Check whether `server_name` matches any of the given patterns.
fn matches_invite_domain(patterns: &[InviteDomainPattern], server_name: &str) -> bool {
    patterns.iter().any(|p| p.matches(server_name))
}

// ── Configuration ───────────────────────────────────────────────────────

/// Complete application configuration, parsed from environment variables.
#[derive(Parser, Clone)]
#[command(about = "Cloud-native Matrix test client")]
struct Config {
    /// Space-separated list of user entries.  Each entry is a
    /// comma-separated list of MXIDs: the first is the user, the rest are
    /// its peers.
    #[arg(env = "USERS", value_delimiter = ' ', required = true)]
    users: Vec<UserSpec>,

    /// When set, print derived passwords/passphrases for all users and exit.
    #[arg(long, default_value_t = false)]
    print: bool,

    // ── Authentication ─────────────────────────────────────────────────
    #[command(flatten)]
    auth: auth::AuthConfig,

    // ── Operational tuning ──────────────────────────────────────────────
    /// Leave a room when message verification fails.
    #[arg(long, env = "LEAVE_ON_FAILURE", default_value_t = false)]
    leave_on_failure: bool,

    /// Probability (0.0–1.0) of sending a PNG image instead of text.
    #[arg(long, env = "MEDIA_PROBABILITY", default_value_t = 0.0)]
    media_probability: f64,

    /// Seconds between successive user logins.  Single value or range
    /// (`5..15`).
    #[arg(long, env = "LOGIN_INTERVAL", default_value = "10")]
    login_interval: IntervalRange,

    /// Timeout in seconds for each `/sync` request.
    #[arg(long, env = "SYNC_TIMEOUT", default_value_t = 10)]
    sync_timeout: u64,

    /// Seconds to wait before retrying after a sync error.  Single value or
    /// range.
    #[arg(long, env = "SYNC_ERROR_DELAY", default_value = "2")]
    sync_error_delay: IntervalRange,

    /// Seconds between main-loop ticks.  Single value or range.
    #[arg(long, env = "LOOP_INTERVAL", default_value = "2")]
    loop_interval: IntervalRange,

    /// Number of main-loop cycles to wait before promoting to sender after
    /// becoming the first device.
    #[arg(long, env = "PROMOTION_WAIT_CYCLES", default_value_t = 1)]
    promotion_wait_cycles: u64,

    /// Comma-separated domain patterns for auto-accepting room invites.
    #[arg(long, env = "ACCEPT_INVITE_DOMAINS", value_delimiter = ',')]
    accept_invite_domains: Vec<InviteDomainPattern>,

    /// Seconds to wait before restarting a failed `run_user` invocation.
    /// Only one restart is attempted at a time; additional failed
    /// invocations queue behind the first using the normal login-interval
    /// stagger.
    #[arg(long, env = "RESTART_INTERVAL", default_value = "5")]
    restart_interval: IntervalRange,

    /// TCP port on localhost to open once all users have completed E2EE
    /// recovery (step 4).  The server is closed again when any `run_user`
    /// invocation is aborted.  Accepted connections are closed as soon as a
    /// single byte is received.  When unset, readiness probing is disabled.
    #[arg(long, env = "READINESS_PORT")]
    readiness_port: Option<u16>,

    /// Seconds after which a device is considered stale based on its
    /// `last_seen_ts`.  Stale devices are logged out and excluded from the
    /// first-device election.
    #[arg(long, env = "STALE_DEVICE_TIMEOUT", default_value_t = 300)]
    stale_device_timeout: u64,
}

// ── Small helpers ───────────────────────────────────────────────────────

/// Check whether our device is the "first" for the account.
/// Only the first device should send messages to avoid duplicates when
/// multiple clients are logged in.
///
/// Devices whose `last_seen_ts` is older than `stale_timeout` are considered
/// stale: they are excluded from the election and deleted from the server
/// (which requires the UIAA password flow).
async fn is_first_device(
    client: &Client,
    stale_timeout: Duration,
    account_password: Option<&str>,
    username: &str,
) -> bool {
    let Ok(response) = client.devices().await else {
        return false;
    };

    let stale_device_ids: Vec<OwnedDeviceId> = response
        .devices
        .iter()
        .filter(|d| client.device_id() != Some(&*d.device_id))
        .filter(|d| {
            d.last_seen_ts
                .and_then(|ts| ts.to_system_time())
                .and_then(|ts| SystemTime::now().duration_since(ts).ok())
                .is_some_and(|duration| duration > stale_timeout)
        })
        .map(|d| d.device_id.clone())
        .collect();

    if !stale_device_ids.is_empty() {
        tracing::info!(
            "Deleting {} stale device(s): {:?}",
            stale_device_ids.len(),
            stale_device_ids,
        );

        // First request without auth data – the server responds with a
        // UIAA challenge (HTTP 401) containing the session token.
        match client.delete_devices(&stale_device_ids, None).await {
            Ok(_) => {
                // Server accepted without UIAA (unlikely but valid).
                tracing::info!("Stale devices deleted (no UIAA required)");
            }
            Err(err) => {
                if let Some(uiaa_info) = err.as_uiaa_response() {
                    if let Some(password) = account_password {
                        let mut pw = uiaa::Password::new(
                            uiaa::UserIdentifier::UserIdOrLocalpart(username.to_owned()),
                            password.to_owned(),
                        );
                        pw.session = uiaa_info.session.clone();

                        match client
                            .delete_devices(&stale_device_ids, Some(uiaa::AuthData::Password(pw)))
                            .await
                        {
                            Ok(_) => {
                                tracing::info!("Stale devices deleted via UIAA password flow");
                            }
                            Err(e) => {
                                tracing::error!("Failed to delete stale devices (UIAA retry): {e}");
                            }
                        }
                    } else {
                        tracing::warn!(
                            "Cannot delete stale devices: UIAA password flow required \
                             but no account password is available"
                        );
                    }
                } else {
                    tracing::error!("Failed to delete stale devices: {err}");
                }
            }
        }
    }

    // Determine the first device among non-stale devices only.
    let first_dev = response
        .devices
        .iter()
        .filter(|d| !stale_device_ids.contains(&d.device_id))
        .min_by_key(|d| (&d.display_name, &d.device_id));

    client
        .device_id()
        .is_some_and(|id| first_dev.is_some_and(|dev| dev.device_id == id))
}

/// Current UNIX timestamp in milliseconds.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Try to parse a message body of the form "Message #<serial> <timestamp_ms>".
/// Returns `(serial, timestamp_ms)` on success.
fn parse_message_body(body: &str) -> Option<(u64, u64)> {
    let rest = body.strip_prefix("Message #")?;
    let mut parts = rest.splitn(2, ' ');
    let serial = parts.next()?.parse::<u64>().ok()?;
    let ts = parts.next()?.parse::<u64>().ok()?;
    Some((serial, ts))
}

/// Wait for either SIGINT or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("register SIGTERM");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
/// Per-room verification / pagination state.
struct RoomVerificationState {
    /// The Matrix room handle.
    room: Room,
    /// Pagination token for reading backwards.  `None` means start from the
    /// most recent event; `Some(token)` continues from where we left off.
    /// Once the server returns no `end` token the room is fully verified.
    pagination_token: Option<String>,
    /// Whether we have started paginating (so `pagination_token` being `None`
    /// at the start means "begin from the end", not "fully done").
    started: bool,
    /// Whether we have finished paginating all the way to the beginning.
    fully_verified: bool,
    /// Whether verification detected an invalid message.  Once set, the room
    /// is no longer eligible for sending or further verification.
    failed: bool,
    /// Last-known serial for each sender, used to verify monotonically
    /// decreasing serials as we paginate backwards.
    last_serial_by_user: HashMap<OwnedUserId, u64>,
    /// Once we know our own last serial, the room is eligible for sending.
    /// This stores the *next* serial to send.
    next_serial: Option<u64>,
}

impl RoomVerificationState {
    fn new(room: Room) -> Self {
        Self {
            room,
            pagination_token: None,
            started: false,
            fully_verified: false,
            failed: false,
            last_serial_by_user: HashMap::new(),
            next_serial: None,
        }
    }

    /// Run one verification step: read one page of events backwards and
    /// validate serials.  Returns `(events_processed, verification_failed)`.
    /// If `verification_failed` is true, the room should be left.
    async fn verify_page(
        &mut self,
        our_user_id: &OwnedUserId,
        client: &Client,
    ) -> anyhow::Result<(usize, bool)> {
        if self.fully_verified {
            return Ok((0, false));
        }

        let mut options = MessagesOptions::backward();
        options.limit = uint!(20);
        if let Some(ref token) = self.pagination_token {
            options = options.from(token.as_str());
        }

        let messages = self.room.messages(options).await?;
        let count = messages.chunk.len();
        let mut failed = false;

        for event in &messages.chunk {
            // Undecryptable events are tolerated – assume they contained a
            // valid serial and adjust tracking accordingly.
            if matches!(&event.kind, TimelineEventKind::UnableToDecrypt { .. }) {
                if let Ok(AnySyncTimelineEvent::MessageLike(
                    AnySyncMessageLikeEvent::RoomEncrypted(enc),
                )) = event.raw().deserialize()
                {
                    let sender: OwnedUserId = enc.sender().to_owned();
                    let entry = self.last_serial_by_user.entry(sender.clone()).or_insert(0);
                    if *entry > 0 {
                        *entry -= 1;
                    }
                    if &sender == our_user_id && self.next_serial.is_none() && *entry > 0 {
                        self.next_serial = Some(*entry + 1);
                    }
                }
                continue;
            }

            let deserialized = event.raw().deserialize();

            // State events are tolerated (e.g. room creation, encryption,
            // membership changes).
            if matches!(&deserialized, Ok(AnySyncTimelineEvent::State(_))) {
                continue;
            }

            // Everything else must be a RoomMessage with a valid "Message #N"
            // text body (or image with that caption).  Any deviation fails
            // verification.
            let Ok(AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(msg))) =
                deserialized
            else {
                tracing::error!(
                    "  ⚠ [{}] Unexpected event type (not a room message)",
                    self.room.room_id(),
                );
                failed = true;
                continue;
            };

            let Some(original) = msg.as_original() else {
                tracing::error!("  ⚠ [{}] Redacted room message", self.room.room_id(),);
                failed = true;
                continue;
            };

            // Extract the body from text messages or the caption from image
            // messages.  For images we also validate the media data.
            let body: &str;
            match &original.content.msgtype {
                MessageType::Text(text) => {
                    body = &text.body;
                }
                MessageType::Image(img) => {
                    let Some(caption) = img.caption() else {
                        tracing::error!(
                            "  ⚠ [{}] Image without caption from {}",
                            self.room.room_id(),
                            original.sender,
                        );
                        failed = true;
                        continue;
                    };
                    body = caption;

                    // Download and validate the image data.
                    let request = MediaRequestParameters {
                        source: img.source.clone(),
                        format: MediaFormat::File,
                    };
                    match client.media().get_media_content(&request, true).await {
                        Ok(data) => {
                            if let Err(e) = image::validate_png(&data) {
                                tracing::error!(
                                    "  ⚠ [{}] Invalid PNG from {}: {e}",
                                    self.room.room_id(),
                                    original.sender,
                                );
                                failed = true;
                                continue;
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "  ⚠ [{}] Failed to download media from {}: {e}",
                                self.room.room_id(),
                                original.sender,
                            );
                            failed = true;
                            continue;
                        }
                    }
                }
                _ => {
                    tracing::error!(
                        "  ⚠ [{}] Unsupported message type from {}",
                        self.room.room_id(),
                        original.sender,
                    );
                    failed = true;
                    continue;
                }
            };

            let Some((n, _ts)) = parse_message_body(body) else {
                tracing::error!(
                    "  ⚠ [{}] Bad message format from {}: {:?}",
                    self.room.room_id(),
                    original.sender,
                    body,
                );
                failed = true;
                continue;
            };

            let sender = original.sender.clone();

            if let Some(expected) = self.last_serial_by_user.get(&sender) {
                // Reading backwards: serials should decrease by 1.
                if *expected > 0 && n != expected - 1 {
                    tracing::error!(
                        "  ⚠ [{}] Serial mismatch for {sender}: expected #{}, got #{n}",
                        self.room.room_id(),
                        expected - 1,
                    );
                    failed = true;
                }
            }

            self.last_serial_by_user.insert(sender.clone(), n);

            // First (most recent) message from us determines next_serial.
            if &sender == our_user_id && self.next_serial.is_none() {
                self.next_serial = Some(n + 1);
                tracing::info!(
                    "  🔍 [{}] Found our last serial #{n} → next #{}",
                    self.room.room_id(),
                    n + 1,
                );
            }
        }

        // Update pagination state.
        self.started = true;
        match messages.end {
            Some(token) if count > 0 => {
                self.pagination_token = Some(token);
            }
            _ => {
                // No more pages.
                self.fully_verified = true;
                // If we never found a message from ourselves, start at #1.
                if self.next_serial.is_none() {
                    self.next_serial = Some(1);
                    tracing::info!(
                        "  🔍 [{}] Verification complete (no messages from us, starting at #1)",
                        self.room.room_id()
                    );
                } else {
                    tracing::info!(
                        "  🔍 [{}] Verification complete (reached beginning)",
                        self.room.room_id()
                    );
                }
            }
        }

        Ok((count, failed))
    }

    /// Whether this room is eligible for sending (we know our serial and
    /// verification has not failed).
    fn is_send_eligible(&self) -> bool {
        !self.failed && self.next_serial.is_some()
    }

    /// Whether this room still needs verification steps.
    fn needs_verification(&self) -> bool {
        !self.failed && !self.fully_verified
    }
}

// ── run_user outcome types ──────────────────────────────────────────────

/// Distinguishes errors that should abort `run_user` permanently (until
/// restart) from transient errors that the caller can retry.
#[derive(Debug)]
enum RunUserError {
    /// A fatal error: sync returned 401/404, or registration failed with 404.
    /// The invocation should be restarted after `RESTART_INTERVAL`.
    Fatal(anyhow::Error),
    /// A non-fatal error (e.g. network hiccup).  Treated the same as Fatal
    /// for restart purposes today, but kept separate for clarity.
    Other(anyhow::Error),
}

impl std::fmt::Display for RunUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fatal(e) => write!(f, "fatal: {e:#}"),
            Self::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl RunUserError {
    /// Wrap an `anyhow::Error` as a non-fatal error.
    fn other(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

/// Outcome of a single `run_user` invocation.
enum RunUserOutcome {
    /// Graceful shutdown (stop signal received).  Do NOT restart.
    Shutdown,
    /// The run failed and should be restarted after `RESTART_INTERVAL`.
    Failed(RunUserError),
}

// ── Entry point ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry_guard = telemetry::init_telemetry();

    // ── Parse configuration from env / CLI ──────────────────────────────
    let mut config = Config::parse();

    // ── PRINT mode ──────────────────────────────────────────────────────
    if config.print {
        for u in &config.users {
            let mxid = u.mxid.as_str();
            let account_password = config
                .auth
                .account_password(mxid)
                .or_else(|| {
                    config
                        .auth
                        .resolve_sta_secret(u.mxid.server_name().as_str())
                })
                .unwrap_or_default();
            let recovery_passphrase = config.auth.recovery_passphrase(mxid);
            let peers_str: Vec<&str> = u.peers.iter().map(|p| p.as_str()).collect();
            println!(
                "{mxid} {account_password} {recovery_passphrase} peers=[{}]",
                peers_str.join(",")
            );
        }
        return Ok(());
    }

    let local_servers: HashSet<_> = config
        .users
        .iter()
        .flat_map(|user| {
            user.peers
                .iter()
                .chain(Some(&user.mxid))
                .map(|mxid| mxid.server_name())
        })
        .collect();
    config
        .accept_invite_domains
        .extend(local_servers.into_iter().map(Into::into));

    // ── Shutdown signal ─────────────────────────────────────────────────
    let (stop_tx, stop_rx) = watch::channel(false);
    {
        let stop_tx_signal = stop_tx.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("⚡ Received shutdown signal");
            let _ = stop_tx_signal.send(true);
        });
    }

    // ── Readiness state ─────────────────────────────────────────────────
    let total_users = config.users.len();
    let ready_count = Arc::new(AtomicUsize::new(0));
    let (ready_tx, ready_rx) = watch::channel(false);
    let ready_tx = Arc::new(ready_tx);

    // Spawn readiness TCP server if a port was configured.
    if let Some(port) = config.readiness_port {
        let rr = ready_rx.clone();
        let sr = stop_rx.clone();
        tokio::spawn(readiness_server(port, rr, sr));
    }

    // ── Restart serialisation ───────────────────────────────────────────
    // A shared mutex ensures that when multiple `run_user` invocations
    // fail concurrently, only one restarts at a time.  After a successful
    // login the holder sleeps `login_interval` (stagger) before releasing
    // the lock so the next restart can proceed.
    let restart_mutex: Arc<TokioMutex<()>> = Arc::new(TokioMutex::new(()));

    // ── Datapoint submission ────────────────────────────────────────────
    // Both are cheap to clone and no-ops when the corresponding env var
    // is unset.
    let account_list = Arc::new(datapoint::AccountList::from_env());
    let datapoint_client = datapoint::DatapointClient::from_env();

    // ── Spawn one supervisor task per user (staggered) ──────────────────
    let mut handles = Vec::with_capacity(total_users);
    let mut stagger = Duration::ZERO;
    for user in config.users.clone() {
        let user_stagger = stagger;
        stagger += config.login_interval.sample();
        let config = config.clone();
        let stop_rx = stop_rx.clone();
        let ready_count = ready_count.clone();
        let ready_tx = ready_tx.clone();
        let restart_mutex = restart_mutex.clone();
        let account_list = account_list.clone();
        let datapoint_client = datapoint_client.clone();

        let handle = tokio::spawn(async move {
            // ── Initial stagger ─────────────────────────────────────────
            if !user_stagger.is_zero() {
                let mut stop = stop_rx.clone();
                tokio::select! {
                    _ = sleep(user_stagger) => {}
                    _ = stop.changed() => {
                        tracing::info!("[{}] Shutdown before login (stagger cancelled)", user.mxid);
                        return;
                    }
                }
            }

            let mxid = user.mxid.as_str().to_owned();
            let restart_interval = config.restart_interval.sample();
            let login_interval_range = config.login_interval;
            let mut first_run = true;

            loop {
                if *stop_rx.borrow() {
                    break;
                }

                // On restart (not the very first run), serialise through
                // the restart mutex so only one user retries at a time.
                let restart_guard = if !first_run {
                    let guard = restart_mutex.lock().await;
                    if *stop_rx.borrow() {
                        break;
                    }

                    // Wait RESTART_INTERVAL before starting the retry.
                    let mut stop = stop_rx.clone();
                    tokio::select! {
                        _ = sleep(restart_interval) => {}
                        _ = stop.changed() => { break; }
                    }
                    if *stop_rx.borrow() {
                        break;
                    }

                    tracing::info!("[{mxid}] ⟳ Restarting …");
                    Some(guard)
                } else {
                    None
                };
                first_run = false;

                let login_notify = Arc::new(Notify::new());

                let run_future = run_user(
                    user.clone(),
                    config.clone(),
                    stop_rx.clone(),
                    ready_count.clone(),
                    ready_tx.clone(),
                    total_users,
                    login_notify.clone(),
                    account_list.clone(),
                    datapoint_client.clone(),
                );
                tokio::pin!(run_future);

                // If we hold the restart guard, keep it until login
                // succeeds (+ stagger) so the next restart waits.
                if restart_guard.is_some() {
                    let login_signaled = tokio::select! {
                        _ = login_notify.notified() => true,
                        outcome = &mut run_future => {
                            // run_user finished before login – failed early
                            drop(restart_guard);
                            match outcome {
                                RunUserOutcome::Shutdown => return,
                                RunUserOutcome::Failed(e) => {
                                    tracing::error!("[{mxid}] Run failed: {e}");
                                    continue;
                                }
                            }
                        }
                    };

                    if login_signaled {
                        // Stagger before releasing the lock for the next
                        // restart.
                        let mut stop = stop_rx.clone();
                        tokio::select! {
                            _ = sleep(login_interval_range.sample()) => {}
                            _ = stop.changed() => {}
                        }
                    }
                }

                // Release the mutex so the next queued restart can proceed
                // while this run_user continues in the background.
                drop(restart_guard);

                // Await run_user completion (may already be done).
                match run_future.await {
                    RunUserOutcome::Shutdown => break,
                    RunUserOutcome::Failed(e) => {
                        tracing::error!("[{mxid}] Run failed: {e}");
                        continue; // loop back → restart path
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all supervisor tasks to finish.
    for handle in handles {
        let _ = handle.await;
    }

    // Ensure the stop channel is marked so any stragglers notice.
    let _ = stop_tx.send(true);

    Ok(())
}

// ── Readiness TCP server ────────────────────────────────────────────────

/// Listen on `127.0.0.1:<port>` exactly while all `run_user` invocations
/// are "ready" (reached step 4).  Accepted connections are closed as soon
/// as a single byte is received.
async fn readiness_server(
    port: u16,
    mut ready_rx: watch::Receiver<bool>,
    mut stop_rx: watch::Receiver<bool>,
) {
    loop {
        // ── Wait until ready ────────────────────────────────────────────
        loop {
            if *stop_rx.borrow() {
                return;
            }
            if *ready_rx.borrow() {
                break;
            }
            tokio::select! {
                _ = ready_rx.changed() => {}
                _ = stop_rx.changed() => { return; }
            }
        }

        // ── Bind ────────────────────────────────────────────────────────
        let listener = match TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind readiness port {port}: {e}");
                return;
            }
        };

        tracing::info!("✔ Readiness server listening on {port}");

        // ── Accept until no longer ready or shutdown ────────────────────
        loop {
            tokio::select! {
                result = listener.accept() => {
                    if let Ok((mut stream, _)) = result {
                        tokio::spawn(async move {
                            let _ = stream.read(&mut [0u8; 1]).await;
                        });
                    }
                }
                _ = ready_rx.changed() => {
                    if !*ready_rx.borrow() {
                        tracing::info!("⚠ Readiness lost – closing readiness server");
                        break; // go back to "wait until ready"
                    }
                }
                _ = stop_rx.changed() => {
                    return;
                }
            }
        }
        // listeners are dropped here
    }
}

// ── Helpers for fatal-error detection ───────────────────────────────────

/// Check whether a `matrix_sdk::Error` carries an HTTP 401 or 404 status.
fn is_fatal_sync_status(err: &matrix_sdk::Error) -> bool {
    let matrix_sdk::Error::Http(http_err) = err else {
        return false;
    };

    // Try the structured Matrix client-API error (most common path for
    // sync responses with a JSON body containing `errcode`).
    if let Some(api_err) = http_err.as_client_api_error() {
        let code = api_err.status_code.as_u16();
        return code == 401 || code == 404;
    }

    // Non-client-API Matrix error (e.g. reverse-proxy HTML page that
    // the SDK parsed into `RumaApiError::Other`).
    if let Some(matrix_sdk::RumaApiError::Other(e)) = http_err.as_ruma_api_error() {
        let code = e.status_code.as_u16();
        return code == 401 || code == 404;
    }

    // Plain reqwest transport error that still carries an HTTP status
    // (e.g. the server replied but the body was unparsable).
    if let matrix_sdk::HttpError::Reqwest(req_err) = http_err.as_ref()
        && let Some(status) = req_err.status()
    {
        let code = status.as_u16();
        return code == 401 || code == 404;
    }

    false
}

/// Update the readiness watch channel after the ready-count changes.
fn update_readiness(count: &AtomicUsize, total: usize, tx: &watch::Sender<bool>) {
    let current = count.load(Ordering::SeqCst);
    let _ = tx.send(current >= total);
}

// ── Per-user lifecycle ──────────────────────────────────────────────────

/// Run the full lifecycle for a single user: register, log in, set up E2EE,
/// verify rooms, send messages, create DMs.  Returns a [`RunUserOutcome`]
/// indicating whether the run ended due to a shutdown signal or a failure
/// that should trigger a restart.
#[tracing::instrument(
    skip_all,
    fields(
        server_name = user.mxid.server_name().as_str(),
        username = user.username.as_str(),
    )
)]
async fn run_user(
    user: UserSpec,
    config: Config,
    stop_rx: watch::Receiver<bool>,
    ready_count: Arc<AtomicUsize>,
    ready_tx: Arc<watch::Sender<bool>>,
    total_users: usize,
    login_notify: Arc<Notify>,
    account_list: Arc<datapoint::AccountList>,
    datapoint_client: datapoint::DatapointClient,
) -> RunUserOutcome {
    // RAII guard: when this function returns for *any* reason, decrement
    // the ready count (if it was incremented) and update the readiness
    // watch channel.
    struct ReadyGuard {
        incremented: bool,
        count: Arc<AtomicUsize>,
        total: usize,
        tx: Arc<watch::Sender<bool>>,
    }
    impl Drop for ReadyGuard {
        fn drop(&mut self) {
            if self.incremented {
                self.count.fetch_sub(1, Ordering::SeqCst);
                update_readiness(&self.count, self.total, &self.tx);
            }
        }
    }
    let mut ready_guard = ReadyGuard {
        incremented: false,
        count: ready_count.clone(),
        total: total_users,
        tx: ready_tx.clone(),
    };

    let mxid = user.mxid.as_str().to_owned();
    let homeserver_url = &user.homeserver_url;
    let username = &user.username;
    let peers = &user.peers;

    // ── 1 & 2. Register (if applicable) and log in ─────────────────────
    let client = match Client::builder()
        .homeserver_url(homeserver_url)
        .with_encryption_settings(EncryptionSettings {
            // Cross-signing keys and the backup must only ever be created by
            // the primary (first) device for an account. If every device
            // auto-created them, two devices starting at the same time would
            // each bootstrap their own cross-signing identity / backup; the
            // last upload wins on the server, but the *primary's* private
            // keys are the ones stored in secret storage, so a later import
            // fails with "the public key of the imported private key doesn't
            // match the public key that was uploaded to the server". We
            // therefore disable auto-creation and drive it explicitly from
            // the primary device below.
            auto_enable_cross_signing: false,
            auto_enable_backups: false,
            ..Default::default()
        })
        .build()
        .await
    {
        Ok(c) => c,
        Err(e) => return RunUserOutcome::Failed(RunUserError::other(e.into())),
    };

    let initial_name = format!("{:0>11x}", now_millis());
    assert_eq!(initial_name.len(), 11);

    let server_name = user.mxid.server_name().as_str();
    if let Err(e) = config
        .auth
        .login(
            &client,
            homeserver_url,
            server_name,
            username,
            &mxid,
            &initial_name,
        )
        .await
    {
        // Registration 404 → the admin API is unreachable; treat as fatal.
        if e.downcast_ref::<RegistrationError>()
            .is_some_and(|reg_err| reg_err.status.is_some_and(|s| s.as_u16() == 404))
        {
            return RunUserOutcome::Failed(RunUserError::Fatal(e));
        }
        return RunUserOutcome::Failed(RunUserError::other(e));
    }

    // Login succeeded – notify the supervisor so restart staggering can
    // proceed.
    login_notify.notify_one();

    let recovery_passphrase = config.auth.recovery_passphrase(&mxid);

    let our_user_id = client
        .user_id()
        .expect("logged in, must have user_id")
        .to_owned();

    tracing::info!("[{mxid}] ✔ Logged in via matrix-sdk");

    // ── 3. Set up E2EE (cross-signing + recovery / secret storage) ──────
    tracing::info!("[{mxid}] ▶ Running initial sync …");
    match client.sync_once(SyncSettings::default()).await {
        Ok(_) => {}
        Err(e) => {
            if is_fatal_sync_status(&e) {
                tracing::error!(
                    server_reachability = false,
                    error = %e,
                    "[{mxid}] ✘ Initial sync fatal error",
                );
                return RunUserOutcome::Failed(RunUserError::Fatal(e.into()));
            }
            return RunUserOutcome::Failed(RunUserError::other(e.into()));
        }
    }

    // Accept pending invites from rooms whose server name matches the
    // configured ACCEPT_INVITE_DOMAINS patterns.
    {
        let invited: Vec<_> = client
            .invited_rooms()
            .into_iter()
            .filter(|r| {
                r.room_id().server_name().is_some_and(|s| {
                    matches_invite_domain(&config.accept_invite_domains, s.as_str())
                })
            })
            .collect();

        if !invited.is_empty() {
            tracing::info!("[{mxid}] ▶ Accepting {} pending invite(s) …", invited.len());
            for room in invited {
                match room.join().await {
                    Ok(()) => tracing::info!("[{mxid}]   ✔ Joined {}", room.room_id()),
                    Err(e) => {
                        tracing::error!("[{mxid}]   ✘ Failed to join {}: {e}", room.room_id())
                    }
                }
            }
            match client.sync_once(SyncSettings::default()).await {
                Ok(_) => {}
                Err(e) => {
                    if is_fatal_sync_status(&e) {
                        tracing::error!(
                            server_reachability = false,
                            error = %e,
                            "[{mxid}] ✘ Post-invite sync fatal error",
                        );
                        return RunUserOutcome::Failed(RunUserError::Fatal(e.into()));
                    }
                    return RunUserOutcome::Failed(RunUserError::other(e.into()));
                }
            }
        }
    }

    // Decide whether *this* device is the primary (first) device for the
    // account. Only the primary creates the cross-signing identity, the
    // backup and the secret storage; every other device waits for the
    // primary and then imports the secrets. This is what prevents the
    // concurrent-bootstrap race described where the EncryptionSettings are
    // configured above.
    let account_password = config.auth.account_password(&mxid);
    let stale_device_timeout = Duration::from_secs(config.stale_device_timeout);
    let we_are_primary = is_first_device(
        &client,
        stale_device_timeout,
        account_password.as_deref(),
        username,
    )
    .await;

    // Enable recovery or import existing secrets.
    let recovery = client.encryption().recovery();

    match recovery.state() {
        RecoveryState::Enabled | RecoveryState::Incomplete => {
            tracing::info!("[{mxid}] ▶ Recovering existing secrets …");
            match recovery.recover(&recovery_passphrase).await {
                Ok(_) => {}
                Err(e) => return RunUserOutcome::Failed(RunUserError::other(e.into())),
            }
            tracing::info!("[{mxid}] ✔ Existing recovery secrets imported");
        }
        _ if we_are_primary => {
            // Primary device on a not-yet-provisioned account: create the
            // cross-signing identity (auto-creation is disabled, so we are
            // the only one doing this) and then enable recovery, which also
            // creates the backup and stores every secret in secret storage.
            tracing::info!("[{mxid}] ▶ Primary device – bootstrapping cross-signing …");
            if let Err(e) = client
                .encryption()
                .bootstrap_cross_signing_if_needed(None)
                .await
            {
                return RunUserOutcome::Failed(RunUserError::other(e.into()));
            }

            tracing::info!("[{mxid}] ▶ Enabling recovery …");
            match recovery
                .enable()
                .wait_for_backups_to_upload()
                .with_passphrase(&recovery_passphrase)
                .await
            {
                Ok(_recovery_key) => {}
                Err(e) => return RunUserOutcome::Failed(RunUserError::other(e.into())),
            }
            tracing::info!("[{mxid}] ✔ E2EE recovery enabled (passphrase-protected)");
        }
        _ => {
            // Secondary device on an account whose primary hasn't finished
            // setting up recovery yet. We must NOT bootstrap anything
            // ourselves; instead we wait for the primary to publish the
            // secrets and then import them.
            tracing::info!(
                "[{mxid}] ⏳ Not primary – waiting for the primary device to enable recovery …"
            );

            const WAIT_STEP: Duration = Duration::from_secs(2);
            const MAX_WAIT: Duration = Duration::from_secs(120);
            let mut waited = Duration::ZERO;
            loop {
                if *stop_rx.borrow() {
                    return RunUserOutcome::Shutdown;
                }

                match client.sync_once(SyncSettings::default()).await {
                    Ok(_) => {}
                    Err(e) => {
                        if is_fatal_sync_status(&e) {
                            tracing::error!(
                                server_reachability = false,
                                error = %e,
                                "[{mxid}] ✘ Sync fatal error while waiting for recovery",
                            );
                            return RunUserOutcome::Failed(RunUserError::Fatal(e.into()));
                        }
                        return RunUserOutcome::Failed(RunUserError::other(e.into()));
                    }
                }

                if matches!(
                    recovery.state(),
                    RecoveryState::Enabled | RecoveryState::Incomplete
                ) {
                    break;
                }

                if waited >= MAX_WAIT {
                    return RunUserOutcome::Failed(RunUserError::other(anyhow::anyhow!(
                        "timed out waiting for the primary device to enable recovery"
                    )));
                }

                let mut stop = stop_rx.clone();
                tokio::select! {
                    _ = sleep(WAIT_STEP) => {}
                    _ = stop.changed() => return RunUserOutcome::Shutdown,
                }
                waited += WAIT_STEP;
            }

            tracing::info!("[{mxid}] ▶ Recovery available – importing secrets …");
            match recovery.recover(&recovery_passphrase).await {
                Ok(_) => {}
                Err(e) => return RunUserOutcome::Failed(RunUserError::other(e.into())),
            }
            tracing::info!("[{mxid}] ✔ Existing recovery secrets imported");
        }
    }

    // ── 4. Register event handlers and start background sync ────────────

    // Signal readiness: E2EE recovery is complete for this user.
    ready_guard.incremented = true;
    ready_count.fetch_add(1, Ordering::SeqCst);
    update_readiness(&ready_count, total_users, &ready_tx);
    tracing::info!("[{mxid}] ✔ User ready (E2EE recovery complete)");

    let live_serials: LiveSerials = Arc::new(TokioMutex::new(HashMap::new()));

    // Print all incoming room messages with delivery time and track serials.
    // For media messages the delivery time includes downloading and validating
    // the image so it reflects true end-to-end latency.
    let live_serials_handler = live_serials.clone();
    let our_user_id_handler = our_user_id.clone();
    let account_list_handler = account_list.clone();
    let datapoint_client_handler = datapoint_client.clone();
    // Pre-compute our receiver-side account number once; it does not change
    // for the lifetime of this login.
    let our_account = account_list.lookup(our_user_id.as_str());
    client.add_event_handler(
        move |ev: OriginalSyncRoomMessageEvent, room: Room, client: Client| {
            let live_serials = live_serials_handler.clone();
            let our_user_id = our_user_id_handler.clone();
            let account_list = account_list_handler.clone();
            let datapoint_client = datapoint_client_handler.clone();
            async move {
                let room_name = room.name().unwrap_or_else(|| room.room_id().to_string());
                // Extract the message body from text or image caption.
                let (body, is_media) = match &ev.content.msgtype {
                    MessageType::Text(text) => (Some(text.body.clone()), false),
                    MessageType::Image(img) => (img.caption().map(|s| s.to_owned()), true),
                    _ => (None, false),
                };

                if let Some(body) = body {
                    if let Some((serial, send_ts)) = parse_message_body(&body) {
                        // For media, download and validate before taking the
                        // timestamp so that delivery time covers the full
                        // receive path.
                        let (media_ok, media_size_bytes) = if is_media {
                            if let MessageType::Image(img) = &ev.content.msgtype {
                                let request = MediaRequestParameters {
                                    source: img.source.clone(),
                                    format: MediaFormat::File,
                                };
                                match client.media().get_media_content(&request, true).await {
                                    Ok(data) => {
                                        let size = data.len() as u64;
                                        if let Err(e) = image::validate_png(&data) {
                                            tracing::error!(
                                                "  ⚠ [{room_name}] {}: Media #{serial} \
                                                 invalid PNG: {e}",
                                                ev.sender,
                                            );
                                            (false, Some(size))
                                        } else {
                                            (true, Some(size))
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "  ⚠ [{room_name}] {}: Media #{serial} \
                                             download failed: {e}",
                                            ev.sender,
                                        );
                                        (false, None)
                                    }
                                }
                            } else {
                                (false, None)
                            }
                        } else {
                            (true, None)
                        };

                        let delivery_ms = now_millis().saturating_sub(send_ts);
                        let kind = if is_media { "media" } else { "text" };
                        let distance = Distance::from_mxids(&our_user_id, &ev.sender);
                        let valid = media_ok;
                        let ev_sender = &ev.sender;
                        let suffix = if valid { "" } else { ", INVALID" };

                        // Submit a datapoint to the configured DATAPOINT_SERVER
                        // (no-op when unset).  Delivery is recorded in
                        // microseconds; the message body only carries
                        // millisecond precision so we scale up.  Received
                        // messages must always report a non-zero delivery time
                        // (a zero value marks *sent* messages) so we clamp to a
                        // minimum of 1µs, which also covers clock skew that
                        // would otherwise saturate the difference to 0.
                        let delivery_us = delivery_ms.saturating_mul(1_000).max(1);
                        datapoint_client.send(datapoint::Datapoint::new(
                            datapoint::now_micros(),
                            account_list.lookup(ev_sender.as_str()),
                            our_account,
                            serial,
                            delivery_us,
                            media_size_bytes.unwrap_or(0),
                        ));

                        tracing::info!(
                            delivery_ms,
                            serial,
                            kind,
                            distance = %distance,
                            media_size_bytes = media_size_bytes,
                            valid,
                            room = %room.room_id(),
                            sender = %ev_sender,
                            user = %our_user_id,
                            "  📩 [{room_name}] {ev_sender}: {kind} #{serial} \
                             (delivery: {delivery_ms}ms{suffix})",
                        );

                        // Update the live serial tracker.
                        let key = (room.room_id().to_owned(), ev.sender.clone());
                        let mut map = live_serials.lock().await;
                        let entry = map.entry(key).or_insert(0);
                        if serial >= *entry {
                            *entry = serial;
                        }
                    } else {
                        tracing::info!("  📩 [{room_name}] {}: {}", ev.sender, body);
                    }
                } else {
                    tracing::info!("  📩 [{room_name}] {}: (non-text message)", ev.sender);
                }
            }
        },
    );

    // Auto-accept invites from rooms whose server name matches the
    // configured ACCEPT_INVITE_DOMAINS patterns.
    //
    // NOTE: We also retry pending invites in the main loop below, because
    // over federation the receiving homeserver may briefly 403 a join that
    // immediately follows the stripped-state invite event (the invite has
    // been streamed to the client via sync, but the local server hasn't
    // finished persisting it for the join endpoint).  Without that retry,
    // a DM created across federation can stay in the "invited" state
    // forever, and the invited user never sends in the room.
    let invite_domains = config.accept_invite_domains.clone();
    let invite_domains_for_main = config.accept_invite_domains.clone();
    client.add_event_handler(
        move |ev: StrippedRoomMemberEvent, room: Room, client: Client| {
            let invite_domains = invite_domains.clone();
            async move {
                let our_user_id = client.user_id().map(|u| u.to_string()).unwrap_or_default();
                if ev.state_key != our_user_id {
                    return;
                }

                let room_id = room.room_id().to_owned();
                if !room_id
                    .server_name()
                    .is_some_and(|s| matches_invite_domain(&invite_domains, s.as_str()))
                {
                    return;
                }

                tracing::info!("  📨 Invited to {room_id} – joining …");
                match room.join().await {
                    Ok(()) => tracing::info!("  ✔ Joined {room_id}"),
                    Err(e) => tracing::info!("  ✘ Failed to join {room_id}: {e}"),
                }
            }
        },
    );

    // Spawn the background sync loop.
    //
    // The sync task sets `sync_fatal_tx` to `true` when it encounters an
    // HTTP 401 or 404 – the main loop picks this up and aborts `run_user`
    // so the supervisor can restart it.
    let (sync_fatal_tx, sync_fatal_rx) = watch::channel(false);
    let sync_client = client.clone();
    let mut sync_stop_rx = stop_rx.clone();
    let sync_timeout = config.sync_timeout;
    let sync_error_delay = config.sync_error_delay;
    let sync_span = tracing::Span::current();
    let sync_mxid = mxid.clone();
    let sync_handle = tokio::spawn(
        async move {
            let settings = SyncSettings::default().timeout(Duration::from_secs(sync_timeout));

            loop {
                let sync = sync_client.sync_once(settings.clone());
                tokio::select! {
                    _ = sync_stop_rx.changed() => {
                        break;
                    }
                    result = sync => {
                        if let Err(e) = result {
                            if is_fatal_sync_status(&e) {
                                tracing::error!(
                                    server_reachability = false,
                                    error = %e,
                                    "[{sync_mxid}] ✘ Fatal sync error (aborting)",
                                );
                                let _ = sync_fatal_tx.send(true);
                                break;
                            }
                            tracing::error!("  ✘ Sync error: {e}");
                            sleep(sync_error_delay.sample()).await;
                        }
                    }
                }
            }
        }
        .instrument(sync_span),
    );

    // ── 5. Main loop: alternate between verify, send, and DM creation ───
    //
    // We maintain a map of room_id → RoomVerificationState.  Each tick (2s)
    // we perform one of three actions in round-robin:
    //   (a) run a verification step on a room that still needs it,
    //   (b) send a message to a send-eligible room,
    //   (c) create a DM with a peer that doesn't have one yet.

    let mut rooms: HashMap<OwnedRoomId, RoomVerificationState> = HashMap::new();

    // Indices for round-robin.
    let mut verify_rr: usize = 0;
    let mut send_rr: usize = 0;
    let mut dm_rr: usize = 0;
    // Cycles through 0 = verify, 1 = send, 2 = dm_create, to give each
    // action type a fair share of steps.
    let mut action_cycle: usize = 0;

    // Track whether we are the primary (first) device for this account.
    // When we first become the first device we wait `promotion_wait_cycles`
    // main-loop ticks before actually sending, so that other devices have a
    // chance to appear. `account_password` and `stale_device_timeout` were
    // computed during the E2EE setup above and are reused here.
    let mut we_are_first = is_first_device(
        &client,
        stale_device_timeout,
        account_password.as_deref(),
        username,
    )
    .await;
    let mut promotion_counter: u64 = 0;
    let mut promoted = false;
    if we_are_first {
        tracing::info!(
            "[{mxid}] ✔ We are the first device – waiting {wait} cycle(s) before sending",
            wait = config.promotion_wait_cycles
        );
    } else {
        tracing::info!("[{mxid}] ℹ Another device is primary – will only verify, not send");
    }

    let mut main_stop_rx = stop_rx.clone();

    tracing::info!("[{mxid}] ▶ Starting verify/send loop (Ctrl-C to stop) …");

    loop {
        if *main_stop_rx.borrow() {
            break;
        }

        // Check for fatal sync errors (401 / 404).
        if *sync_fatal_rx.borrow() {
            tracing::error!(
                server_reachability = false,
                "[{mxid}] Sync reported fatal error – aborting run_user",
            );
            sync_handle.abort();
            let _ = sync_handle.await;
            return RunUserOutcome::Failed(RunUserError::Fatal(anyhow::anyhow!(
                "sync returned 401 or 404"
            )));
        }

        // Update next_serial in each room from live sync data so that
        // when we become the first device, we pick up where others left off.
        {
            let map = live_serials.lock().await;
            for (state_room_id, state) in rooms.iter_mut() {
                let key = (state_room_id.clone(), our_user_id.clone());
                if let Some(&live_serial) = map.get(&key) {
                    let candidate = live_serial + 1;
                    match state.next_serial {
                        Some(current) if candidate > current => {
                            state.next_serial = Some(candidate);
                        }
                        None => {
                            state.next_serial = Some(candidate);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Remove rooms we are no longer a member of.
        let joined_ids: std::collections::HashSet<OwnedRoomId> = client
            .joined_rooms()
            .iter()
            .map(|r| r.room_id().to_owned())
            .collect();
        rooms.retain(|rid, _| {
            if joined_ids.contains(rid) {
                true
            } else {
                tracing::info!(
                    "[{mxid}]   🚪 Room {rid} is no longer joined, removing from tracking"
                );
                false
            }
        });

        // Re-check first-device status (handles other devices logging out).
        let was_first = we_are_first;
        we_are_first = is_first_device(
            &client,
            stale_device_timeout,
            account_password.as_deref(),
            username,
        )
        .await;
        if we_are_first && !was_first {
            // Just became the first device – start the promotion countdown.
            promotion_counter = 0;
            promoted = false;
            tracing::info!(
                "[{mxid}]   🔼 We are now the first device – waiting {wait} cycle(s) before sending",
                wait = config.promotion_wait_cycles
            );
        } else if !we_are_first && was_first {
            promoted = false;
            promotion_counter = 0;
            tracing::info!("[{mxid}]   🔽 Another device took over – will stop sending");
        }

        // Advance the promotion counter while we are the first device but
        // not yet promoted.
        if we_are_first && !promoted {
            promotion_counter += 1;
            if promotion_counter > config.promotion_wait_cycles {
                promoted = true;
                tracing::info!("[{mxid}]   🔼 Promotion wait complete – will start sending");
            }
        }

        // Retry any pending invites whose server name matches the
        // configured ACCEPT_INVITE_DOMAINS patterns.  The event-handler
        // above already attempts to join once when the invite arrives via
        // sync, but over federation that first attempt can race the local
        // server's invite persistence and fail with HTTP 403 M_FORBIDDEN.
        // Retrying here on every main-loop tick lets the join succeed as
        // soon as the local server is ready.
        for invited in client.invited_rooms() {
            let room_id = invited.room_id().to_owned();
            if !room_id
                .server_name()
                .is_some_and(|s| matches_invite_domain(&invite_domains_for_main, s.as_str()))
            {
                continue;
            }
            match invited.join().await {
                Ok(()) => tracing::info!("[{mxid}]   ✔ Joined pending invite {room_id}"),
                Err(e) => {
                    tracing::debug!("[{mxid}]   ⏳ Pending invite {room_id} not yet joinable: {e}")
                }
            }
        }

        // Discover newly joined rooms and add them to the tracking map.
        for joined in client.joined_rooms() {
            let rid = joined.room_id();
            if let std::collections::hash_map::Entry::Vacant(entry) = rooms.entry(rid.to_owned()) {
                tracing::info!("[{mxid}]   🆕 Discovered new room {rid}, downloading room keys …");
                if let Err(e) = client
                    .encryption()
                    .backups()
                    .download_room_keys_for_room(rid)
                    .await
                {
                    tracing::error!("[{mxid}]   ✘ Failed to download room keys for {rid}: {e}");
                }
                entry.insert(RoomVerificationState::new(joined));
            }
        }

        // Collect room IDs in a stable order.
        let room_ids: Vec<OwnedRoomId> = rooms.keys().cloned().collect();

        // Find rooms that need verification.
        let verify_candidates: Vec<OwnedRoomId> = room_ids
            .iter()
            .filter(|id| rooms[*id].needs_verification())
            .cloned()
            .collect();

        // Find rooms eligible for sending (only if we are the first device
        // and the promotion wait has elapsed).
        let send_candidates: Vec<OwnedRoomId> = if we_are_first && promoted {
            room_ids
                .iter()
                .filter(|id| rooms[*id].is_send_eligible())
                .cloned()
                .collect()
        } else {
            vec![]
        };

        // Find peers that don't have a DM yet (only create DMs if we are the
        // first device).
        let peers_with_dm: HashSet<OwnedUserId> = rooms
            .values()
            .filter_map(|state| {
                let targets = state.room.direct_targets();
                if targets.len() == 1 {
                    targets
                        .iter()
                        .next()
                        .and_then(|t| OwnedUserId::try_from(t.to_string()).ok())
                } else {
                    None
                }
            })
            .collect();
        let dm_candidates: Vec<&UserId> = if we_are_first && promoted {
            peers
                .iter()
                .filter(|p| !peers_with_dm.contains(*p))
                .map(AsRef::as_ref)
                .collect()
        } else {
            vec![]
        };

        // Three-way round-robin: try the preferred action first, then fall
        // through to the others.
        let actions = [0, 1, 2];
        let mut did_something = false;
        for offset in 0..3 {
            let action = actions[(action_cycle + offset) % 3];
            match action {
                0 => {
                    let verify_result = try_verify(
                        &mut rooms,
                        &verify_candidates,
                        &mut verify_rr,
                        &our_user_id,
                        &client,
                        config.leave_on_failure,
                    )
                    .await;
                    if let Some(verified) = match verify_result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!("[{mxid}] Verification error: {e:#}");
                            None
                        }
                    } {
                        tracing::info!("[{mxid}]   🔍 Verified page in {verified}");
                        did_something = true;
                        break;
                    }
                }
                1 => {
                    if let Some(sent) = try_send(
                        &mut rooms,
                        &send_candidates,
                        &mut send_rr,
                        config.media_probability,
                        &datapoint_client,
                        &account_list,
                        our_account,
                    )
                    .await
                    {
                        tracing::info!("[{mxid}]   ✔ Sent {sent}");
                        did_something = true;
                        break;
                    }
                }
                2 => {
                    let dm_result = try_create_dm(&client, &dm_candidates, &mut dm_rr).await;
                    if let Some(result) = match dm_result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!("[{mxid}] DM creation error: {e:#}");
                            None
                        }
                    } {
                        tracing::info!("[{mxid}] DM creation success: {result}");
                        did_something = true;
                        break;
                    }
                }
                _ => unreachable!(),
            }
        }

        if did_something {
            action_cycle = (action_cycle + 1) % 3;
        }

        // Sleep for 2 seconds, but break early on shutdown or fatal sync.
        let mut sync_fatal_watcher = sync_fatal_rx.clone();
        tokio::select! {
            _ = main_stop_rx.changed() => {
                break;
            }
            _ = sync_fatal_watcher.changed() => {
                if *sync_fatal_watcher.borrow() {
                    tracing::error!(
                        server_reachability = false,
                        "[{mxid}] Sync reported fatal error – aborting run_user",
                    );
                    sync_handle.abort();
                    let _ = sync_handle.await;
                    return RunUserOutcome::Failed(RunUserError::Fatal(
                        anyhow::anyhow!("sync returned 401 or 404"),
                    ));
                }
            }
            _ = sleep(config.loop_interval.sample()) => {}
        }
    }

    tracing::info!("[{mxid}] ✔ Main loop stopped");

    // Signal the sync loop to stop (it shares the same stop_rx).
    sync_handle.abort();
    let _ = sync_handle.await;
    tracing::info!("[{mxid}] ✔ Sync loop stopped");

    // ── 6. Wait for key backup to finish uploading ──────────────────────
    tracing::info!("[{mxid}] ▶ Waiting for room key backup to complete …");
    match client.encryption().backups().wait_for_steady_state().await {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("[{mxid}] ✘ Key backup wait failed: {e}");
        }
    }
    tracing::info!("[{mxid}] ✔ Key backup upload complete");

    // ── 7. Log out ──────────────────────────────────────────────────────
    tracing::info!("[{mxid}] ▶ Logging out …");
    match client.matrix_auth().logout().await {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("[{mxid}] ✘ Logout failed: {e}");
        }
    }
    tracing::info!("[{mxid}] ✔ Logged out – all done!");

    RunUserOutcome::Shutdown
}

// ── Action helpers ──────────────────────────────────────────────────────

/// Try to run a verification step on the next room in round-robin order.
/// Returns `Some(room_id)` if a page was verified, `None` if no candidate.
/// If verification fails the room is marked as failed and, when
/// `leave_on_failure` is true, the room is also left.
#[tracing::instrument(skip_all, fields(room_id))]
async fn try_verify(
    rooms: &mut HashMap<OwnedRoomId, RoomVerificationState>,
    candidates: &[OwnedRoomId],
    rr: &mut usize,
    our_user_id: &OwnedUserId,
    client: &Client,
    leave_on_failure: bool,
) -> anyhow::Result<Option<String>> {
    if candidates.is_empty() {
        return Ok(None);
    }

    let idx = *rr % candidates.len();
    *rr = rr.wrapping_add(1);

    let room_id = &candidates[idx];
    tracing::Span::current().record("room_id", room_id.as_str());

    let state = rooms.get_mut(room_id).unwrap();
    let (count, failed) = match state.verify_page(our_user_id, client).await {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    if failed {
        state.failed = true;
        if leave_on_failure {
            tracing::error!("Verification failed – leaving room");
            if let Err(e) = state.room.leave().await {
                tracing::error!(error = %e, "Failed to leave room after verification failure");
            }
        } else {
            tracing::error!("Verification failed – room disabled");
        }
        return Ok(Some(format!("{room_id} (FAILED)")));
    }

    tracing::debug!(events = count, "Verified page");
    Ok(Some(format!("{room_id} ({count} events)")))
}

/// Try to send a message (or media) to the next send-eligible room in
/// round-robin order.  When `media_probability` is > 0, a random draw
/// decides whether to upload a PNG image instead of sending plain text.
/// Returns `Some(description)` if a message was sent, `None` if no candidate.
#[tracing::instrument(skip_all, fields(room_id, serial, kind))]
async fn try_send(
    rooms: &mut HashMap<OwnedRoomId, RoomVerificationState>,
    candidates: &[OwnedRoomId],
    rr: &mut usize,
    media_probability: f64,
    datapoint_client: &datapoint::DatapointClient,
    account_list: &datapoint::AccountList,
    our_account: u32,
) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }

    let idx = *rr % candidates.len();
    *rr = rr.wrapping_add(1);

    let room_id = &candidates[idx];
    let state = rooms.get_mut(room_id).unwrap();

    let serial = state.next_serial.unwrap_or(1);
    let ts = now_millis();
    let message_text = format!("Message #{serial} {ts}");

    let send_media = media_probability > 0.0 && random::<f64>() < media_probability;
    let kind = if send_media { "media" } else { "text" };

    let span = tracing::Span::current();
    span.record("room_id", room_id.as_str());
    span.record("serial", serial);
    span.record("kind", kind);

    // When the room is a DM (exactly one recipient besides us), record that
    // recipient as the datapoint receiver; otherwise leave it as `0`
    // (unknown) since a room may have many recipients.
    let targets = state.room.direct_targets();
    let receiver = if targets.len() == 1 {
        targets
            .iter()
            .next()
            .map(|t| account_list.lookup(&t.to_string()))
            .unwrap_or(0)
    } else {
        0
    };

    // For media we know the payload size up front; generate it before
    // recording the datapoint so the size is available either way.
    let png_data = if send_media {
        Some(image::generate_png())
    } else {
        None
    };
    let media_size_bytes = png_data.as_ref().map(|d| d.len() as u64).unwrap_or(0);

    // Mark the *intent* to send as a datapoint, before actually sending.  A
    // zero delivery time marks the record as *sent* (as opposed to
    // *received*, which always reports a non-zero delivery time).
    datapoint_client.send(datapoint::Datapoint::new(
        datapoint::now_micros(),
        our_account,
        receiver,
        serial,
        0,
        media_size_bytes,
    ));

    let result = if let Some(png_data) = png_data {
        let config = AttachmentConfig::new()
            .info(AttachmentInfo::Image(BaseImageInfo {
                width: Some(UInt::new(image::IMAGE_WIDTH as u64).unwrap()),
                height: Some(UInt::new(image::IMAGE_HEIGHT as u64).unwrap()),
                size: Some(UInt::new(png_data.len() as u64).unwrap()),
                ..Default::default()
            }))
            .caption(Some(TextMessageEventContent::plain(&message_text)));

        state
            .room
            .send_attachment("image.png", &mime::IMAGE_PNG, png_data, config)
            .await
            .map(|_| ())
    } else {
        let content = RoomMessageEventContent::text_plain(&message_text);
        state.room.send(content).await.map(|_| ())
    };

    match result {
        Ok(()) => {
            state.next_serial = Some(serial + 1);
            tracing::info!("Message sent");
            Some(format!("{kind} #{serial} to {room_id}"))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to send message");
            None
        }
    }
}

/// Try to create a DM with the next peer in round-robin order.
/// Returns `Some(description)` if the step was taken (even if no room was
/// created due to missing E2EE keys), `None` if there are no candidates.
#[tracing::instrument(skip_all, fields(peer))]
async fn try_create_dm(
    client: &Client,
    candidates: &[&UserId],
    rr: &mut usize,
) -> anyhow::Result<Option<String>> {
    if candidates.is_empty() {
        return Ok(None);
    }

    let idx = *rr % candidates.len();
    *rr = rr.wrapping_add(1);

    let peer = candidates[idx];
    tracing::Span::current().record("peer", peer.as_str());

    tracing::info!("DM creation started: {}", peer.as_str());

    match client.create_dm(peer).await {
        Ok(room) => {
            tracing::info!(room_id = %room.room_id(), "Created DM");
            Ok(Some(format!(
                "🤝 Created DM {} with {peer}",
                room.room_id()
            )))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to create DM");
            Ok(Some(format!("✘ Failed to create DM with {peer}: {e}")))
        }
    }
}
