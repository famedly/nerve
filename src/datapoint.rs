//! Datapoint submission to a remote TCP collector.
//!
//! When the `DATAPOINT_SERVER` env var is set (to a `host:port` endpoint),
//! a background tokio task keeps a persistent TCP connection to the
//! collector and forwards [`Datapoint`] records as fixed-size
//! [`STRIDE`]-byte writes.  See the `datapoint` sub-crate for the
//! server-side protocol; in short, the first byte is the stride and the
//! remainder is a stream of back-to-back records.
//!
//! `ACCOUNT_LIST` provides a stable MXID → 1-based account-number
//! mapping that turns user IDs into the compact `sender` / `receiver`
//! fields of each datapoint.  It accepts either a space-delimited list
//! of MXIDs or a path to a file with one MXID per line.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::{U32, U64};

/// Size of one record on the wire.  Sent verbatim as the stride header
/// byte on connect.
pub const STRIDE: usize = 32;

/// One datapoint as it appears on the wire.
///
/// All integers are little-endian, regardless of host byte order, so the
/// captured stream is portable between architectures.
#[derive(Debug, Clone, Copy, IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
pub struct Datapoint {
    /// UNIX timestamp at the moment the datapoint is generated, in
    /// microseconds.
    pub timestamp_us: U64,
    /// 1-based account number of the sender.  `0` when the MXID is not
    /// in the configured `ACCOUNT_LIST`.
    pub sender: U32,
    /// 1-based account number of the receiver.  `0` when the MXID is not
    /// in the configured `ACCOUNT_LIST`.
    pub receiver: U32,
    /// Per-(room, sender) message serial number.
    pub serial: U64,
    /// End-to-end delivery time in microseconds, clamped to `u32::MAX`.
    pub delivery_us: U32,
    /// Media size in bytes (0 for plain text messages), clamped to
    /// `u32::MAX`.
    pub media_size: U32,
}

// Compile-time check: the struct must be exactly `STRIDE` bytes with no
// padding so the receiver can reinterpret records directly.
const _: () = assert!(std::mem::size_of::<Datapoint>() == STRIDE);

impl Datapoint {
    /// Build a datapoint, clamping any out-of-range field to its maximum.
    pub fn new(
        timestamp_us: u64,
        sender: u32,
        receiver: u32,
        serial: u64,
        delivery_us: u64,
        media_size: u64,
    ) -> Self {
        Self {
            timestamp_us: U64::new(timestamp_us),
            sender: U32::new(sender),
            receiver: U32::new(receiver),
            serial: U64::new(serial),
            delivery_us: U32::new(clamp_u32(delivery_us)),
            media_size: U32::new(clamp_u32(media_size)),
        }
    }
}

fn clamp_u32(value: u64) -> u32 {
    if value > u32::MAX as u64 {
        u32::MAX
    } else {
        value as u32
    }
}

/// Current UNIX timestamp with microsecond resolution.
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

// ── Account list ────────────────────────────────────────────────────────

/// MXID → 1-based account number.  Look-ups for MXIDs not in the list
/// return `0`.
///
/// Loaded from the `ACCOUNT_LIST` env var, which is interpreted as:
///   * a path to a file containing one MXID per line if it resolves to
///     an existing file, otherwise
///   * a space-delimited list of MXIDs.
#[derive(Debug, Default, Clone)]
pub struct AccountList {
    map: HashMap<String, u32>,
}

impl AccountList {
    /// Build an [`AccountList`] from the `ACCOUNT_LIST` env var.  An
    /// unset or empty variable yields an empty list (every MXID maps to
    /// account `0`).
    pub fn from_env() -> Self {
        match env::var("ACCOUNT_LIST") {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Self::default(),
        }
    }

    fn parse(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::default();
        }

        let mxids: Vec<String> = if trimmed.starts_with("@") {
            trimmed.split_whitespace().map(str::to_owned).collect()
        } else {
            match fs::read_to_string(trimmed) {
                Ok(content) => content
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                Err(e) => {
                    tracing::warn!("ACCOUNT_LIST file {trimmed:?} unreadable: {e}");
                    return Self::default();
                }
            }
        };

        let map = mxids
            .into_iter()
            .enumerate()
            .map(|(i, mxid)| (mxid, (i + 1) as u32))
            .collect();
        Self { map }
    }

    /// Returns the 1-based account number for `mxid`, or `0` when unknown.
    pub fn lookup(&self, mxid: &str) -> u32 {
        self.map.get(mxid).copied().unwrap_or(0)
    }
}

// ── Datapoint TCP client ────────────────────────────────────────────────

/// Background TCP client that ships [`Datapoint`]s to `DATAPOINT_SERVER`.
///
/// Cheap to clone (shares the underlying channel).  Calling
/// [`send`](Self::send) when no server is configured is a no-op.
#[derive(Debug, Clone, Default)]
pub struct DatapointClient {
    tx: Option<mpsc::UnboundedSender<Datapoint>>,
}

const RECONNECT_DELAY: Duration = Duration::from_secs(5);

impl DatapointClient {
    /// Create a client from the `DATAPOINT_SERVER` env var, spawning a
    /// background task on the current tokio runtime.  Returns a disabled
    /// (no-op) client when the variable is unset or empty.
    pub fn from_env() -> Self {
        let Ok(endpoint) = env::var("DATAPOINT_SERVER") else {
            return Self::default();
        };
        let endpoint = endpoint.trim().to_owned();
        if endpoint.is_empty() {
            return Self::default();
        }
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(run_loop(endpoint, rx));
        Self { tx: Some(tx) }
    }

    /// Submit a datapoint.  Non-blocking; silently dropped when no
    /// server is configured or the worker has terminated.
    pub fn send(&self, dp: Datapoint) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(dp);
        }
    }
}

/// Background task: maintains a TCP connection, reconnecting on any
/// failure, and forwards every received [`Datapoint`] as a single
/// [`STRIDE`]-byte write.
async fn run_loop(endpoint: String, mut rx: mpsc::UnboundedReceiver<Datapoint>) {
    tracing::info!("datapoint client → {endpoint}");

    loop {
        let mut stream = match TcpStream::connect(&endpoint).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("datapoint connect to {endpoint} failed: {e}");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        // Stride header: one byte (0 means 256; we use STRIDE == 32).
        if let Err(e) = stream.write_all(&[STRIDE as u8]).await {
            tracing::warn!("datapoint header write to {endpoint} failed: {e}");
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        }

        loop {
            let Some(dp) = rx.recv().await else {
                // All senders dropped – shut the worker down.
                return;
            };
            if let Err(e) = stream.write_all(dp.as_bytes()).await {
                tracing::warn!("datapoint write to {endpoint} failed: {e} – reconnecting");
                break;
            }
        }
    }
}
