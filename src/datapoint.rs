//! Datapoint submission to a remote TCP collector.
//!
//! When the `DATAPOINT_SERVER` env var is set (to a `host:port` endpoint),
//! a background tokio task keeps a persistent TCP connection to the
//! collector and forwards [`Datapoint`] records using the datapoint TCP
//! write protocol.
//!
//! On every (re)connect three types are defined:
//!
//! | slot | type        | definition                                    |
//! |------|-------------|-----------------------------------------------|
//! | 1    | `Domain`    | `text str` (referenceable, `u16` references)  |
//! | 2    | `Localpart` | `text str` (referenceable, `u16` references)  |
//! | 3    | `Message`   | see [`MESSAGE_DEFINITION`]                    |
//!
//! MXIDs are split into localpart and domain; each distinct string is
//! submitted once per connection and afterwards referenced by its
//! connection-local index.  The server never replies; it closes the
//! connection on any protocol error.

use std::collections::HashMap;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use zerocopy::byteorder::little_endian::{U16, U32, U64};
use zerocopy::{Immutable, IntoBytes};

const DOMAIN_SLOT: u8 = 1;
const LOCALPART_SLOT: u8 = 2;
const MESSAGE_SLOT: u8 = 3;

/// Index byte `2`: references to the type are 2 bytes wide, little-endian.
const REFERENCE_INDEX_BYTE: u8 = 2;
/// Index byte `0`: not referenceable.
const PLAIN_INDEX_BYTE: u8 = 0;

/// Maximum number of values per connection for a type with 2-byte references.
const MAX_REFERENCEABLE: usize = 1 << 16;

/// Definition of the `Message` type.  Scalars are sent little-endian.
const MESSAGE_DEFINITION: &str = "timestamp_us u64,serial u64,delivery_us u32,media_size u32,\
                                  sender_name Localpart,sender_domain Domain,\
                                  receiver_name Localpart,receiver_domain Domain";

/// The messages that define all types: `00 <index byte> <Name>\0 <definition>\0`.
fn type_definitions() -> Vec<u8> {
    let mut msg = Vec::new();
    for (index_byte, name, definition) in [
        (REFERENCE_INDEX_BYTE, "Domain", "text str"),
        (REFERENCE_INDEX_BYTE, "Localpart", "text str"),
        (PLAIN_INDEX_BYTE, "Message", MESSAGE_DEFINITION),
    ] {
        msg.extend_from_slice(&[0x00, index_byte]);
        msg.extend_from_slice(name.as_bytes());
        msg.push(0);
        msg.extend_from_slice(definition.as_bytes());
        msg.push(0);
    }
    msg
}

/// A `Message` value as it appears on the wire, including the leading slot
/// byte.  Field order and widths must match [`MESSAGE_DEFINITION`]; the
/// reference fields are local indices of `Localpart` / `Domain` values
/// (index byte `2` = `u16`, little-endian).
#[derive(Debug, Clone, Copy, IntoBytes, Immutable)]
#[repr(C)]
struct MessageWire {
    slot: u8,
    timestamp_us: U64,
    serial: U64,
    delivery_us: U32,
    media_size: U32,
    sender_name: U16,
    sender_domain: U16,
    receiver_name: U16,
    receiver_domain: U16,
}

/// One datapoint.
#[derive(Debug, Clone)]
pub struct Datapoint {
    /// UNIX timestamp at the moment the datapoint is generated, in
    /// microseconds.
    timestamp_us: u64,
    /// Per-(room, sender) message serial number.
    serial: u64,
    /// End-to-end delivery time in microseconds, clamped to `u32::MAX`.
    /// `0` marks a *sent* message.
    delivery_us: u32,
    /// Media size in bytes (0 for plain text messages), clamped to
    /// `u32::MAX`.
    media_size: u32,
    sender: Mxid,
    receiver: Mxid,
}

impl Datapoint {
    /// Build a datapoint, clamping any out-of-range field to its maximum.
    /// `receiver` is `None` when unknown (e.g. a room with many recipients);
    /// it is then submitted as an empty localpart and domain.
    pub fn new(
        timestamp_us: u64,
        sender: &str,
        receiver: Option<&str>,
        serial: u64,
        delivery_us: u64,
        media_size: u64,
    ) -> Self {
        Self {
            timestamp_us,
            serial,
            delivery_us: clamp_u32(delivery_us),
            media_size: clamp_u32(media_size),
            sender: Mxid::parse(sender),
            receiver: receiver.map(Mxid::parse).unwrap_or_default(),
        }
    }

    /// Append the encoded value (including the new `Domain` / `Localpart`
    /// values it needs and the leading slot bytes) to `out`.  Returns `false`
    /// when the session ran out of reference indices; `out` is then garbage
    /// and the session must be discarded.
    fn encode(&self, session: &mut Session, out: &mut Vec<u8>) -> bool {
        let wire = (|| {
            Some(MessageWire {
                slot: MESSAGE_SLOT,
                timestamp_us: U64::new(self.timestamp_us),
                serial: U64::new(self.serial),
                delivery_us: U32::new(self.delivery_us),
                media_size: U32::new(self.media_size),
                sender_name: U16::new(session.localparts.intern(&self.sender.localpart, out)?),
                sender_domain: U16::new(session.domains.intern(&self.sender.domain, out)?),
                receiver_name: U16::new(session.localparts.intern(&self.receiver.localpart, out)?),
                receiver_domain: U16::new(session.domains.intern(&self.receiver.domain, out)?),
            })
        })();
        let Some(wire) = wire else {
            return false;
        };
        out.extend_from_slice(wire.as_bytes());
        true
    }
}

fn clamp_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Current UNIX timestamp with microsecond resolution.
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

// ── MXID splitting ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Mxid {
    localpart: String,
    domain: String,
}

impl Mxid {
    /// Split `@localpart:domain`.  The domain may itself contain a colon
    /// (port).  Input that does not look like an MXID ends up entirely in the
    /// localpart.  NUL bytes are dropped as they would terminate the string
    /// on the wire.
    fn parse(mxid: &str) -> Self {
        let mxid = mxid.strip_prefix('@').unwrap_or(mxid);
        let (localpart, domain) = mxid.split_once(':').unwrap_or((mxid, ""));
        Self {
            localpart: localpart.replace('\0', ""),
            domain: domain.replace('\0', ""),
        }
    }
}

// ── Per-connection state ────────────────────────────────────────────────

/// Maps strings to their connection-local index for one referenceable type.
struct Interner {
    slot: u8,
    map: HashMap<String, u16>,
    /// Number of values submitted on this connection (= next local index).
    count: usize,
}

impl Interner {
    fn new(slot: u8) -> Self {
        Self {
            slot,
            map: HashMap::new(),
            count: 0,
        }
    }

    /// Local index of `value`, appending the value to `out` if it has not
    /// been submitted on this connection yet.  `None` when out of indices.
    fn intern(&mut self, value: &str, out: &mut Vec<u8>) -> Option<u16> {
        if let Some(&index) = self.map.get(value) {
            return Some(index);
        }
        if self.count >= MAX_REFERENCEABLE {
            return None;
        }
        let index = self.count as u16;
        self.count += 1;
        out.push(self.slot);
        out.extend_from_slice(value.as_bytes());
        out.push(0);
        self.map.insert(value.to_owned(), index);
        Some(index)
    }
}

/// Everything the server knows about one connection.
struct Session {
    domains: Interner,
    localparts: Interner,
}

impl Session {
    fn new() -> Self {
        Self {
            domains: Interner::new(DOMAIN_SLOT),
            localparts: Interner::new(LOCALPART_SLOT),
        }
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
/// failure.  Each connection starts with the type definitions; every
/// received [`Datapoint`] is then written as a single buffer containing any
/// new `Domain` / `Localpart` values followed by the `Message`.
async fn run_loop(endpoint: String, mut rx: mpsc::UnboundedReceiver<Datapoint>) {
    tracing::info!("datapoint client → {endpoint}");

    // A datapoint that could not be encoded because the session ran out of
    // reference indices; it is re-encoded on the next connection.
    let mut carry: Option<Datapoint> = None;

    loop {
        let stream = match TcpStream::connect(&endpoint).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("datapoint connect to {endpoint} failed: {e}");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };
        let (mut reader, mut writer) = stream.into_split();

        if let Err(e) = writer.write_all(&type_definitions()).await {
            tracing::warn!("datapoint type definition write to {endpoint} failed: {e}");
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        }

        let mut session = Session::new();
        let mut buf = Vec::new();
        let mut discard = [0u8; 1];
        loop {
            let dp = match carry.take() {
                Some(dp) => dp,
                None => tokio::select! {
                    dp = rx.recv() => match dp {
                        Some(dp) => dp,
                        // All senders dropped – shut the worker down.
                        None => return,
                    },
                    // The server never sends anything; a read completing
                    // means it closed the connection (which it does on any
                    // protocol error).
                    r = reader.read(&mut discard) => {
                        match r {
                            Ok(0) => tracing::warn!(
                                "datapoint server {endpoint} closed the connection – reconnecting"
                            ),
                            Ok(_) => continue,
                            Err(e) => tracing::warn!(
                                "datapoint read from {endpoint} failed: {e} – reconnecting"
                            ),
                        }
                        tokio::time::sleep(RECONNECT_DELAY).await;
                        break;
                    }
                },
            };

            buf.clear();
            if !dp.encode(&mut session, &mut buf) {
                // Out of local indices: start over on a fresh connection
                // (which resets the indices) without delay.
                tracing::info!("datapoint reference indices exhausted – reconnecting");
                carry = Some(dp);
                break;
            }
            if let Err(e) = writer.write_all(&buf).await {
                tracing::warn!("datapoint write to {endpoint} failed: {e} – reconnecting");
                tokio::time::sleep(RECONNECT_DELAY).await;
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_definition_wire_format() {
        assert_eq!(
            type_definitions(),
            b"\x00\x02Domain\0text str\0\
              \x00\x02Localpart\0text str\0\
              \x00\x00Message\0timestamp_us u64,serial u64,delivery_us u32,media_size u32,\
              sender_name Localpart,sender_domain Domain,\
              receiver_name Localpart,receiver_domain Domain\0"
        );
    }

    #[test]
    fn mxid_parsing() {
        assert_eq!(
            Mxid::parse("@alice:example.org:8448"),
            Mxid {
                localpart: "alice".into(),
                domain: "example.org:8448".into()
            }
        );
        assert_eq!(Mxid::parse("weird").domain, "");
    }

    #[test]
    fn encoding_interns_per_session() {
        let mut session = Session::new();
        let dp = Datapoint::new(1, "@alice:example.org", Some("@bob:example.org"), 4, 5, 6);

        let mut out = Vec::new();
        assert!(dp.encode(&mut session, &mut out));

        let expected = [
            &b"\x02alice\0"[..],  // Localpart 0
            b"\x01example.org\0", // Domain 0
            b"\x02bob\0",         // Localpart 1
            &[MESSAGE_SLOT],
            &1u64.to_le_bytes(),
            &4u64.to_le_bytes(),
            &5u32.to_le_bytes(),
            &6u32.to_le_bytes(),
            &[0, 0, 0, 0, 1, 0, 0, 0], // sender 0/0, receiver 1/0
        ]
        .concat();
        assert_eq!(out, expected);

        // Same peers again: only the message is emitted; unknown receiver
        // interns the empty strings.
        let dp = Datapoint::new(2, "@bob:example.org", None, 7, 0, 0);
        out.clear();
        assert!(dp.encode(&mut session, &mut out));
        let expected = [
            &b"\x02\0"[..], // Localpart 2 = ""
            b"\x01\0",      // Domain 1 = ""
            &[MESSAGE_SLOT],
            &2u64.to_le_bytes(),
            &7u64.to_le_bytes(),
            &0u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &[1, 0, 0, 0, 2, 0, 1, 0], // sender 1/0, receiver 2/1
        ]
        .concat();
        assert_eq!(out, expected);
    }

    #[test]
    fn indices_exhaust() {
        let mut interner = Interner::new(1);
        let mut out = Vec::new();
        for i in 0..MAX_REFERENCEABLE {
            assert_eq!(interner.intern(&i.to_string(), &mut out), Some(i as u16));
        }
        assert_eq!(interner.intern("one more", &mut out), None);
        assert_eq!(interner.intern("0", &mut out), Some(0));
    }
}
