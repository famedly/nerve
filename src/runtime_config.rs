//! Runtime-configurable parameters, fetched from the datapoint HTTP API.
//!
//! When `DATAPOINT_HTTP` is set (base URL of the datapoint server's HTTP
//! API), a background task follows the `Config` type and publishes the latest
//! value through a [`watch`] channel.  The expected definition is
//! [`CONFIG_DEFINITION`]; scalars are interpreted as little-endian.
//!
//! The task first verifies the definition via `GET /type`, then catches up to
//! the latest stored value (`GET /Config?start=<n>`) and afterwards long-polls
//! (`GET /Config?start=<n>&timeout=<s>`) for new values.  Consumers read the
//! current value whenever they need it, so a change only affects the next
//! use (e.g. the next sampled loop interval), never an ongoing wait.

use std::time::Duration;

use tokio::sync::watch;

use crate::IntervalRange;

/// Parameters that can change while running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Seconds between main-loop ticks.
    pub loop_interval: IntervalRange,
    /// Only users whose index in `USERS` is below this value send messages.
    pub active_users: u32,
}

impl RuntimeConfig {
    /// Whether the user at `index` (0-based position in `USERS`) may send.
    pub fn is_active(&self, index: usize) -> bool {
        index < self.active_users as usize
    }
}

const TYPE_NAME: &str = "Config";
/// Normalised definition of the `Config` type.
const CONFIG_DEFINITION: &str = "loop_interval_lo u16,loop_interval_hi u16,active_users u32";
/// Size of one `Config` value in bytes.
const VALUE_SIZE: usize = 8;

/// Server-side long-poll timeout: the response ends after this long without
/// new values and is then re-issued.
const LONG_POLL_TIMEOUT: Duration = Duration::from_secs(60);
/// Client-side read timeout; must exceed [`LONG_POLL_TIMEOUT`] so that only
/// dead connections trip it.
const READ_TIMEOUT: Duration = Duration::from_secs(90);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_DELAY: Duration = Duration::from_secs(5);

/// Decode one little-endian `Config` value.
fn decode(value: &[u8; VALUE_SIZE]) -> RuntimeConfig {
    let lo = u16::from_le_bytes([value[0], value[1]]) as u64;
    let hi = u16::from_le_bytes([value[2], value[3]]) as u64;
    RuntimeConfig {
        loop_interval: IntervalRange {
            lo: lo.min(hi),
            hi: lo.max(hi),
        },
        active_users: u32::from_le_bytes([value[4], value[5], value[6], value[7]]),
    }
}

/// Find the definition of `name` in a `GET /type` response
/// (records of `index u8, name str, definition str`).
fn find_definition(types: &[u8], name: &str) -> Option<String> {
    let mut rest = types;
    while let Some((_index, after_index)) = rest.split_first() {
        let mut fields = after_index.splitn(3, |&b| b == 0);
        let record_name = fields.next()?;
        let definition = fields.next()?;
        if record_name == name.as_bytes() {
            return Some(String::from_utf8_lossy(definition).into_owned());
        }
        rest = fields.next().unwrap_or_default();
    }
    None
}

/// Spawn the background task if `base_url` is set and return the receiver
/// for the current runtime configuration, initialised with `initial`.
pub fn spawn(base_url: Option<&str>, initial: RuntimeConfig) -> watch::Receiver<RuntimeConfig> {
    let (tx, rx) = watch::channel(initial);
    let base_url = base_url.map(str::trim).filter(|s| !s.is_empty());
    if let Some(base_url) = base_url {
        let base_url = if base_url.contains("://") {
            base_url.trim_end_matches('/').to_owned()
        } else {
            format!("http://{}", base_url.trim_end_matches('/'))
        };
        tokio::spawn(run(base_url, tx));
    }
    rx
}

async fn run(base_url: String, tx: watch::Sender<RuntimeConfig>) {
    tracing::info!("runtime config ← {base_url}/{TYPE_NAME}");
    let client = match reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("runtime config: failed to build HTTP client: {e}");
            return;
        }
    };

    // Index of the next value to fetch.
    let mut next = 0u64;
    loop {
        if let Err(e) = follow(&client, &base_url, &mut next, &tx).await {
            tracing::warn!("runtime config: {e:#} – retrying in {RETRY_DELAY:?}");
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

/// Verify the type definition, catch up and long-poll until an error occurs.
async fn follow(
    client: &reqwest::Client,
    base_url: &str,
    next: &mut u64,
    tx: &watch::Sender<RuntimeConfig>,
) -> anyhow::Result<()> {
    let types = client
        .get(format!("{base_url}/type"))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    match find_definition(&types, TYPE_NAME) {
        None => anyhow::bail!("type {TYPE_NAME} is not defined (yet)"),
        Some(definition) if definition != CONFIG_DEFINITION => anyhow::bail!(
            "type {TYPE_NAME} has definition {definition:?}, expected {CONFIG_DEFINITION:?}"
        ),
        Some(_) => {}
    }

    // Catch up: only the latest of the already stored values matters.
    let mut latest = None;
    fetch(client, base_url, next, None, |value| latest = Some(value)).await?;
    if let Some(value) = latest {
        apply(tx, value);
    }

    loop {
        fetch(client, base_url, next, Some(LONG_POLL_TIMEOUT), |value| {
            apply(tx, value)
        })
        .await?;
    }
}

/// Stream the values from index `*next` on, advancing `*next` for every
/// complete value.  `on_value` is called with the last complete value of
/// each received chunk.
async fn fetch(
    client: &reqwest::Client,
    base_url: &str,
    next: &mut u64,
    timeout: Option<Duration>,
    mut on_value: impl FnMut(RuntimeConfig),
) -> anyhow::Result<()> {
    let mut url = format!("{base_url}/{TYPE_NAME}?start={next}");
    if let Some(timeout) = timeout {
        url.push_str(&format!("&timeout={}", timeout.as_secs()));
    }
    let mut response = client.get(url).send().await?.error_for_status()?;

    // Chunks are not aligned to values; keep a trailing partial value.
    let mut buf = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        buf.extend_from_slice(&chunk);
        let complete = buf.len() / VALUE_SIZE;
        if complete == 0 {
            continue;
        }
        let last = &buf[(complete - 1) * VALUE_SIZE..complete * VALUE_SIZE];
        on_value(decode(last.try_into().expect("slice has VALUE_SIZE bytes")));
        *next += complete as u64;
        buf.drain(..complete * VALUE_SIZE);
    }
    Ok(())
}

fn apply(tx: &watch::Sender<RuntimeConfig>, value: RuntimeConfig) {
    let changed = tx.send_if_modified(|current| {
        if *current == value {
            false
        } else {
            *current = value;
            true
        }
    });
    if changed {
        tracing::info!(
            loop_interval_lo = value.loop_interval.lo,
            loop_interval_hi = value.loop_interval.hi,
            active_users = value.active_users,
            "runtime config updated",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_little_endian() {
        let mut value = [0u8; VALUE_SIZE];
        value[..2].copy_from_slice(&5u16.to_le_bytes());
        value[2..4].copy_from_slice(&3u16.to_le_bytes());
        value[4..].copy_from_slice(&70000u32.to_le_bytes());
        assert_eq!(
            decode(&value),
            RuntimeConfig {
                loop_interval: IntervalRange { lo: 3, hi: 5 },
                active_users: 70000,
            }
        );
    }

    #[test]
    fn finds_definition() {
        let types = b"\x00type\0index u8,name str,definition str\0\
                      \x02Domain\0text str\0\
                      \x00Config\0loop_interval_lo u16,loop_interval_hi u16,active_users u32\0";
        assert_eq!(
            find_definition(types, "Config").as_deref(),
            Some(CONFIG_DEFINITION)
        );
        assert_eq!(
            find_definition(types, "Domain").as_deref(),
            Some("text str")
        );
        assert_eq!(find_definition(types, "Missing"), None);
    }

    #[test]
    fn active_users() {
        let config = RuntimeConfig {
            loop_interval: IntervalRange { lo: 1, hi: 1 },
            active_users: 2,
        };
        assert!(config.is_active(1));
        assert!(!config.is_active(2));
    }
}
