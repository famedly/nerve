use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use clap::Parser;
use hmac::{Hmac, Mac};
use jsonwebtoken::{EncodingKey, Header};
use matrix_sdk::{
    Client, SessionMeta, SessionTokens,
    authentication::matrix::MatrixSession,
    encryption::vodozemac::base64_encode,
    ruma::{OwnedDeviceId, UserId, serde::JsonObject},
    store::RoomLoadSettings,
};
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::registration;

/// How tokens from fuss are used to authenticate against the homeserver.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FussMode {
    /// Synapse with synapse-token-authenticator: log in with the
    /// `com.famedly.login.token.oauth` login type.
    Sta,
    /// the token is the access token.
    Native,
}

#[derive(Parser, Clone)]
pub struct AuthConfig {
    /// Synapse shared registration secret (uses admin API + password login).
    #[arg(long, env = "SHARED_REGISTRATION_SECRET", requires = "password_secret", required = true, conflicts_with_all = ["sta_secret", "sta_seed", "fuss_url"])]
    shared_registration_secret: Option<String>,

    /// Secret from which per-user login passwords are derived.
    #[arg(long, env = "PASSWORD_SECRET", requires = "shared_registration_secret")]
    password_secret: Option<String>,

    /// STA JWT secret (uses com.famedly.login.token login).
    #[arg(long, env = "STA_SECRET", conflicts_with_all = ["shared_registration_secret", "password_secret", "sta_seed", "fuss_url"])]
    sta_secret: Option<String>,

    /// STA seed from which per-server STA secrets are derived.
    /// The STA secret is computed as `SHA-256(seed || hostname)` where
    /// `hostname` is the first DNS label of the server name from the MXID.
    #[arg(long, env = "STA_SEED", conflicts_with_all = ["shared_registration_secret", "password_secret", "sta_secret", "fuss_url"])]
    sta_seed: Option<String>,

    /// Base URL of fuss (Fake User and Session Service). Matrix tokens are
    /// requested from its token API; see `FUSS_MODE` for how they are used.
    #[arg(long, env = "FUSS_URL", conflicts_with_all = ["shared_registration_secret", "password_secret", "sta_secret", "sta_seed"])]
    fuss_url: Option<Url>,

    /// How fuss tokens are used: `sta` logs in to Synapse with
    /// `com.famedly.login.token.oauth`, `native` uses them directly as
    /// access tokens.
    #[arg(long, env = "FUSS_MODE", value_enum, default_value_t = FussMode::Sta)]
    fuss_mode: FussMode,

    /// File containing the Kubernetes service account token (with the
    /// audience fuss expects) that authenticates requests to fuss' token API.
    /// Read again for every login, as projected tokens are rotated.
    #[arg(
        long,
        env = "FUSS_SERVICE_ACCOUNT_TOKEN_FILE",
        default_value = "/var/run/secrets/fuss/token"
    )]
    fuss_service_account_token_file: PathBuf,

    /// Secret from which per-user E2EE recovery passphrases are derived.
    #[arg(long, env = "RECOVERY_SECRET")]
    recovery_secret: String,
}

impl AuthConfig {
    /// Derive a deterministic login password from the shared secret and an MXID.
    pub fn account_password(&self, mxid: &str) -> Option<String> {
        self.password_secret
            .as_ref()
            .map(|secret| derive_secret(secret, mxid))
    }

    /// Derive a deterministic E2EE recovery passphrase from the shared secret
    /// and an MXID.
    pub fn recovery_passphrase(&self, mxid: &str) -> String {
        derive_secret(&self.recovery_secret, mxid)
    }

    /// Resolve the STA secret, either directly from `STA_SECRET` or by
    /// deriving it from `STA_SEED` and the server's hostname.
    ///
    /// `server_name` is the full server name from the MXID (e.g.
    /// `hs1.example.com`); only its first DNS label (`hs1`) is used for
    /// derivation.
    pub fn resolve_sta_secret(&self, server_name: &str) -> Option<String> {
        if let Some(secret) = &self.sta_secret {
            return Some(secret.clone());
        }
        if let Some(seed) = &self.sta_seed {
            let hostname = server_name.split('.').next().unwrap_or(server_name);
            return Some(derive_sta_secret(seed, hostname));
        }
        None
    }

    /// Register (if applicable) and log in to the homeserver.
    #[tracing::instrument(skip_all, fields(mxid, server_name, username))]
    pub async fn login(
        &self,
        client: &Client,
        homeserver_url: &str,
        server_name: &str,
        username: &str,
        mxid: &str,
        initial_device_display_name: &str,
    ) -> anyhow::Result<()> {
        if let Some(shared_registration_secret) = &self.shared_registration_secret {
            let password_secret = self.password_secret.as_ref().unwrap();
            let account_password = derive_secret(password_secret, mxid);

            tracing::info!(
                server_name,
                username,
                "[{mxid}] ▶ Registering on {homeserver_url} …",
            );

            let http = reqwest::Client::new();
            let reg_result = registration::register_with_shared_secret(
                &http,
                homeserver_url,
                shared_registration_secret,
                username,
                &account_password,
            )
            .await;

            match &reg_result {
                Ok(()) => {
                    tracing::info!(
                        server_name,
                        username,
                        server_reachability = true,
                        "[{mxid}] ✔ Registered",
                    );
                }
                Err(e) => {
                    tracing::error!(
                        server_name,
                        username,
                        server_reachability = false,
                        error = %e,
                        "[{mxid}] ✘ Registration failed",
                    );
                }
            }
            reg_result?;

            tracing::info!(
                server_name,
                username,
                "[{mxid}] ▶ Logging in with password …",
            );
            client
                .matrix_auth()
                .login_username(username, &account_password)
                .initial_device_display_name(initial_device_display_name)
                .send()
                .await?;
        } else if let Some(fuss_url) = &self.fuss_url {
            tracing::info!(
                server_name,
                username,
                "[{mxid}] ▶ Requesting token from fuss at {fuss_url} …",
            );

            let token =
                match fetch_fuss_token(fuss_url, &self.fuss_service_account_token_file, username)
                    .await
                {
                    Ok(token) => token,
                    Err(e) => {
                        tracing::error!(
                            server_name,
                            username,
                            error = %format!("{e:#}"),
                            "[{mxid}] ✘ Requesting token from fuss failed",
                        );
                        return Err(e);
                    }
                };

            match self.fuss_mode {
                FussMode::Sta => {
                    tracing::info!(
                        server_name,
                        username,
                        "[{mxid}] ▶ Logging in via STA (fuss token) …",
                    );
                    sta_login(
                        client,
                        "com.famedly.login.token.oauth",
                        token.access_token,
                        server_name,
                        username,
                        mxid,
                        initial_device_display_name,
                    )
                    .await?;
                }
                FussMode::Native => {
                    restore_fuss_session(client, token, server_name, username, mxid).await?;
                }
            }
        } else if let Some(sta_secret) = self.resolve_sta_secret(server_name) {
            tracing::info!(
                server_name,
                username,
                "[{mxid}] ▶ Logging in via STA (JWT) …",
            );

            let exp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600;
            let token = jsonwebtoken::encode(
                &Header::new(jsonwebtoken::Algorithm::HS512),
                &json!({ "sub": username, "exp": exp }),
                &EncodingKey::from_secret(sta_secret.as_bytes()),
            )
            .map_err(|e| anyhow::anyhow!("failed to encode JWT: {e}"))?;

            sta_login(
                client,
                "com.famedly.login.token",
                token,
                server_name,
                username,
                mxid,
                initial_device_display_name,
            )
            .await?;
        } else {
            panic!("violated clap requirements");
        }

        Ok(())
    }
}

/// Log in with a token-based STA login type (`com.famedly.login.token` or
/// `com.famedly.login.token.oauth`). The homeserver generates the device ID.
async fn sta_login(
    client: &Client,
    login_type: &str,
    token: String,
    server_name: &str,
    username: &str,
    mxid: &str,
    initial_device_display_name: &str,
) -> anyhow::Result<()> {
    let mut data = JsonObject::new();
    data.insert(
        "identifier".to_owned(),
        json!({ "type": "m.id.user", "user": username }),
    );
    data.insert("token".to_owned(), serde_json::Value::String(token));

    let builder = client
        .matrix_auth()
        .login_custom(login_type, data)?
        .initial_device_display_name(initial_device_display_name);

    let login_result = builder.send().await;

    match &login_result {
        Ok(_) => {
            tracing::info!(
                server_name,
                username,
                server_reachability = true,
                "[{mxid}] ✔ STA login succeeded",
            );
        }
        Err(e) => {
            tracing::error!(
                server_name,
                username,
                server_reachability = false,
                error = %e,
                "[{mxid}] ✘ STA login failed",
            );
        }
    }
    login_result?;

    Ok(())
}

/// Use a fuss token directly as access token (native). There is no login:
/// the device is the one of the user's single fuss OIDC session.
async fn restore_fuss_session(
    client: &Client,
    token: FussTokenResponse,
    server_name: &str,
    username: &str,
    mxid: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        server_name,
        username,
        device_id = token.device_id,
        "[{mxid}] ▶ Using fuss token as access token for device {} …",
        token.device_id,
    );

    let user_id = <&UserId>::try_from(mxid)
        .with_context(|| format!("invalid MXID {mxid:?}"))?
        .to_owned();
    let device_id = OwnedDeviceId::from(token.device_id.as_str());

    client
        .matrix_auth()
        .restore_session(
            MatrixSession {
                meta: SessionMeta {
                    user_id: user_id.clone(),
                    device_id: device_id.clone(),
                },
                tokens: SessionTokens {
                    access_token: token.access_token,
                    refresh_token: None,
                },
            },
            RoomLoadSettings::default(),
        )
        .await?;

    // Restoring a session makes no request, so check the token right away.
    let whoami_result = client
        .whoami()
        .await
        .map_err(anyhow::Error::from)
        .and_then(|whoami| {
            if whoami.user_id != user_id {
                anyhow::bail!(
                    "token belongs to {}, not {user_id}; does the fuss user ID match the localpart?",
                    whoami.user_id
                );
            }
            if whoami.device_id.as_ref().is_some_and(|id| *id != device_id) {
                tracing::warn!(
                    "[{mxid}] Homeserver reports device {:?}, fuss reported {device_id}",
                    whoami.device_id,
                );
            }
            Ok(())
        });

    match &whoami_result {
        Ok(()) => {
            tracing::info!(
                server_name,
                username,
                server_reachability = true,
                "[{mxid}] ✔ fuss token accepted by homeserver",
            );
        }
        Err(e) => {
            tracing::error!(
                server_name,
                username,
                server_reachability = false,
                error = %format!("{e:#}"),
                "[{mxid}] ✘ fuss token rejected by homeserver",
            );
        }
    }
    whoami_result
}

// ── fuss ────────────────────────────────────────────────────────────────

/// Successful response of fuss' `POST /v1/users/{user}/token` (only the
/// fields we care about).
#[derive(Deserialize)]
struct FussTokenResponse {
    access_token: String,
    device_id: String,
}

/// Error response of the fuss API.
#[derive(Deserialize)]
struct FussError {
    error: String,
    message: String,
}

/// Request a Matrix token for `username` (the SCIM user ID in fuss, which
/// equals the localpart) from fuss' token API, authenticated with the
/// Kubernetes service account token in `service_account_token_file`.
async fn fetch_fuss_token(
    fuss_url: &Url,
    service_account_token_file: &Path,
    username: &str,
) -> anyhow::Result<FussTokenResponse> {
    let service_account_token =
        std::fs::read_to_string(service_account_token_file).with_context(|| {
            format!(
                "failed to read service account token from {}",
                service_account_token_file.display()
            )
        })?;

    let mut url = fuss_url.clone();
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("FUSS_URL {fuss_url} cannot be a base URL"))?
        .pop_if_empty()
        .extend(["v1", "users", username, "token"]);

    let resp = reqwest::Client::new()
        .post(url.clone())
        .bearer_auth(service_account_token.trim())
        .send()
        .await
        .with_context(|| format!("fuss token request to {url} failed"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let detail = match serde_json::from_str::<FussError>(&body) {
            Ok(err) => format!("{}: {}", err.error, err.message),
            Err(_) => body,
        };
        anyhow::bail!("fuss token request to {url} failed ({status}): {detail}");
    }

    resp.json()
        .await
        .context("failed to decode fuss token response")
}

// ── Small helpers ───────────────────────────────────────────────────────

/// Derive a deterministic secret string from a shared secret and an MXID.
///
/// Returns `HMAC-SHA1(shared_secret, mxid)` encoded as base64.
pub fn derive_secret(shared_secret: &str, mxid: &str) -> String {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(shared_secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(mxid.as_bytes());
    base64_encode(mac.finalize().into_bytes())
}

/// Derive a per-server STA secret from a seed and a hostname.
///
/// Returns `SHA-256(seed || hostname)` encoded as lower-case hex.
fn derive_sta_secret(seed: &str, hostname: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(hostname.as_bytes());
    let result = hasher.finalize();

    format!("{:x}", result)
}
