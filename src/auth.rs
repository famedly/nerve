use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use hmac::{Hmac, Mac};
use jsonwebtoken::{EncodingKey, Header};
use matrix_sdk::{
    Client,
    encryption::vodozemac::base64_encode,
    ruma::{
        api::client::{account::register, error::ErrorKind, uiaa},
        serde::JsonObject,
    },
};
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::registration;

#[derive(Parser, Clone)]
pub struct AuthConfig {
    /// Synapse shared registration secret (uses admin API + password login).
    #[arg(long, env = "SHARED_REGISTRATION_SECRET", requires = "password_secret", required = true, conflicts_with_all = ["sta_secret", "sta_seed", "open_registration"])]
    shared_registration_secret: Option<String>,

    /// Secret from which per-user login passwords are derived.
    #[arg(long, env = "PASSWORD_SECRET")]
    password_secret: Option<String>,

    /// STA JWT secret (uses com.famedly.login.token login).
    #[arg(long, env = "STA_SECRET", conflicts_with_all = ["shared_registration_secret", "password_secret", "sta_seed", "open_registration"])]
    sta_secret: Option<String>,

    /// STA seed from which per-server STA secrets are derived.
    /// The STA secret is computed as `SHA-256(seed || hostname)` where
    /// `hostname` is the first DNS label of the server name from the MXID.
    #[arg(long, env = "STA_SEED", conflicts_with_all = ["shared_registration_secret", "password_secret", "sta_secret", "open_registration"])]
    sta_seed: Option<String>,

    /// Register via the standard Matrix `/register` endpoint without any
    /// additional authorization (requires open registration on the
    /// homeserver). If the account already exists, falls back to a password
    /// login.
    #[arg(long, env = "OPEN_REGISTRATION", requires = "password_secret", conflicts_with_all = ["shared_registration_secret", "sta_secret", "sta_seed"])]
    open_registration: bool,

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
        } else if self.open_registration {
            let password_secret = self.password_secret.as_ref().unwrap();
            let account_password = derive_secret(password_secret, mxid);

            tracing::info!(
                server_name,
                username,
                "[{mxid}] ▶ Registering on {homeserver_url} (open registration) …",
            );

            let auth = client.matrix_auth();

            let mut request = register::v3::Request::new();
            request.username = Some(username.to_owned());
            request.password = Some(account_password.clone());
            request.initial_device_display_name = Some(initial_device_display_name.to_owned());

            let mut reg_result = auth.register(request.clone()).await;

            // Complete UIAA with the dummy stage if the server asks for it.
            if let Err(e) = &reg_result {
                if let Some(uiaa_info) = e.as_uiaa_response() {
                    let mut dummy = uiaa::Dummy::new();
                    dummy.session = uiaa_info.session.clone();
                    request.auth = Some(uiaa::AuthData::Dummy(dummy));
                    reg_result = auth.register(request).await;
                }
            }

            match reg_result {
                Ok(_) => {
                    tracing::info!(
                        server_name,
                        username,
                        server_reachability = true,
                        "[{mxid}] ✔ Registered",
                    );
                }
                // The account already exists – fine, just log in below.
                Err(e) if matches!(e.client_api_error_kind(), Some(ErrorKind::UserInUse)) => {
                    tracing::info!(
                        server_name,
                        username,
                        server_reachability = true,
                        "[{mxid}] ✔ Already registered",
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
                    return Err(e.into());
                }
            }

            // A successful registration already stored the session from the
            // returned access token; a password login is only needed when the
            // account existed before.
            if !auth.logged_in() {
                tracing::info!(
                    server_name,
                    username,
                    "[{mxid}] ▶ Logging in with password …",
                );
                auth.login_username(username, &account_password)
                    .initial_device_display_name(initial_device_display_name)
                    .send()
                    .await?;
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

            let mut data = JsonObject::new();
            data.insert(
                "identifier".to_owned(),
                json!({ "type": "m.id.user", "user": username }),
            );
            data.insert("token".to_owned(), serde_json::Value::String(token));

            let builder = client
                .matrix_auth()
                .login_custom("com.famedly.login.token", data)?
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
        } else {
            panic!("violated clap requirements");
        }

        Ok(())
    }
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
