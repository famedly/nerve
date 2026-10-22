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
    authentication::{
        matrix::MatrixSession,
        oauth::{ClientId, OAuthSession, UserSession},
    },
    encryption::vodozemac::base64_encode,
    ruma::{OwnedDeviceId, UserId, serde::JsonObject},
    store::RoomLoadSettings,
};
use rand::Rng;
use reqwest::{StatusCode, Url};
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
    /// The homeserver delegates authentication to an OAuth 2.0 authorization
    /// server that brokers fuss as its upstream IdP: the fuss token is
    /// exchanged there for a session of its own, with a fresh device.
    Broker,
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
    /// access tokens, `broker` exchanges them for a session at the
    /// homeserver's OAuth 2.0 authorization server, whose upstream IdP is
    /// fuss.
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
    /// Optional with fuss: if unset, the `security_phrase` suggested by fuss'
    /// token API is used instead.
    #[arg(long, env = "RECOVERY_SECRET", required_unless_present = "fuss_url")]
    recovery_secret: Option<String>,
}

impl AuthConfig {
    /// Derive a deterministic login password from the shared secret and an MXID.
    pub fn account_password(&self, mxid: &str) -> Option<String> {
        self.password_secret
            .as_ref()
            .map(|secret| derive_secret(secret, mxid))
    }

    /// Derive a deterministic E2EE recovery passphrase from the shared secret
    /// and an MXID. `None` if `RECOVERY_SECRET` is unset (fuss only).
    pub fn recovery_passphrase(&self, mxid: &str) -> Option<String> {
        self.recovery_secret
            .as_ref()
            .map(|secret| derive_secret(secret, mxid))
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

    /// Whether sessions come with refresh tokens, so the client has to be
    /// built with `ClientBuilder::handle_refresh_tokens()`.
    pub fn refreshes_tokens(&self) -> bool {
        self.fuss_url.is_some() && self.fuss_mode == FussMode::Broker
    }

    /// End the session: revoke it at the OAuth 2.0 authorization server if it
    /// is one of its sessions, log out through the Matrix API otherwise.
    pub async fn logout(&self, client: &Client) -> anyhow::Result<()> {
        match client.oauth().full_session() {
            Some(session) => revoke_oauth_session(client, session).await,
            None => {
                client.matrix_auth().logout().await?;
                Ok(())
            }
        }
    }

    /// Register (if applicable) and log in to the homeserver.
    ///
    /// Returns the user's E2EE recovery passphrase: derived from
    /// `RECOVERY_SECRET` if set, otherwise the `security_phrase` from fuss.
    #[tracing::instrument(skip_all, fields(mxid, server_name, username))]
    pub async fn login(
        &self,
        client: &Client,
        homeserver_url: &str,
        server_name: &str,
        username: &str,
        mxid: &str,
        initial_device_display_name: &str,
    ) -> anyhow::Result<String> {
        let mut recovery_passphrase = self.recovery_passphrase(mxid);

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

            let mut token =
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

            // Checked before logging in, so no device is created in vain.
            if recovery_passphrase.is_none() {
                let security_phrase = token
                    .security_phrase
                    .take()
                    .context("RECOVERY_SECRET is unset and fuss returned no security_phrase")?;
                tracing::info!(
                    server_name,
                    username,
                    "[{mxid}] Using the security phrase from fuss for E2EE recovery",
                );
                recovery_passphrase = Some(security_phrase);
            }

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
                FussMode::Broker => {
                    let result = broker_login(
                        client,
                        homeserver_url,
                        token.access_token,
                        server_name,
                        username,
                        mxid,
                    )
                    .await;
                    match &result {
                        Ok(()) => tracing::info!(
                            server_name,
                            username,
                            server_reachability = true,
                            "[{mxid}] ✔ Brokered login succeeded",
                        ),
                        Err(e) => tracing::error!(
                            server_name,
                            username,
                            server_reachability = false,
                            error = %format!("{e:#}"),
                            "[{mxid}] ✘ Brokered login failed",
                        ),
                    }
                    result?;
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

        Ok(recovery_passphrase.expect("clap requires RECOVERY_SECRET unless FUSS_URL is set"))
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

// ── Brokered OAuth 2.0 login ────────────────────────────────────────────

/// The OAuth 2.0 client ID nerve presents to the authorization server. The
/// authorization server is expected to accept it without registration.
const BROKER_CLIENT_ID: &str = "nerve";

/// The redirect URI of the authorization request. Never visited: the
/// authorization code is returned by the upstream login callback directly.
const BROKER_REDIRECT_URI: &str = "http://localhost/";

/// How long to wait for the homeserver to learn about a new session.
const BROKER_SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Response of the authorization server's upstream login callback.
#[derive(Deserialize)]
struct BrokerLoginResponse {
    code: String,
}

/// Successful response of the token endpoint (only the fields we care about).
#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
}

/// Log in at an OAuth 2.0 authorization server that brokers fuss as its
/// upstream IdP, as its login page would after fuss redirected back to it:
///
/// 1. Discover the authorization server through the homeserver's
///    `auth_metadata`.
/// 2. `POST <issuer>/login` with the fuss token as `id_token` and the
///    authorization request (with a PKCE challenge and a fresh device ID in
///    its scope) as `state`. The authorization server checks the token
///    against fuss' keys, creates a session, and returns an authorization
///    code.
/// 3. Exchange the code at the token endpoint (authorization code grant).
/// 4. Wait until the homeserver knows the new session, then use it.
///
/// Every login creates a new device, as device IDs must not be reused.
async fn broker_login(
    client: &Client,
    homeserver_url: &str,
    fuss_token: String,
    server_name: &str,
    username: &str,
    mxid: &str,
) -> anyhow::Result<()> {
    let user_id = <&UserId>::try_from(mxid)
        .with_context(|| format!("invalid MXID {mxid:?}"))?
        .to_owned();

    let metadata = client
        .oauth()
        .server_metadata()
        .await
        .context("failed to discover the homeserver's OAuth 2.0 authorization server")?;

    let device_id = OwnedDeviceId::from(format!("NERVE{}", random_uppercase_alphanumeric(10)));
    let scope = format!("openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}");
    let verifier = base64url_encode(rand::rng().random::<[u8; 32]>());
    let challenge = base64url_encode(Sha256::digest(verifier.as_bytes()));
    let authorization_request = json!({
        "response_type": "code",
        "client_id": BROKER_CLIENT_ID,
        "redirect_uri": BROKER_REDIRECT_URI,
        "scope": scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    });
    let state = base64url_encode(authorization_request.to_string());

    tracing::info!(
        server_name,
        username,
        device_id = device_id.as_str(),
        "[{mxid}] ▶ Exchanging fuss token at {} for device {device_id} …",
        metadata.issuer,
    );

    let http = reqwest::Client::new();

    let login_url = metadata
        .issuer
        .join("login")
        .with_context(|| format!("invalid issuer {}", metadata.issuer))?;
    let resp = http
        .post(login_url.clone())
        .form(&[
            ("id_token", fuss_token.as_str()),
            // Only meaningful for real upstream IdPs.
            ("access_token", "unused"),
            ("state", state.as_str()),
        ])
        .send()
        .await
        .with_context(|| format!("login request to {login_url} failed"))?;
    let BrokerLoginResponse { code } = json_response(resp, &login_url).await?;

    let token_url = metadata.token_endpoint.clone();
    let resp = http
        .post(token_url.clone())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", BROKER_REDIRECT_URI),
            ("client_id", BROKER_CLIENT_ID),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .with_context(|| format!("token request to {token_url} failed"))?;
    let tokens: OAuthTokenResponse = json_response(resp, &token_url).await?;

    wait_for_session(homeserver_url, &tokens.access_token, mxid).await?;

    client
        .oauth()
        .restore_session(
            OAuthSession {
                client_id: ClientId::new(BROKER_CLIENT_ID.to_owned()),
                user: UserSession {
                    meta: SessionMeta { user_id, device_id },
                    tokens: SessionTokens {
                        access_token: tokens.access_token,
                        refresh_token: tokens.refresh_token,
                    },
                },
            },
            RoomLoadSettings::default(),
        )
        .await?;

    Ok(())
}

/// Wait until the homeserver accepts a new access token. The homeserver learns
/// about sessions from the authorization server asynchronously, so it rejects
/// the token as unknown until then.
async fn wait_for_session(
    homeserver_url: &str,
    access_token: &str,
    mxid: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/_matrix/client/v3/account/whoami",
        homeserver_url.trim_end_matches('/')
    );
    let deadline = tokio::time::Instant::now() + BROKER_SESSION_TIMEOUT;
    let http = reqwest::Client::new();
    loop {
        let resp = http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .with_context(|| format!("whoami request to {url} failed"))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        if status != StatusCode::UNAUTHORIZED || tokio::time::Instant::now() >= deadline {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("homeserver did not accept the new session ({status}): {body}");
        }
        tracing::debug!("[{mxid}] Session not known to the homeserver yet, waiting …");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Revoke an OAuth 2.0 session (RFC 7009). The refresh token is revoked if
/// there is one, which ends the whole session.
async fn revoke_oauth_session(client: &Client, session: OAuthSession) -> anyhow::Result<()> {
    let metadata = client.oauth().server_metadata().await?;
    let tokens = session.user.tokens;
    let (token, hint) = match tokens.refresh_token {
        Some(refresh_token) => (refresh_token, "refresh_token"),
        None => (tokens.access_token, "access_token"),
    };
    let url = metadata.revocation_endpoint;
    let resp = reqwest::Client::new()
        .post(url.clone())
        .form(&[
            ("token", token.as_str()),
            ("token_type_hint", hint),
            ("client_id", session.client_id.as_str()),
        ])
        .send()
        .await
        .with_context(|| format!("revocation request to {url} failed"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("revocation request to {url} failed ({status}): {body}");
    }
    Ok(())
}

/// Decode a successful JSON response, or fail with its status and body.
async fn json_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    url: &Url,
) -> anyhow::Result<T> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("request to {url} failed ({status}): {body}");
    }
    resp.json()
        .await
        .with_context(|| format!("failed to decode response of {url}"))
}

// ── fuss ────────────────────────────────────────────────────────────────

/// Successful response of fuss' `POST /v1/users/{user}/token` (only the
/// fields we care about).
#[derive(Deserialize)]
struct FussTokenResponse {
    access_token: String,
    device_id: String,
    /// Suggested E2EE recovery passphrase for the user. Used if
    /// `RECOVERY_SECRET` is unset.
    security_phrase: Option<String>,
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

/// Unpadded base64url, as OAuth 2.0 (PKCE) uses it.
fn base64url_encode(input: impl AsRef<[u8]>) -> String {
    base64_encode(input)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// A random string of `len` characters from `A-Z0-9`, e.g. for device IDs.
fn random_uppercase_alphanumeric(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect()
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
