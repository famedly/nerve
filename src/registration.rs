use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha1::Sha1;

/// Registration-specific error that optionally carries the HTTP status code
/// returned by the server.  Callers can inspect [`Self::status`] to decide
/// whether the failure is fatal (e.g. 404 → admin API not available).
#[derive(Debug)]
pub struct RegistrationError {
    pub status: Option<StatusCode>,
    pub message: String,
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(status) = self.status {
            write!(f, "Registration failed ({status}): {}", self.message)
        } else {
            write!(f, "Registration failed: {}", self.message)
        }
    }
}

impl std::error::Error for RegistrationError {}

impl RegistrationError {
    fn from_status(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status: Some(status),
            message: message.into(),
        }
    }

    fn without_status(message: impl Into<String>) -> Self {
        Self {
            status: None,
            message: message.into(),
        }
    }
}

/// Response from `GET /_synapse/admin/v1/register` containing a one-time nonce.
#[derive(Deserialize)]
struct NonceResponse {
    nonce: String,
}

/// Request body for `POST /_synapse/admin/v1/register`.
#[derive(Serialize)]
struct RegisterRequest<'a> {
    nonce: &'a str,
    username: &'a str,
    password: &'a str,
    admin: bool,
    mac: String,
}

/// A Matrix error response body (only the fields we care about).
#[derive(Deserialize)]
struct MatrixError {
    errcode: String,
}

/// Check whether the response has a JSON content-type header.
fn is_json_response(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"))
}

/// Successful response from `POST /_synapse/admin/v1/register`.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct RegisterResponse {
    pub access_token: String,
    pub device_id: String,
    pub home_server: Option<String>,
    pub user_id: String,
}

/// Compute the HMAC-SHA1 that Synapse expects for shared-secret registration.
///
/// The signed message is:
/// `nonce\x00username\x00password\x00<"admin"|"notadmin">`
fn compute_mac(
    shared_secret: &str,
    nonce: &str,
    username: &str,
    password: &str,
    admin: bool,
) -> String {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(shared_secret.as_bytes()).expect("HMAC accepts any key size");

    let flag = if admin { "admin" } else { "notadmin" };
    for p in [nonce, "\0", username, "\0", password, "\0", flag] {
        mac.update(p.as_bytes());
    }

    hex::encode(mac.finalize().into_bytes())
}

/// Register a new account on a Synapse homeserver using the shared registration
/// secret admin API.
///
/// The flow is:
///   1. `GET  /_synapse/admin/v1/register` → obtain a one-time nonce
///   2. `POST /_synapse/admin/v1/register` → send username, password, nonce and
///      the HMAC-SHA1 computed over the shared secret
///
/// If the server responds with `M_USER_IN_USE`, the error is silently ignored.
pub async fn register_with_shared_secret(
    http: &reqwest::Client,
    homeserver: &str,
    shared_secret: &str,
    username: &str,
    password: &str,
) -> Result<(), RegistrationError> {
    let url = format!("{homeserver}/_synapse/admin/v1/register");

    let nonce_http_resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| RegistrationError::without_status(format!("nonce request failed: {e}")))?;

    let nonce_status = nonce_http_resp.status();
    if !nonce_status.is_success() {
        let text = nonce_http_resp.text().await.unwrap_or_default();
        return Err(RegistrationError::from_status(
            nonce_status,
            format!("nonce request: {text}"),
        ));
    }

    let nonce_resp: NonceResponse = nonce_http_resp
        .json()
        .await
        .map_err(|e| RegistrationError::without_status(format!("nonce decode failed: {e}")))?;

    let body = RegisterRequest {
        nonce: &nonce_resp.nonce,
        username,
        password,
        admin: false,
        mac: compute_mac(shared_secret, &nonce_resp.nonce, username, password, false),
    };

    let resp =
        http.post(&url).json(&body).send().await.map_err(|e| {
            RegistrationError::without_status(format!("register request failed: {e}"))
        })?;
    let status = resp.status();

    if status.is_success() {
        let reg: RegisterResponse = resp.json().await.map_err(|e| {
            RegistrationError::without_status(format!("register response decode failed: {e}"))
        })?;

        // Immediately log out the newly created device so it doesn't linger.
        let logout_url = format!("{homeserver}/_matrix/client/v3/logout");
        let logout_result = http
            .post(&logout_url)
            .bearer_auth(&reg.access_token)
            .send()
            .await;
        match logout_result {
            Ok(resp) if !resp.status().is_success() => {
                return Err(RegistrationError::from_status(
                    resp.status(),
                    "post-registration logout failed",
                ));
            }
            Err(e) => {
                return Err(RegistrationError::without_status(format!(
                    "post-registration logout failed: {e}"
                )));
            }
            _ => {}
        }

        return Ok(());
    }

    // If the server returned a JSON error body, check for M_USER_IN_USE.
    if is_json_response(&resp) {
        let err = resp.json::<MatrixError>().await.map_err(|e| {
            RegistrationError::from_status(status, format!("error response decode failed: {e}"))
        })?;
        if err.errcode == "M_USER_IN_USE" {
            return Ok(());
        }

        return Err(RegistrationError::from_status(status, err.errcode));
    }

    let text = resp.text().await.unwrap_or_default();
    Err(RegistrationError::from_status(status, text))
}
