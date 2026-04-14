use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;

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
) -> anyhow::Result<()> {
    let url = format!("{homeserver}/_synapse/admin/v1/register");
    let nonce_resp: NonceResponse = http.get(&url).send().await?.json().await?;

    let body = RegisterRequest {
        nonce: &nonce_resp.nonce,
        username,
        password,
        admin: false,
        mac: compute_mac(shared_secret, &nonce_resp.nonce, username, password, false),
    };

    let resp = http.post(&url).json(&body).send().await?;
    let status = resp.status();

    if status.is_success() {
        let reg: RegisterResponse = resp.json().await?;

        // Immediately log out the newly created device so it doesn't linger.
        let logout_url = format!("{homeserver}/_matrix/client/v3/logout");
        http.post(&logout_url)
            .bearer_auth(&reg.access_token)
            .send()
            .await?
            .error_for_status()?;

        return Ok(());
    }

    // If the server returned a JSON error body, check for M_USER_IN_USE.
    if is_json_response(&resp) {
        let err = resp.json::<MatrixError>().await?;
        if err.errcode == "M_USER_IN_USE" {
            return Ok(());
        }

        anyhow::bail!("Registration failed ({status}): {}", err.errcode);
    }

    let text = resp.text().await.unwrap_or_default();
    anyhow::bail!("Registration failed ({status}): {text}");
}
