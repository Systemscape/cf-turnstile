#![doc = include_str!("../README.md")]
use connector::Connector;
use error::{SiteVerifyErrors, TurnstileError};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Bytes,
    header::{CONTENT_TYPE, USER_AGENT},
    Method, Request,
};
use hyper_util::{client::legacy::Client as HyperClient, rt::TokioExecutor};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

mod connector;
pub mod error;

#[cfg(test)]
mod test;

/// A client for the Cloudflare Turnstile API.
pub struct TurnstileClient {
    secret: SecretString,
    http: HyperClient<Connector, Full<Bytes>>,
}

/// Represents a request to the Turnstile API.
///
/// The `secret` parameter is not part of this struct: it is supplied by the
/// [`TurnstileClient`] the request is sent with.
///
/// <https://developers.cloudflare.com/turnstile/get-started/server-side-validation/#accepted-parameters>
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SiteVerifyRequest {
    /// The response token from the client.
    pub response: String,
    /// The remote IP address of the client providing the response.
    #[serde(rename = "remoteip", skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// The idempotency key for the request.
    #[cfg(feature = "idempotency")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<uuid::Uuid>,
}

/// The body sent to the Turnstile API: the client's secret, plus the caller's request.
///
/// Deliberately private and `Debug`-less so the secret cannot escape through a
/// formatter. Borrows the secret rather than copying it out of the [`SecretString`].
#[derive(Serialize)]
struct SiteVerifyBody<'a> {
    secret: &'a str,
    #[serde(flatten)]
    request: &'a SiteVerifyRequest,
}

/// Represents a successful response from the Turnstile API.
///
/// Deliberately neither [`Serialize`] nor [`Deserialize`]: this type is only ever
/// produced by [`TurnstileClient::siteverify`], which returns it solely when
/// Cloudflare verified the token. Parsing one from arbitrary JSON would yield a
/// value that looks verified without any verification having taken place.
///
/// <https://developers.cloudflare.com/turnstile/get-started/server-side-validation/#api-response-format>
#[derive(Debug, Clone)]
pub struct SiteVerifyResponse {
    /// The timestamp of the request, from the API's `challenge_ts` field.
    pub timestamp: String,
    /// The hostname of the request.
    pub hostname: String,
    /// The action that was invoked by the turnstile.
    pub action: String,
    /// Data provided by the client.
    pub cdata: String,
}

impl From<RawSiteVerifyResponse> for SiteVerifyResponse {
    fn from(raw: RawSiteVerifyResponse) -> Self {
        Self {
            timestamp: raw.timestamp.unwrap_or_default(),
            hostname: raw.hostname.unwrap_or_default(),
            action: raw.action.unwrap_or_default(),
            cdata: raw.cdata.unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawSiteVerifyResponse {
    success: bool,
    #[serde(rename = "challenge_ts")]
    timestamp: Option<String>,
    hostname: Option<String>,
    /// Absent rather than empty on some responses, so treat a missing key as "no errors".
    #[serde(rename = "error-codes", default)]
    error_codes: SiteVerifyErrors,
    action: Option<String>,
    cdata: Option<String>,
}

/// Maximum accepted size of a siteverify response body. The real endpoint returns
/// a few hundred bytes; this only exists to bound what a hostile or broken upstream
/// can make the client buffer.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

const TURNSTILE_USER_AGENT: &str = concat!(
    "cf-turnstile (",
    env!("CARGO_PKG_HOMEPAGE"),
    ", ",
    env!("CARGO_PKG_VERSION"),
    ")",
);

impl TurnstileClient {
    /// Create a new Turnstile client.
    pub fn new(secret: SecretString) -> Self {
        let connector = connector::create();
        let http =
            hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(connector);

        Self { http, secret }
    }

    /// Verify a Cloudflare Turnstile response.
    pub async fn siteverify(
        &self,
        request: SiteVerifyRequest,
    ) -> Result<SiteVerifyResponse, TurnstileError> {
        let body = SiteVerifyBody {
            secret: self.secret.expose_secret(),
            request: &request,
        };

        // The serialized body contains the secret key. Hand `Bytes` a zeroizing owner
        // so the buffer is wiped when the request is done rather than merely freed,
        // which would leave the key readable in a core dump or swapped-out page.
        let body = Zeroizing::new(serde_json::to_vec(&body)?);
        let body = Full::new(Bytes::from_owner(body));

        let request = Request::builder()
            .method(Method::POST)
            .uri("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .header(USER_AGENT, TURNSTILE_USER_AGENT)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .expect("request builder");

        let response = self.http.request(request).await?;

        // Read the status before the body: `Response` itself implements `Body`, so
        // collecting the response rather than its body silently discards the status.
        let status = response.status();
        if !status.is_success() {
            return Err(TurnstileError::UnexpectedStatus(status));
        }

        let body_bytes = match Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            // `Limited` boxes the inner body's error, so anything that is not a
            // transport failure is the length limit being hit.
            Err(err) => {
                return Err(match err.downcast::<hyper::Error>() {
                    Ok(err) => TurnstileError::HyperError(*err),
                    Err(_) => TurnstileError::ResponseTooLarge,
                })
            }
        };

        let body = serde_json::from_slice::<RawSiteVerifyResponse>(&body_bytes)?;

        if !body.error_codes.is_empty() {
            return Err(TurnstileError::SiteVerifyError(body.error_codes));
        }

        // Cloudflare always accompanies `success: false` with an error code, but do
        // not rely on it: a caller using `?` must never be handed an unverified token.
        if !body.success {
            return Err(TurnstileError::VerificationFailed);
        }

        let transformed = SiteVerifyResponse::from(body);

        Ok(transformed)
    }
}

/// Generate a new idempotency key.
#[cfg(feature = "idempotency")]
pub fn generate_idempotency_key() -> Option<uuid::Uuid> {
    Some(uuid::Uuid::new_v4())
}

// Turnstile's API is HTTPS only. Without a TLS backend the client would send the
// secret key over an unencrypted connection, so refuse to build instead.
//
// Enabling *several* backends is not an error: Cargo features are additive, and two
// unrelated crates in one dependency graph may each ask for a different backend. That
// is unresolvable if the combination fails to compile, so `connector::create` picks by
// precedence instead — see its module docs.
#[cfg(not(any(
    feature = "native-tls",
    feature = "rustls-native-roots",
    feature = "rustls-webpki-roots"
)))]
compile_error!(
    r#"A TLS backend is required: enable at least one of "rustls-native-roots" (the default), "rustls-webpki-roots" or "native-tls".
Turnstile's API is HTTPS only, and without TLS the secret key would be sent in cleartext."#
);
