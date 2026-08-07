#![doc = include_str!("../README.md")]
use connector::Connector;
use error::{SiteVerifyErrors, TokenRejection, TurnstileError};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request,
    body::Bytes,
    header::{CONTENT_TYPE, USER_AGENT},
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
    #[must_use]
    pub fn new(secret: SecretString) -> Self {
        let connector = connector::create();
        let http =
            hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(connector);

        Self { secret, http }
    }

    /// Verify a Cloudflare Turnstile response.
    ///
    /// `valid_hostnames` is an optional list of hostnames to verify against. The function
    /// will error if the hostname returned by the Turnstile API does not match any of the
    /// provided hostnames.
    /// When it is None, the hostname is not verified.
    ///
    /// # Timeouts
    ///
    /// No timeout is applied, and hyper's client has none of its own, so a stalled
    /// connection waits indefinitely. In a request handler that pins a task and a
    /// connection until the process runs out of both. The latency budget belongs to
    /// the caller, so bound it at the call site:
    ///
    /// ```no_run
    /// # use cf_turnstile::{SiteVerifyRequest, SiteVerifyResponse, TurnstileClient};
    /// # use cf_turnstile::error::TurnstileError;
    /// # async fn verify(
    /// #     client: &TurnstileClient,
    /// #     request: SiteVerifyRequest,
    /// # ) -> Option<Result<SiteVerifyResponse, TurnstileError>> {
    /// use std::time::Duration;
    ///
    /// tokio::time::timeout(
    ///     Duration::from_secs(5),
    ///     client.siteverify(request, Some(&["example.com"]))
    /// ).await.ok()
    /// # }
    /// ```
    ///
    /// This bounds the whole operation: connect, TLS handshake, response and body read.
    ///
    /// # Cancellation
    ///
    /// Dropping the returned future is safe, but it does not un-send the request. If
    /// that already reached Cloudflare the token is spent, since each token may only
    /// be validated once, so retrying with the same token returns
    /// [`SiteVerifyError::TimeoutOrDuplicate`]. To retry safely, enable the
    /// `idempotency` feature and send the same `idempotency_key` on every attempt,
    /// generated once before the first call.
    ///
    /// [`SiteVerifyError::TimeoutOrDuplicate`]: error::SiteVerifyError::TimeoutOrDuplicate
    ///
    /// # Errors
    ///
    /// The variants split by fault: [`TokenRejected`](error::TurnstileError::TokenRejected) means the visitor failed
    /// verification, [`InvalidRequest`](error::TurnstileError::InvalidRequest) means this integration is misconfigured
    /// (e.g. a bad secret) and retrying cannot help, and everything else means the
    /// outcome is unknown. Most callers only need to tell the first apart from the
    /// rest:
    ///
    /// ```no_run
    /// # use cf_turnstile::{SiteVerifyRequest, TurnstileClient};
    /// # use cf_turnstile::error::TurnstileError;
    /// # async fn handle(client: &TurnstileClient, token: String) -> bool {
    /// match client
    ///     .siteverify(
    ///         SiteVerifyRequest { response: token, ..Default::default() },
    ///         Some(&["example.com"]),
    ///     )
    ///     .await
    /// {
    ///     Ok(_response) => true,
    ///     Err(TurnstileError::TokenRejected(_reason)) => false,
    ///     Err(err) => {
    ///         // Misconfiguration, Cloudflare trouble or a transport failure:
    ///         // log it and apply your fail-open/fail-closed policy.
    ///         eprintln!("could not verify: {err}");
    ///         false
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// # Panics
    /// When the http Request Builder returns an error, which should never happen and is covered by tests.
    pub async fn siteverify(
        &self,
        request: SiteVerifyRequest,
        valid_hostnames: Option<&[&str]>,
    ) -> Result<SiteVerifyResponse, TurnstileError> {
        let body = SiteVerifyBody {
            secret: self.secret.expose_secret(),
            request: &request,
        };

        // The serialized body contains the secret key. Hand `Bytes` a zeroizing owner
        // so the buffer is wiped when the request is done rather than merely freed,
        // which is best practice, but only works on a best-effort level, not a 100% guarantee.
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

        // Keep the status but do not act on it yet. Cloudflare answers an invalid
        // secret or a malformed body with HTTP 400 *and* the actionable `error-codes`
        // payload, so the body is the better diagnostic whenever it parses.
        //
        // Note `Response` itself implements `Body`, so collecting the response rather
        // than its body would silently discard the status.
        let status = response.status();

        let body_bytes = match Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            // `Limited` boxes the inner body's error, so anything that is not a
            // transport failure is the length limit being hit.
            Err(err) => {
                return Err(err.downcast::<hyper::Error>().map_or_else(
                    |_| TurnstileError::ResponseTooLarge,
                    |err| TurnstileError::HyperError(*err),
                ));
            }
        };

        let body = match serde_json::from_slice::<RawSiteVerifyResponse>(&body_bytes) {
            Ok(body) => body,
            // Nothing usable in the body, so fall back to reporting the status.
            Err(err) if status.is_success() => return Err(TurnstileError::SerdeError(err)),
            Err(_) => return Err(TurnstileError::UnexpectedStatus(status)),
        };

        if !body.error_codes.is_empty() {
            return Err(body.error_codes.into());
        }

        // A parseable body carrying no error codes is still not a verification if the
        // transport disagrees: an intermediary can answer 4xx or 5xx with a
        // success-shaped payload.
        if !status.is_success() {
            return Err(TurnstileError::UnexpectedStatus(status));
        }

        // Cloudflare always accompanies `success: false` with an error code, but do
        // not rely on it: a caller using `?` must never be handed an unverified token.
        if !body.success {
            return Err(TokenRejection::Unverified.into());
        }

        if let Some(valid_hostnames) = valid_hostnames
            && let Some(ref body_hostname) = body.hostname
            && !valid_hostnames.contains(&body_hostname.as_str())
        {
            return Err(TokenRejection::HostnameMismatch(body_hostname.clone()).into());
        }

        let transformed = SiteVerifyResponse::from(body);

        Ok(transformed)
    }
}

/// Generate a new idempotency key.
///
/// Call this once per token, before the first attempt, and reuse the value if you
/// retry. Generating a fresh key per attempt makes each one a separate validation,
/// which fails once the token is spent.
#[cfg(feature = "idempotency")]
#[must_use]
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
