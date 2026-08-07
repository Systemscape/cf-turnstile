//! Error types for the Turnstile API.
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error returned by [`TurnstileClient::siteverify`](crate::TurnstileClient::siteverify).
///
/// The variants separate the three failure classes a caller handles differently:
/// [`TokenRejected`](Self::TokenRejected) means deny the visitor,
/// [`InvalidRequest`](Self::InvalidRequest) means fix this integration, and
/// everything else means the outcome is unknown.
#[derive(Debug, Error)]
pub enum TurnstileError {
    /// The visitor's token failed verification. Deny the request.
    #[error("token rejected: {0}")]
    TokenRejected(#[from] TokenRejection),

    /// The verification request itself was invalid, e.g. a missing or invalid
    /// secret key. This integration is misconfigured; retrying cannot help.
    #[error("invalid siteverify request: {0:?}")]
    InvalidRequest(SiteVerifyErrors),

    /// The Turnstile API failed internally. The request can be retried, with the
    /// same idempotency key (if enabled).
    #[error("Turnstile internal error: {0:?}")]
    InternalApiError(SiteVerifyErrors),

    /// A non-success HTTP status arrived without a usable Turnstile payload.
    ///
    /// This usually means something other than the Turnstile API answered: a
    /// Cloudflare incident page, or a proxy or WAF on the network path. A 5xx is
    /// worth retrying (with the same idempotency key); a 4xx points at the network
    /// path, since the API's own rejections carry error codes and are reported as
    /// [`InvalidRequest`](Self::InvalidRequest) or
    /// [`TokenRejected`](Self::TokenRejected) instead.
    #[error("Turnstile API returned HTTP status {0}")]
    UnexpectedStatus(hyper::StatusCode),

    /// The response body exceeded the maximum size the client will buffer.
    #[error(
        "Turnstile API response body exceeded {} bytes",
        crate::MAX_RESPONSE_BYTES
    )]
    ResponseTooLarge,

    /// The error originated from Legacy Hyper.
    #[error("Legacy hyper error: {0:?}")]
    LegacyHyperError(#[from] hyper_util::client::legacy::Error),

    /// The error originated from Hyper.
    #[error("Hyper error: {0:?}")]
    HyperError(#[from] hyper::Error),

    /// The error originated from Serde.
    #[error("Serde error: {0:?}")]
    SerdeError(#[from] serde_json::Error),
}

impl From<SiteVerifyErrors> for TurnstileError {
    /// Classify the API's error codes by fault.
    ///
    /// A caller-fault code wins over everything, since a misconfigured integration
    /// invalidates any other signal. Codes unknown to this crate count as
    /// rejections, failing closed.
    fn from(codes: SiteVerifyErrors) -> Self {
        let caller_fault = |code: &SiteVerifyError| {
            matches!(
                code,
                SiteVerifyError::MissingInputSecret
                    | SiteVerifyError::InvalidInputSecret
                    | SiteVerifyError::BadRequest
            )
        };

        if codes.iter().any(caller_fault) {
            Self::InvalidRequest(codes)
        } else if codes
            .iter()
            .all(|code| matches!(code, SiteVerifyError::InternalError))
        {
            Self::InternalApiError(codes)
        } else {
            Self::TokenRejected(TokenRejection::ErrorCodes(codes))
        }
    }
}

/// Why a token failed verification.
#[derive(Debug, Clone, Error)]
pub enum TokenRejection {
    /// The API rejected the token with these codes.
    #[error("{0:?}")]
    ErrorCodes(SiteVerifyErrors),

    /// The token was issued for a hostname not in `valid_hostnames`.
    #[error("token was issued for hostname {0:?}")]
    HostnameMismatch(String),

    /// The API reported failure without naming an error code.
    #[error("the API reported failure without naming an error code")]
    Unverified,
}

/// Represents a list of errors from the Turnstile API.
pub type SiteVerifyErrors = Vec<SiteVerifyError>;

/// Represents an error from the Turnstile API.
///
/// <https://developers.cloudflare.com/turnstile/get-started/server-side-validation/#error-codes-reference>
#[derive(Debug, Clone, Error, Deserialize, Serialize)]
pub enum SiteVerifyError {
    /// The secret parameter was not passed.
    #[serde(rename = "missing-input-secret")]
    #[error("The secret parameter was not passed.")]
    MissingInputSecret,

    /// The secret parameter was invalid or did not exist.
    #[serde(rename = "invalid-input-secret")]
    #[error("The secret parameter was invalid or did not exist.")]
    InvalidInputSecret,

    /// The response parameter was not passed.
    #[serde(rename = "missing-input-response")]
    #[error("The response parameter was not passed.")]
    MissingInputResponse,

    /// The response parameter is invalid or has expired.
    #[serde(rename = "invalid-input-response")]
    #[error("The response parameter is invalid or has expired.")]
    InvalidInputResponse,

    /// The request was rejected because it was malformed.
    #[serde(rename = "bad-request")]
    #[error("The request was rejected because it was malformed.")]
    BadRequest,

    /// The response parameter has already been validated before.
    #[serde(rename = "timeout-or-duplicate")]
    #[error("The response parameter has already been validated before.")]
    TimeoutOrDuplicate,

    /// An internal error happened while validating the response. The request can be retried.
    #[serde(rename = "internal-error")]
    #[error(
        "An internal error happened while validating the response. The request can be retried."
    )]
    InternalError,

    /// An error code not known to this version of the crate.
    ///
    /// Without this catch-all a single unrecognised code would fail the whole
    /// response, costing the caller every other code in the array.
    #[serde(other)]
    #[error("The Turnstile API returned an error code unknown to this version of the crate.")]
    Unknown,
}
