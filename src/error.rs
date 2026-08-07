//! Error types for the Turnstile API.
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Represents a list of errors from the Turnstile API.
#[derive(Debug, Error)]
pub enum TurnstileError {
    /// The error originated from the Turnstile API.
    #[error("Turnstile API error: {0:?}")]
    SiteVerifyError(SiteVerifyErrors),

    /// The Turnstile API responded with a non-success HTTP status.
    #[error("Turnstile API returned HTTP status {0}")]
    UnexpectedStatus(hyper::StatusCode),

    /// The Turnstile API rejected the token but returned no error code.
    #[error("Turnstile rejected the token without returning an error code")]
    VerificationFailed,

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
