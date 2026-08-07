//! <https://developers.cloudflare.com/turnstile/reference/testing/>
use crate::{
    RawSiteVerifyResponse, SiteVerifyBody, SiteVerifyRequest,
    error::{SiteVerifyError, TokenRejection, TurnstileError},
};

#[cfg(any(feature = "network-tests", feature = "integration"))]
use crate::TurnstileClient;

#[cfg(any(feature = "network-tests", feature = "integration"))]
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

/// The wire format must match Turnstile's accepted parameters, and optional
/// parameters must be omitted rather than sent as `null`.
#[test]
fn test_request_serialization() {
    let request = SiteVerifyRequest {
        response: "myresponse".to_string(),
        remote_ip: Some("1.2.3.4".to_string()),
        #[cfg(feature = "idempotency")]
        idempotency_key: None,
    };

    let json: serde_json::Value = serde_json::to_value(SiteVerifyBody {
        secret: "my-secret",
        request: &request,
    })
    .unwrap();

    assert_eq!(json["secret"], "my-secret");
    assert_eq!(json["response"], "myresponse");
    // Cloudflare's parameter is `remoteip`; `remote_ip` is silently ignored.
    assert_eq!(json["remoteip"], "1.2.3.4");
    assert!(json.get("remote_ip").is_none());

    let minimal = SiteVerifyRequest {
        response: "myresponse".to_string(),
        ..Default::default()
    };

    assert_eq!(
        serde_json::to_string(&SiteVerifyBody {
            secret: "my-secret",
            request: &minimal,
        })
        .unwrap(),
        r#"{"secret":"my-secret","response":"myresponse"}"#
    );
}

/// A code Cloudflare adds later must not cost us the rest of the response, and a
/// missing `error-codes` key must mean "no errors" rather than a parse failure.
#[test]
fn test_unknown_error_code() {
    let raw: RawSiteVerifyResponse = serde_json::from_str(
        r#"{"success":false,"error-codes":["invalid-input-response","brand-new-code"]}"#,
    )
    .unwrap();

    assert!(matches!(
        raw.error_codes.as_slice(),
        [
            SiteVerifyError::InvalidInputResponse,
            SiteVerifyError::Unknown
        ]
    ));

    let raw: RawSiteVerifyResponse =
        serde_json::from_str(r#"{"success":true,"hostname":"example.com"}"#).unwrap();

    assert!(raw.error_codes.is_empty());
}

/// Error codes must classify by fault: caller-fault codes win over everything,
/// internal errors are retryable, the rest (including unknown codes) reject the token.
#[test]
fn test_error_code_classification() {
    use SiteVerifyError as Code;

    let classify = |codes: Vec<Code>| TurnstileError::from(codes);

    assert!(matches!(
        classify(vec![Code::InvalidInputSecret]),
        TurnstileError::InvalidRequest(_)
    ));
    // A bad secret invalidates any other signal.
    assert!(matches!(
        classify(vec![Code::InvalidInputResponse, Code::InvalidInputSecret]),
        TurnstileError::InvalidRequest(_)
    ));
    assert!(matches!(
        classify(vec![Code::InvalidInputResponse]),
        TurnstileError::TokenRejected(TokenRejection::ErrorCodes(_))
    ));
    // Unknown codes fail closed.
    assert!(matches!(
        classify(vec![Code::Unknown]),
        TurnstileError::TokenRejected(_)
    ));
    assert!(matches!(
        classify(vec![Code::InternalError]),
        TurnstileError::InternalApiError(_)
    ));
    // An internal error next to a rejection is still a rejection.
    assert!(matches!(
        classify(vec![Code::InternalError, Code::TimeoutOrDuplicate]),
        TurnstileError::TokenRejected(_)
    ));
}

#[cfg(feature = "network-tests")]
#[tokio::test]
async fn test_success() -> Result<()> {
    let client = TurnstileClient::new("1x0000000000000000000000000000000AA".to_string().into());

    let validated = client
        .siteverify(
            SiteVerifyRequest {
                response: "myresponse".to_string(),
                ..Default::default()
            },
            Some(&["example.com"]),
        )
        .await?;

    // `siteverify` returns `Err` unless the token was verified, so reaching this
    // point is the assertion; check the payload was parsed as well.
    assert!(!validated.timestamp.is_empty());

    Ok(())
}

#[cfg(feature = "network-tests")]
#[tokio::test]
async fn test_success_with_hostname() -> Result<()> {
    let client = TurnstileClient::new("1x0000000000000000000000000000000AA".to_string().into());

    let validated = client
        .siteverify(
            SiteVerifyRequest {
                response: "myresponse".to_string(),
                ..Default::default()
            },
            Some(&["example.com"]),
        )
        .await?;

    // `siteverify` returns `Err` unless the token was verified, so reaching this
    // point is the assertion; check the payload was parsed as well.
    assert!(!validated.timestamp.is_empty());

    Ok(())
}

#[cfg(feature = "network-tests")]
#[tokio::test]
async fn test_reject_invalid_hostname() -> Result<()> {
    let client = TurnstileClient::new("1x0000000000000000000000000000000AA".to_string().into());

    let result = client
        .siteverify(
            SiteVerifyRequest {
                response: "myresponse".to_string(),
                ..Default::default()
            },
            Some(&["evil.com"]),
        )
        .await;

    std::assert_matches!(
        result.err(),
        Some(TurnstileError::TokenRejected(
            TokenRejection::HostnameMismatch(_)
        ))
    );

    Ok(())
}

#[cfg(feature = "network-tests")]
#[tokio::test]
async fn test_fail() -> Result<()> {
    let client = TurnstileClient::new("2x0000000000000000000000000000000AA".to_string().into());

    let validated = client
        .siteverify(
            SiteVerifyRequest {
                response: "myresponse".to_string(),
                ..Default::default()
            },
            Some(&["example.com"]),
        )
        .await;

    // Assert the API rejected the token, not merely that something went wrong:
    // a DNS, TLS or parse failure must not satisfy this test.
    match validated.unwrap_err() {
        TurnstileError::TokenRejected(TokenRejection::ErrorCodes(codes)) => assert!(
            matches!(codes.as_slice(), [SiteVerifyError::InvalidInputResponse]),
            "unexpected error codes: {codes:?}"
        ),
        e => panic!("expected a Turnstile API rejection, got: {e}"),
    }

    Ok(())
}

/// Cloudflare answers an invalid secret with HTTP 400 *and* the error codes, so the
/// body must win over the status, and a bad secret must classify as our fault.
#[cfg(feature = "network-tests")]
#[tokio::test]
async fn test_error_codes_survive_http_400() -> Result<()> {
    let client = TurnstileClient::new("bogus-secret".to_string().into());

    let validated = client
        .siteverify(
            SiteVerifyRequest {
                response: "myresponse".to_string(),
                ..Default::default()
            },
            None,
        )
        .await;

    match validated.unwrap_err() {
        TurnstileError::InvalidRequest(codes) => assert!(
            matches!(codes.as_slice(), [SiteVerifyError::InvalidInputSecret]),
            "unexpected error codes: {codes:?}"
        ),
        e => panic!("expected the API's error codes, got: {e}"),
    }

    Ok(())
}

#[cfg(feature = "network-tests")]
#[tokio::test]
async fn test_token_already_spent() -> Result<()> {
    let client = TurnstileClient::new("3x0000000000000000000000000000000AA".to_string().into());

    let validated = client
        .siteverify(
            SiteVerifyRequest {
                response: "myresponse".to_string(),
                ..Default::default()
            },
            Some(&["example.com"]),
        )
        .await;

    assert!(validated.is_err());
    match validated.unwrap_err() {
        TurnstileError::TokenRejected(TokenRejection::ErrorCodes(e)) => match e.first().unwrap() {
            SiteVerifyError::TimeoutOrDuplicate => {}
            _ => panic!("Unexpected error"),
        },
        e => panic!("Unexpected error: {e}"),
    }

    Ok(())
}

// cargo test --features integration -- --nocapture
#[cfg(feature = "integration")]
#[tokio::test]
async fn test_integration() -> Result<()> {
    use crate::generate_idempotency_key;
    use std::env::var;

    let secret_key = var("TURNSTILE_SECRET_KEY").expect("TURNSTILE_SECRET_KEY not set");
    let response = var("TURNSTILE_RESPONSE").expect("TURNSTILE_RESPONSE not set");
    let hostname = var("TURNSTILE_HOSTNAME").expect("TURNSTILE_HOSTNAME not set");
    let idempotency_key = generate_idempotency_key();

    let client = TurnstileClient::new(secret_key.into());

    let validated = client
        .siteverify(
            SiteVerifyRequest {
                response,
                idempotency_key,
                ..Default::default()
            },
            Some(&["example.com"]),
        )
        .await?;

    assert_eq!(validated.hostname, hostname);

    println!("validated: {validated:#?}");

    Ok(())
}
