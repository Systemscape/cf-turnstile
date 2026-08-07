> [!NOTE]
> This is an actively maintained fork of <https://github.com/Fyko/cf-turnstile>

# cf-turnstile

A Rust client for [Cloudflare Turnstile].


# Example
```rust,no_run
use cf_turnstile::{SiteVerifyRequest, TurnstileClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = TurnstileClient::new("my-secret".to_string().into());

    let validated = client
        .siteverify(SiteVerifyRequest {
            response: "myresponse".to_string(),
            ..Default::default()
        })
        .await?;

    // `siteverify` returns `Err` unless Cloudflare verified the token.
    println!("verified on {}", validated.hostname);

    Ok(())
}
```

## Features

### Idempotency

To utilize Turnstile's [`idempotency_key`](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/#:~:text=A%20response%20may,for%20that%20response.) feature, you can enable the `idempotency` feature flag.  

This will enable the `idempotency_key` field on the [`SiteVerifyRequest`](struct.SiteVerifyRequest.html) struct and the [`generate_idempotency_key`](fn.generate_idempotency_key.html) function.

### TLS

**Note**: Turnstile's API is HTTPS only, so at least one TLS feature must be enabled.
Building without a TLS backend is a compile error.

**Note**: this TLS code was taken from [twilight-http](https://github.com/twilight-rs/twilight/tree/main/twilight-http) in accordance with its license.

`cf-turnstile` has features to enable HTTPS connectivity with [`hyper`].
`rustls-native-roots` is enabled by default.

Enabling more than one backend is allowed rather than a build failure: Cargo features
are additive, so two unrelated crates in the same dependency graph may each select a
different backend, and that combination has to keep compiling. When several are
enabled the backend is chosen by precedence:

1. `rustls-native-roots`
2. `rustls-webpki-roots`
3. `native-tls`

#### `native-tls`

The `native-tls` feature uses a HTTPS connector provided by [`hyper-tls`].

To enable `native-tls`, do something like this in your `Cargo.toml`:

```toml
[dependencies]
cf-turnstile = { default-features = false, features = ["native-tls", "hickory"], version = "0.3" }
```

#### `rustls-native-roots`

The `rustls-native-roots` feature uses a HTTPS connector provided by [`hyper-rustls`], which uses
[`rustls`] as the TLS backend, and enables its `native-tokio` feature, which uses [`rustls-native-certs`]
for root certificates.

This is enabled by default.

#### `rustls-webpki-roots`

The `rustls-webpki-roots` feature uses a HTTPS connector provided by [`hyper-rustls`], which uses
[`rustls`] as the TLS backend, and enables its `webpki-tokio` feature, which uses [`webpki-roots`]
for root certificates.

This should be preferred over `rustls-native-roots` in Docker containers based on `scratch`.

### Hickory DNS

The `hickory` feature enables [`hyper-hickory`], which replaces the default
`GaiResolver` in [`hyper`]. [`hyper-hickory`] instead provides a fully
async DNS resolver on the application level.

This is enabled by default. Note that `default-features = false` turns it off, so
add it back explicitly if you want it alongside a non-default TLS backend.

[Cloudflare Turnstile]: https://developers.cloudflare.com/turnstile/
[`hyper`]: https://crates.io/crates/hyper
[`hyper-rustls`]: https://crates.io/crates/hyper-rustls
[`hyper-tls`]: https://crates.io/crates/hyper-tls
[`rustls`]: https://crates.io/crates/rustls
[`rustls-native-certs`]: https://crates.io/crates/rustls-native-certs
[`hyper-hickory`]: https://crates.io/crates/hyper-hickory
[`webpki-roots`]: https://crates.io/crates/webpki-roots
