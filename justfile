# Development commands for cf-turnstile. Run `just` to list them and `just setup`
# to install the tools they need.

# The feature set CI tests with: the defaults plus the optional API surface.
test_features := "network-tests,idempotency"

# At least one of these is required for the crate to build.
tls_backends := "rustls-native-roots,rustls-webpki-roots,native-tls"

# List the available recipes.
default:
    @just --list

# Run everything CI runs.
verify: fmt-check lint test doc features

# Build with all features enabled.
build *args:
    cargo build --all-features {{ args }}

# Type-check the crate, its tests and its examples.
check *args:
    cargo check --all-targets --all-features {{ args }}

# Format all code in place.
fmt:
    cargo fmt --all

# Fail if anything is unformatted.
fmt-check:
    cargo fmt --all --check

# Lint with clippy, denying warnings.
lint *args:
    cargo clippy --all-targets --all-features {{ args }} -- -D warnings

# Run the tests and doctests. Needs network access.
test *args:
    cargo nextest run --features {{ test_features }} {{ args }}
    cargo test --doc --all-features

# Run only the tests that work offline.
test-offline *args:
    cargo nextest run {{ args }}

# Verify a real token. Needs the TURNSTILE_* environment variables.
test-integration:
    cargo nextest run --features integration --no-capture test_integration

# Check that every meaningful feature combination compiles.
features:
    cargo hack check --feature-powerset \
        --exclude-features integration,network-tests \
        --at-least-one-of {{ tls_backends }}

# Build the docs, denying warnings.
doc *args:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features {{ args }}

audit:
    cargo deny check

# Install the components and tools the other recipes need.
setup:
    rustup component add clippy rustfmt llvm-tools-preview
    cargo install --locked cargo-nextest cargo-hack cargo-llvm-cov cargo-deny
