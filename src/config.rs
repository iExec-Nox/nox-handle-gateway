use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use alloy::{
    primitives::{Address, hex},
    signers::local::PrivateKeySigner,
};
use anyhow::anyhow;
use axum::http::HeaderName;
use config::{Config as ConfigBuilder, ConfigError, Environment};
use config_secret::EnvironmentSecretFile;
use serde::{Deserialize, Deserializer};
use tracing::{debug, info};
use validator::{Validate, ValidationError};

/// Top-level application configuration loaded from environment variables.
///
/// Fields are populated by [`Config::load`]. Invariants beyond serde parsing
/// (non-zero addresses, non-empty chains map, `default_chain_id` ∈ `chains`,
/// per-chain wallet-key shape, S3 field presence) are enforced by
/// [`Config::validate`] — `main` calls both before any I/O.
///
/// Required without defaults: `chains` (at least one entry), `runner_address`
/// (non-zero), `kms.signer_address` (non-zero), and every `chains[*]`
/// sub-field except S3 tuning knobs.
#[derive(Clone, Deserialize, Validate)]
#[validate(schema(function = "validate_non_empty_chains"))]
pub struct Config {
    #[validate(nested)]
    pub server: ServerConfig,
    #[validate(nested)]
    pub chains: HashMap<u32, PerChainConfig>,
    #[validate(nested)]
    pub kms: KmsConfig,
    #[validate(custom(function = "validate_non_zero_address"))]
    pub runner_address: Address,
    /// Maximum number of operands accepted in a single `GET /v0/compute/operands`
    /// request.
    ///
    /// Each operand costs one KMS delegate call, so this bounds the KMS fan-out a
    /// single authenticated Runner request can trigger. The floor of 3 matches the
    /// widest operation the Runner currently emits — a lower value would reject
    /// legitimate traffic.
    #[serde(default = "default_compute_max_operands_per_request")]
    #[validate(range(min = 3, max = 50))]
    pub compute_max_operands_per_request: usize,
    #[serde(default = "default_s3_max_concurrent_requests")]
    #[validate(range(min = 1, max = 1_000))]
    pub s3_max_concurrent_requests: usize,
    #[serde(default = "default_s3_max_handles_per_request")]
    #[validate(range(min = 1))]
    pub s3_max_handles_per_request: usize,
}

/// HTTP server bind configuration.
///
/// `cors_allowed_headers` lists the request headers the browser is permitted to
/// send cross-origin (`Access-Control-Allow-Headers`). The default covers the
/// two headers used by this API: `content-type` (JSON bodies) and `authorization`
/// (EIP-712 token). Extend via `NOX_HANDLE_GATEWAY_SERVER__CORS_ALLOWED_HEADERS`
/// as a comma-separated list.
///
/// Entries are parsed into [`HeaderName`] at deserialisation time, so malformed
/// HTTP token syntax (RFC 7230) causes a hard error at startup. Typos that are
/// valid tokens (e.g. `"authoriation"`) parse successfully and surface only as
/// CORS preflight rejections at runtime.
#[derive(Clone, Deserialize, Validate)]
pub struct ServerConfig {
    #[validate(length(min = 1))]
    pub host: String,
    #[validate(range(min = 1))]
    pub port: u16,
    #[serde(deserialize_with = "deserialize_header_names")]
    pub cors_allowed_headers: Vec<HeaderName>,
    /// Wall-clock ceiling on a single `/v0` request, including time spent queued on the
    /// KMS semaphore.
    ///
    /// Must stay above one KMS request timeout ([`KmsConfig::timeout`]) plus the queue
    /// wait expected once [`KmsConfig::max_concurrent_requests`] saturates, or legitimate
    /// operand batches are cut short under load. Operands are fetched concurrently, so the
    /// floor is one KMS timeout rather than one per operand.
    ///
    /// The `/`, `/health`, and `/metrics` routes use a shorter fixed ceiling instead — see
    /// [`crate::application`].
    #[serde(with = "humantime_serde", default = "default_request_timeout")]
    #[validate(custom(function = "validate_timeout"))]
    pub request_timeout: Duration,
}

/// Per-chain configuration combining RPC, signing key, and S3 storage settings.
///
/// One entry per configured chain ID under `NOX_HANDLE_GATEWAY_CHAINS__{chain_id}__*`.
/// Duplicating values across chains (e.g. the same `wallet_key`) is intentional —
/// it supports both single-key and per-chain-key deployments without special-casing.
#[derive(Clone, Deserialize, Validate)]
pub struct PerChainConfig {
    #[serde(with = "humantime_serde", default = "default_rpc_call_timeout")]
    #[validate(custom(function = "validate_timeout"))]
    pub call_timeout: Duration,
    #[serde(with = "humantime_serde", default = "default_rpc_connect_timeout")]
    #[validate(custom(function = "validate_timeout"))]
    pub connect_timeout: Duration,
    #[validate(custom(function = "validate_non_zero_address"))]
    pub nox_compute_contract_address: Address,
    #[validate(url)]
    pub rpc_url: String,
    #[validate(nested)]
    pub s3: S3Config,
    #[validate(custom(function = "validate_wallet_key"))]
    pub wallet_key: String,
}

impl PerChainConfig {
    /// Loads an EIP-712 signer from a hex-encoded private key.
    ///
    /// Format invariants (hex, 32 bytes, non-zero) are enforced upstream by
    /// `Config::validate`; this only handles the secp256k1 scalar conversion.
    pub fn load_signer(&self) -> anyhow::Result<PrivateKeySigner> {
        let bytes: [u8; 32] = hex::decode(&self.wallet_key)
            .map_err(|e| anyhow!("wallet_key is not valid hex: {e}"))?
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("wallet_key must be 32 bytes, got {}", v.len()))?;

        let signer = PrivateKeySigner::from_bytes(&bytes.into())
            .map_err(|e| anyhow!("invalid secp256k1 key: {e}"))?;

        info!("Loaded signer, address: {}", signer.address());

        Ok(signer)
    }
}

/// S3 connection configuration.
///
/// `access_key`, `secret_key`, `bucket`, and `region` have no defaults — the
/// process exits at startup if they are not provided via environment
/// variables or a config file.
///
/// `endpoint_url` is optional. When absent the AWS SDK uses standard regional
/// endpoints (native AWS S3). When set, the SDK targets that custom endpoint
/// and enables path-style addressing (required for S3-compatible backends).
///
/// `object_lock_enabled` controls whether Object Lock Compliance headers are
/// written on each stored handle and whether the startup bucket check verifies
/// that Object Lock is active. Set to `false` for buckets where Object Lock is
/// not configured (e.g. the Sepolia S3 bucket).
#[derive(Clone, Deserialize, Validate)]
pub struct S3Config {
    #[validate(length(min = 1))]
    pub access_key: String,
    #[validate(length(min = 1))]
    pub secret_key: String,
    #[validate(length(min = 1))]
    pub bucket: String,
    #[validate(url)]
    pub endpoint_url: Option<String>,
    #[serde(default = "default_s3_object_lock_enabled")]
    pub object_lock_enabled: bool,
    #[validate(length(min = 1))]
    pub region: String,
    #[serde(default = "default_s3_timeout")]
    #[validate(range(min = 1))]
    pub timeout: u64,
}

/// KMS service configuration.
///
/// `url` defaults to `http://localhost:9000`. `signer_address` has no default
/// and must be non-zero — it is the expected EIP-712 signer for KMS responses
/// and is checked against on each delegate call.
#[derive(Clone, Deserialize, Validate)]
pub struct KmsConfig {
    #[validate(url)]
    pub url: String,
    #[serde(with = "humantime_serde")]
    #[validate(custom(function = "validate_timeout"))]
    pub connect_timeout: Duration,
    /// Global cap on delegate calls in flight against the KMS, across every
    /// endpoint and chain.
    ///
    /// Backpressure guard, not a rate limit: callers queue on the semaphore in
    /// [`crate::kms::KmsClient`] rather than being rejected. Deliberately separate
    /// from [`Config::s3_max_concurrent_requests`] — the two protect different
    /// resources.
    ///
    /// The floor of 1 matters: a value of 0 would make every delegate call wait
    /// forever on a permit that is never issued.
    #[serde(default = "default_kms_max_concurrent_requests")]
    #[validate(range(min = 1, max = 1_000))]
    pub max_concurrent_requests: usize,
    #[serde(with = "humantime_serde")]
    #[validate(custom(function = "validate_timeout"))]
    pub timeout: Duration,
    #[validate(custom(function = "validate_non_zero_address"))]
    pub signer_address: Address,
}

/// Default cap on operands accepted in a single `GET /v0/compute/operands` request.
///
/// Sized just above the widest operation the Runner currently emits (3 handles), which
/// leaves headroom without licensing large KMS fan-outs. Raise it when the Runner starts
/// batching operations into a single request.
fn default_compute_max_operands_per_request() -> usize {
    5
}

/// Default global cap on concurrent in-flight KMS delegate requests.
fn default_kms_max_concurrent_requests() -> usize {
    50
}

/// Default wall-clock ceiling on a single `/v0` request.
///
/// Three times the default KMS request timeout (10s), which leaves room for one KMS call
/// plus queue wait and S3 reads without letting a stuck request hold a connection for
/// minutes. [`validate_timeout`] caps any override at 60s.
fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

pub(crate) fn default_rpc_call_timeout() -> Duration {
    Duration::from_secs(8)
}

pub(crate) fn default_rpc_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

/// Default S3 operation timeout in seconds.
fn default_s3_timeout() -> u64 {
    30
}

/// Default S3 Object Lock enabled flag.
fn default_s3_object_lock_enabled() -> bool {
    true
}

/// Default global cap on concurrent in-flight S3 requests across all chains.
fn default_s3_max_concurrent_requests() -> usize {
    500
}

/// Default maximum number of handles accepted in a single status request.
fn default_s3_max_handles_per_request() -> usize {
    1000
}

fn validate_non_empty_chains(cfg: &Config) -> Result<(), ValidationError> {
    if cfg.chains.is_empty() {
        return Err(ValidationError::new(
            "at least one chain must be configured",
        ));
    }
    Ok(())
}

fn validate_non_zero_address(address: &Address) -> Result<(), ValidationError> {
    if *address == Address::ZERO {
        return Err(ValidationError::new("address should not be zero address"));
    }
    Ok(())
}

/// Validate a timeout is not zero and is less than 60 seconds.
fn validate_timeout(value: &Duration) -> Result<(), ValidationError> {
    if *value == Duration::ZERO {
        let err =
            ValidationError::new("timeout_zero").with_message(Cow::from("must be greater than 0s"));
        return Err(err);
    }
    if *value > Duration::from_secs(60) {
        let err = ValidationError::new("timeout_too_large")
            .with_message(Cow::from("must not exceed 60s"));
        return Err(err);
    }
    Ok(())
}

fn validate_wallet_key(wallet_key: &str) -> Result<(), ValidationError> {
    let bytes = hex::decode(wallet_key)
        .map_err(|_| ValidationError::new("wallet key is not a valid hex"))?;
    if bytes.len() != 32 {
        return Err(ValidationError::new(
            "wallet key should have a 32-byte length",
        ));
    }
    if bytes == [0u8; 32] {
        return Err(ValidationError::new("wallet key should not contain only 0"));
    }
    Ok(())
}

fn deserialize_header_names<'de, D>(deserializer: D) -> Result<Vec<HeaderName>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Vec::<String>::deserialize(deserializer)?;
    raw.into_iter()
        .map(|h| {
            HeaderName::from_bytes(h.as_bytes()).map_err(|e| {
                serde::de::Error::custom(format!("invalid HTTP header name '{h}': {e}"))
            })
        })
        .collect()
}

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// Variables are prefixed `NOX_HANDLE_GATEWAY_` with `__` as the nested
    /// separator (e.g. `NOX_HANDLE_GATEWAY_CHAINS__421614__BUCKET`). Secret-file variants
    /// are also supported via `config_secret`.
    ///
    /// Loading only covers serde parsing — including
    /// [`ServerConfig::cors_allowed_headers`] which is parsed into
    /// [`HeaderName`] at deserialise time. Callers must invoke
    /// [`Config::validate`] (auto-derived via the `validator` crate) before
    /// using the result, to enforce non-zero addresses, wallet-key shape,
    /// non-empty `chains`, and `default_chain_id ∈ chains`.
    pub fn load() -> Result<Self, ConfigError> {
        let config = ConfigBuilder::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 3000)?
            .set_default(
                "server.cors_allowed_headers",
                vec!["content-type", "authorization"],
            )?
            .set_default("kms.url", "http://localhost:9000")?
            .set_default("kms.connect_timeout", "3s")?
            .set_default("kms.timeout", "10s")?
            .set_default("default_chain_id", 421614)?
            .add_source(
                Environment::with_prefix("NOX_HANDLE_GATEWAY")
                    .prefix_separator("_")
                    .separator("__")
                    .try_parsing(true)
                    .list_separator(",")
                    .with_list_parse_key("server.cors_allowed_headers"),
            )
            .add_source(EnvironmentSecretFile::with_prefix("NOX_HANDLE_GATEWAY").separator("_"))
            .build()?;
        config.try_deserialize()
    }

    /// Returns the `host:port` string used to bind the HTTP listener.
    pub fn bind_addr(&self) -> String {
        let addr = format!("{}:{}", self.server.host, self.server.port);
        debug!("Binding address: {}", addr);
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use validator::ValidationErrors;

    /// Every variable that has no default, so [`Config::load`] succeeds.
    ///
    /// Tests that exercise an optional field override one entry on top of this set, which
    /// keeps them from asserting on a `load` failure caused by an unrelated missing field.
    fn required_vars() -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            (
                "NOX_HANDLE_GATEWAY_CHAINS__31337__NOX_COMPUTE_CONTRACT_ADDRESS",
                Some("0x9c3244fa8F8D46e9f251eda52E759A6D6f47eaC9"),
            ),
            (
                "NOX_HANDLE_GATEWAY_CHAINS__31337__RPC_URL",
                Some("http://localhost:8545"),
            ),
            (
                "NOX_HANDLE_GATEWAY_CHAINS__31337__S3__ACCESS_KEY",
                Some("username"),
            ),
            (
                "NOX_HANDLE_GATEWAY_CHAINS__31337__S3__SECRET_KEY",
                Some("password"),
            ),
            (
                "NOX_HANDLE_GATEWAY_CHAINS__31337__S3__BUCKET",
                Some("bucket"),
            ),
            (
                "NOX_HANDLE_GATEWAY_CHAINS__31337__S3__REGION",
                Some("region"),
            ),
            (
                "NOX_HANDLE_GATEWAY_CHAINS__31337__WALLET_KEY",
                Some("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            ),
            ("NOX_HANDLE_GATEWAY_DEFAULT_CHAIN_ID", Some("31337")),
            (
                "NOX_HANDLE_GATEWAY_KMS__SIGNER_ADDRESS",
                Some("0xD60BB0381d2712863e241F003349591475E0b961"),
            ),
            (
                "NOX_HANDLE_GATEWAY_RUNNER_ADDRESS",
                Some("0x6cf34A6f8295c0478791A58c87CFe6E9e827B220"),
            ),
        ]
    }

    #[test]
    fn check_config() {
        let mut vars = required_vars();
        vars.push((
            "NOX_HANDLE_GATEWAY_SERVER__CORS_ALLOWED_HEADERS",
            Some("a,b"),
        ));
        temp_env::with_vars(vars, || {
            let config = Config::load().expect("should load");
            config.validate().expect("should validate");
            assert_eq!(Duration::from_secs(8), config.chains[&31337].call_timeout);
            assert_eq!(
                Duration::from_secs(5),
                config.chains[&31337].connect_timeout
            );
            assert_eq!(
                Address::from_str("0x9c3244fa8F8D46e9f251eda52E759A6D6f47eaC9").unwrap(),
                config.chains[&31337].nox_compute_contract_address
            );
            assert_eq!("http://localhost:8545", config.chains[&31337].rpc_url);
            assert_eq!("username", config.chains[&31337].s3.access_key);
            assert_eq!("password", config.chains[&31337].s3.secret_key);
            assert_eq!("bucket", config.chains[&31337].s3.bucket);
            assert_eq!("region", config.chains[&31337].s3.region);
            assert_eq!(
                "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                config.chains[&31337].wallet_key
            );
            assert_eq!(
                Address::from_str("0xD60BB0381d2712863e241F003349591475E0b961").unwrap(),
                config.kms.signer_address
            );
            assert_eq!(
                Address::from_str("0x6cf34A6f8295c0478791A58c87CFe6E9e827B220").unwrap(),
                config.runner_address
            );
            assert_eq!(vec!["a", "b"], config.server.cors_allowed_headers);
            assert_eq!(5, config.compute_max_operands_per_request);
            assert_eq!(50, config.kms.max_concurrent_requests);
            assert_eq!(Duration::from_secs(30), config.server.request_timeout);
        })
    }

    /// Both concurrency knobs and the request ceiling must stay optional: each was added to
    /// a service that was already deployed, so a missing variable has to fall back rather
    /// than fail to load.
    #[test]
    fn check_concurrency_limits_are_optional() {
        let mut vars = required_vars();
        vars.push(("NOX_HANDLE_GATEWAY_COMPUTE_MAX_OPERANDS_PER_REQUEST", None));
        vars.push(("NOX_HANDLE_GATEWAY_KMS__MAX_CONCURRENT_REQUESTS", None));
        vars.push(("NOX_HANDLE_GATEWAY_SERVER__REQUEST_TIMEOUT", None));
        temp_env::with_vars(vars, || {
            let config = Config::load().expect("should load without concurrency limits set");
            config.validate().expect("should validate");
            assert_eq!(5, config.compute_max_operands_per_request);
            assert_eq!(50, config.kms.max_concurrent_requests);
            assert_eq!(Duration::from_secs(30), config.server.request_timeout);
        })
    }

    /// The request ceiling shares [`validate_timeout`] with every other timeout in this
    /// config, so it inherits the 60s upper bound — a request allowed to run for minutes
    /// defeats the point of having a ceiling at all.
    #[test]
    fn check_request_timeout_upper_bound() {
        let mut vars = required_vars();
        vars.push(("NOX_HANDLE_GATEWAY_SERVER__REQUEST_TIMEOUT", Some("61s")));
        temp_env::with_vars(vars, || {
            let config = Config::load().expect("should load");
            assert!(ValidationErrors::has_error(&config.validate(), "server"));
        })
    }

    /// `kms.max_concurrent_requests = 0` would build a `Semaphore` that never issues a
    /// permit, hanging every KMS call forever instead of erroring — and the operand cap has
    /// to stay at or above the widest operation the runner emits. Validation rejects both.
    #[test]
    fn check_invalid_concurrency_limits() {
        let mut vars = required_vars();
        vars.push((
            "NOX_HANDLE_GATEWAY_COMPUTE_MAX_OPERANDS_PER_REQUEST",
            Some("2"),
        ));
        vars.push(("NOX_HANDLE_GATEWAY_KMS__MAX_CONCURRENT_REQUESTS", Some("0")));
        temp_env::with_vars(vars, || {
            let config = Config::load().expect("should load");
            let result = config.validate();
            assert!(ValidationErrors::has_error(
                &result,
                "compute_max_operands_per_request"
            ));
            assert!(ValidationErrors::has_error(&result, "kms"));
        })
    }

    #[test]
    fn check_operand_cap_upper_bound() {
        let mut vars = required_vars();
        vars.push((
            "NOX_HANDLE_GATEWAY_COMPUTE_MAX_OPERANDS_PER_REQUEST",
            Some("51"),
        ));
        temp_env::with_vars(vars, || {
            let config = Config::load().expect("should load");
            assert!(ValidationErrors::has_error(
                &config.validate(),
                "compute_max_operands_per_request"
            ));
        })
    }

    #[test]
    fn check_invalid_config() {
        temp_env::with_vars(
            [
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__NOX_COMPUTE_CONTRACT_ADDRESS",
                    Some("0x0000000000000000000000000000000000000000"),
                ),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__RPC_URL", Some("")),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__S3__ACCESS_KEY", Some("")),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__S3__SECRET_KEY", Some("")),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__S3__BUCKET", Some("")),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__S3__REGION", Some("")),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__WALLET_KEY", Some("0x")),
                ("NOX_HANDLE_GATEWAY_DEFAULT_CHAIN_ID", Some("65535")),
                (
                    "NOX_HANDLE_GATEWAY_KMS__SIGNER_ADDRESS",
                    Some("0x0000000000000000000000000000000000000000"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_RUNNER_ADDRESS",
                    Some("0x0000000000000000000000000000000000000000"),
                ),
            ],
            || {
                let config = Config::load().expect("should load");
                let result = config.validate();
                assert!(result.is_err());
                assert!(ValidationErrors::has_error(&result, "chains"));
                assert!(ValidationErrors::has_error(&result, "kms"));
                assert!(ValidationErrors::has_error(&result, "runner_address"));
            },
        )
    }

    #[test]
    fn check_invalid_chain_config() {
        let s3_config = S3Config {
            access_key: "".to_string(),
            secret_key: "".to_string(),
            bucket: "".to_string(),
            endpoint_url: None,
            object_lock_enabled: false,
            region: "".to_string(),
            timeout: 0,
        };
        let per_chain_config = PerChainConfig {
            call_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(90),
            nox_compute_contract_address: Address::ZERO,
            rpc_url: "".to_string(),
            s3: s3_config,
            wallet_key: "".to_string(),
        };
        let result = per_chain_config.validate();
        assert!(ValidationErrors::has_error(&result, "call_timeout"));
        assert!(ValidationErrors::has_error(&result, "connect_timeout"));
        assert!(ValidationErrors::has_error(
            &result,
            "nox_compute_contract_address"
        ));
        assert!(ValidationErrors::has_error(&result, "rpc_url"));
        assert!(ValidationErrors::has_error(&result, "wallet_key"));
    }
}
