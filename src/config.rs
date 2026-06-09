use std::collections::HashMap;

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
#[derive(Debug, Clone, Deserialize, Validate)]
#[validate(schema(function = "validate_non_empty_chains"))]
#[validate(schema(function = "validate_default_chain_id"))]
pub struct Config {
    #[validate(nested)]
    pub server: ServerConfig,
    #[validate(nested)]
    pub chains: HashMap<u32, PerChainConfig>,
    #[validate(nested)]
    pub kms: KmsConfig,
    #[validate(custom(function = "validate_non_zero_address"))]
    pub runner_address: Address,
    /// Fallback chain ID when the SDK omits the `chain_id` query parameter.
    /// Must match a key in [`Config::chains`] — checked by
    /// [`validate_default_chain_id`] at startup.
    // TODO: Remove when SDK supports chain ID query param.
    pub default_chain_id: u32,
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
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ServerConfig {
    #[validate(length(min = 1))]
    pub host: String,
    #[validate(range(min = 1))]
    pub port: u16,
    #[serde(deserialize_with = "deserialize_header_names")]
    pub cors_allowed_headers: Vec<HeaderName>,
}

/// Per-chain configuration combining RPC, signing key, and S3 storage settings.
///
/// One entry per configured chain ID under `NOX_HANDLE_GATEWAY_CHAINS__{chain_id}__*`.
/// Duplicating values across chains (e.g. the same `wallet_key`) is intentional —
/// it supports both single-key and per-chain-key deployments without special-casing.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PerChainConfig {
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
            .map_err(|e| anyhow!(format!("wallet_key is not valid hex: {e}")))?
            .try_into()
            .map_err(|v: Vec<u8>| {
                anyhow!(format!("wallet_key must be 32 bytes, got {}", v.len()))
            })?;

        let signer = PrivateKeySigner::from_bytes(&bytes.into())
            .map_err(|e| anyhow!(format!("invalid secp256k1 key: {e}")))?;

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
#[derive(Debug, Clone, Deserialize, Validate)]
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
#[derive(Clone, Debug, Deserialize, Validate)]
pub struct KmsConfig {
    #[validate(url)]
    pub url: String,
    #[validate(custom(function = "validate_non_zero_address"))]
    pub signer_address: Address,
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

fn validate_default_chain_id(cfg: &Config) -> Result<(), ValidationError> {
    if !cfg.chains.contains_key(&cfg.default_chain_id) {
        return Err(ValidationError::new(
            "default_chain_id must reference a configured chain",
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

        debug!("Configuration loaded: {config:#?}");
        config.try_deserialize()
    }

    /// Returns the `host:port` string used to bind the HTTP listener.
    pub fn bind_addr(&self) -> String {
        let addr = format!("{}:{}", self.server.host, self.server.port);
        debug!("Binding address: {}", addr);
        addr
    }
}
