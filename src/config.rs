use std::collections::HashMap;

use alloy_primitives::{Address, hex};
use axum::http::HeaderName;
use config::{Config as ConfigBuilder, ConfigError, Environment};
use config_secret::EnvironmentSecretFile;
use serde::Deserialize;
use tracing::debug;
use validator::{Validate, ValidationError};

/// Top-level application configuration loaded from environment variables.
///
/// All fields are populated by [`Config::load`]. Most have sensible defaults;
/// exceptions are noted on the individual sub-config types.
#[derive(Debug, Clone, Deserialize, Validate)]
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
    /// Fallback chain ID when the SDK omits the `chain_id` query parameter.
    // TODO: Remove when SDK supports chain ID query param.
    pub default_chain_id: u32,
}

/// HTTP server bind configuration.
///
/// `cors_allowed_headers` lists the request headers the browser is permitted to
/// send cross-origin (`Access-Control-Allow-Headers`). The default covers the
/// two headers used by this API: `content-type` (JSON bodies) and `authorization`
/// (EIP-712 token). Extend via `NOX_HANDLE_GATEWAY_SERVER__CORS_ALLOWED_HEADERS`
/// as a JSON array.
///
/// Each entry is validated at startup with [`axum::http::HeaderName::from_bytes`]
/// via [`Config::validate`], which enforces HTTP token syntax (RFC 7230).
/// Malformed values cause a hard error, but typos (e.g. `"authoriation"`) are
/// valid tokens and will be accepted silently, causing CORS preflight rejections
/// at runtime.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ServerConfig {
    #[validate(length(min = 1))]
    pub host: String,
    #[validate(range(min = 1))]
    pub port: u16,
    #[validate(custom(function = "validate_cors_allowed_headers"))]
    pub cors_allowed_headers: Vec<String>,
}

/// Per-chain configuration combining RPC, signing key, and S3/MinIO storage settings.
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

/// S3/MinIO connection configuration.
///
/// `access_key`, `secret_key`, and `region` have no defaults — the process
/// exits at startup if they are not provided via environment variables or a
/// config file.
///
/// `endpoint_url` is optional. When absent the AWS SDK uses standard regional
/// endpoints (native AWS S3). When set, the SDK targets that custom endpoint
/// and enables path-style addressing (required for MinIO and other S3-compatible
/// backends).
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
    #[serde(default = "default_s3_max_concurrent_requests")]
    #[validate(range(min = 1))]
    pub max_concurrent_requests: usize,
    #[serde(default = "default_s3_max_handles_per_request")]
    #[validate(range(min = 1))]
    pub max_handles_per_request: usize,
    #[serde(default = "default_s3_object_lock_enabled")]
    pub object_lock_enabled: bool,
    #[validate(length(min = 1))]
    pub region: String,
    #[serde(default = "default_s3_timeout")]
    #[validate(range(min = 1))]
    pub timeout: u64,
}

/// KMS service configuration.
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

/// Default maximum number of concurrent in-flight S3 requests.
fn default_s3_max_concurrent_requests() -> usize {
    100
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

fn validate_cors_allowed_headers(headers: &[String]) -> Result<(), ValidationError> {
    for h in headers {
        if HeaderName::from_bytes(h.as_bytes()).is_err() {
            return Err(ValidationError::new("invalid HTTP header name"));
        }
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

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// Variables are prefixed `NOX_HANDLE_GATEWAY_` with `__` as the nested
    /// separator (e.g. `NOX_HANDLE_GATEWAY_CHAINS__421614__BUCKET`). Secret-file variants
    /// are also supported via `config_secret`.
    pub fn load() -> Result<Self, ConfigError> {
        let config = ConfigBuilder::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 3000)?
            .set_default(
                "server.cors_allowed_headers",
                vec!["content-type", "authorization"],
            )?
            .set_default("kms.url", "http://localhost:9000")?
            .set_default(
                "kms.signer_address",
                "0x0000000000000000000000000000000000000000",
            )?
            .set_default(
                "runner_address",
                "0x0000000000000000000000000000000000000000",
            )?
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use validator::ValidationErrors;

    #[test]
    fn check_config() {
        temp_env::with_vars(
            [
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__RPC_URL",
                    Some("http://localhost:8545"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__NOX_COMPUTE_CONTRACT_ADDRESS",
                    Some("0x0A59a4e1F7f740CD6474312AfFC1446fA9B5ad9B"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__WALLET_KEY",
                    Some("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__S3__ACCESS_KEY",
                    Some("minioadmin"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__S3__SECRET_KEY",
                    Some("minioadmin"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__S3__BUCKET",
                    Some("test-bucket"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__S3__REGION",
                    Some("us-east-1"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_RUNNER_ADDRESS",
                    Some("0x1111111111111111111111111111111111111111"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_KMS__SIGNER_ADDRESS",
                    Some("0x2222222222222222222222222222222222222222"),
                ),
            ],
            || {
                let config = Config::load().expect("should load");
                config.validate().expect("should validate");
                assert_eq!("http://localhost:8545", config.chains[&31337].rpc_url);
                assert_eq!(
                    Address::from_str("0x0A59a4e1F7f740CD6474312AfFC1446fA9B5ad9B").unwrap(),
                    config.chains[&31337].nox_compute_contract_address
                );
            },
        )
    }

    #[test]
    fn check_invalid_config() {
        temp_env::with_vars(
            [
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__RPC_URL",
                    Some("not-a-url"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__NOX_COMPUTE_CONTRACT_ADDRESS",
                    Some("0x0000000000000000000000000000000000000000"),
                ),
                (
                    "NOX_HANDLE_GATEWAY_CHAINS__31337__WALLET_KEY",
                    Some("0x0000000000000000000000000000000000000000000000000000000000000000"),
                ),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__S3__ACCESS_KEY", Some("")),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__S3__SECRET_KEY", Some("")),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__S3__BUCKET", Some("")),
                ("NOX_HANDLE_GATEWAY_CHAINS__31337__S3__REGION", Some("")),
            ],
            || {
                let config = Config::load().expect("should load");
                let result = config.validate();
                assert!(result.is_err());
                assert!(ValidationErrors::has_error(&result, "chains"));
            },
        )
    }

    fn valid_chain_config() -> PerChainConfig {
        PerChainConfig {
            rpc_url: "http://localhost:8545".to_string(),
            nox_compute_contract_address: Address::from_str(
                "0x0A59a4e1F7f740CD6474312AfFC1446fA9B5ad9B",
            )
            .unwrap(),
            wallet_key: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            s3: S3Config {
                access_key: "minioadmin".to_string(),
                secret_key: "minioadmin".to_string(),
                bucket: "test-bucket".to_string(),
                endpoint_url: None,
                max_concurrent_requests: default_s3_max_concurrent_requests(),
                max_handles_per_request: default_s3_max_handles_per_request(),
                object_lock_enabled: default_s3_object_lock_enabled(),
                region: "us-east-1".to_string(),
                timeout: default_s3_timeout(),
            },
        }
    }

    fn valid_config() -> Config {
        let mut chains = HashMap::new();
        chains.insert(31337, valid_chain_config());
        Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
                cors_allowed_headers: vec!["content-type".to_string(), "authorization".to_string()],
            },
            chains,
            kms: KmsConfig {
                url: "http://localhost:9000".to_string(),
                signer_address: Address::from_str("0x2222222222222222222222222222222222222222")
                    .unwrap(),
            },
            runner_address: Address::from_str("0x1111111111111111111111111111111111111111")
                .unwrap(),
            default_chain_id: 31337,
        }
    }

    #[test]
    fn check_empty_chains_invalid() {
        let mut cfg = valid_config();
        cfg.chains.clear();
        let result = cfg.validate();
        assert!(result.is_err());
        assert!(ValidationErrors::has_error(&result, "__all__"));
    }

    #[test]
    fn check_invalid_server_config() {
        let mut cfg = valid_config();
        cfg.server.host = "".to_string();
        cfg.server.port = 0;
        cfg.server.cors_allowed_headers = vec!["not a valid header!".to_string()];
        let result = cfg.validate();
        assert!(result.is_err());
        assert!(ValidationErrors::has_error(&result, "server"));
    }

    #[test]
    fn check_zero_runner_and_kms_signer_invalid() {
        let mut cfg = valid_config();
        cfg.runner_address = Address::ZERO;
        cfg.kms.signer_address = Address::ZERO;
        let result = cfg.validate();
        assert!(result.is_err());
        assert!(ValidationErrors::has_error(&result, "runner_address"));
        assert!(ValidationErrors::has_error(&result, "kms"));
    }

    #[test]
    fn check_invalid_chain_config() {
        let chain_config = PerChainConfig {
            rpc_url: "".to_string(),
            nox_compute_contract_address: Address::ZERO,
            wallet_key: "0x".to_string(),
            s3: S3Config {
                access_key: "".to_string(),
                secret_key: "".to_string(),
                bucket: "".to_string(),
                endpoint_url: None,
                max_concurrent_requests: default_s3_max_concurrent_requests(),
                max_handles_per_request: default_s3_max_handles_per_request(),
                object_lock_enabled: default_s3_object_lock_enabled(),
                region: "".to_string(),
                timeout: default_s3_timeout(),
            },
        };
        let result = chain_config.validate();
        assert!(ValidationErrors::has_error(&result, "rpc_url"));
        assert!(ValidationErrors::has_error(
            &result,
            "nox_compute_contract_address"
        ));
        assert!(ValidationErrors::has_error(&result, "wallet_key"));
        assert!(ValidationErrors::has_error(&result, "s3"));
    }
}
