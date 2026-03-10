use alloy_primitives::Address;
use config::{Config as ConfigBuilder, ConfigError, Environment};
use config_secret::EnvironmentSecretFile;
use serde::Deserialize;
use tracing::debug;

/// Top-level application configuration loaded from environment variables.
///
/// All fields are populated by [`Config::load`]. Most have sensible defaults;
/// exceptions are noted on the individual sub-config types.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub chain: ChainConfig,
    pub kms: KmsConfig,
    pub s3: S3Config,
    pub signer: SignerConfig,
}

/// HTTP server bind configuration.
///
/// `cors_allowed_headers` lists the request headers the browser is permitted to
/// send cross-origin (`Access-Control-Allow-Headers`). The default covers the
/// two headers used by this API: `content-type` (JSON bodies) and `authorization`
/// (EIP-712 token). Extend via `NOX_HANDLE_GATEWAY_SERVER__CORS_ALLOWED_HEADERS`
/// as a JSON array.
///
/// Each entry is validated at startup with [`http::header::HeaderName::from_bytes`],
/// which enforces HTTP token syntax (RFC 7230: no control characters, no separators
/// such as `:` or `/`). This catches malformed values but **not** typos — a value
/// like `"authoriation"` is a valid HTTP token and will be accepted silently. If a
/// critical header is accidentally omitted or misspelled, browsers will reject
/// cross-origin requests for that header at the CORS preflight stage.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cors_allowed_headers: Vec<String>,
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
#[derive(Debug, Clone, Deserialize)]
pub struct S3Config {
    pub access_key: String,
    pub secret_key: String,
    pub bucket: String,
    pub endpoint_url: Option<String>,
    pub object_lock_enabled: bool,
    pub region: String,
    pub timeout: u64,
}

/// Ethereum chain and NoxCompute contract configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub id: u32,
    pub nox_compute_contract: Address,
    pub rpc_url: String,
}

/// KMS service configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct KmsConfig {
    pub url: String,
    pub signer_address: Address,
}

/// EIP-712 signer configuration.
///
/// The private key is injected via the `NOX_HANDLE_GATEWAY_SIGNER__WALLET_KEY`
/// environment variable as a hex-encoded 32-byte scalar (with or without `0x`
/// prefix). There is no default — the process exits at startup if the key is
/// absent or malformed.
#[derive(Debug, Clone, Deserialize)]
pub struct SignerConfig {
    pub wallet_key: String,
}

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// Variables are prefixed `NOX_HANDLE_GATEWAY_` with `__` as the nested
    /// separator (e.g. `NOX_HANDLE_GATEWAY_S3__BUCKET`). Secret-file variants
    /// are also supported via `config_secret`.
    pub fn load() -> Result<Self, ConfigError> {
        let config = ConfigBuilder::builder()
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 3000)?
            .set_default(
                "server.cors_allowed_headers",
                vec!["content-type", "authorization"],
            )?
            .set_default("s3.bucket", "handles")?
            .set_default("s3.object_lock_enabled", true)?
            .set_default("s3.timeout", 30)?
            .set_default("chain.id", 421614)?
            .set_default(
                "chain.nox_compute_contract",
                "0x0000000000000000000000000000000000000000",
            )?
            .set_default("chain.rpc_url", "http://localhost:8545")?
            .set_default("kms.url", "http://localhost:9000")?
            .set_default(
                "kms.signer_address",
                "0x0000000000000000000000000000000000000000",
            )?
            .set_default("signer.wallet_key", "")?
            .add_source(
                Environment::with_prefix("NOX_HANDLE_GATEWAY")
                    .prefix_separator("_")
                    .separator("__"),
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
