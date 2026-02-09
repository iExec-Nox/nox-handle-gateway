use std::path::PathBuf;

use alloy_primitives::Address;
use config::{Config as ConfigBuilder, ConfigError, Environment};
use config_secret::EnvironmentSecretFile;
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub chain: ChainConfig,
    pub kms: KmsConfig,
    pub s3: S3Config,
    pub signer: SignerConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S3Config {
    pub endpoint_url: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub timeout: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub id: u32,
    pub tee_compute_manager_contract: Address,
    pub rpc_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KmsConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignerConfig {
    pub keystore_filename: PathBuf,
    pub keystore_password: String,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let config = ConfigBuilder::builder()
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 3000)?
            .set_default("s3.endpoint_url", "http://localhost:9900")?
            .set_default("s3.bucket", "handles")?
            .set_default("s3.access_key", "minioAccessKey")?
            .set_default("s3.secret_key", "minioSecretKey")?
            .set_default("s3.region", "us-east-1")?
            .set_default("s3.timeout", 30)?
            .set_default("chain.id", 421614)?
            .set_default(
                "chain.tee_compute_manager_contract",
                "0x0000000000000000000000000000000000000000",
            )?
            .set_default("chain.rpc_url", "https://sepolia-rollup.arbitrum.io/rpc")?
            .set_default("kms.url", "http://localhost:9000")?
            .set_default("signer.keystore_filename", "gateway_keystore.json")?
            .set_default("signer.keystore_password", "")?
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

    pub fn bind_addr(&self) -> String {
        let addr = format!("{}:{}", self.server.host, self.server.port);
        debug!("Binding address: {}", addr);
        addr
    }
}
