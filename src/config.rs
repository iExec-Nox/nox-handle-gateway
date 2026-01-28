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
    pub signer: SignerConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub backend_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub id: u32,
    pub acl_contract: Address,
    pub tee_compute_manager_contract: Address,
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
            .set_default("chain.id", 1)?
            .set_default(
                "chain.acl_contract",
                "0x0000000000000000000000000000000000000000",
            )?
            .set_default(
                "chain.tee_compute_manager_contract",
                "0x0000000000000000000000000000000000000000",
            )?
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
