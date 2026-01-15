use alloy_primitives::Address;
use config::{Config as ConfigBuilder, ConfigError, Environment};
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub chain: ChainConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub id: u32,
    pub acl_contract: Address,
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
            .add_source(
                Environment::with_prefix("NOX_HANDLE_GATEWAY")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?;

        config.try_deserialize()
    }

    pub fn bind_addr(&self) -> String {
        let addr = format!("{}:{}", self.server.host, self.server.port);
        debug!("Binding address: {}", addr);
        addr
    }
}
