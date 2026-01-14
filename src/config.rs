use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use config::{Config as ConfigBuilder, ConfigError, Environment};
use serde::Deserialize;
use tracing::debug;

// TODO: Simplify the configuration nesting when wallet generation is no longer needed at startup
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub env: EnvConfig,
    pub signer: PrivateKeySigner,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvConfig {
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
    pub contract_address: Address,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let config: EnvConfig = ConfigBuilder::builder()
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 3000)?
            .set_default("chain.id", 1)?
            .set_default(
                "chain.contract_address",
                "0x0000000000000000000000000000000000000000",
            )?
            .add_source(
                Environment::with_prefix("NOX_HANDLE_GATEWAY")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?
            .try_deserialize()?;

        let signer = PrivateKeySigner::random();

        Ok(AppConfig {
            env: config,
            signer,
        })
    }

    pub fn signer_address(&self) -> Address {
        self.signer.address()
    }

    pub fn bind_addr(&self) -> String {
        let addr = format!("{}:{}", self.env.server.host, self.env.server.port);
        debug!("Binding address: {}", addr);
        addr
    }
}
