pub mod config;
pub mod error;
pub mod handlers;
pub mod server;
pub mod types;

use config::Config;
use server::Server;

use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::load().map_err(|e| {
        error!("Failed to load configuration: {e}");
        e
    })?;
    debug!("Configuration loaded: {:?}", config);

    info!("Starting nox-handle-gateway on {}", config.bind_addr());
    let server = Server::new(config);
    server.run().await?;

    Ok(())
}
