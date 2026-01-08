pub mod config;
pub mod server;

use config::Config;
use server::Server;

use tracing::{debug, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load().map_err(|e| {
        eprintln!("Failed to load configuration: {e}");
        e
    })?;
    debug!("Configuration loaded: {:?}", config);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| config.log_level.clone().into());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting nox-handle-gateway on {}", config.bind_addr());
    let server = Server::new(config);
    server.run().await?;

    Ok(())
}
