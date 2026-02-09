pub mod acl;
pub mod application;
pub mod config;
pub mod crypto;
pub mod error;
pub mod handlers;
pub mod kms;
pub mod repository;
pub mod s3;
pub mod types;
pub mod utils;
pub mod validation;

use tracing::{debug, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use application::Application;
use config::Config;

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
    debug!("Configuration loaded");

    Application::new(config).run().await?;

    Ok(())
}
