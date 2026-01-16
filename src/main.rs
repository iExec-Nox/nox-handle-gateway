pub mod application;
pub mod config;
pub mod error;
pub mod handlers;
pub mod kms;
pub mod types;

use alloy_signer_local::PrivateKeySigner;
use application::Application;
use config::Config;
use kms::KmsPublicKey;
use metrics_exporter_prometheus::PrometheusHandle;
use tracing::{debug, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Config,
    pub signer: PrivateKeySigner,
    pub metrics_handle: PrometheusHandle,
    pub kms_public_key: KmsPublicKey,
}

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
