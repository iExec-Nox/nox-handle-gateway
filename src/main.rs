//! Handle Gateway for the Nox Compute protocol.
//!
//! Accepts plaintext values from clients, encrypts them under the KMS public
//! key via ECIES, stores the resulting ciphertexts in S3/MinIO under an
//! immutable Object Lock policy, and issues EIP-712 [`HandleProof`]s for
//! on-chain verification.
//!
//! Serving decryption requests requires a valid EIP-712
//! [`DataAccessAuthorization`] signed by the handle owner, plus an on-chain
//! ACL check against the NoxCompute contract.
//!
//! [`HandleProof`]: crate::types::HandleProof
//! [`DataAccessAuthorization`]: crate::types::DataAccessAuthorization

pub mod application;
pub mod config;
pub mod crypto;
pub mod error;
pub mod handlers;
pub mod kms;
pub mod repository;
pub mod rpc;
pub mod types;
pub mod validation;

use tracing::{debug, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::application::Application;
use crate::config::Config;

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
