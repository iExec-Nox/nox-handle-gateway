//! Handle Gateway for the Nox Compute protocol.
//!
//! Accepts plaintext values from clients, encrypts them under the KMS public
//! key via ECIES, stores the resulting ciphertexts in S3 under an
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
mod observability;
pub mod repository;
pub mod rpc;
pub mod types;
pub mod validation;

use opentelemetry::{KeyValue, global, trace::TracerProvider};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource, logs::SdkLoggerProvider, propagation::TraceContextPropagator,
    trace::SdkTracerProvider,
};
use tracing::{debug, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use validator::Validate;

use crate::application::Application;
use crate::config::Config;

fn init_logs(url: &str, resource: Resource) -> anyhow::Result<SdkLoggerProvider> {
    let exporter = LogExporter::builder()
        .with_http()
        .with_endpoint(format!("{}/v1/logs", url))
        .with_protocol(Protocol::HttpBinary)
        .build()?;

    Ok(SdkLoggerProvider::builder()
        .with_simple_exporter(exporter)
        .with_resource(resource)
        .build())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let config = Config::load().map_err(|e| {
        error!("Failed to load configuration: {e}");
        e
    })?;
    config
        .validate()
        .inspect_err(|e| error!("Invalid configuration: {e}"))?;
    debug!("Configuration loaded");

    let tracing_registry = tracing_subscriber::registry()
        //.with(observability::TracingEventsCountLayer)
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer());

    if config.otel.enabled {
        let exporter = SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/traces", config.otel.url))
            .with_protocol(Protocol::HttpBinary)
            .build()?;

        let resource = Resource::builder()
            .with_attribute(KeyValue::new("service.name", "nox-handle-gateway"))
            .build();

        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .with_resource(resource.clone())
            .build();

        global::set_text_map_propagator(TraceContextPropagator::new());
        global::set_tracer_provider(provider.clone());

        let telemetry_layer =
            tracing_opentelemetry::layer().with_tracer(provider.tracer("nox-handle-gateway"));

        let log_provider = init_logs(&config.otel.url, resource.clone())?;

        tracing_registry
            .with(telemetry_layer)
            .with(OpenTelemetryTracingBridge::new(&log_provider))
            .init();
    } else {
        tracing_registry.init();
    }

    Application::new(config).run().await?;

    Ok(())
}
