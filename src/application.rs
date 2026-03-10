use alloy_signer_local::PrivateKeySigner;
use axum::{
    Json, Router,
    extract::State,
    http::header::AUTHORIZATION,
    routing::{get, post},
};
use axum_prometheus::PrometheusMetricLayer;
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::{Value, json};
use tokio::{net::TcpListener, signal};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::crypto::load_signer;
use crate::handlers;
use crate::kms::KmsClient;
use crate::repository::DataRepository;
use crate::rpc::NoxClient;

/// Shared application state injected into every Axum handler via [`State`].
#[derive(Clone)]
pub struct AppState {
    pub nox_client: NoxClient,
    pub config: Config,
    pub kms_client: KmsClient,
    pub metrics_handle: PrometheusHandle,
    pub repository: DataRepository,
    pub signer: PrivateKeySigner,
}

/// Top-level application builder and entry point.
///
/// Call [`Application::new`] with a loaded [`Config`], then [`Application::run`]
/// to initialise all dependencies and start the HTTP server.
pub struct Application {
    config: Config,
}

impl Application {
    /// Creates a new application instance from the provided configuration.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Builds the Axum [`Router`] with all routes, middleware layers, and shared state.
    fn build_router(state: AppState, prometheus_layer: PrometheusMetricLayer<'static>) -> Router {
        debug!("Building application router");

        let cors = CorsLayer::new()
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([AUTHORIZATION])
            .allow_origin(tower_http::cors::Any);

        Router::new()
            .route("/", get(Self::root))
            .route("/handles/status", post(handlers::handle_status))
            .route("/health", get(Self::health_check))
            .route("/metrics", get(Self::metrics))
            .route("/v0/compute/operands", get(handlers::get_operand_handles))
            .route("/v0/compute/results", post(handlers::publish_results))
            .route("/v0/secrets", post(handlers::create_handle))
            .route(
                "/v0/secrets/{handle}",
                get(handlers::get_handle_crypto_material),
            )
            .with_state(state)
            .layer(TraceLayer::new_for_http())
            .layer(cors)
            .layer(prometheus_layer)
    }

    /// Initialises all dependencies and runs the HTTP server until a shutdown signal.
    ///
    /// Startup order:
    /// 1. Load EIP-712 signer from `config.signer.wallet_key`
    /// 2. Connect to NoxCompute on-chain, fetch the KMS public key
    /// 3. Build [`KmsClient`] and validate the S3 bucket
    /// 4. Bind the TCP listener and serve until `SIGTERM` / `Ctrl+C`
    pub async fn run(self) -> anyhow::Result<()> {
        let signer = load_signer(&self.config.signer.wallet_key)?;
        info!("EIP-712 signer address: {}", signer.address());

        let nox_client: NoxClient = NoxClient::new(
            &self.config.chain.rpc_url,
            self.config.chain.nox_compute_contract,
        )
        .await?;
        let kms_public_key = nox_client.kms_public_key().await?;
        let kms_client = KmsClient::new(
            self.config.kms.url.clone(),
            kms_public_key,
            self.config.kms.signer_address,
        )?;
        let repository = DataRepository::new(&self.config.s3).await?;

        let (prometheus_layer, metrics_handle) = PrometheusMetricLayer::pair();
        let state = AppState {
            nox_client,
            config: self.config.clone(),
            kms_client,
            metrics_handle,
            repository,
            signer,
        };

        let address = self.config.bind_addr();
        info!("Starting Handle Gateway on {address}");
        let listener = TcpListener::bind(address).await?;
        axum::serve(listener, Self::build_router(state, prometheus_layer))
            .with_graceful_shutdown(Self::shutdown_signal())
            .await?;

        Ok(())
    }

    /// `GET /health` — returns `{"status":"ok"}`.
    async fn health_check() -> Json<Value> {
        Json(json!({"status": "ok"}))
    }

    /// `GET /` — returns service name and current UTC timestamp.
    async fn root() -> Json<Value> {
        Json(json!({
            "service": "Handle Gateway",
            "timestamp": Utc::now().to_rfc3339()
        }))
    }

    /// `GET /metrics` — renders Prometheus metrics as plain text.
    async fn metrics(State(state): State<AppState>) -> String {
        state.metrics_handle.render()
    }

    /// Resolves when `SIGTERM` or `Ctrl+C` is received, triggering graceful shutdown.
    async fn shutdown_signal() {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C, shutting down gracefully...");
            },
            _ = terminate => {
                info!("Received SIGTERM, shutting down gracefully...");
            },
        }

        warn!("Shutdown signal received, cleaning up...");
    }
}
