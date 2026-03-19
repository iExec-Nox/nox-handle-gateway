use alloy_signer_local::PrivateKeySigner;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderName, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post},
};
use axum_prometheus::{
    Handle, MakeDefaultHandle, PrometheusMetricLayer, PrometheusMetricLayerBuilder,
};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::{Value, json};
use tokio::{net::TcpListener, signal};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::crypto::CryptoService;
use crate::handlers;
use crate::kms::KmsClient;
use crate::repository::DataRepository;
use crate::rpc::NoxClient;

const ENDPOINT_VERSION: &str = "/v0";
const VERSIONED_PATHS: &str = "/v0/*path";

/// Shared application state injected into every Axum handler via [`State`].
#[derive(Clone)]
pub struct AppState {
    pub nox_client: NoxClient,
    pub config: Config,
    pub crypto_svc: CryptoService,
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
    fn build_router(
        state: AppState,
        prometheus_layer: PrometheusMetricLayer<'static>,
        cors_allowed_headers: Vec<HeaderName>,
    ) -> Router {
        debug!("Building application router");

        let cors = CorsLayer::new()
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers(cors_allowed_headers)
            .allow_origin(tower_http::cors::Any);

        let versioned_routes = Router::new()
            .route("/compute/operands", get(handlers::get_operand_handles))
            .route("/compute/results", post(handlers::publish_results))
            .route("/public/{handle}", get(handlers::public_decrypt))
            .route("/public/handles/status", post(handlers::handle_status))
            .route("/secrets", post(handlers::create_handle))
            .route(
                "/secrets/{handle}",
                get(handlers::get_handle_crypto_material),
            );

        Router::new()
            .route("/", get(Self::root))
            .route("/health", get(Self::health_check))
            .route("/metrics", get(Self::metrics))
            .nest(ENDPOINT_VERSION, versioned_routes)
            .fallback(Self::not_found)
            .with_state(state)
            .layer(TraceLayer::new_for_http())
            .layer(cors)
            .layer(prometheus_layer)
    }

    /// Initialises all dependencies and runs the HTTP server until a shutdown signal.
    ///
    /// Startup order:
    /// 1. Validate CORS allowed headers from config
    /// 2. Load EIP-712 signer from `config.signer.wallet_key`
    /// 3. Connect to NoxCompute on-chain, fetch the KMS public key
    /// 4. Build [`KmsClient`] and validate the S3 bucket
    /// 5. Bind the TCP listener and serve until `SIGTERM` / `Ctrl+C`
    pub async fn run(self) -> anyhow::Result<()> {
        let cors_allowed_headers: Vec<HeaderName> = self
            .config
            .server
            .cors_allowed_headers
            .iter()
            .map(|h| {
                HeaderName::from_bytes(h.as_bytes()).map_err(|_| {
                    anyhow::anyhow!(
                        "Invalid CORS header name in SERVER__CORS_ALLOWED_HEADERS: {h:?}"
                    )
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let signer = CryptoService::load_signer(&self.config.signer.wallet_key)?;
        info!("EIP-712 signer address: {}", signer.address());

        let nox_client: NoxClient = NoxClient::new(
            &self.config.chain.rpc_url,
            self.config.chain.nox_compute_contract,
        )
        .await?;
        let kms_public_key = nox_client.kms_public_key().await?;
        let crypto_svc = CryptoService::new(kms_public_key)?;
        let kms_client =
            KmsClient::new(self.config.kms.url.clone(), self.config.kms.signer_address)?;
        let repository = DataRepository::new(&self.config.s3).await?;

        let prometheus_layer = PrometheusMetricLayerBuilder::new()
            .with_allow_patterns(&["/", "/health", "/metrics", VERSIONED_PATHS])
            .build();
        let metrics_handle = Handle::make_default_handle(Handle::default());
        let state = AppState {
            nox_client,
            config: self.config.clone(),
            crypto_svc,
            kms_client,
            metrics_handle,
            repository,
            signer,
        };

        let address = self.config.bind_addr();
        info!("Starting Handle Gateway on {address}");
        let listener = TcpListener::bind(address).await?;
        axum::serve(
            listener,
            Self::build_router(state, prometheus_layer, cors_allowed_headers),
        )
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

    /// Fallback handler for non-existing routes.
    ///
    /// Returns 404 NOT_FOUND to indicate the requested route does not exist.
    pub async fn not_found(uri: Uri) -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error":format!("Route not found {}", uri.path()) })),
        )
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
