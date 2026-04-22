use std::collections::HashMap;

use alloy_primitives::hex;
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

use crate::config::{Config, PerChainConfig};
use crate::crypto::CryptoService;
use crate::error::AppError;
use crate::handlers;
use crate::kms::KmsClient;
use crate::repository::DataRepository;
use crate::rpc::NoxClient;

const ENDPOINT_VERSION: &str = "/v0";
const VERSIONED_PATHS: &str = "/v0/{*path}";

/// Shared application state injected into every Axum handler via [`State`].
#[derive(Clone)]
pub struct AppState {
    pub nox_clients: HashMap<u32, NoxClient>,
    pub config: Config,
    pub crypto_svc: CryptoService,
    pub kms_client: KmsClient,
    pub metrics_handle: PrometheusHandle,
    pub repository: DataRepository,
    pub signers: HashMap<u32, PrivateKeySigner>,
}

impl AppState {
    /// Returns the [`NoxClient`] for `chain_id`, or [`AppError::UnknownChain`].
    pub fn nox_client(&self, chain_id: u32) -> Result<&NoxClient, AppError> {
        self.nox_clients
            .get(&chain_id)
            .ok_or(AppError::UnknownChain(chain_id))
    }

    /// Returns the [`PerChainConfig`] for `chain_id`, or [`AppError::UnknownChain`].
    pub fn chain_cfg(&self, chain_id: u32) -> Result<&PerChainConfig, AppError> {
        self.config
            .chains
            .get(&chain_id)
            .ok_or(AppError::UnknownChain(chain_id))
    }

    /// Returns the [`PrivateKeySigner`] for `chain_id`, or [`AppError::UnknownChain`].
    pub fn signer(&self, chain_id: u32) -> Result<&PrivateKeySigner, AppError> {
        self.signers
            .get(&chain_id)
            .ok_or(AppError::UnknownChain(chain_id))
    }
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
    /// 2. Validate at least one chain is configured
    /// 3. For each chain: connect to NoxCompute, fetch KMS public key, load signer,
    ///    cross-check signer address against on-chain `gateway()` address
    /// 4. Build [`CryptoService`] with per-chain KMS public keys
    /// 5. Build [`KmsClient`] and validate S3 buckets
    /// 6. Bind the TCP listener and serve until `SIGTERM` / `Ctrl+C`
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

        if self.config.chains.is_empty() {
            anyhow::bail!("at least one chain must be configured");
        }

        let mut nox_clients: HashMap<u32, NoxClient> = HashMap::new();
        let mut protocol_keys = HashMap::new();
        let mut signers: HashMap<u32, PrivateKeySigner> = HashMap::new();

        for (chain_id, chain_cfg) in &self.config.chains {
            let chain_id = *chain_id;

            let nox_client =
                NoxClient::new(&chain_cfg.rpc_url, chain_cfg.nox_compute_contract).await?;

            let kms_public_key = nox_client.kms_public_key().await?;

            let signer = CryptoService::load_signer(&chain_cfg.wallet_key)?;

            let onchain_gateway = nox_client.gateway_address().await?;

            if signer.address() != onchain_gateway {
                anyhow::bail!(
                    "chain {chain_id}: wallet address {} does not match on-chain gateway {}",
                    signer.address(),
                    onchain_gateway
                );
            }

            info!(
                nox_compute = %chain_cfg.nox_compute_contract,
                rpc = %chain_cfg.rpc_url,
                kms_pubkey = %hex::encode(&kms_public_key.to_sec1_bytes()[..4]),
                gateway_addr = %onchain_gateway,
                "Chain configuration complete for chain {chain_id}"
            );

            nox_clients.insert(chain_id, nox_client);
            protocol_keys.insert(chain_id, kms_public_key);
            signers.insert(chain_id, signer);
        }

        let crypto_svc = CryptoService::new(protocol_keys)?;
        let kms_client =
            KmsClient::new(self.config.kms.url.clone(), self.config.kms.signer_address)?;
        let repository = DataRepository::new(&self.config.chains).await?;

        let prometheus_layer = PrometheusMetricLayerBuilder::new()
            .with_allow_patterns(&["/", "/health", "/metrics", VERSIONED_PATHS])
            .build();
        let metrics_handle = Handle::make_default_handle(Handle::default());
        let state = AppState {
            nox_clients,
            config: self.config.clone(),
            crypto_svc,
            kms_client,
            metrics_handle,
            repository,
            signers,
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
