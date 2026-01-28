use std::path::Path;

use alloy_signer_local::PrivateKeySigner;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use axum_prometheus::PrometheusMetricLayer;
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusHandle;
use rand_core::OsRng;
use serde_json::{Value, json};
use tokio::{net::TcpListener, signal};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, info, warn};

use crate::config::{Config, SignerConfig};
use crate::handlers;
use crate::kms::KmsClient;
use crate::repository::DataRepository;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub kms_client: KmsClient,
    pub metrics_handle: PrometheusHandle,
    pub repository: DataRepository,
    pub signer: PrivateKeySigner,
}

pub struct Application {
    config: Config,
}

impl Application {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn build_router(state: AppState, prometheus_layer: PrometheusMetricLayer<'static>) -> Router {
        debug!("Building application router");

        let cors = CorsLayer::permissive()
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_origin(tower_http::cors::Any);

        Router::new()
            .route("/", get(Self::root))
            .route("/health", get(Self::health_check))
            .route("/metrics", get(Self::metrics))
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

    pub async fn run(self) -> anyhow::Result<()> {
        let signer = Self::load_or_create_signer(&self.config.signer)?;
        info!("EIP-712 signer address: {}", signer.address());

        let kms_client = KmsClient::new(self.config.kms.url.clone()).await?;
        let repository = DataRepository::new(&self.config.server.backend_url).await?;

        let (prometheus_layer, metrics_handle) = PrometheusMetricLayer::pair();
        let state = AppState {
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

    async fn health_check() -> Json<Value> {
        Json(json!({"status": "ok"}))
    }

    async fn root() -> Json<Value> {
        Json(json!({
            "service": "Handle Gateway",
            "timestamp": Utc::now().to_rfc3339()
        }))
    }

    async fn metrics(State(state): State<AppState>) -> String {
        state.metrics_handle.render()
    }

    fn load_or_create_signer(config: &SignerConfig) -> anyhow::Result<PrivateKeySigner> {
        let path = &config.keystore_filename;
        let password = &config.keystore_password;

        if path.exists() {
            debug!("Loading signer from keystore: {}", path.display());
            PrivateKeySigner::decrypt_keystore(path, password)
                .map_err(|e| anyhow::anyhow!("Failed to decrypt keystore: {e}"))
        } else {
            debug!("Creating new signer keystore: {}", path.display());
            Self::create_keystore(path, password)
        }
    }

    fn create_keystore(path: &Path, password: &str) -> anyhow::Result<PrivateKeySigner> {
        let dir = path.parent().unwrap_or(Path::new("."));
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid keystore path"))?;

        if !dir.exists() && !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }

        let mut rng = OsRng;
        let (signer, _) = PrivateKeySigner::encrypt_keystore(
            dir,
            &mut rng,
            PrivateKeySigner::random().credential().to_bytes(),
            password,
            Some(filename),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create keystore: {e}"))?;

        Ok(signer)
    }

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
