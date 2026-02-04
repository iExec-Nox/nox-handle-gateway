use alloy_signer_local::PrivateKeySigner;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use axum_prometheus::PrometheusMetricLayer;
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::{Value, json};
use tokio::{net::TcpListener, signal};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, info, warn};

use crate::acl::AclClient;
use crate::config::Config;
use crate::crypto::load_or_create_signer;
use crate::handlers;
use crate::kms::KmsClient;
use crate::repository::DataRepository;

#[derive(Clone)]
pub struct AppState {
    pub acl_client: AclClient,
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

    pub async fn run(self) -> anyhow::Result<()> {
        let signer = load_or_create_signer(&self.config.signer)?;
        info!("EIP-712 signer address: {}", signer.address());

        let acl_client = AclClient::new(
            &self.config.chain.rpc_url,
            self.config.chain.tee_compute_manager_contract,
        )?;
        let kms_client = KmsClient::new(self.config.kms.url.clone(), self.config.chain.id).await?;
        let repository = DataRepository::new(&self.config.server.backend_url).await?;

        let (prometheus_layer, metrics_handle) = PrometheusMetricLayer::pair();
        let state = AppState {
            acl_client,
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
