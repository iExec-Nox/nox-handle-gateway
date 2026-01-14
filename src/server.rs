use axum::{
    Json, Router,
    routing::{get, post},
};
use chrono::Utc;
use serde_json::{Value, json};
use tokio::{net::TcpListener, signal};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, info, warn};

use crate::config::AppConfig;
use crate::handlers;

pub struct Server {
    config: AppConfig,
}

impl Server {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    fn build_router(&self) -> Router {
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
            .route("/v0/secrets", post(handlers::create_handle))
            .with_state(self.config.clone())
            .layer(TraceLayer::new_for_http())
            .layer(cors)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let addr = self.config.bind_addr();
        let listener = TcpListener::bind(&addr).await?;

        info!("Listening on {}", addr);

        axum::serve(listener, self.build_router())
            .with_graceful_shutdown(Self::shutdown_signal())
            .await?;

        Ok(())
    }

    async fn health_check() -> Json<Value> {
        Json(json!({"status": "ok"}))
    }

    async fn root() -> Json<Value> {
        Json(json!({
            "service": "nox-handle-gateway",
            "timestamp": Utc::now().to_rfc3339()
        }))
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
