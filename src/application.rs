use std::collections::HashMap;
use std::time::Duration;

use alloy::{primitives::hex, signers::local::PrivateKeySigner};
use anyhow::{Context, anyhow};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderName, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_prometheus::{
    Handle, MakeDefaultHandle, PrometheusMetricLayer, PrometheusMetricLayerBuilder,
    metrics_exporter_prometheus::PrometheusHandle,
};
use chrono::Utc;
use serde_json::{Value, json};
use tokio::{net::TcpListener, signal};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::crypto::CryptoService;
use crate::error::AppError;
use crate::handlers;
use crate::kms::KmsClient;
use crate::repository::DataRepository;
use crate::rpc::NoxClient;

const ENDPOINT_VERSION: &str = "/v0";
const VERSIONED_PATHS: &str = "/v0/{*path}";

/// Wall-clock ceiling on `/`, `/health`, and `/metrics`.
///
/// Not configurable, and independent of [`crate::config::ServerConfig::request_timeout`]:
/// these routes touch no external dependency — not even the KMS client, whose own
/// saturation only ever affects `versioned_routes` — so anything slower than a few seconds
/// here is a stuck process or a client dribbling out its request, never legitimate work.
const SERVICE_ROUTE_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Verify that a `chain_id` is configured
    pub fn verify_chain(&self, chain_id: u32) -> bool {
        self.config.chains.contains_key(&chain_id)
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
    ///
    /// Timeouts are attached per route group *before* the shared layers, which puts them
    /// innermost. That ordering is load-bearing: the trace, CORS, and Prometheus layers all
    /// sit outside, so each observes the 408 response. Were the timeout outermost instead,
    /// elapsing would drop their futures and a timed-out request would go unlogged and
    /// uncounted.
    fn build_router(
        state: AppState,
        prometheus_layer: PrometheusMetricLayer<'static>,
        cors_allowed_headers: Vec<HeaderName>,
        request_timeout: Duration,
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
            )
            .layer(middleware::from_fn(move |request, next| {
                Self::enforce_timeout(request_timeout, request, next)
            }));

        let service_routes = Router::new()
            .route("/", get(Self::root))
            .route("/health", get(Self::health_check))
            .route("/metrics", get(Self::metrics))
            .layer(middleware::from_fn(move |request, next| {
                Self::enforce_timeout(SERVICE_ROUTE_TIMEOUT, request, next)
            }));

        Router::new()
            .merge(service_routes)
            .nest(ENDPOINT_VERSION, versioned_routes)
            .fallback(Self::not_found)
            .with_state(state)
            .layer(TraceLayer::new_for_http())
            .layer(cors)
            .layer(prometheus_layer)
    }

    /// Abandons a request that exceeds `limit`, answering [`AppError::Timeout`] (408).
    ///
    /// Bounds everything the handler does, including body extraction, time queued on the KMS
    /// semaphore, and the S3 and delegate calls made once a permit is granted. The KMS
    /// semaphore wait is separately bounded by [`crate::kms::KmsClient`]'s own acquire
    /// timeout, but that only covers the queueing, not the request as a whole — this
    /// middleware is what keeps the total, end to end, from exceeding `limit`.
    ///
    /// Returning [`AppError`] rather than using `tower_http::timeout::TimeoutLayer` is
    /// deliberate: that layer answers with an empty body, whereas callers get the same
    /// `{"error", "message"}` envelope here as for every other rejection.
    ///
    /// Does not cover a slow response body, nor the TCP accept and TLS handshake, neither of
    /// which is reached through this middleware.
    async fn enforce_timeout(
        limit: Duration,
        request: Request,
        next: Next,
    ) -> Result<Response, AppError> {
        tokio::time::timeout(limit, next.run(request))
            .await
            .map_err(|_| AppError::Timeout)
    }

    /// Initialises all dependencies and runs the HTTP server until a shutdown signal.
    ///
    /// Startup order:
    /// 1. For each chain: connect to NoxCompute, fetch KMS public key, load signer,
    ///    cross-check signer address against on-chain `gateway()` address
    /// 2. Build [`CryptoService`] with per-chain KMS public keys
    /// 3. Build [`KmsClient`] and validate S3 buckets
    /// 4. Bind the TCP listener and serve until `SIGTERM` / `Ctrl+C`
    pub async fn run(self) -> anyhow::Result<()> {
        let prometheus_layer = PrometheusMetricLayerBuilder::new()
            .with_allow_patterns(&["/", "/health", "/metrics", VERSIONED_PATHS])
            .build();
        // Moved before for loop to correctly initialize metrics when calling init_metrics
        let metrics_handle = Handle::make_default_handle(Handle::default());
        let cors_allowed_headers = self.config.server.cors_allowed_headers.clone();

        let kms_client = KmsClient::new(&self.config.kms)?;

        let mut nox_clients: HashMap<u32, NoxClient> = HashMap::new();
        let mut protocol_keys = HashMap::new();
        let mut signers: HashMap<u32, PrivateKeySigner> = HashMap::new();

        for (chain_id, chain_cfg) in &self.config.chains {
            let chain_id = *chain_id;

            let nox_client = NoxClient::new(
                &chain_cfg.rpc_url,
                chain_cfg.call_timeout,
                chain_cfg.connect_timeout,
                chain_cfg.nox_compute_contract_address,
            )
            .await?;

            let kms_public_key = nox_client.kms_public_key().await?;

            let signer = chain_cfg
                .load_signer()
                .with_context(|| format!("chain {chain_id}"))?;

            let onchain_gateway = nox_client.gateway_address().await?;

            if signer.address() != onchain_gateway {
                anyhow::bail!(
                    "chain {chain_id}: wallet address {} does not match on-chain gateway {onchain_gateway}",
                    signer.address(),
                );
            }

            if nox_clients.insert(chain_id, nox_client.clone()).is_some() {
                return Err(anyhow!(
                    "Failed to register Nox client {nox_client:#?} for chain {chain_id}"
                ));
            };
            if protocol_keys.insert(chain_id, kms_public_key).is_some() {
                return Err(anyhow!(
                    "Failed to register protocol key {} for chain {chain_id}",
                    hex::encode_prefixed(kms_public_key.to_sec1_bytes())
                ));
            };
            if signers.insert(chain_id, signer.clone()).is_some() {
                return Err(anyhow!(
                    "Failed to register private signer {} for chain {chain_id}",
                    signer.address()
                ));
            };
            info!(
                nox_compute = %chain_cfg.nox_compute_contract_address,
                rpc = %chain_cfg.rpc_url,
                kms_pubkey = %hex::encode_prefixed(kms_public_key.to_sec1_bytes()),
                gateway_addr = %onchain_gateway,
                "Chain configuration complete for chain {chain_id}"
            );
            handlers::init_metrics(chain_id);
            kms_client.init_metrics(chain_id);
        }

        let crypto_svc = CryptoService::new(protocol_keys)?;
        let repository =
            DataRepository::new(&self.config.chains, self.config.s3_max_concurrent_requests)
                .await?;

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
            Self::build_router(
                state,
                prometheus_layer,
                cors_allowed_headers,
                self.config.server.request_timeout,
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    /// Outlives any limit these tests set, so it only ever completes by being timed out.
    async fn slow_handler() -> &'static str {
        tokio::time::sleep(Duration::from_secs(60)).await;
        "unreachable"
    }

    async fn fast_handler() -> &'static str {
        "ok"
    }

    /// Mirrors how [`Application::build_router`] attaches the timeout: innermost, wrapping
    /// the routes only.
    fn router(limit: Duration) -> Router {
        Router::new()
            .route("/slow", get(slow_handler))
            .route("/fast", get(fast_handler))
            .layer(middleware::from_fn(move |request, next| {
                Application::enforce_timeout(limit, request, next)
            }))
    }

    /// Named `send` rather than `get` so it does not shadow [`axum::routing::get`] above.
    async fn send(uri: &str, limit: Duration) -> Response {
        router(limit)
            .oneshot(
                HttpRequest::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router is infallible")
    }

    #[tokio::test(start_paused = true)]
    async fn handler_exceeding_the_limit_answers_408() {
        let response = send("/slow", Duration::from_secs(1)).await;

        assert_eq!(StatusCode::REQUEST_TIMEOUT, response.status());
    }

    /// The whole reason this is a `from_fn` rather than `tower_http::timeout::TimeoutLayer`:
    /// the 408 carries the same envelope as every other error instead of an empty body.
    #[tokio::test(start_paused = true)]
    async fn timeout_response_carries_the_standard_error_envelope() {
        let response = send("/slow", Duration::from_secs(1)).await;

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let json: Value = serde_json::from_slice(&body).expect("body should be JSON");
        assert_eq!("timeout", json["error"]);
    }

    #[tokio::test(start_paused = true)]
    async fn handler_within_the_limit_is_untouched() {
        let response = send("/fast", Duration::from_secs(1)).await;

        assert_eq!(StatusCode::OK, response.status());
    }
}
