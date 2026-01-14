use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::U256;
use axum::{Json, extract::State};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::types::{Handle, HandleRequest, HandleResponse, InputProof};

pub async fn create_handle(
    State(config): State<AppConfig>,
    Json(request): Json<HandleRequest>,
) -> Result<Json<HandleResponse>, AppError> {
    // TODO: use ciphertext when encryption is implemented
    let data = request.value.to_string().into_bytes();

    let handle = Handle::new(
        &data,
        config.env.chain.contract_address,
        config.env.chain.id,
        request.solidity_type,
    );

    let created_at = U256::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs(),
    );

    let input_proof = InputProof::new(&config, &handle, request.owner, created_at)?;

    Ok(Json(HandleResponse {
        handle,
        input_proof,
    }))
}
