use alloy_primitives::U256;
use axum::{Json, extract::State};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;
use crate::error::AppError;
use crate::types::{Handle, HandleRequest, HandleResponse, InputProof};

pub async fn create_handle(
    State(state): State<AppState>,
    Json(request): Json<HandleRequest>,
) -> Result<Json<HandleResponse>, AppError> {
    // TODO: use ciphertext when encryption is implemented
    let data = request.value.to_string().into_bytes();

    let handle = Handle::new(
        &data,
        state.config.chain.contract_address,
        state.config.chain.id,
        request.solidity_type,
    );

    let created_at = U256::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs(),
    );

    let input_proof = InputProof::new(&state, &handle, request.owner, created_at)?;

    Ok(Json(HandleResponse {
        handle,
        input_proof,
    }))
}
