use axum::{Json, extract::State};

use crate::config::Config;
use crate::error::AppError;
use crate::types::{Handle, HandleRequest, HandleResponse};

pub async fn create_handle(
    State(config): State<Config>,
    Json(request): Json<HandleRequest>,
) -> Result<Json<HandleResponse>, AppError> {
    // TODO: use ciphertext when encryption is implemented
    let data = request.value.to_string().into_bytes();

    let handle = Handle::new(
        &data,
        config.chain.contract_address,
        config.chain.id,
        request.solidity_type,
    );

    // TODO: Implement real proof
    let input_proof = format!("0x{}", "0".repeat(234));

    Ok(Json(HandleResponse {
        handle,
        input_proof,
    }))
}
