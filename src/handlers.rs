use axum::Json;

use crate::error::AppError;
use crate::types::{HandleRequest, HandleResponse};

pub async fn create_handle(
    Json(_request_body): Json<HandleRequest>,
) -> Result<Json<HandleResponse>, AppError> {
    // Handle: 32 bytes (0x + 64 hex digits)
    // InputProof: 117 bytes (0x + 234 hex digits)
    Ok(Json(HandleResponse {
        handle: format!("0x{}", "0".repeat(64)),
        input_proof: format!("0x{}", "0".repeat(234)),
    }))
}
