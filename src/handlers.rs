use alloy_primitives::{B256, U256};
use alloy_signer::SignerSync;
use alloy_sol_types::eip712_domain;
use axum::{Json, extract::State};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;
use crate::error::AppError;
use crate::types::{
    CiphertextVerification, Handle, HandleRequest, HandleResponse, InputProof, serialize_bytes,
};

pub async fn create_handle(
    State(state): State<AppState>,
    Json(request): Json<HandleRequest>,
) -> Result<Json<HandleResponse>, AppError> {
    // Handle
    // TODO: use ciphertext when encryption is implemented
    let data = request.value.to_string().into_bytes();

    let handle = Handle::new(
        &data,
        state.config.chain.contract_address,
        state.config.chain.id,
        request.solidity_type,
    )
    .to_bytes();

    let serialized_handle = serialize_bytes(&handle);

    // InputProof
    let domain = eip712_domain! {
        name: "TEEComputeManager",
        version: "1",
        chain_id: u64::from(state.config.chain.id),
        verifying_contract: state.config.chain.contract_address,
    };

    let created_at = U256::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs(),
    );

    let verification = CiphertextVerification {
        handle: B256::from(&handle),
        noxACLAddress: request.owner,
        createdAt: created_at,
    };

    let signature = state
        .signer
        .sign_typed_data_sync(&verification, &domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .as_bytes();

    let input_proof = InputProof::new(created_at, request.owner, signature).to_bytes();
    let serialized_input_proof = serialize_bytes(&input_proof);

    // Response
    Ok(Json(HandleResponse {
        handle: serialized_handle,
        input_proof: serialized_input_proof,
    }))
}
