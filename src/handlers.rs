use alloy_primitives::{Address, B256, U256};
use alloy_signer::SignerSync;
use alloy_sol_types::eip712_domain;
use axum::{
    Json,
    extract::{Path, State},
    http::header::HeaderMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::NaiveDateTime;
use reqwest::header;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::application::AppState;
use crate::crypto::ecies_encrypt;
use crate::error::AppError;
use crate::repository::HandleEntry;
use crate::types::{CiphertextVerification, Handle, InputProof, SolidityType, serialize_bytes};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleRequest {
    value: serde_json::Value,
    solidity_type: SolidityType,
    owner: Address,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleResponse {
    handle: String,
    input_proof: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayDelegateRequest {
    user_address: Address,
    encryption_pub_key: String,
    not_before: U256,
    expires_at: U256,
    signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayDelegateResponse {
    ciphertext: String,
    encrypted_shared_secret: String,
    iv: String,
}

pub async fn create_handle(
    State(state): State<AppState>,
    Json(request): Json<HandleRequest>,
) -> Result<Json<HandleResponse>, AppError> {
    // Handle
    let plaintext = request.value.to_string().into_bytes();
    let ecies_ciphertext = ecies_encrypt(&plaintext, &state.kms_client.public_key)?;

    let handle = Handle::new(
        &ecies_ciphertext.ciphertext,
        state.config.chain.acl_contract,
        state.config.chain.id,
        request.solidity_type,
    )
    .to_bytes();

    let serialized_handle = serialize_bytes(&handle);

    let entry = HandleEntry {
        handle: serialized_handle.clone(),
        ciphertext: serialize_bytes(&ecies_ciphertext.ciphertext),
        public_key: serialize_bytes(&ecies_ciphertext.ephemeral_pubkey),
        nonce: serialize_bytes(&ecies_ciphertext.nonce),
        owner: request.owner.to_string(),
        created_at: NaiveDateTime::default(),
    };
    let new_handle = state.repository.create_handle(&entry).await?;

    // InputProof
    let domain = eip712_domain! {
        name: "TEEComputeManager",
        version: "1",
        chain_id: u64::from(state.config.chain.id),
        verifying_contract: state.config.chain.acl_contract,
    };

    let created_at = U256::from(new_handle.created_at.and_utc().timestamp());

    let verification = CiphertextVerification {
        handle: B256::from(&handle),
        owner: request.owner,
        ACL: state.config.chain.acl_contract,
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

pub async fn get_handle_crypto_material(
    Path(handle): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<GatewayDelegateResponse>, AppError> {
    info!("query for handle {}", handle);
    let authorization = headers
        .get(header::AUTHORIZATION)
        .ok_or(AppError::Unauthorized("header missing".to_string()))?;
    let auth_bytes = STANDARD
        .decode(authorization)
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;
    let request: GatewayDelegateRequest =
        serde_json::from_slice(&auth_bytes).map_err(|e| AppError::Unauthorized(e.to_string()))?;
    let entry = state.repository.fetch_handle(&handle).await?;
    info!(
        "request for handle {} with key {}",
        handle, request.encryption_pub_key
    );
    let encrypted_shared_secret = state
        .kms_client
        .get_encrypted_shared_secret(entry.public_key, request.encryption_pub_key)
        .await?;
    Ok(Json(GatewayDelegateResponse {
        ciphertext: entry.ciphertext,
        encrypted_shared_secret,
        iv: entry.nonce,
    }))
}
