use alloy_primitives::{Address, B256, U256, hex};
use alloy_signer::{Signature, SignerSync};
use alloy_sol_types::{SolStruct, eip712_domain};
use axum::{
    Json,
    extract::{Path, State},
    http::header::HeaderMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{NaiveDateTime, TimeZone, Utc};
use reqwest::header;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::application::AppState;
use crate::crypto::ecies_encrypt;
use crate::error::AppError;
use crate::repository::HandleEntry;
use crate::types::{
    CiphertextVerification, DataAccessAuthorization, Handle, InputProof, SolidityType,
    serialize_bytes,
};

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
struct GatewayDelegateAuthorization {
    payload: DataAccessAuthorization,
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
    info!("get_handle_crypto_material query for handle {}", handle);
    let token = headers
        .get(header::AUTHORIZATION)
        .ok_or(AppError::Unauthorized("header missing".to_string()))?;
    let token_bytes = STANDARD
        .decode(token)
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;
    let authorization: GatewayDelegateAuthorization =
        serde_json::from_slice(&token_bytes).map_err(|e| AppError::Unauthorized(e.to_string()))?;

    let domain = eip712_domain! {
        name: "Handle Gateway",
        version: "1",
        chain_id: u64::from(state.config.chain.id),
        verifying_contract: state.config.chain.acl_contract,
    };
    let payload = authorization.payload;
    let hash = payload.eip712_signing_hash(&domain);
    let signature_bytes = hex::decode(authorization.signature.trim_start_matches("0x"))
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;
    let signature =
        Signature::from_raw(&signature_bytes).map_err(|e| AppError::Unauthorized(e.to_string()))?;
    let recovered_address = signature
        .recover_address_from_prehash(&hash)
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;

    if payload.userAddress != recovered_address {
        warn!(
            user = payload.userAddress.to_string(),
            recovered = recovered_address.to_string(),
            "revovered address mismatch",
        );
        return Err(AppError::Unauthorized("invalid signature".to_string()));
    }

    let now = U256::from(Utc::now().timestamp());
    if now < payload.notBefore || payload.expiresAt < now {
        warn!(
            not_before = Utc
                .timestamp_opt(payload.notBefore.to::<i64>(), 0)
                .unwrap()
                .to_string(),
            expires_at = Utc
                .timestamp_opt(payload.expiresAt.to::<i64>(), 0)
                .unwrap()
                .to_string(),
            "token is not active or expired",
        );
        return Err(AppError::Unauthorized(
            "token is not active or expired".to_string(),
        ));
    }

    let entry = state.repository.fetch_handle(&handle).await?;
    info!(
        "request for handle {} with key {}",
        handle, payload.encryptionPubKey
    );
    let encrypted_shared_secret = state
        .kms_client
        .get_encrypted_shared_secret(entry.public_key, payload.encryptionPubKey)
        .await?;
    Ok(Json(GatewayDelegateResponse {
        ciphertext: entry.ciphertext,
        encrypted_shared_secret,
        iv: entry.nonce,
    }))
}
