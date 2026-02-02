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
use crate::types::{DataAccessAuthorization, Handle, HandleProof, SolidityType, serialize_bytes};
use crate::validation::decode_and_validate_value;

// EIP-712 domain name for HandleProof generation
const TEE_COMPUTE_MANAGER_EIP712_DOMAIN_NAME: &str = "TEEComputeManager";
// EIP-712 domain name for DataAccessAuthorization validation
const HANDLE_GATEWAY_EIP712_DOMAIN_NAME: &str = "Handle Gateway";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleRequest {
    value: String,
    solidity_type: SolidityType,
    owner: Address,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleResponse {
    handle: String,
    proof: String,
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
    let plaintext = decode_and_validate_value(&request.value, &request.solidity_type)?;
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

    // HandleProof
    let domain = eip712_domain! {
        name: TEE_COMPUTE_MANAGER_EIP712_DOMAIN_NAME,
        version: "1",
        chain_id: u64::from(state.config.chain.id),
        verifying_contract: state.config.chain.tee_compute_manager_contract,
    };

    let created_at = U256::from(new_handle.created_at.and_utc().timestamp());
    let proof = HandleProof {
        handle: B256::from(&handle),
        owner: request.owner,
        acl: state.config.chain.acl_contract,
        createdAt: created_at,
    };

    let signature = state
        .signer
        .sign_typed_data_sync(&proof, &domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .as_bytes();

    let serialized_handle_proof = proof.to_serialized_bytes(signature);

    // Response
    Ok(Json(HandleResponse {
        handle: serialized_handle,
        proof: serialized_handle_proof,
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
        .ok_or(AppError::Unauthorized("header missing".to_string()))?
        .to_str()
        .map_err(|e| AppError::Unauthorized(e.to_string()))?
        .trim_start_matches("EIP712 ");
    let token_bytes = STANDARD
        .decode(token)
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;
    let authorization: GatewayDelegateAuthorization =
        serde_json::from_slice(&token_bytes).map_err(|e| AppError::Unauthorized(e.to_string()))?;

    let domain = eip712_domain! {
        name: HANDLE_GATEWAY_EIP712_DOMAIN_NAME,
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
            "recovered address mismatch",
        );
        return Err(AppError::Unauthorized("invalid signature".to_string()));
    }

    let now = U256::from(Utc::now().timestamp());
    if now < payload.notBefore || payload.expiresAt <= now {
        warn!(
            not_before = format_timestamp(payload.notBefore),
            expires_at = format_timestamp(payload.expiresAt),
            "token is not active or expired",
        );
        return Err(AppError::Unauthorized(
            "token is not active or expired".to_string(),
        ));
    }

    let handle_raw = hex::decode(handle.trim_start_matches("0x"))
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;
    if handle_raw.len() != 32 {
        return Err(AppError::Unauthorized("invalid handle".to_string()));
    }
    let handle_b256 = B256::from_slice(&handle_raw);
    state
        .acl_client
        .check_access(handle_b256, payload.userAddress)
        .await?;

    let entry = state.repository.fetch_handle(&handle).await?;

    info!(
        "request for handle {} with key {}",
        handle, payload.encryptionPubKey
    );
    let encrypted_shared_secret = state
        .kms_client
        .get_encrypted_shared_secret(
            &entry.public_key,
            &payload.encryptionPubKey,
            &state.signer,
            state.config.chain.id,
        )
        .await?;
    Ok(Json(GatewayDelegateResponse {
        ciphertext: entry.ciphertext,
        encrypted_shared_secret,
        iv: entry.nonce,
    }))
}

fn format_timestamp(ts: U256) -> String {
    ts.try_into()
        .ok()
        .and_then(|secs| Utc.timestamp_opt(secs, 0).single())
        .map(|dt| dt.to_string())
        .unwrap_or_else(|| format!("invalid({ts})"))
}
