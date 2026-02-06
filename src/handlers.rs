use alloy_primitives::{Address, B256, U256, hex};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolStruct, eip712_domain};
use axum::{
    Json,
    extract::{Path, State},
    http::header::HeaderMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{NaiveDateTime, TimeZone, Utc};
use futures::future::join_all;
use reqwest::header;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::application::AppState;
use crate::crypto::ecies_encrypt;
use crate::error::AppError;
use crate::kms::KmsClient;
use crate::repository::HandleEntry;
use crate::types::{DataAccessAuthorization, Handle, HandleProof, SolidityType};
use crate::utils::{serialize_bytes, strip_0x_prefix};
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
    application_contract: Address,
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
    handle: String,
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

    let handle = Handle::new(state.config.chain.id, request.solidity_type).to_bytes();

    let serialized_handle = serialize_bytes(&handle);

    let entry = HandleEntry {
        handle: serialized_handle.clone(),
        ciphertext: serialize_bytes(&ecies_ciphertext.ciphertext),
        public_key: serialize_bytes(&ecies_ciphertext.ephemeral_pubkey),
        nonce: serialize_bytes(&ecies_ciphertext.nonce),
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
        app: request.application_contract,
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
        verifying_contract: state.config.chain.tee_compute_manager_contract,
    };
    let payload = authorization.payload;
    let hash = payload.eip712_signing_hash(&domain);
    let signature_bytes = hex::decode(strip_0x_prefix(&authorization.signature))
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

    let handle_raw =
        hex::decode(strip_0x_prefix(&handle)).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if handle_raw.len() != 32 {
        return Err(AppError::BadRequest("invalid handle".to_string()));
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
        handle,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TEEComputeRequest {
    caller: Address,
    rsa_public_key: String,
    operands: Vec<String>,
    results: Vec<String>,
}

pub async fn get_operand_handles(
    State(state): State<AppState>,
    Json(compute_request): Json<TEEComputeRequest>,
) -> Result<Json<Vec<GatewayDelegateResponse>>, AppError> {
    // TODO check caller has permissions
    debug!("preparing handles for caller {}", compute_request.caller);
    let result_handles: Vec<HandleEntry> = state
        .repository
        .read_handles(&compute_request.results)
        .await;
    debug!("result handles count {}", result_handles.len());
    if !result_handles.is_empty() {
        let unexpected_handles: Vec<String> = result_handles
            .iter()
            .map(|entry| entry.handle.clone())
            .collect();
        error!("unexpected result handles found in handle database {unexpected_handles:?}");
        return Err(AppError::HandleConflict);
    }
    let operand_handles: Vec<HandleEntry> = state
        .repository
        .read_handles(&compute_request.operands)
        .await;
    debug!("operand handles count {}", operand_handles.len());
    if operand_handles.len() != compute_request.operands.len() {
        let missing_handles: Vec<String> = operand_handles
            .iter()
            .map(|entry| entry.handle.clone())
            .filter(|handle| compute_request.operands.contains(handle))
            .collect();
        error!("expected operand handles not found in handle database {missing_handles:?}");
        return Err(AppError::HandleNotFound);
    }
    let operands_crypto_material: Vec<GatewayDelegateResponse> =
        join_all(operand_handles.iter().map(|entry| {
            get_crypto_material_for_entry(
                state.kms_client.clone(),
                entry,
                &compute_request.rsa_public_key,
                &state.signer,
                state.config.chain.id,
            )
        }))
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    if operands_crypto_material.len() != compute_request.operands.len() {
        let missing_handles: Vec<String> = operands_crypto_material
            .iter()
            .map(|crypto_material| crypto_material.handle.clone())
            .filter(|handle| compute_request.operands.contains(handle))
            .collect();
        error!("expected operand handles not prepared {missing_handles:?}");
        return Err(AppError::HandleNotPrepared);
    }
    Ok(Json(operands_crypto_material))
}

async fn get_crypto_material_for_entry(
    kms_client: KmsClient,
    entry: &HandleEntry,
    rsa_public_key: &str,
    signer: &PrivateKeySigner,
    chain_id: u32,
) -> Result<GatewayDelegateResponse, AppError> {
    let encrypted_shared_secret = kms_client
        .get_encrypted_shared_secret(&entry.public_key, rsa_public_key, signer, chain_id)
        .await?;
    info!(
        ciphertext = entry.ciphertext,
        encrypted_shared_secret = encrypted_shared_secret,
        iv = entry.nonce,
        "GatewayDelegateReponse"
    );
    Ok(GatewayDelegateResponse {
        handle: entry.handle.clone(),
        ciphertext: entry.ciphertext.clone(),
        encrypted_shared_secret,
        iv: entry.nonce.clone(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TEEComputeResult {
    chain_id: u32,
    block_number: u64,
    transaction_hash: String,
    handles: Vec<HandleEntry>,
}

// TODO missing checks on chain_id, block_number and transaction_hash
pub async fn publish_results(
    State(state): State<AppState>,
    Json(compute_result): Json<TEEComputeResult>,
) -> Result<(), AppError> {
    info!(
        chain_id = compute_result.chain_id,
        block_number = compute_result.block_number,
        transaction_hash = compute_result.transaction_hash,
        "Try to publish results in handles database {}",
        compute_result.handles.len()
    );
    // try create all handles in DB single transaction
    state
        .repository
        .create_handles(compute_result.handles)
        .await?;
    Ok(())
}
