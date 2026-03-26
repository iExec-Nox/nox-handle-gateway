//! Handlers implementations for Handle Gateway REST endpoints.
//!
//! The handlers implement interactions for users or runners.
//! User interactions, specifically the access to encrypted data
//! held by a handle are verified against on-chain ACL.

use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{Eip712Domain, SolStruct, eip712_domain, sol};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::header::HeaderMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{TimeZone, Utc};
use futures::future::join_all;
use reqwest::header;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::application::AppState;
use crate::error::AppError;
use crate::kms::KmsClient;
use crate::repository::{HandleEntry, HandleS3Metadata};
use crate::types::{DataAccessAuthorization, DecryptionProof, Handle, HandleProof, SolidityType};
use crate::validation::{decode_and_validate_value, parse_handle};

/// EIP-712 domain name for HandleProof generation.
const NOX_COMPUTE_EIP712_DOMAIN_NAME: &str = "NoxCompute";
/// EIP-712 domain name for DataAccessAuthorization validation.
const HANDLE_GATEWAY_EIP712_DOMAIN_NAME: &str = "Handle Gateway";
/// Maximum allowed validity window for DataAccessAuthorization tokens, in seconds.
const MAX_AUTHORIZATION_VALIDITY_WINDOW_SECS: u64 = 3600;

/// Optional `?salt=<0x bytes32>` query parameter present on all endpoints.
///
/// If absent the salt defaults to `bytes32(0)` and is bound into the Handle Gateway
/// EIP-712 response-signing domain so callers can associate a response with a specific request.
#[derive(Debug, Deserialize)]
pub struct SaltQuery {
    salt: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleRequest {
    value: String,
    solidity_type: SolidityType,
    owner: Address,
    application_contract: Address,
}

/// Response for `POST /v0/secrets` — carries signed [`HandleWithProof`].
#[derive(Serialize)]
pub struct HandleResponse {
    payload: HandleWithProof,
    signature: String,
}

/// Inner payload of `GET /v0/public/{handle}` response.
/// Response for `GET /v0/public/{handle}` — carries signed [`PublicDecryptionResult`].
#[derive(Serialize)]
pub struct PublicDecryptResponse {
    payload: PublicDecryptionResult,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayDelegateAuthorization {
    payload: DataAccessAuthorization,
    signature: String,
}

/// Response for `GET /v0/secrets/{handle}` — carries signed [`HandleCryptoMaterial`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayDelegateResponse {
    payload: HandleCryptoMaterial,
    signature: String,
}

/// Encrypts a plaintext value and stores it under a freshly generated handle.
///
/// Validates the `value` against `solidityType`, encrypts it under the KMS public key,
/// stores the ciphertext in S3, and returns a signed EIP-712 `HandleProof` wrapped in
/// a Handle Gateway outer signature.
///
/// # HTTP responses
///
/// - `200 OK` — JSON `{ "payload": { "handle": "0x...", "proof": "0x..." }, "signature": "0x..." }`.
/// - `400 Bad Request` — `value` does not match the declared `solidityType`, or `salt` is malformed.
/// - `409 Conflict` — handle already exists in S3.
/// - `500 Internal Server Error` — encryption, signing, or unexpected S3 error.
pub async fn create_handle(
    State(state): State<AppState>,
    Query(salt_query): Query<SaltQuery>,
    Json(request): Json<HandleRequest>,
) -> Result<Json<HandleResponse>, AppError> {
    let salt = extract_salt(salt_query)?;
    // Handle
    let plaintext = decode_and_validate_value(&request.value, &request.solidity_type)?;
    let ecies_ciphertext = state.crypto_svc.ecies_encrypt(&plaintext)?;

    let data_type = request.solidity_type.to_string();
    let handle = Handle::new(state.config.chain.id, request.solidity_type).to_bytes();

    let serialized_handle = hex::encode_prefixed(handle);

    let handle_value_tag = {
        let mut input = Vec::with_capacity(handle.len() + plaintext.len());
        input.extend_from_slice(&handle);
        input.extend_from_slice(&plaintext);
        hex::encode_prefixed(keccak256(input))
    };

    let entry = HandleEntry {
        handle: serialized_handle.clone(),
        ciphertext: hex::encode_prefixed(&ecies_ciphertext.ciphertext),
        public_key: hex::encode_prefixed(ecies_ciphertext.ephemeral_pubkey),
        nonce: hex::encode_prefixed(ecies_ciphertext.nonce),
    };

    let metadata = HandleS3Metadata {
        handle: serialized_handle.clone(),
        created_at: Utc::now().naive_utc(),
        chain_id: state.config.chain.id,
        data_type,
        origin: "gateway".to_string(),
        is_public: false,
        handle_value_tag,
        application_contract: request.application_contract.to_string(),
    };

    state.repository.create_handle(&entry, &metadata).await?;

    // HandleProof
    let domain = eip712_domain! {
        name: NOX_COMPUTE_EIP712_DOMAIN_NAME,
        version: "1",
        chain_id: u64::from(state.config.chain.id),
        verifying_contract: state.config.chain.nox_compute_contract,
    };

    let created_at = U256::from(metadata.created_at.and_utc().timestamp());
    let proof = HandleProof {
        handle: B256::from(&handle),
        owner: request.owner,
        app: request.application_contract,
        createdAt: created_at,
    };

    let handle_proof_signature = state
        .signer
        .sign_typed_data_sync(&proof, &domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .as_bytes();

    let serialized_handle_proof = proof.to_serialized_bytes(handle_proof_signature);

    let handle_with_proof = HandleWithProof {
        handle: serialized_handle,
        proof: serialized_handle_proof,
    };
    let domain = handle_gateway_response_domain(state.config.chain.id, salt);
    let handle_response_signature = state
        .signer
        .sign_typed_data_sync(&handle_with_proof, &domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .to_string();

    Ok(Json(HandleResponse {
        payload: handle_with_proof,
        signature: handle_response_signature,
    }))
}

/// Serve encrypted crypto material for a handle after verifying caller identity and ACL.
///
/// Decodes the `Authorization: EIP712 <base64>` header and enforces the token's
/// `notBefore`/`expiresAt` window first to avoid unnecessary cryptographic work
/// on expired tokens. Then recovers the signer address from the EIP-712 signature;
/// for EOA callers the recovered address must match `userAddress`, for Smart Account
/// callers an ERC-1271 fallback is attempted by calling `isValidSignature` on the
/// contract at `userAddress`. Finally `isViewer` is checked on-chain and the stored
/// ciphertext with a KMS-delegated re-encrypted shared secret are returned.
///
/// # HTTP responses
///
/// - `200 OK` — JSON object `{ "payload": { "handle", "ciphertext", "encryptedSharedSecret", "iv" }, "signature": "0x..." }`.
/// - `400 Bad Request` — handle path parameter is not valid hex or not 32 bytes.
/// - `401 Unauthorized` — authorization token is missing, malformed, expired, or wrongly signed.
/// - `403 Forbidden` — caller does not have viewer access to this handle.
/// - `404 Not Found` — handle does not exist in S3.
/// - `500 Internal Server Error` — unexpected S3 or KMS error.
/// - `503 Service Unavailable` — RPC or KMS is unreachable.
pub async fn get_handle_crypto_material(
    Path(handle): Path<String>,
    State(state): State<AppState>,
    Query(salt_query): Query<SaltQuery>,
    headers: HeaderMap,
) -> Result<Json<GatewayDelegateResponse>, AppError> {
    let salt = extract_salt(salt_query)?;
    info!(handle = handle, "get_handle_crypto_material query");
    let token_bytes = extract_authorization(headers)?;
    let authorization: GatewayDelegateAuthorization =
        serde_json::from_slice(&token_bytes).map_err(|e| AppError::Unauthorized(e.to_string()))?;

    let payload = authorization.payload;

    let validity_window = match payload.expiresAt.checked_sub(payload.notBefore) {
        Some(window) => window,
        None => {
            warn!(
                not_before = format_timestamp(payload.notBefore),
                expires_at = format_timestamp(payload.expiresAt),
                "token validity window is invalid",
            );
            return Err(AppError::Unauthorized(
                "token validity window is invalid".to_string(),
            ));
        }
    };
    if validity_window > U256::from(MAX_AUTHORIZATION_VALIDITY_WINDOW_SECS) {
        warn!(
            not_before = format_timestamp(payload.notBefore),
            expires_at = format_timestamp(payload.expiresAt),
            "token validity window is too long",
        );
        return Err(AppError::Unauthorized(
            "token validity window is too long".to_string(),
        ));
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

    let auth_domain = eip712_domain! {
        name: HANDLE_GATEWAY_EIP712_DOMAIN_NAME,
        version: "1",
        chain_id: u64::from(state.config.chain.id),
        verifying_contract: state.config.chain.nox_compute_contract,
    };
    let hash = payload.eip712_signing_hash(&auth_domain);
    let signature_bytes =
        hex::decode(&authorization.signature).map_err(|e| AppError::Unauthorized(e.to_string()))?;

    let is_valid_ec_sig = match Signature::from_raw(&signature_bytes) {
        Ok(sig) => match sig.recover_address_from_prehash(&hash) {
            Ok(address) => {
                let is_valid = payload.userAddress == address;
                if !is_valid {
                    warn!(
                        handle,
                        user = payload.userAddress.to_string(),
                        recovered = address.to_string(),
                        "Recovered address does not match userAddress in payload",
                    );
                }
                is_valid
            }
            Err(e) => {
                warn!(
                    handle,
                    user = payload.userAddress.to_string(),
                    "Failed to recover address from signature: {e}",
                );
                false
            }
        },
        Err(e) => {
            warn!(
                handle,
                user = payload.userAddress.to_string(),
                "EC signature recovery failed: {e}",
            );
            false
        }
    };

    if !is_valid_ec_sig {
        warn!(
            handle,
            user = payload.userAddress.to_string(),
            "attempting ERC-1271 fallback",
        );
        state
            .nox_client
            .verify_erc1271(hash, &signature_bytes, payload.userAddress)
            .await
            .map_err(|e| {
                warn!(
                    handle,
                    user = payload.userAddress.to_string(),
                    "ERC-1271 signature verification failed: {e}",
                );
                AppError::Unauthorized("invalid signature".to_string())
            })?;
    }

    let handle_b256 = parse_handle(&handle)?;
    state
        .nox_client
        .check_access(handle_b256, payload.userAddress)
        .await?;

    let entry = state.repository.fetch_handle(&handle).await?;

    info!(handle, "decryption delegation request");
    let crypto_material = get_crypto_material_for_entry(
        state.kms_client.clone(),
        &entry,
        &payload.encryptionPubKey,
        &state.signer,
        state.config.chain.id,
    )
    .await?;

    let response_domain = handle_gateway_response_domain(state.config.chain.id, salt);
    let signature = state
        .signer
        .sign_typed_data_sync(&crypto_material, &response_domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .to_string();

    Ok(Json(GatewayDelegateResponse {
        payload: crypto_material,
        signature,
    }))
}

/// Returns a verifiable EIP-712 decryption proof for a publicly decryptable handle.
///
/// Checks handle format, on-chain public decryptability, and S3 existence (in that
/// order) before performing decryption. The `decryptionProof` field in the payload is
/// the 65-byte NoxCompute EIP-712 gateway signature concatenated with the decrypted value.
/// The outer `signature` signs the whole payload under the Handle Gateway domain with salt.
///
/// # HTTP responses
///
/// - `200 OK` — JSON `{ "payload": { "decryptionProof": "0x..." }, "signature": "0x..." }`.
/// - `400 Bad Request` — handle is not valid 32-byte hex, or `salt` is malformed.
/// - `403 Forbidden` — handle is not marked as publicly decryptable on-chain.
/// - `404 Not Found` — handle does not exist in S3.
/// - `500 Internal Server Error` — crypto or signing failure.
/// - `503 Service Unavailable` — RPC or KMS unreachable.
pub async fn public_decrypt(
    Path(handle): Path<String>,
    State(state): State<AppState>,
    Query(salt_query): Query<SaltQuery>,
) -> Result<Json<PublicDecryptResponse>, AppError> {
    let salt = extract_salt(salt_query)?;
    let handle_b256 = parse_handle(&handle)?;
    SolidityType::try_from(handle_b256[5])?;

    info!(handle = %handle, "public_decrypt query");

    state
        .nox_client
        .is_publicly_decryptable(handle_b256)
        .await?;

    let entry = state.repository.fetch_handle(&handle).await?;

    // KMS delegate → encrypted shared secret
    let encrypted_shared_secret = state
        .kms_client
        .get_encrypted_shared_secret(
            &entry.public_key,
            &state.crypto_svc.rsa_public_key,
            &state.signer,
            state.config.chain.id,
        )
        .await?;

    // RSA-OAEP decrypt → HKDF + AES-256-GCM → decrypted_result bytes
    let decrypted_result = state.crypto_svc.ecies_decrypt(
        &entry.ciphertext,
        &encrypted_shared_secret,
        &entry.nonce,
    )?;

    // Sign `DecryptionProof` EIP-712 under the `NoxCompute` domain
    let nox_compute_domain = eip712_domain! {
        name: NOX_COMPUTE_EIP712_DOMAIN_NAME,
        version: "1",
        chain_id: u64::from(state.config.chain.id),
        verifying_contract: state.config.chain.nox_compute_contract,
    };
    let proof_struct = DecryptionProof {
        handle: handle_b256,
        decryptedResult: Bytes::from(decrypted_result.clone()),
    };
    let signature = state
        .signer
        .sign_typed_data_sync(&proof_struct, &nox_compute_domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .as_bytes();

    // Serialize: sig (65 bytes) || decryptedResult (N bytes)
    let mut serialized = Vec::with_capacity(65 + decrypted_result.len());
    serialized.extend_from_slice(&signature);
    serialized.extend_from_slice(&decrypted_result);

    let result_payload = PublicDecryptionResult {
        decryptionProof: hex::encode_prefixed(serialized),
    };
    let response_domain = handle_gateway_response_domain(state.config.chain.id, salt);
    let public_decrypt_response_signature = state
        .signer
        .sign_typed_data_sync(&result_payload, &response_domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .to_string();

    Ok(Json(PublicDecryptResponse {
        payload: result_payload,
        signature: public_decrypt_response_signature,
    }))
}

fn format_timestamp(ts: U256) -> String {
    ts.try_into()
        .ok()
        .and_then(|secs| Utc.timestamp_opt(secs, 0).single())
        .map(|dt| dt.to_string())
        .unwrap_or_else(|| format!("invalid({ts})"))
}

sol! {
    /// EIP-712 outer payload wrapping the handle and HandleProof returned by `POST /v0/secrets`.
    ///
    /// Signed under the Handle Gateway domain (with salt) to bind the response to the request.
    #[derive(Serialize)]
    struct HandleWithProof {
        string handle;
        string proof;
    }

    /// EIP-712 compatible payload to authorize a Runner to retrieve operands from the Handle Gateway.
    ///
    /// The Handle Gateway will receive a [`ComputeOperandRequest`] and will be able to verify
    /// the query comes from a known Runner.
    #[derive(Deserialize)]
    struct OperandAccessAuthorization {
        address caller;
        string[] operands;
        string rsaPublicKey;
        string transactionHash;
    }

    /// EIP-712 compatible payload to authorize a Runner to publish results to the Handle Gateway.
    ///
    /// The Handle Gateway will receive a [`ComputeResultRequest`] and will be able to verify
    /// the query comes from a known Runner.
    #[derive(Deserialize)]
    struct ResultPublishingAuthorization {
        uint256 chainId;
        uint256 blockNumber;
        address caller;
        string transactionHash;
    }

    /// EIP-712 compatible payload to share a handle after decryption delegation through the KMS.
    ///
    /// `encryptedSharedSecret` is encrypted with RSA in order to protect the shared secret.
    ///
    /// The fact that this is an EIP-712 payload allows to sign the typed data with the Handle Gateway
    /// signer key. The client receiving the data can then verify it knows the Handle Gateway which
    /// provided it the data.
    #[derive(Serialize)]
    struct HandleCryptoMaterial {
        string handle;
        string ciphertext;
        string encryptedSharedSecret;
        string iv;
    }

    /// EIP-712 compatible payload to sign and send operands from the Handle Gateway to a Runner.
    ///
    /// It wraps a list of [`HandleCryptoMaterial`]s for all handles prepared for a Runner computation.
    /// The Runner will receive a [`ComputeOperandResponse`] and will be able to verify data are received
    /// from a known Handle Gateway.
    #[derive(Serialize)]
    struct ComputeOperands {
        HandleCryptoMaterial[] operands;
    }

    /// EIP-712 outer payload wrapping the decryption proof returned by `GET /v0/public/{handle}`.
    ///
    /// Signed under the Handle Gateway domain (with salt) to bind the response to the request.
    #[derive(Serialize)]
    struct PublicDecryptionResult {
        string decryptionProof;
    }

    /// EIP-712 compatible payload to sign and send a result publishing report to the Runner.
    ///
    /// The fact that this is an EIP-712 payload allows to sign the typed data with the Handle Gateway
    /// signer key. The client receiving the data can then verify it knows the Handle Gateway which
    /// provided it the data.
    #[derive(Serialize)]
    struct ResultPublishingReport {
        string message;
    }

    /// Resolution status of a single handle within a [`HandleStatusReport`].
    #[derive(Serialize)]
    struct HandleResolution {
        string handle;
        bool resolved;
    }

    /// EIP-712 signed payload carrying the resolution status of a batch of handles.
    ///
    /// Signed under the `Handle Gateway` domain and returned by `POST /v0/public/handles/status`.
    #[derive(Serialize)]
    struct HandleStatusReport {
        HandleResolution[] statuses;
    }
}

/// Full authorization data to retrieve compute operands from the Handle Gateway.
///
/// It contains the plain [`OperandAccessAuthorization`] EIP-712 data with its signed hash.
/// This allows the Handle Gateway to verify the Runner is known.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeOperandRequest {
    payload: OperandAccessAuthorization,
    signature: String,
}

/// Full response to send operands from the Handle Gateway to the Runner.
///
/// It contains the plain [`ComputeOperands`] EIP-712 data with its signed hash.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeOperandResponse {
    payload: ComputeOperands,
    signature: String,
}

/// Full authorization data to receive compute results from a Runner.
///
/// It contains the plain [`ResultPublishingAuthorization`] EIP-712 data with its signed hash.
/// This allows the Handle Gateway to verify the Runner is known.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeResultRequest {
    payload: ResultPublishingAuthorization,
    signature: String,
}

/// Atomic handle data sent by a known Runner when publishing results.
///
/// The `handle_value_tag` field allows to verify if the same handle
/// has already been published with the same plaintext value.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleEntryWithTag {
    pub handle: String,
    pub handle_value_tag: String,
    pub ciphertext: String,
    pub public_key: String,
    pub nonce: String,
}

/// Response sent to the Runner when publishing computation results.
///
/// The response contains [`ResultPublishingReport`] EIP-712 data with its signed hash.
/// This allows the Runner to verify the data was sent to a known Handle Gateway.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeResultResponse {
    payload: ResultPublishingReport,
    signature: String,
}

/// Retrieves from S3 Handles required as operands by a Runner to perform a computation.
///
/// An `Authorization` header is mandatory and used to check the query comes from
/// a known Runner. At the end of the execution, a [`response`](ComputeOperandResponse)
/// containing an EIP-712 payload with its signed hash is sent to the Runner.
///
/// # Errors
///
/// The operation will fail with:
/// - [`AppError::Unauthorized`] if the authorization token cannot be verified.
/// - [`AppError::BadRequest`] if not all operands can be delivered to the Runner,
///   either due to an operand not retrieved from S3 or not prepared through the KMS.
pub async fn get_operand_handles(
    State(state): State<AppState>,
    Query(salt_query): Query<SaltQuery>,
    headers: HeaderMap,
) -> Result<Json<ComputeOperandResponse>, AppError> {
    let salt = extract_salt(salt_query)?;
    let token_bytes = extract_authorization(headers)?;
    let authorization: ComputeOperandRequest =
        serde_json::from_slice(&token_bytes).map_err(|e| AppError::Unauthorized(e.to_string()))?;

    let auth_domain = eip712_domain! {
        name: HANDLE_GATEWAY_EIP712_DOMAIN_NAME,
        version: "1",
        chain_id: u64::from(state.config.chain.id),
    };
    let compute_request = authorization.payload;
    let hash = compute_request.eip712_signing_hash(&auth_domain);
    recover_and_check_address(
        &state.config.runner_address,
        &hash,
        &authorization.signature,
    )?;

    debug!("preparing handles for caller {}", compute_request.caller);

    let operands_expected_count = compute_request.operands.len();

    let operand_handles: Vec<HandleEntry> = state
        .repository
        .read_handles(&compute_request.operands)
        .await?;
    debug!("operand handles count {}", operand_handles.len());
    if operand_handles.len() != operands_expected_count {
        let found_handles: Vec<String> = operand_handles
            .iter()
            .map(|entry| entry.handle.clone())
            .collect();
        let missing_handles: Vec<String> = compute_request
            .operands
            .into_iter()
            .filter(|handle| !found_handles.contains(handle))
            .collect();
        error!(
            transaction_hash = compute_request.transactionHash,
            requested = operands_expected_count,
            fetched = operand_handles.len(),
            "expected operand handles not found in handle database {missing_handles:?}"
        );
        return Err(AppError::BadRequest(
            "impossible to perform computation, missing operand handles".to_string(),
        ));
    }

    let operands_crypto_material: Vec<HandleCryptoMaterial> =
        join_all(operand_handles.iter().map(|entry| {
            get_crypto_material_for_entry(
                state.kms_client.clone(),
                entry,
                &compute_request.rsaPublicKey,
                &state.signer,
                state.config.chain.id,
            )
        }))
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    if operands_crypto_material.len() != operands_expected_count {
        let found_handles: Vec<String> = operands_crypto_material
            .iter()
            .map(|crypto_material| crypto_material.handle.clone())
            .collect();
        let missing_handles: Vec<String> = compute_request
            .operands
            .into_iter()
            .filter(|handle| !found_handles.contains(handle))
            .collect();
        error!(
            transaction_hash = compute_request.transactionHash,
            requested = operands_expected_count,
            fetched = operands_crypto_material.len(),
            "expected operand handles not prepared {missing_handles:?}"
        );
        return Err(AppError::OperandsNotPrepared);
    }
    let payload = ComputeOperands {
        operands: operands_crypto_material,
    };

    let response_domain = handle_gateway_response_domain(state.config.chain.id, salt);
    let signature = state
        .signer
        .sign_typed_data_sync(&payload, &response_domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .to_string();

    Ok(Json(ComputeOperandResponse { payload, signature }))
}

async fn get_crypto_material_for_entry(
    kms_client: KmsClient,
    entry: &HandleEntry,
    rsa_public_key: &str,
    signer: &PrivateKeySigner,
    chain_id: u32,
) -> Result<HandleCryptoMaterial, AppError> {
    let encrypted_shared_secret = kms_client
        .get_encrypted_shared_secret(&entry.public_key, rsa_public_key, signer, chain_id)
        .await?;
    info!(
        handle = entry.handle,
        ciphertext = entry.ciphertext,
        encrypted_shared_secret = encrypted_shared_secret,
        iv = entry.nonce,
        "handle crypto material"
    );
    Ok(HandleCryptoMaterial {
        handle: entry.handle.clone(),
        ciphertext: entry.ciphertext.clone(),
        encryptedSharedSecret: encrypted_shared_secret,
        iv: entry.nonce.clone(),
    })
}

/// Receives Handles generating by a Runner computation and publishes them to S3.
///
/// An `Authorization` header is mandatory and used to check the query comes from
/// a known Runner. At the end of the execution, a [`response`](ComputeResultResponse)
/// containing an EIP-712 payload with its signed hash is sent to the Runner.
///
/// # Errors
///
/// The operation will fail with:
/// - [`AppError::Unauthorized`] if the authorization token cannot be verified.
/// - [`super::repository::S3Error`] if an error occurs during publishing.
pub async fn publish_results(
    State(state): State<AppState>,
    Query(salt_query): Query<SaltQuery>,
    headers: HeaderMap,
    Json(handles): Json<Vec<HandleEntryWithTag>>,
) -> Result<Json<ComputeResultResponse>, AppError> {
    let salt = extract_salt(salt_query)?;
    let token_bytes = extract_authorization(headers)?;
    let authorization: ComputeResultRequest =
        serde_json::from_slice(&token_bytes).map_err(|e| AppError::Unauthorized(e.to_string()))?;

    let auth_domain = eip712_domain! {
        name: HANDLE_GATEWAY_EIP712_DOMAIN_NAME,
        version: "1",
        chain_id: u64::from(state.config.chain.id),
    };
    let compute_result = authorization.payload;
    let hash = compute_result.eip712_signing_hash(&auth_domain);
    recover_and_check_address(
        &state.config.runner_address,
        &hash,
        &authorization.signature,
    )?;

    let total = handles.len();
    info!(
        count = total,
        chain_id = compute_result.chainId.to_string(),
        block_number = compute_result.blockNumber.to_string(),
        transaction_hash = compute_result.transactionHash.to_string(),
        "publishing result handles to S3"
    );

    let summary = state
        .repository
        .create_handles(
            handles,
            &compute_result.transactionHash,
            &compute_result.caller.to_string(),
        )
        .await?;

    let payload = ResultPublishingReport {
        message: format!(
            "On the {total} handles submitted to publishing, {} were successfully created, {} were unchanged and {} conflicted",
            summary.created, summary.unchanged, summary.conflicted
        ),
    };

    let response_domain = handle_gateway_response_domain(state.config.chain.id, salt);
    let signature = state
        .signer
        .sign_typed_data_sync(&payload, &response_domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .to_string();

    Ok(Json(ComputeResultResponse { payload, signature }))
}

/// Request body for `POST /v0/public/handles/status`.
///
/// Lists the handle keys (hex strings with `0x` prefix) whose resolution
/// status the caller wants to query.
#[derive(Debug, Deserialize)]
pub struct HandleStatusRequest {
    handles: Vec<String>,
}

/// Response for `POST /v0/public/handles/status` — carries signed [`HandleStatusReport`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleStatusReportResponse {
    payload: HandleStatusReport,
    signature: String,
}

/// Reports which handles from the request are already resolved (stored in S3).
///
/// Each entry in the response corresponds to one handle from the request, in
/// the same order. The endpoint performs HEAD checks only and never returns
/// the encrypted payload. The response is signed under the `Handle Gateway`
/// EIP-712 domain so callers can verify it originates from this gateway.
///
/// # HTTP responses
///
/// - `200 OK` — JSON object `{ "payload": { "statuses": [{ "handle", "resolved" }] }, "signature": "0x..." }`.
/// - `500 Internal Server Error` — unexpected S3 error (e.g. network failure or permission error).
pub async fn handle_status(
    State(state): State<AppState>,
    Query(salt_query): Query<SaltQuery>,
    Json(request): Json<HandleStatusRequest>,
) -> Result<Json<HandleStatusReportResponse>, AppError> {
    let salt = extract_salt(salt_query)?;
    info!(count = request.handles.len(), "handle status request");
    let exists_map = state.repository.handles_exist(&request.handles).await?;
    let statuses: Vec<HandleResolution> = request
        .handles
        .iter()
        .map(|h| HandleResolution {
            handle: h.clone(),
            resolved: *exists_map.get(h).unwrap_or(&false),
        })
        .collect();
    let payload = HandleStatusReport { statuses };
    let response_domain = handle_gateway_response_domain(state.config.chain.id, salt);
    let signature = state
        .signer
        .sign_typed_data_sync(&payload, &response_domain)
        .map_err(|e| AppError::SigningError(e.to_string()))?
        .to_string();
    Ok(Json(HandleStatusReportResponse { payload, signature }))
}

/// Builds the Handle Gateway EIP-712 domain used to sign all gateway responses.
///
/// The `salt` parameter binds the signature to a specific request, preventing
/// response replay across different callers or requests.
fn handle_gateway_response_domain(chain_id: u32, salt: B256) -> Eip712Domain {
    eip712_domain! {
        name: HANDLE_GATEWAY_EIP712_DOMAIN_NAME,
        version: "1",
        chain_id: u64::from(chain_id),
        salt: salt,
    }
}

/// Parses the optional `salt` query parameter into a 32-byte value.
///
/// Returns `B256::ZERO` when the parameter is absent. When present, the value must
/// be hex-decoded to exactly 32 bytes.
fn extract_salt(query: SaltQuery) -> Result<B256, AppError> {
    let Some(s) = query.salt else {
        return Ok(B256::ZERO);
    };
    let bytes =
        hex::decode(&s).map_err(|e| AppError::BadRequest(format!("invalid salt hex {s}: {e}")))?;
    let bytes_len = bytes.len();
    if bytes_len != 32 {
        return Err(AppError::BadRequest(format!(
            "salt must decode to exactly 32 bytes, got {bytes_len} bytes",
        )));
    }
    Ok(B256::from_slice(&bytes))
}

/// Extracts authorization token from headers.
///
/// # Errors
///
/// The method will return [`AppError::Unauthorized`] in the following situations:
/// - no header was found.
/// - the header value could not be parsed to a String value.
/// - the header is malformed and does not start with the right prefix.
/// - the header value following the `EIP712 ` prefix is not base64 encoded.
fn extract_authorization(headers: HeaderMap) -> Result<Vec<u8>, AppError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .ok_or(AppError::Unauthorized("header missing".to_string()))?
        .to_str()
        .map_err(|e| AppError::Unauthorized(e.to_string()))?
        .strip_prefix("EIP712 ")
        .ok_or(AppError::Unauthorized(
            "malformed authorization header".to_string(),
        ))?;
    STANDARD
        .decode(token)
        .map_err(|e| AppError::Unauthorized(e.to_string()))
}

/// Recovers the address used to sign an authorization token and verifies it against an expected address.
///
/// # Errors
///
/// The method will return [`AppError::Unauthorized`] in the following situations:
/// - The `signature` is not encoded as a valid hex value.
/// - The signature bytes can not be converted to a `Signature`.
/// - No address can be recovered from the provided `hash`.
/// - There is a mismatch between the recovered address and the expected one.
fn recover_and_check_address(
    expected_address: &Address,
    hash: &B256,
    signature: &str,
) -> Result<(), AppError> {
    let signature_bytes =
        hex::decode(signature).map_err(|e| AppError::Unauthorized(e.to_string()))?;
    let signature =
        Signature::from_raw(&signature_bytes).map_err(|e| AppError::Unauthorized(e.to_string()))?;
    let recovered_address = signature
        .recover_address_from_prehash(hash)
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;
    if expected_address != &recovered_address {
        warn!(
            user = expected_address.to_string(),
            recovered = recovered_address.to_string(),
            "recovered address mismatch",
        );
        return Err(AppError::Unauthorized("invalid signature".to_string()));
    }
    Ok(())
}
