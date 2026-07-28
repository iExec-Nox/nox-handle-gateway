use std::sync::Arc;

use alloy::{
    primitives::{Address, B256, hex},
    signers::{Signature, SignerSync, local::PrivateKeySigner},
    sol_types::{SolStruct, eip712_domain},
};
use axum_prometheus::metrics::{counter, gauge};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use reqwest::{Client, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use crate::config::KmsConfig;
use crate::types::{
    DelegateAuthorization, DelegateResponseProof, EIP_712_DOMAIN_VERSION,
    PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
};

/// Delegate calls attempted against the KMS, labelled `chain_id` and `status`.
///
/// [`KmsClient::get_encrypted_shared_secret`] owns the only increment, so no early return
/// inside [`KmsClient::delegate`] can escape uncounted and every call contributes exactly
/// one sample.
///
/// Counts attempts rather than requests that reached the wire: a call that fails earlier —
/// an [`Error::Signing`] failure while building the EIP-712 authorization, or a closed
/// semaphore — still records a sample, under whichever label [`Error::metric_status`]
/// assigns it. [`KMS_STATUSES`] lists the full label set.
const KMS_REQUESTS_TOTAL: &str = "nox_handle_gateway_kms_requests_total";

/// Delegate calls currently in flight against the KMS, across every endpoint and chain.
///
/// Unlabelled on purpose: the KMS has one capacity regardless of which endpoint or chain
/// drives it, so this must be comparable against the single
/// [`KmsConfig::max_concurrent_requests`] ceiling. A plateau at that value means callers
/// are queueing on [`KmsClient::semaphore`].
const KMS_INFLIGHT: &str = "nox_handle_gateway_kms_inflight";

const KMS_STATUS_SUCCESS: &str = "SUCCESS";
const KMS_STATUS_UNAVAILABLE: &str = "UNAVAILABLE";
const KMS_STATUS_INVALID_RESPONSE: &str = "INVALID_RESPONSE";
const KMS_STATUS_INVALID_SIGNATURE: &str = "INVALID_SIGNATURE";
const KMS_STATUS_SIGNING_ERROR: &str = "SIGNING_ERROR";

/// Every `status` label reported on [`KMS_REQUESTS_TOTAL`].
///
/// Used by [`KmsClient::init_metrics`] to publish each series at zero on startup, so
/// dashboards and ratio-based alerts have a denominator before the first failure occurs.
const KMS_STATUSES: [&str; 5] = [
    KMS_STATUS_SUCCESS,
    KMS_STATUS_UNAVAILABLE,
    KMS_STATUS_INVALID_RESPONSE,
    KMS_STATUS_INVALID_SIGNATURE,
    KMS_STATUS_SIGNING_ERROR,
];

/// Errors returned by [`KmsClient`] operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to build KMS HTTP client: {0}")]
    ClientBuild(reqwest::Error),
    #[error("Invalid KMS response: {0}")]
    InvalidResponse(String),
    #[error("Invalid KMS response signature: {0}")]
    InvalidResponseSignature(String),
    #[error("KMS unavailable: {0}")]
    Unavailable(String),
    #[error("Signing error: {0}")]
    Signing(String),
}

impl Error {
    /// `status` label reported on [`KMS_REQUESTS_TOTAL`] when a delegate call fails with
    /// this error.
    ///
    /// Exhaustive by construction: adding a variant to [`enum@Error`] fails to compile until a
    /// label is chosen for it, which keeps `sum(kms_requests_total)` equal to the number of
    /// delegate calls actually made.
    fn metric_status(&self) -> &'static str {
        match self {
            // Only produced by `KmsClient::new`, never by a delegate call.
            Error::ClientBuild(_) => KMS_STATUS_UNAVAILABLE,
            Error::InvalidResponse(_) => KMS_STATUS_INVALID_RESPONSE,
            Error::InvalidResponseSignature(_) => KMS_STATUS_INVALID_SIGNATURE,
            Error::Unavailable(_) => KMS_STATUS_UNAVAILABLE,
            Error::Signing(_) => KMS_STATUS_SIGNING_ERROR,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_status() {
            let status = err.status().map(|s| s.as_u16()).unwrap_or(0);
            Error::Unavailable(format!("HTTP {status}: {err}"))
        } else {
            Error::Unavailable(err.to_string())
        }
    }
}

/// Request body sent to `POST /v0/delegate` on the KMS.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KmsDelegateRequestBody {
    ephemeral_pub_key: String,
    target_pub_key: String,
}

/// Response body received from `POST /v0/delegate` on the KMS.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsDelegateResponse {
    pub encrypted_shared_secret: String,
    pub proof: String,
}

/// HTTP client for the KMS `POST /v0/delegate` endpoint.
///
/// Holds the KMS EC public key (used for ECIES encryption) and the expected
/// signer address (used to verify EIP-712 proofs on every delegate response).
#[derive(Clone)]
pub struct KmsClient {
    pub client: Client,
    pub base_url: String,
    pub kms_signer_address: Address,
    /// Shared by every clone of this client, so the cap is global rather than per-clone.
    semaphore: Arc<Semaphore>,
}

/// Keeps [`KMS_INFLIGHT`] accurate for the lifetime of a single delegate call.
///
/// Decrementing at the end of the call site would leak the gauge upward whenever the
/// request future is dropped instead of completing — which is exactly what Axum does when
/// a client disconnects mid-request. `Drop` runs on that path too.
struct InflightGuard;

impl InflightGuard {
    fn enter() -> Self {
        gauge!(KMS_INFLIGHT).increment(1.0);
        Self
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        gauge!(KMS_INFLIGHT).decrement(1.0);
    }
}

impl KmsClient {
    /// Creates a new KMS client.
    ///
    /// `public_key` is the KMS EC public key fetched on-chain from NoxCompute.
    /// `kms_signer_address` is the Ethereum address whose EIP-712 signature must
    /// appear on every delegate response.
    pub fn new(config: &KmsConfig) -> Result<Self, Error> {
        let client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.timeout)
            .build()
            .map_err(Error::ClientBuild)?;

        info!(kms_signer_address = %config.signer_address, "KMS client initialized");
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));

        Ok(Self {
            client,
            base_url: config.url.trim_end_matches('/').to_string(),
            kms_signer_address: config.signer_address,
            semaphore,
        })
    }

    /// Publishes every [`KMS_REQUESTS_TOTAL`] series for `chain_id` at zero, plus the
    /// unlabelled [`KMS_INFLIGHT`] gauge.
    ///
    /// Must run after the global metrics recorder is installed, otherwise the samples are
    /// dropped. Called once per configured chain: re-setting the chain-agnostic
    /// [`KMS_INFLIGHT`] gauge to zero on each call is idempotent, and it happens at startup
    /// before any delegate call can be in flight.
    pub(crate) fn init_metrics(&self, chain_id: u32) {
        let chain_id = chain_id.to_string();
        for status in KMS_STATUSES {
            counter!(KMS_REQUESTS_TOTAL, "chain_id" => chain_id.clone(), "status" => status)
                .absolute(0);
        }
        gauge!(KMS_INFLIGHT).set(0.0);
    }

    /// Calls `POST /v0/delegate` and returns the encrypted shared secret.
    ///
    /// Signs the request with an EIP-712 [`DelegateAuthorization`] and verifies
    /// the KMS response carries a valid [`DelegateResponseProof`] from the
    /// expected signer address.
    ///
    /// Records exactly one [`KMS_REQUESTS_TOTAL`] sample per call, labelled with
    /// [`Error::metric_status`] on failure and `SUCCESS` otherwise.
    pub async fn get_encrypted_shared_secret(
        &self,
        handle: &str,
        ephemeral_pub_key: &str,
        target_pub_key: &str,
        signer: &PrivateKeySigner,
        chain_id: u32,
    ) -> Result<String, Error> {
        // Held across the delegate call and released on drop, so the cap bounds concurrent
        // calls rather than total calls. Matched rather than `?`-propagated to keep the
        // "exactly one KMS_REQUESTS_TOTAL sample per call" invariant below intact.
        let result = match self.semaphore.acquire().await {
            Ok(_permit) => {
                let _inflight = InflightGuard::enter();
                self.delegate(handle, ephemeral_pub_key, target_pub_key, signer, chain_id)
                    .await
            }
            // Unreachable today: the semaphore is owned by this client and never closed.
            // Surfaced as `Unavailable` (503) so a future `close()` degrades instead of
            // silently succeeding.
            Err(err) => Err(Error::Unavailable(format!("KMS semaphore closed: {err}"))),
        };

        let status = match &result {
            Ok(_) => KMS_STATUS_SUCCESS,
            Err(err) => err.metric_status(),
        };
        counter!(KMS_REQUESTS_TOTAL, "chain_id" => chain_id.to_string(), "status" => status)
            .increment(1);

        result
    }

    /// Delegate call proper. Reports failures through the returned [`enum@Error`] only —
    /// metrics are recorded once by [`Self::get_encrypted_shared_secret`], so no early
    /// return here can escape uncounted.
    async fn delegate(
        &self,
        handle: &str,
        ephemeral_pub_key: &str,
        target_pub_key: &str,
        signer: &PrivateKeySigner,
        chain_id: u32,
    ) -> Result<String, Error> {
        let url = format!("{}/v0/delegate", self.base_url);

        let authorization = self.build_delegate_authorization(
            handle,
            ephemeral_pub_key,
            target_pub_key,
            signer,
            chain_id,
        )?;

        info!(
            ephemeral_pub_key = %ephemeral_pub_key,
            target_pub_key = %target_pub_key,
            "KMS delegate request (signed)"
        );

        let request_body = KmsDelegateRequestBody {
            ephemeral_pub_key: ephemeral_pub_key.to_string(),
            target_pub_key: target_pub_key.to_string(),
        };

        let mut salt_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut salt_bytes);
        let salt = B256::from(salt_bytes);

        let response = self
            .client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {authorization}"))
            .query(&[
                ("chain_id", chain_id.to_string()),
                ("salt", hex::encode_prefixed(salt)),
            ])
            .json(&request_body)
            .send()
            .await?;

        if let Err(err) = response.error_for_status_ref() {
            let status = response.status();
            // Read the body for diagnostics only: a failure here must not mask the HTTP
            // status we are about to report.
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|e| format!("<unreadable body: {e}>"));
            error!("KMS delegate error: {err} {error_body}");
            return Err(Error::InvalidResponse(format!(
                "delegate call failed with status {status}"
            )));
        }

        let data = response
            .json::<KmsDelegateResponse>()
            .await
            .inspect_err(|e| error!("Failed to deserialize response: {e}"))
            .map_err(|_| Error::InvalidResponse("failed to deserialize response".to_string()))?;

        self.verify_delegate_response(&data, chain_id, salt)?;

        Ok(data.encrypted_shared_secret)
    }

    /// Verifies the EIP-712 [`DelegateResponseProof`] in a KMS delegate response.
    ///
    /// Returns an error if the recovered signer does not match [`Self::kms_signer_address`].
    fn verify_delegate_response(
        &self,
        response: &KmsDelegateResponse,
        chain_id: u32,
        salt: B256,
    ) -> Result<(), Error> {
        let response_struct = DelegateResponseProof {
            encryptedSharedSecret: response.encrypted_shared_secret.clone(),
        };

        let domain = eip712_domain! {
            name: PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
            version: EIP_712_DOMAIN_VERSION,
            chain_id: u64::from(chain_id),
            salt: salt,
        };

        let signing_hash = response_struct.eip712_signing_hash(&domain);

        let signature_bytes = hex::decode(&response.proof)
            .map_err(|e| Error::InvalidResponseSignature(format!("invalid hex: {e}")))?;
        let proof = Signature::from_raw(&signature_bytes)
            .map_err(|e| Error::InvalidResponseSignature(format!("invalid proof: {e}")))?;
        let recovered = proof
            .recover_address_from_prehash(&signing_hash)
            .map_err(|e| Error::InvalidResponseSignature(format!("failed to recover: {e}")))?;

        if recovered != self.kms_signer_address {
            return Err(Error::InvalidResponseSignature(format!(
                "signer mismatch: expected {}, got {}",
                self.kms_signer_address, recovered
            )));
        }

        debug!("KMS delegate response signature verified");
        Ok(())
    }

    /// Builds and signs an EIP-712 [`DelegateAuthorization`] for a delegate request.
    ///
    /// Returns the hex-encoded signature to be sent as the `Authorization: Bearer` header.
    fn build_delegate_authorization(
        &self,
        handle: &str,
        ephemeral_pub_key: &str,
        target_pub_key: &str,
        signer: &PrivateKeySigner,
        chain_id: u32,
    ) -> Result<String, Error> {
        let auth = DelegateAuthorization {
            ephemeralPubKey: ephemeral_pub_key.to_string(),
            targetPubKey: target_pub_key.to_string(),
        };

        let domain = eip712_domain! {
            name: PROTOCOL_DELEGATE_EIP712_DOMAIN_NAME,
            version: EIP_712_DOMAIN_VERSION,
            chain_id: u64::from(chain_id),
        };

        let signature = signer
            .sign_typed_data_sync(&auth, &domain)
            .inspect_err(|e| error!("failed to prepare KMS authorization: {e}"))
            .map_err(|_| {
                Error::Signing(format!(
                    "failed to prepare KMS authorization for {handle} on chain {chain_id}"
                ))
            })?;

        Ok(hex::encode_prefixed(signature.as_bytes()))
    }
}
