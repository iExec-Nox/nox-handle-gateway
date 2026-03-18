//! S3/MinIO storage backend for encrypted handle entries.
//!
//! Handles bucket validation at startup, atomic single-object writes via
//! `If-None-Match: *`, and idempotent batch publishing with pre-flight conflict
//! detection.

use std::collections::HashMap;
use std::fmt::Debug;
use std::time::{Duration, SystemTime};

use alloy_primitives::hex;
use aws_sdk_s3::{
    Client,
    config::{Builder, Credentials, timeout::TimeoutConfig},
    error::SdkError,
    primitives::DateTime,
    types::{ChecksumAlgorithm, ObjectLockEnabled, ObjectLockMode},
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{error, info, warn};

use crate::config::S3Config;
use crate::handlers::HandleEntryWithTag;
use crate::types::SolidityType;

/// Object Lock retention period: 100 years expressed in seconds.
const RETENTION_DURATION_SECS: u64 = 100 * 365 * 24 * 3600;
/// S3 metadata key for the SHA-256 hex digest of the stored JSON body.
const METADATA_CONTENT_SHA256: &str = "content-sha256";

/// Errors returned by [`DataRepository`] operations.
#[derive(Error, Debug)]
pub enum S3Error {
    #[error("Object already exists: {key}")]
    AlreadyExists { key: String },
    #[error("Object not found: {key}")]
    NotFound { key: String },
    #[error("S3 operation failed: {message}")]
    S3Operation { message: String },
}

impl<E: std::error::Error + 'static, R: Debug> From<SdkError<E, R>> for S3Error {
    fn from(err: SdkError<E, R>) -> Self {
        let message = match &err {
            SdkError::ServiceError(se) => se.err().to_string(),
            _ => err.to_string(),
        };
        S3Error::S3Operation { message }
    }
}

/// The handle entry stored as a JSON object in S3.
///
/// The S3 key is `0x` + the `handle` hex string. Only the crypto material
/// needed to serve decryption requests is stored in the body. Enrichment
/// fields (chain ID, data type, origin, …) live exclusively in S3 user
/// metadata via [`HandleS3Metadata`].
#[derive(Clone, Deserialize, Serialize)]
pub struct HandleEntry {
    pub handle: String,
    pub ciphertext: String,
    pub public_key: String,
    pub nonce: String,
}

/// S3 user-metadata attached to every stored handle object.
///
/// These fields are not part of the JSON body — they are written once at
/// creation time via [`PutObjectFluentBuilder::set_metadata`] and are
/// available for external inspection (e.g. via `HeadObject`) without
/// downloading the object body.
///
/// `created-at` and `content-sha256` are **not** included here; they are
/// computed and inserted by [`DataRepository::create_handle`] itself.
pub struct HandleS3Metadata {
    pub chain_id: u32,
    pub data_type: String,
    pub origin: String,
    pub is_public: bool,
    pub handle_value_tag: String,
    pub application_contract: String,
}

impl HandleS3Metadata {
    fn to_metadata_map(&self) -> HashMap<String, String> {
        HashMap::from([
            ("chain-id".to_string(), self.chain_id.to_string()),
            ("data-type".to_string(), self.data_type.clone()),
            ("origin".to_string(), self.origin.clone()),
            ("public".to_string(), self.is_public.to_string()),
            (
                "handle-value-tag".to_string(),
                self.handle_value_tag.clone(),
            ),
            (
                "application-contract".to_string(),
                self.application_contract.clone(),
            ),
        ])
    }
}

/// Per-handle outcome counts from a batch publish operation.
#[derive(Serialize)]
pub struct PublishSummary {
    pub created: usize,
    pub unchanged: usize,
    pub conflicted: usize,
}

/// S3/MinIO client wrapper for handle storage operations.
#[derive(Clone)]
pub struct DataRepository {
    client: Client,
    bucket: String,
    object_lock_enabled: bool,
}

impl DataRepository {
    /// Builds the S3 client from config and validates the target bucket.
    ///
    /// Fails fast: returns an error (and the process exits) if the bucket is
    /// unreachable, or — when `object_lock_enabled` is `true` — if the bucket
    /// does not have S3 Object Lock enabled. Object Lock is required in that
    /// mode because handles are immutable.
    ///
    /// When `endpoint_url` is set, the client targets that custom endpoint with
    /// path-style addressing (MinIO / S3-compatible backends). When absent, the
    /// AWS SDK uses standard regional endpoints (native AWS S3).
    pub async fn new(config: &S3Config) -> anyhow::Result<Self> {
        let credentials =
            Credentials::new(&config.access_key, &config.secret_key, None, None, "static");

        let mut aws_config_builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .credentials_provider(credentials)
            .region(aws_config::Region::new(config.region.clone()))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(config.timeout))
                    .build(),
            );

        if let Some(ref url) = config.endpoint_url {
            aws_config_builder = aws_config_builder.endpoint_url(url);
        }

        let aws_config = aws_config_builder.load().await;

        let path_style = config.endpoint_url.is_some();
        let s3_config = Builder::from(&aws_config)
            .force_path_style(path_style)
            .build();

        let repo = Self {
            client: Client::from_conf(s3_config),
            bucket: config.bucket.clone(),
            object_lock_enabled: config.object_lock_enabled,
        };

        repo.validate_bucket().await?;
        Ok(repo)
    }

    /// Verifies the bucket is accessible and that its Object Lock state matches
    /// the configured `object_lock_enabled` flag.
    ///
    /// Always performs a HEAD check for bucket existence, then calls
    /// `GetObjectLockConfiguration` to determine the actual bucket state. The
    /// result is matched against the configured flag — both directions are
    /// enforced:
    ///
    /// - `(enabled=true,  lock=false)` → error: Object Lock required but missing
    /// - `(enabled=false, lock=true)`  → error: Object Lock present but not
    ///   requested; update `object_lock_enabled` or reconfigure the bucket
    /// - `(enabled=true,  lock=true)`  → info, proceed
    /// - `(enabled=false, lock=false)` → info, proceed
    ///
    /// Called once at startup; any failure aborts the process.
    async fn validate_bucket(&self) -> anyhow::Result<()> {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "S3 bucket '{}' is not accessible: {}",
                    self.bucket,
                    e.into_service_error()
                )
            })?;

        let lock_enabled = match self
            .client
            .get_object_lock_configuration()
            .bucket(&self.bucket)
            .send()
            .await
        {
            Ok(value) => {
                matches!(
                    value
                        .object_lock_configuration()
                        .and_then(|c| c.object_lock_enabled()),
                    Some(ObjectLockEnabled::Enabled)
                )
            }
            Err(e) => {
                warn!(
                    "S3 bucket {} does not have Object Lock configured: {}",
                    self.bucket,
                    e.into_service_error()
                );
                false
            }
        };

        match (self.object_lock_enabled, lock_enabled) {
            (true, false) => Err(anyhow::anyhow!(
                "S3 bucket '{}': Object Lock requested but not configured",
                self.bucket
            )),
            (false, true) => Err(anyhow::anyhow!(
                "S3 bucket '{}': Object Lock not requested but configured — set object_lock_enabled=true or use a different bucket",
                self.bucket
            )),
            (true, true) => {
                info!(bucket = %self.bucket, "running in Object Lock mode (handles are immutable)");
                Ok(())
            }
            (false, false) => {
                info!(bucket = %self.bucket, "running in non-locked mode (handles are not immutable)");
                Ok(())
            }
        }
    }

    /// # Retry note
    ///
    /// If the network drops after S3 has durably written the object but before
    /// the response arrives, an SDK retry of this request will receive a 412
    /// and return [`S3Error::AlreadyExists`] even though the write was ours.
    /// Callers must treat [`S3Error::AlreadyExists`] on a fresh write as a
    /// possible false positive and verify the stored object if needed.
    pub async fn create_handle(
        &self,
        entry: &HandleEntry,
        s3_metadata: &HandleS3Metadata,
    ) -> Result<NaiveDateTime, S3Error> {
        let created_at = Utc::now().naive_utc();

        let data = serde_json::to_vec(entry).map_err(|e| S3Error::S3Operation {
            message: format!("Failed to serialize entry: {e}"),
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = format!("{:x}", hasher.finalize());

        let mut metadata = s3_metadata.to_metadata_map();
        metadata.insert("handle".to_string(), entry.handle.clone());
        metadata.insert("created-at".to_string(), created_at.to_string());
        metadata.insert(METADATA_CONTENT_SHA256.to_string(), sha256);

        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&entry.handle)
            .body(data.into())
            .content_type("application/octet-stream")
            .if_none_match("*")
            .checksum_algorithm(ChecksumAlgorithm::Crc64Nvme)
            .set_metadata(Some(metadata));

        if self.object_lock_enabled {
            request = request
                .object_lock_mode(ObjectLockMode::Compliance)
                .object_lock_retain_until_date(DateTime::from(
                    SystemTime::now() + Duration::from_secs(RETENTION_DURATION_SECS),
                ))
        };

        let output = request.send().await.map_err(|err| {
            if let SdkError::ServiceError(ref service_err) = err
                && service_err.raw().status().as_u16() == 412
            {
                return S3Error::AlreadyExists {
                    key: entry.handle.clone(),
                };
            }
            S3Error::from(err)
        })?;

        info!(
            handle = %entry.handle,
            e_tag = output.e_tag(),
            version_id = output.version_id(),
            checksum_crc64_nvme = output.checksum_crc64_nvme(),
            "handle stored in S3",
        );

        Ok(created_at)
    }

    /// HEAD-checks a handle key and returns its stored `handle-value-tag` metadata.
    ///
    /// Returns `Ok(None)` if the key does not exist (404).
    /// Returns `Ok(Some(tag))` if the key exists, where `tag` is the stored
    /// `"handle-value-tag"` metadata value.
    /// Any non-404 S3 error propagates as `Err(S3Error::S3Operation)`.
    async fn head_handle(&self, key: &str) -> Result<Option<String>, S3Error> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => {
                let tag = output
                    .metadata()
                    .and_then(|m| m.get("handle-value-tag"))
                    .cloned()
                    .unwrap_or_default();
                Ok(Some(tag))
            }
            Err(e) => {
                if let SdkError::ServiceError(ref se) = e
                    && se.raw().status().as_u16() == 404
                {
                    return Ok(None);
                }
                Err(e.into())
            }
        }
    }

    /// Stores a batch of handle entries with per-handle tag-based idempotency.
    ///
    /// For each handle:
    /// - **404 (absent):** writes it; if the object appears between HEAD and PUT, counts as `unchanged`.
    /// - **200, same tag:** skips silently (`unchanged`).
    /// - **200, different tag:** logs at `error!` level (`conflicted`).
    ///
    /// Always returns `Ok(PublishSummary)` for business-level outcomes. S3
    /// infrastructure errors (network, permissions) and invalid handle bytes
    /// propagate as `Err(S3Error::S3Operation)`.
    pub async fn create_handles(
        &self,
        entries: Vec<HandleEntryWithTag>,
        origin: &str,
        application_contract: &str,
    ) -> Result<PublishSummary, S3Error> {
        let mut summary = PublishSummary {
            created: 0,
            unchanged: 0,
            conflicted: 0,
        };

        for entry_with_tag in entries {
            // Decode handle bytes to extract data-type ([5]) and attrs ([6])
            let handle_bytes =
                hex::decode(entry_with_tag.handle.clone()).map_err(|e| S3Error::S3Operation {
                    message: format!("invalid handle hex '{}': {e}", entry_with_tag.handle),
                })?;
            let data_type = SolidityType::try_from(handle_bytes[5])
                .map(|t| t.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let is_public = handle_bytes[6] != 0x01;
            let chain_id = u32::from_be_bytes(handle_bytes[1..5].try_into().map_err(|e| {
                S3Error::S3Operation {
                    message: format!("invalid chain id: {e}"),
                }
            })?);

            match self.head_handle(&entry_with_tag.handle).await? {
                None => {
                    let entry = HandleEntry {
                        handle: entry_with_tag.handle.clone(),
                        ciphertext: entry_with_tag.ciphertext,
                        public_key: entry_with_tag.public_key,
                        nonce: entry_with_tag.nonce,
                    };
                    let s3_metadata = HandleS3Metadata {
                        chain_id,
                        data_type,
                        origin: origin.to_string(),
                        is_public,
                        handle_value_tag: entry_with_tag.handle_value_tag,
                        application_contract: application_contract.to_string(),
                    };
                    match self.create_handle(&entry, &s3_metadata).await {
                        Ok(_) => {
                            summary.created += 1;
                        }
                        Err(S3Error::AlreadyExists { key }) => {
                            warn!(
                                handle = %key,
                                "handle already present in storage, counting as unchanged",
                            );
                            summary.unchanged += 1;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Some(stored_tag) if stored_tag == entry_with_tag.handle_value_tag => {
                    summary.unchanged += 1;
                }
                Some(stored_tag) => {
                    error!(
                        handle = %entry_with_tag.handle,
                        stored_tag = %stored_tag,
                        incoming_tag = %entry_with_tag.handle_value_tag,
                        "handle-value-tag mismatch, possible data integrity issue",
                    );
                    summary.conflicted += 1;
                }
            }
        }

        Ok(summary)
    }

    /// Fetches and deserializes a single handle entry by its S3 key.
    ///
    /// Returns [`S3Error::NotFound`] if the key does not exist.
    pub async fn fetch_handle(&self, handle: &str) -> Result<HandleEntry, S3Error> {
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(handle)
            .send()
            .await
            .map_err(|e| {
                if e.as_service_error().map(|se| se.is_no_such_key()) == Some(true) {
                    S3Error::NotFound {
                        key: handle.to_string(),
                    }
                } else {
                    e.into()
                }
            })?;

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| S3Error::S3Operation {
                message: format!("Failed to read response body: {e}"),
            })?
            .to_vec();

        serde_json::from_slice(&bytes).map_err(|e| S3Error::S3Operation {
            message: format!("Failed to deserialize entry: {e}"),
        })
    }

    /// Fetches multiple handle entries by ID, silently skipping missing keys.
    ///
    /// Missing handles are omitted from the result rather than producing an
    /// error. Any other S3 error (network, permissions) is propagated immediately.
    pub async fn read_handles(&self, ids: &[String]) -> Result<Vec<HandleEntry>, S3Error> {
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            match self.fetch_handle(id).await {
                Ok(entry) => results.push(entry),
                Err(S3Error::NotFound { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(results)
    }

    /// Returns the resolution status of each id in `ids`.
    ///
    /// Uses HEAD requests to check each key. Any S3 error other than 404 is
    /// propagated immediately.
    pub async fn handles_exist(&self, ids: &[String]) -> Result<HashMap<String, bool>, S3Error> {
        let mut result = HashMap::with_capacity(ids.len());
        for id in ids {
            let exists = self.head_handle(id).await?.is_some();
            result.insert(id.clone(), exists);
        }
        Ok(result)
    }
}
