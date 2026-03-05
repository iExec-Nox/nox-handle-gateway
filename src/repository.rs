//! S3/MinIO storage backend for encrypted handle entries.
//!
//! Handles bucket validation at startup, atomic single-object writes via
//! `If-None-Match: *`, and idempotent batch publishing with pre-flight conflict
//! detection.

use std::fmt::Debug;
use std::time::{Duration, SystemTime};

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
use tracing::{info, warn};

use crate::config::S3Config;

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
    #[error("Batch conflict: handles already exist: {}", conflicts.join(", "))]
    BatchConflict { conflicts: Vec<String> },
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

/// An encrypted handle entry stored as a JSON object in S3.
///
/// The S3 key is the `handle` field with a `0x` prefix.
#[derive(Clone, Deserialize, Serialize)]
pub struct HandleEntry {
    pub handle: String,
    pub ciphertext: String,
    pub public_key: String,
    pub nonce: String,
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

        let lock_response = self
            .client
            .get_object_lock_configuration()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "S3 bucket '{}' does not have Object Lock configured: {}",
                    self.bucket,
                    e.into_service_error()
                )
            })?;

        let lock_enabled = matches!(
            lock_response
                .object_lock_configuration()
                .and_then(|c| c.object_lock_enabled()),
            Some(ObjectLockEnabled::Enabled)
        );

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
    pub async fn create_handle(&self, entry: &HandleEntry) -> Result<NaiveDateTime, S3Error> {
        let created_at = Utc::now().naive_utc();

        let data = serde_json::to_vec(entry).map_err(|e| S3Error::S3Operation {
            message: format!("Failed to serialize entry: {e}"),
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = format!("{:x}", hasher.finalize());

        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&entry.handle)
            .body(data.into())
            .content_type("application/octet-stream")
            .if_none_match("*")
            .checksum_algorithm(ChecksumAlgorithm::Crc64Nvme)
            .metadata("handle", &entry.handle)
            .metadata("created-at", created_at.to_string())
            .metadata(METADATA_CONTENT_SHA256, sha256);

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

    /// HEAD-checks whether a handle key is absent.
    ///
    /// Returns `Ok(true)` if the key does not exist (404), `Ok(false)` if it
    /// does (200), or `Err` on any other S3 error.
    async fn check_handle_absent(&self, key: &str) -> Result<bool, S3Error> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(false),
            Err(e) => {
                if e.as_service_error().map(|se| se.is_not_found()) == Some(true) {
                    Ok(true)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Stores a batch of handle entries using a two-phase pre-flight strategy.
    ///
    /// **Phase 1 — pre-flight:** HEAD-checks every handle to build a conflict
    /// list before touching any data.
    ///
    /// **Phase 2 — write:** proceeds only if the pre-flight found no conflicts.
    /// Each write uses `If-None-Match: *` as an additional guard against races
    /// between the check and write phases.
    ///
    /// Three outcomes:
    /// - All handles absent → writes all.
    /// - All handles already exist → idempotent success. This covers NATS
    ///   redelivery where the runner replays an already-committed batch.
    /// - Partial conflict (some exist, some don't) → returns
    ///   [`S3Error::BatchConflict`] with the conflicting keys; nothing is written.
    pub async fn create_handles(&self, entries: Vec<HandleEntry>) -> Result<(), S3Error> {
        let mut conflicts = Vec::new();
        for entry in &entries {
            match self.check_handle_absent(&entry.handle).await? {
                true => {}
                false => conflicts.push(entry.handle.clone()),
            }
        }

        if conflicts.len() == entries.len() {
            info!("all handles already exist, idempotent retry — returning success");
            return Ok(());
        }

        if !conflicts.is_empty() {
            warn!(conflicts = ?conflicts, "partial batch conflict — refusing to write");
            return Err(S3Error::BatchConflict { conflicts });
        }

        for entry in &entries {
            self.create_handle(entry).await?;
        }
        Ok(())
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
}
