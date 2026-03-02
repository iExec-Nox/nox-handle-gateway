//! S3/MinIO storage backend for encrypted handle entries.
//!
//! Handles bucket validation at startup, atomic single-object writes via
//! `If-None-Match: *`, and idempotent batch publishing with pre-flight conflict
//! detection.

use std::fmt::Debug;
use std::time::{Duration, SystemTime};

use aws_sdk_s3::{
    Client,
    config::Credentials,
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

const RETENTION_DURATION_SECS: u64 = 100 * 365 * 24 * 3600;
const METADATA_CONTENT_SHA256: &str = "content-sha256";

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
/// The S3 key is the `handle` field with a `0x` prefix. The `created_at`
/// field is set server-side by [`DataRepository::create_handle`] and written
/// to the S3 object metadata under `"created-at"` for observability; it is
/// excluded from the JSON body via `#[serde(skip)]`.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HandleEntry {
    pub handle: String,
    pub ciphertext: String,
    pub public_key: String,
    pub nonce: String,
    #[serde(skip)]
    pub created_at: Option<NaiveDateTime>,
}

/// S3/MinIO client wrapper for handle storage operations.
#[derive(Clone)]
pub struct DataRepository {
    client: Client,
    bucket: String,
}

impl DataRepository {
    /// Builds the S3 client from config and validates the target bucket.
    ///
    /// Fails fast: returns an error (and the process exits) if the bucket is
    /// unreachable or does not have S3 Object Lock enabled. Object Lock is
    /// required because handles are immutable — once written they must not be
    /// overwritten or deleted.
    pub async fn new(config: &S3Config) -> anyhow::Result<Self> {
        let credentials =
            Credentials::new(&config.access_key, &config.secret_key, None, None, "static");

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .credentials_provider(credentials)
            .region(aws_config::Region::new(config.region.clone()))
            .endpoint_url(&config.endpoint_url)
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(config.timeout))
                    .build(),
            )
            .load()
            .await;

        let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
            .force_path_style(true)
            .build();

        let repo = Self {
            client: Client::from_conf(s3_config),
            bucket: config.bucket.clone(),
        };

        repo.validate_bucket().await?;
        Ok(repo)
    }

    /// Verifies the bucket is accessible and has Object Lock enabled.
    ///
    /// Checks bucket existence via HEAD and confirms Object Lock is in Compliance
    /// mode. Called once at startup; any failure aborts the process.
    async fn validate_bucket(&self) -> anyhow::Result<()> {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!("S3 bucket '{}' is not accessible: {:?}", self.bucket, e)
            })?;

        let lock_response = self
            .client
            .get_object_lock_configuration()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "S3 bucket '{}' does not have Object Lock configured: {:?}",
                    self.bucket,
                    e
                )
            })?;

        let lock_enabled = matches!(
            lock_response
                .object_lock_configuration()
                .and_then(|c| c.object_lock_enabled()),
            Some(ObjectLockEnabled::Enabled)
        );

        if !lock_enabled {
            return Err(anyhow::anyhow!(
                "S3 bucket '{}' does not have Object Lock enabled",
                self.bucket
            ));
        }

        Ok(())
    }

    /// Stores a single handle entry in S3 under an If-None-Match guard.
    ///
    /// Sets `created_at` to the current server time before writing. The
    /// timestamp is excluded from the JSON body but written to the S3 object
    /// metadata under `"created-at"` for observability.
    ///
    /// Uses `If-None-Match: *` so the existence check and write are a single
    /// atomic operation. A 412 response (key already exists) is mapped to
    /// [`S3Error::AlreadyExists`]; all other errors become [`S3Error::S3Operation`].
    ///
    /// Objects are written with S3 Object Lock Compliance mode and a 100-year
    /// retention period, making them immutable for the lifetime of the system.
    ///
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
    ) -> Result<(HandleEntry, NaiveDateTime), S3Error> {
        let mut entry = entry.clone();
        let created_at = Utc::now().naive_utc();
        entry.created_at = Some(created_at);

        let data = serde_json::to_vec(&entry).map_err(|e| S3Error::S3Operation {
            message: format!("Failed to serialize entry: {e}"),
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = format!("{:x}", hasher.finalize());

        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&entry.handle)
            .body(data.into())
            .content_type("application/octet-stream")
            .if_none_match("*")
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from(
                SystemTime::now() + Duration::from_secs(RETENTION_DURATION_SECS),
            ))
            .checksum_algorithm(ChecksumAlgorithm::Crc64Nvme)
            .metadata("handle", &entry.handle)
            .metadata("created-at", entry.created_at.unwrap().to_string())
            .metadata(METADATA_CONTENT_SHA256, sha256);

        let output = request.send().await.map_err(|err| {
            if let aws_sdk_s3::error::SdkError::ServiceError(ref service_err) = err
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
            e_tag = ?output.e_tag(),
            version_id = ?output.version_id(),
            checksum_crc64_nvme = ?output.checksum_crc64_nvme(),
            "handle stored in S3",
        );

        Ok((entry, created_at))
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
    /// - All handles absent → writes all, returns them.
    /// - All handles already exist → idempotent success; returns an empty vec.
    ///   This covers NATS redelivery where the runner replays an already-committed
    ///   batch.
    /// - Partial conflict (some exist, some don't) → returns
    ///   [`S3Error::BatchConflict`] with the conflicting keys; nothing is written.
    pub async fn create_handles(
        &self,
        entries: Vec<HandleEntry>,
    ) -> Result<Vec<HandleEntry>, S3Error> {
        let mut conflicts = Vec::new();
        for entry in &entries {
            match self.check_handle_absent(&entry.handle).await? {
                true => {}
                false => conflicts.push(entry.handle.clone()),
            }
        }

        if conflicts.len() == entries.len() {
            info!("all handles already exist, idempotent retry — returning success");
            return Ok(vec![]);
        }

        if !conflicts.is_empty() {
            warn!(conflicts = ?conflicts, "partial batch conflict — refusing to write");
            return Err(S3Error::BatchConflict { conflicts });
        }

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            let (handle_entry, _) = self.create_handle(&entry).await?;
            results.push(handle_entry);
        }
        Ok(results)
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
