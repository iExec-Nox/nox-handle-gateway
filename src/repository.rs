use std::error::Error as stdError;
use std::fmt::Debug;
use std::time::{Duration, SystemTime};

use aws_sdk_s3::{
    Client,
    config::Credentials,
    error::SdkError,
    primitives::DateTime,
    types::{ObjectLockEnabled, ObjectLockMode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::S3Config;

const RETENTION_DURATION_SECS: u64 = 100 * 365 * 24 * 3600;
const METADATA_CONTENT_SHA256: &str = "content-sha256";

#[derive(Error, Debug)]
pub enum S3Error {
    #[error("Object already exists: {key}")]
    AlreadyExists { key: String },
    #[error("Object not found: {key}")]
    NotFound { key: String },
    #[error("S3 operation failed: {message}")]
    S3Operation { message: String },
}

fn extract_error_message<E: stdError + 'static, R: Debug>(err: &SdkError<E, R>) -> String {
    let mut current: &dyn stdError = err;
    let mut deepest = String::new();
    while let Some(source) = current.source() {
        deepest = source.to_string();
        current = source;
    }
    if deepest.is_empty() {
        format!("{err:?}")
    } else {
        deepest
    }
}

impl<E: stdError + 'static, R: Debug> From<SdkError<E, R>> for S3Error {
    fn from(err: SdkError<E, R>) -> Self {
        S3Error::S3Operation {
            message: extract_error_message(&err),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HandleEntry {
    pub handle: String,
    pub ciphertext: String,
    pub public_key: String,
    pub nonce: String,
    #[serde(skip)]
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Clone)]
pub struct DataRepository {
    client: Client,
    bucket: String,
}

impl DataRepository {
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

    async fn put_if_not_exist(
        &self,
        key: &str,
        data: &[u8],
        metadata: Vec<(String, String)>,
    ) -> Result<(), S3Error> {
        if self.exists(key).await? {
            return Err(S3Error::AlreadyExists {
                key: key.to_string(),
            });
        }

        let retain_until = SystemTime::now() + Duration::from_secs(RETENTION_DURATION_SECS);
        let content_md5 = STANDARD.encode(md5::compute(data).0);

        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(data.to_vec().into())
            .content_type("application/octet-stream")
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from(retain_until))
            .content_md5(content_md5);

        for (k, v) in metadata {
            request = request.metadata(k, v);
        }

        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());
        request = request.metadata(METADATA_CONTENT_SHA256, hash);

        request.send().await?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, S3Error> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.as_service_error().map(|se| se.is_not_found()) == Some(true) {
                    Ok(false)
                } else {
                    Err(S3Error::S3Operation {
                        message: extract_error_message(&e),
                    })
                }
            }
        }
    }

    pub async fn create_handle(&self, entry: &HandleEntry) -> Result<HandleEntry, S3Error> {
        let mut entry = entry.clone();
        entry.created_at = Some(Utc::now().naive_utc());

        let data = serde_json::to_vec(&entry).map_err(|e| S3Error::S3Operation {
            message: format!("Failed to serialize entry: {e}"),
        })?;

        let metadata = vec![
            ("handle".to_string(), entry.handle.clone()),
            (
                "created-at".to_string(),
                entry.created_at.unwrap().to_string(),
            ),
        ];

        self.put_if_not_exist(&entry.handle, &data, metadata)
            .await?;

        Ok(entry)
    }

    pub async fn create_handles(
        &self,
        entries: Vec<HandleEntry>,
    ) -> Result<Vec<HandleEntry>, S3Error> {
        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            results.push(self.create_handle(&entry).await?);
        }
        Ok(results)
    }

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
                    S3Error::S3Operation {
                        message: extract_error_message(&e),
                    }
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
