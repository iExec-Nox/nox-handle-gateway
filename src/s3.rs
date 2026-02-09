use std::fmt::Debug;
use std::time::{Duration, SystemTime};

use aws_sdk_s3::{
    Client, config::Credentials, error::SdkError, primitives::DateTime, types::ObjectLockMode,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::S3Config;

pub const RETENTION_DURATION_SECS: u64 = 100 * 365 * 24 * 3600;
pub const METADATA_CONTENT_SHA256: &str = "content-sha256";

#[derive(Error, Debug)]
pub enum S3Error {
    #[error("Object already exists: {key}")]
    AlreadyExists { key: String },
    #[error("Object not found: {key}")]
    NotFound { key: String },
    #[error("S3 operation failed: {message}")]
    S3Operation { message: String },
}

impl<E: Debug, R: Debug> From<SdkError<E, R>> for S3Error {
    fn from(err: SdkError<E, R>) -> Self {
        S3Error::S3Operation {
            message: format!("{:?}", err),
        }
    }
}

#[derive(Clone)]
pub struct S3Client {
    client: Client,
    bucket: String,
}

impl S3Client {
    pub async fn new(config: &S3Config) -> Self {
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

        Self {
            client: Client::from_conf(s3_config),
            bucket: config.bucket.clone(),
        }
    }

    pub async fn put_if_not_exist(
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
        let content_md5 = aws_smithy_types::base64::encode(md5::compute(data).0);

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

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                let error_str = format!("{:?}", e);
                if error_str.contains("NoSuchKey") || error_str.contains("NotFound") {
                    S3Error::NotFound {
                        key: key.to_string(),
                    }
                } else {
                    S3Error::S3Operation { message: error_str }
                }
            })?;

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| S3Error::S3Operation {
                message: format!("Failed to read response body: {:?}", e),
            })?
            .to_vec();

        Ok(bytes)
    }

    pub async fn exists(&self, key: &str) -> Result<bool, S3Error> {
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
                let error_str = format!("{:?}", e);
                if error_str.contains("NotFound") || error_str.contains("NoSuchKey") {
                    Ok(false)
                } else {
                    Err(S3Error::S3Operation { message: error_str })
                }
            }
        }
    }
}
