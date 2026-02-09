use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::S3Config;
use crate::s3::{S3Client, S3Error};
use crate::utils::strip_0x_prefix;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HandleEntry {
    pub handle: String,
    pub ciphertext: String,
    pub public_key: String,
    pub nonce: String,
    pub created_at: NaiveDateTime,
}

#[derive(Clone)]
pub struct DataRepository {
    s3: S3Client,
}

impl DataRepository {
    pub async fn new(config: &S3Config) -> Self {
        let s3 = S3Client::new(config).await;
        Self { s3 }
    }

    pub async fn create_handle(&self, entry: &HandleEntry) -> Result<HandleEntry, S3Error> {
        let mut entry = entry.clone();
        entry.created_at = Utc::now().naive_utc();

        let data = serde_json::to_vec(&entry).map_err(|e| S3Error::S3Operation {
            message: format!("Failed to serialize entry: {e}"),
        })?;

        let metadata = vec![
            ("handle".to_string(), entry.handle.clone()),
            ("created-at".to_string(), entry.created_at.to_string()),
        ];

        let key = strip_0x_prefix(&entry.handle);

        self.s3.put_if_not_exist(key, &data, metadata).await?;

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
        let key = strip_0x_prefix(handle);
        let data = self.s3.get(key).await?;

        let entry: HandleEntry =
            serde_json::from_slice(&data).map_err(|e| S3Error::S3Operation {
                message: format!("Failed to deserialize entry: {e}"),
            })?;

        Ok(entry)
    }
}
