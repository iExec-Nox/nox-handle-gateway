//! Chain-routing repository layer for handle storage.
//!
//! [`DataRepository`] is the public interface: it dispatches every read and
//! write operation to the correct [`BucketRepository`] by extracting the
//! chain ID from the handle bytes (bytes 1–4, big-endian). One
//! [`BucketRepository`] is maintained per configured chain ID, each backed by
//! its own S3 bucket. All buckets are validated concurrently at startup.

mod bucket;

use bucket::{BucketRepository, S3Error};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::future::try_join_all;
use tokio::sync::Semaphore;

use crate::config::PerChainConfig;
use crate::validation::chain_id_from_handle;

/// The JSON handle entry stored in the repository.
///
/// It contains:
/// - handle bytes32 id
/// - the ciphertext
/// - the public key
/// - the nonce.
///
/// Only the crypto material needed to serve decryption requests is stored in the body.
/// Enrichment fields (chain ID, data type, origin, …) live exclusively in HandleMetadata.
#[derive(Clone, Deserialize, Serialize)]
pub struct HandleEntry {
    pub handle: String,
    pub ciphertext: String,
    pub public_key: String,
    pub nonce: String,
}

/// Atomic handle data sent by a Runner when publishing computation results.
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

/// User-metadata attached to every stored handle object.
///
/// These fields are not part of the HandleEntry JSON body - they are written once at creation time and are available for external inspection without downloading the object body.
///
/// `content-sha256` is **not** included here; it is computed and inserted
/// by [`BucketRepository::create_handle`] itself.
pub struct HandleMetadata {
    pub handle: String,
    pub created_at: NaiveDateTime,
    pub chain_id: u32,
    pub data_type: String,
    pub origin: String,
    pub is_public: bool,
    pub handle_value_tag: String,
    pub application_contract: String,
}

impl HandleMetadata {
    fn to_metadata_map(&self) -> HashMap<String, String> {
        HashMap::from([
            ("handle".to_string(), self.handle.clone()),
            ("created-at".to_string(), self.created_at.to_string()),
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

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Storage failure: {0}")]
    Internal(S3Error), // only escapes if it's a genuine infra failure
    #[error("Invalid handle: {reason}")]
    InvalidHandle { reason: String },
    #[error("No S3 bucket configured for chain ID {chain_id}")]
    UnknownChain { chain_id: u32 },
}

impl From<S3Error> for RepositoryError {
    fn from(e: S3Error) -> Self {
        RepositoryError::Internal(e)
    }
}

/// Chain-routing repository that dispatches all handle operations to the
/// correct [`BucketRepository`] based on the chain ID encoded in each handle.
#[derive(Clone)]
pub struct DataRepository {
    repos: HashMap<u32, BucketRepository>,
}

impl DataRepository {
    /// Builds one [`BucketRepository`] per configured chain ID, validating all
    /// buckets concurrently at startup. A single `Arc<Semaphore>` sized from
    /// `s3_max_concurrent_requests` is shared across every repository, capping
    /// in-flight S3 operations globally. Fails if any bucket is unreachable or
    /// has a mismatched Object Lock state.
    pub async fn new(
        configs: &HashMap<u32, PerChainConfig>,
        s3_max_concurrent_requests: usize,
    ) -> anyhow::Result<Self> {
        let s3_semaphore = Arc::new(Semaphore::new(s3_max_concurrent_requests));
        let repos = try_join_all(configs.iter().map(|(&chain_id, cfg)| {
            let sem = Arc::clone(&s3_semaphore);
            async move {
                BucketRepository::new(&cfg.s3, sem)
                    .await
                    .map(|repo| (chain_id, repo))
            }
        }))
        .await?
        .into_iter()
        .collect();

        Ok(Self { repos })
    }

    /// Builds a [`DataRepository`] with no configured chains, skipping the S3
    /// bucket validation that [`DataRepository::new`] performs.
    ///
    /// For handler-level tests that never reach a repository call — every
    /// lookup fails with [`RepositoryError::UnknownChain`].
    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        Self {
            repos: HashMap::new(),
        }
    }

    fn repo_for_chain(&self, chain_id: u32) -> Result<&BucketRepository, RepositoryError> {
        self.repos
            .get(&chain_id)
            .ok_or(RepositoryError::UnknownChain { chain_id })
    }

    pub async fn create_handle(
        &self,
        chain_id: u32,
        entry: &HandleEntry,
        metadata: &HandleMetadata,
    ) -> Result<(), RepositoryError> {
        self.repo_for_chain(chain_id)?
            .create_handle(entry, metadata)
            .await
            .map_err(|e| match e {
                S3Error::AlreadyExists { key } => RepositoryError::Conflict(key),
                _ => RepositoryError::Internal(e),
            })
    }

    pub async fn create_handles(
        &self,
        entries: Vec<HandleEntryWithTag>,
        chain_id: u32,
        origin: &str,
        application_contract: &str,
    ) -> Result<PublishSummary, RepositoryError> {
        self.repo_for_chain(chain_id)?
            .create_handles(entries, origin, application_contract)
            .await
            .map_err(|e| match e {
                S3Error::AlreadyExists { key } => RepositoryError::Conflict(key),
                _ => RepositoryError::Internal(e),
            })
    }

    /// Routes to the bucket for the handle's chain ID.
    ///
    /// Returns [`RepositoryError::NotFound`] rather than [`RepositoryError::UnknownChain`] when
    /// the chain ID is not configured because an unconfigured chain means the handle
    /// cannot exist, which is indistinguishable from a missing key to the caller.
    // TODO: surface a richer not-found variant that distinguishes
    // "no such key in the configured bucket" from "handle references a chain
    // the gateway does not know" and includes the set of configured chain IDs
    // so operators can spot misconfiguration quickly.
    pub async fn fetch_handle(&self, handle: &str) -> Result<HandleEntry, RepositoryError> {
        let chain_id =
            chain_id_from_handle(handle).map_err(|e| RepositoryError::InvalidHandle {
                reason: e.to_string(),
            })?;
        self.repo_for_chain(chain_id)
            .map_err(|_| RepositoryError::NotFound(handle.to_string()))?
            .fetch_handle(handle)
            .await
            .map_err(|e| match e {
                S3Error::NotFound { key } => RepositoryError::NotFound(key),
                _ => RepositoryError::Internal(e),
            })
    }

    /// Fetches entries from the bucket for a single chain.
    ///
    /// All operands in one compute request belong to the same transaction and
    /// therefore to the same chain. A mixed-chain batch is a caller issue and
    /// is rejected with [`RepositoryError::InvalidHandle`].
    pub async fn read_handles(
        &self,
        chain_id: u32,
        ids: &[String],
    ) -> Result<Vec<HandleEntry>, RepositoryError> {
        for id in ids {
            let handle_chain =
                chain_id_from_handle(id).map_err(|e| RepositoryError::InvalidHandle {
                    reason: e.to_string(),
                })?;
            if handle_chain != chain_id {
                return Err(RepositoryError::InvalidHandle {
                    reason: format!(
                        "handle {id} encodes chain {handle_chain}, expected {chain_id}",
                    ),
                });
            }
        }
        Ok(self.repo_for_chain(chain_id)?.read_handles(ids).await?)
    }

    /// Checks existence of handles within a single chain's bucket.
    ///
    /// The caller is responsible for ensuring all `ids` belong to `chain_id`
    /// and that `chain_id` is a configured chain.
    pub async fn handles_exist(
        &self,
        chain_id: u32,
        ids: &[String],
    ) -> Result<HashMap<String, bool>, RepositoryError> {
        Ok(self.repo_for_chain(chain_id)?.handles_exist(ids).await?)
    }
}
