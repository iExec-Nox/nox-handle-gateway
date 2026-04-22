//! Chain-routing repository layer for handle storage.
//!
//! [`DataRepository`] is the public interface: it dispatches every read and
//! write operation to the correct [`BucketRepository`] by extracting the
//! chain ID from the handle bytes (bytes 1–4, big-endian). One
//! [`BucketRepository`] is maintained per configured chain ID, each backed by
//! its own S3 bucket. All buckets are validated concurrently at startup.

mod bucket;

use bucket::BucketRepository;
pub use bucket::{HandleEntry, HandleS3Metadata, PublishSummary, S3Error, S3HandleCreationStatus};

use std::collections::HashMap;

use futures_util::future::try_join_all;

use crate::config::PerChainConfig;
use crate::handlers::HandleEntryWithTag;
use crate::validation::chain_id_from_handle;

/// Chain-routing repository that dispatches all handle operations to the
/// correct [`BucketRepository`] based on the chain ID encoded in each handle.
#[derive(Clone)]
pub struct DataRepository {
    repos: HashMap<u32, BucketRepository>,
}

impl DataRepository {
    /// Builds one [`BucketRepository`] per configured chain ID, validating all
    /// buckets concurrently at startup. Fails if any bucket is unreachable or
    /// has a mismatched Object Lock state.
    pub async fn new(configs: &HashMap<u32, PerChainConfig>) -> anyhow::Result<Self> {
        let repos = try_join_all(configs.iter().map(|(&chain_id, cfg)| async move {
            BucketRepository::new(&cfg.s3)
                .await
                .map(|repo| (chain_id, repo))
        }))
        .await?
        .into_iter()
        .collect();

        Ok(Self { repos })
    }

    fn repo_for_chain(&self, chain_id: u32) -> Result<&BucketRepository, S3Error> {
        self.repos
            .get(&chain_id)
            .ok_or(S3Error::UnknownChain { chain_id })
    }

    pub async fn create_handle(
        &self,
        chain_id: u32,
        entry: &HandleEntry,
        s3_metadata: &HandleS3Metadata,
    ) -> Result<(), S3Error> {
        self.repo_for_chain(chain_id)?
            .create_handle(entry, s3_metadata)
            .await
    }

    pub async fn create_handles(
        &self,
        entries: Vec<HandleEntryWithTag>,
        chain_id: u32,
        origin: &str,
        application_contract: &str,
    ) -> Result<PublishSummary, S3Error> {
        self.repo_for_chain(chain_id)?
            .create_handles(entries, origin, application_contract)
            .await
    }

    /// Routes to the bucket for the handle's chain ID.
    ///
    /// Returns [`S3Error::NotFound`] rather than [`S3Error::UnknownChain`] when
    /// the chain ID is not configured because an unconfigured chain means the handle
    /// cannot exist, which is indistinguishable from a missing key to the caller.
    // TODO: surface a richer not-found variant that distinguishes
    // "no such key in the configured bucket" from "handle references a chain
    // the gateway does not know" and includes the set of configured chain IDs
    // so operators can spot misconfiguration quickly.
    pub async fn fetch_handle(&self, handle: &str) -> Result<HandleEntry, S3Error> {
        let chain_id = chain_id_from_handle(handle).map_err(|e| S3Error::InvalidHandle {
            reason: e.to_string(),
        })?;
        match self.repo_for_chain(chain_id) {
            Ok(repo) => repo.fetch_handle(handle).await,
            Err(S3Error::UnknownChain { .. }) => Err(S3Error::NotFound {
                key: handle.to_string(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Fetches entries from the bucket for a single chain.
    ///
    /// All operands in one compute request belong to the same transaction and
    /// therefore to the same chain. A mixed-chain batch is a caller bug and is
    /// rejected with [`S3Error::InvalidHandle`].
    pub async fn read_handles(
        &self,
        chain_id: u32,
        ids: &[String],
    ) -> Result<Vec<HandleEntry>, S3Error> {
        for id in ids {
            let handle_chain = chain_id_from_handle(id).map_err(|e| S3Error::InvalidHandle {
                reason: e.to_string(),
            })?;
            if handle_chain != chain_id {
                return Err(S3Error::InvalidHandle {
                    reason: format!(
                        "handle {id} encodes chain {handle_chain}, expected {chain_id}",
                    ),
                });
            }
        }
        self.repo_for_chain(chain_id)?.read_handles(ids).await
    }

    /// Checks existence of handles within a single chain's bucket.
    ///
    /// The caller is responsible for ensuring all `ids` belong to `chain_id`
    /// and that `chain_id` is a configured chain.
    pub async fn handles_exist(
        &self,
        chain_id: u32,
        ids: &[String],
    ) -> Result<HashMap<String, bool>, S3Error> {
        self.repo_for_chain(chain_id)?.handles_exist(ids).await
    }
}
