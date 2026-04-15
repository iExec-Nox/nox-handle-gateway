//! Chain-routing repository layer for handle storage.
//!
//! [`DataRepository`] is the public interface: it dispatches every read and
//! write operation to the correct [`BucketRepository`] by extracting the
//! chain ID from the handle bytes (bytes 1–4, big-endian). One
//! [`BucketRepository`] is maintained per configured chain ID, each backed by
//! its own S3 bucket. All buckets are validated concurrently at startup.

mod bucket;

pub use bucket::{
    BucketRepository, HandleEntry, HandleS3Metadata, PublishSummary, S3Error,
    S3HandleCreationStatus,
};

use std::{collections::HashMap, iter::zip};

use alloy_primitives::hex;
use futures_util::future::join_all;

use crate::config::S3Config;
use crate::handlers::HandleEntryWithTag;

/// Extracts the chain ID from a validated handle hex string.
fn chain_id_from_handle(handle: &str) -> u32 {
    let bytes = hex::decode(handle).unwrap();
    u32::from_be_bytes(bytes[1..5].try_into().unwrap())
}

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
    pub async fn new(configs: &HashMap<u32, S3Config>) -> anyhow::Result<Self> {
        let pairs = join_all(configs.iter().map(|(&chain_id, cfg)| async move {
            let repo = BucketRepository::new(cfg).await?;
            Ok::<_, anyhow::Error>((chain_id, repo))
        }))
        .await;

        let repos = pairs
            .into_iter()
            .collect::<anyhow::Result<HashMap<_, _>>>()?;

        Ok(Self { repos })
    }

    fn repo_for_chain(&self, chain_id: u32) -> Result<&BucketRepository, S3Error> {
        self.repos
            .get(&chain_id)
            .ok_or(S3Error::UnknownChain { chain_id })
    }

    pub async fn create_handle(
        &self,
        entry: &HandleEntry,
        s3_metadata: &HandleS3Metadata,
    ) -> Result<(), S3Error> {
        let chain_id = chain_id_from_handle(&entry.handle);
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
    pub async fn fetch_handle(&self, handle: &str) -> Result<HandleEntry, S3Error> {
        let chain_id = chain_id_from_handle(handle);
        match self.repo_for_chain(chain_id) {
            Ok(repo) => repo.fetch_handle(handle).await,
            Err(S3Error::UnknownChain { .. }) => Err(S3Error::NotFound {
                key: handle.to_string(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Fetches entries from each chain's bucket in a single pass per chain.
    ///
    /// Handles are grouped by chain ID so each [`BucketRepository`] is called
    /// once with its subset rather than once per handle. Original ordering is
    /// preserved by tracking each handle's position before grouping and
    /// reinserting results by index. Handles whose chain ID is not configured
    /// are silently omitted as they cannot exist in any bucket.
    pub async fn read_handles(&self, ids: &[String]) -> Result<Vec<HandleEntry>, S3Error> {
        let mut groups: HashMap<u32, Vec<(usize, &String)>> = HashMap::new();
        for (i, id) in ids.iter().enumerate() {
            let chain_id = chain_id_from_handle(id);
            groups.entry(chain_id).or_default().push((i, id));
        }

        let mut results: Vec<Option<HandleEntry>> = vec![None; ids.len()];

        for (chain_id, indexed_ids) in groups {
            let repo = match self.repo_for_chain(chain_id) {
                Ok(repo) => repo,
                Err(S3Error::UnknownChain { .. }) => continue,
                Err(e) => return Err(e),
            };
            let raw_ids: Vec<String> = indexed_ids.iter().map(|(_, id)| (*id).clone()).collect();
            let entries = repo.read_handles(&raw_ids).await?;
            for (entry, (orig_idx, _)) in zip(entries, indexed_ids) {
                results[orig_idx] = Some(entry);
            }
        }

        Ok(results.into_iter().flatten().collect())
    }

    /// Checks existence of handles across chains, one bucket call per chain.
    ///
    /// Uses the same grouping strategy as [`Self::read_handles`]. Handles whose
    /// chain ID is not configured are reported as `false` as the caller asked
    /// about existence and an unconfigured chain is a definitive "no".
    pub async fn handles_exist(&self, ids: &[String]) -> Result<HashMap<String, bool>, S3Error> {
        let mut groups: HashMap<u32, Vec<&String>> = HashMap::new();
        for id in ids {
            let chain_id = chain_id_from_handle(id);
            groups.entry(chain_id).or_default().push(id);
        }

        let mut result = HashMap::with_capacity(ids.len());
        for (chain_id, group_ids) in groups {
            let repo = match self.repo_for_chain(chain_id) {
                Ok(repo) => repo,
                Err(S3Error::UnknownChain { .. }) => {
                    for id in group_ids {
                        result.insert(id.clone(), false);
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            let raw_ids: Vec<String> = group_ids.iter().map(|id| (*id).clone()).collect();
            let group_result = repo.handles_exist(&raw_ids).await?;
            result.extend(group_result);
        }
        Ok(result)
    }
}
