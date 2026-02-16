use alloy_primitives::{Address, B256, hex};
use alloy_sol_types::{SolCall, sol};
use reqwest::Client;
use thiserror::Error;

use crate::rpc::{self, RpcError};
use crate::utils::strip_0x_prefix;

sol! {
    function isViewer(bytes32 handle, address viewer) external view returns (bool);
}

#[derive(Debug, Error)]
pub enum AclError {
    #[error("Access denied: not viewer and not publicly decryptable")]
    AccessDenied,
    #[error("Failed to build RPC HTTP client: {0}")]
    ClientBuild(reqwest::Error),
    #[error("ACL misconfigured: {0}")]
    Misconfigured(String),
    #[error("RPC call failed: {0}")]
    Rpc(#[from] RpcError),
    #[error("RPC call decode: {0}")]
    RpcCallDecode(String),
}

#[derive(Clone)]
pub struct AclClient {
    client: Client,
    rpc_url: String,
    contract: String,
}

impl AclClient {
    pub fn new(rpc_url: &str, contract: Address) -> Result<Self, AclError> {
        let client = Client::builder().build().map_err(AclError::ClientBuild)?;
        let rpc_url = rpc_url.trim();
        if rpc_url.is_empty() {
            return Err(AclError::Misconfigured(
                "NOX_HANDLE_GATEWAY_CHAIN__RPC_URL is required".to_string(),
            ));
        }

        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
            contract: contract.to_string(),
        })
    }

    pub async fn check_access(&self, handle: B256, viewer: Address) -> Result<(), AclError> {
        let viewer_call = isViewerCall { handle, viewer };
        let result = rpc::eth_call(
            &self.client,
            &self.rpc_url,
            &self.contract,
            &viewer_call.abi_encode(),
        )
        .await?;
        let is_viewer =
            decode_abi_bool(&result).map_err(|e| AclError::RpcCallDecode(e.to_string()))?;
        if is_viewer {
            return Ok(());
        }

        Err(AclError::AccessDenied)
    }
}

fn decode_abi_bool(hex_value: &str) -> Result<bool, &'static str> {
    let hex_str = strip_0x_prefix(hex_value);
    let bytes = hex::decode(hex_str).map_err(|_| "invalid hex")?;
    if bytes.len() < 32 {
        return Err("invalid ABI bool length");
    }

    // ABI bool is left-padded to 32 bytes; non-zero means true.
    Ok(bytes[bytes.len() - 1] != 0)
}
