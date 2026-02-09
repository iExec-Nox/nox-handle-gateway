use alloy_primitives::{Address, B256, hex};
use alloy_sol_types::{SolCall, sol};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

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
    #[error("RPC call decode: {0}")]
    RpcCallDecode(String),
    #[error("RPC call remote: {0}")]
    RpcCallRemote(String),
    #[error("RPC call transport: {0}")]
    RpcCallTransport(String),
}

#[derive(Clone)]
pub struct AclClient {
    client: Client,
    rpc_url: String,
    contract: Address,
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
            contract,
        })
    }

    pub async fn check_access(&self, handle: B256, viewer: Address) -> Result<(), AclError> {
        if self.contract == Address::ZERO {
            warn!("ACL check skipped: contract is zero address (dev mode)");
            return Ok(());
        }

        let viewer_call = isViewerCall { handle, viewer };
        let is_viewer = self
            .eth_call_bool(viewer_call.abi_encode())
            .await
            .map_err(|e| AclError::RpcCallDecode(e.to_string()))?;
        if is_viewer {
            return Ok(());
        }

        Err(AclError::AccessDenied)
    }

    async fn eth_call_bool(&self, calldata: Vec<u8>) -> Result<bool, AclError> {
        let to = self.contract.to_string();
        let data = format!("0x{}", hex::encode(calldata));

        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_call",
            params: (
                EthCallObject {
                    to: &to,
                    input: &data,
                },
                "latest",
            ),
            id: 1,
        };

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await
            .map_err(|e| AclError::RpcCallTransport(e.to_string()))?;

        let status = resp.status();
        let body: JsonRpcResponse = resp
            .json()
            .await
            .map_err(|e| AclError::RpcCallTransport(e.to_string()))?;

        if let Some(err) = body.error {
            return Err(AclError::RpcCallRemote(format!(
                "status {status}: code {}: {}",
                err.code, err.message
            )));
        }

        let Some(result) = body.result else {
            return Err(AclError::RpcCallRemote(format!(
                "status {status}: missing result"
            )));
        };

        decode_abi_bool(&result).map_err(|e| AclError::RpcCallDecode(e.to_string()))
    }
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'static str,
    params: (EthCallObject<'a>, &'static str),
    id: u64,
}

#[derive(Serialize)]
struct EthCallObject<'a> {
    to: &'a str,
    input: &'a str,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<String>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
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
