use alloy_primitives::hex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC transport: {0}")]
    Transport(String),
    #[error("RPC remote: {0}")]
    Remote(String),
}

pub async fn eth_call(
    client: &Client,
    rpc_url: &str,
    to: &str,
    calldata: &[u8],
) -> Result<String, RpcError> {
    let data = format!("0x{}", hex::encode(calldata));

    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method: "eth_call",
        params: (EthCallObject { to, input: &data }, "latest"),
        id: 1,
    };

    let resp = client
        .post(rpc_url)
        .json(&req)
        .send()
        .await
        .map_err(|e| RpcError::Transport(e.to_string()))?;

    let status = resp.status();
    let body: JsonRpcResponse = resp
        .json()
        .await
        .map_err(|e| RpcError::Transport(e.to_string()))?;

    if let Some(err) = body.error {
        return Err(RpcError::Remote(format!(
            "status {status}: code {}: {}",
            err.code, err.message
        )));
    }

    body.result
        .ok_or_else(|| RpcError::Remote(format!("status {status}: missing result")))
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
