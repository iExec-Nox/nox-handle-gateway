use std::time::Duration;

use alloy::{
    hex,
    primitives::{Address, B256, address, b256},
};

use nox_handle_gateway::rpc::{NoxClient, RpcError};

/// RPC node for Arbitrum Sepolia, any RPC node that supports Arbitrum Sepolia should work, this one is operated by a third party and may break.
const RPC_URL: &str = "https://arbitrum-sepolia.drpc.org";
/// ERC1271 Account contract deployed on Arbitrum Sepolia (https://sepolia.arbiscan.io/address/0xE831ed7F6F79eE19005fF3C5d8Ee3938F1655873)
const ERC1271_ACCOUNT_ADDRESS: Address = address!("0xE831ed7F6F79eE19005fF3C5d8Ee3938F1655873");
/// dummy EIP712 hash
const HASH: B256 = b256!("0xf38604494066bb3860ba01ca14f45b0dea9bb90c28b3cc197c7110b2ee15dd2d");
/// valid signature from ERC1271_ACCOUNT_ADDRESS for the above HASH on Arbitrum Sepolia
const SIGNATURE: [u8; 66] = hex!(
    "0x002eb79fe60ed2bf8fdbe98b062be86ce942e7aa2f60a1b34031b4cec0f6c0cfc605a5585d8d2a699c15d35c5fed84c85638a1865e04df49da56a8b9675b49e7481b"
);

async fn make_arbitrum_sepolia_client(rpc_url: &str) -> NoxClient {
    NoxClient::new(
        rpc_url,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Address::ZERO,
    )
    .await
    .unwrap()
}

#[tokio::test]
#[ignore]
async fn test_verify_erc1271_rpc_error() {
    let bad_rpc_url: &str = "https://not-an-rpc-node.invalid";
    let client = make_arbitrum_sepolia_client(bad_rpc_url).await;
    let result = client
        .verify_erc1271(HASH, &SIGNATURE, ERC1271_ACCOUNT_ADDRESS)
        .await;
    let err = result.expect_err("should fail on invalid RPC URL");
    assert!(
        matches!(err, RpcError::CallFailure(_)),
        "should return CallFailure error on RPC failure"
    );
}

#[tokio::test]
#[ignore]
async fn test_verify_erc1271_eoa() {
    let client = make_arbitrum_sepolia_client(RPC_URL).await;
    let eoa = Address::ZERO;
    let result = client.verify_erc1271(HASH, &SIGNATURE, eoa).await;
    let is_valid = result.expect("should not fail on EOA");
    assert!(!is_valid, "should return false for EOA");
}

#[tokio::test]
#[ignore]
async fn test_verify_erc1271_non_erc1271_contract() {
    let client = make_arbitrum_sepolia_client(RPC_URL).await;
    let non_erc1271_contract = address!("0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d"); // USDC contract on Arbitrum Sepolia, not an ERC1271 contract
    let result = client
        .verify_erc1271(HASH, &SIGNATURE, non_erc1271_contract)
        .await;
    let is_valid = result.expect("should not fail on non-ERC1271 contract");
    assert!(!is_valid, "should return false for non-ERC1271 contract");
}

#[tokio::test]
#[ignore]
async fn test_verify_erc1271_erc1271_contract_invalid_signature() {
    let client = make_arbitrum_sepolia_client(RPC_URL).await;
    let invalid_signature = [0u8; 65]; // invalid signature
    let result = client
        .verify_erc1271(HASH, &invalid_signature, ERC1271_ACCOUNT_ADDRESS)
        .await;
    let is_valid = result.expect("should not fail on ERC1271 contract");
    assert!(
        !is_valid,
        "should return false for ERC1271 contract with invalid signature"
    );
}

#[tokio::test]
#[ignore]
async fn test_verify_erc1271_erc1271_contract_valid_signature() {
    let client = make_arbitrum_sepolia_client(RPC_URL).await;
    let result = client
        .verify_erc1271(HASH, &SIGNATURE, ERC1271_ACCOUNT_ADDRESS)
        .await;
    let is_valid = result.expect("should not fail on ERC1271 contract");
    assert!(
        is_valid,
        "should return true for ERC1271 contract with valid signature"
    );
}
