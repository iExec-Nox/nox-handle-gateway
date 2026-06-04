use alloy::{
    primitives::{Address, B256, Bytes, FixedBytes},
    providers::RootProvider,
    sol,
};
use k256::PublicKey;
use thiserror::Error;

sol! {
    /// On-chain interface for ACL checks and KMS public key retrieval.
    #[sol(rpc)]
    interface INoxCompute {
        function isViewer(bytes32 handle, address viewer) external view returns (bool);
        function isPubliclyDecryptable(bytes32 handle) external view returns (bool);
        function kmsPublicKey() external view returns (bytes memory);
        function gateway() external view returns (address);
    }

    /// ERC-1271 standard interface for Smart Account signature verification.
    #[sol(rpc)]
    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes memory signature)
            external view returns (bytes4);
    }
}

/// Errors returned by [`NoxClient`] operations.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error(transparent)]
    CallFailure(alloy::contract::Error),
    #[error("Invalid KMS public key: {0}")]
    InvalidKey(String),
    #[error("RPC provider error: {0}")]
    ProviderError(String),
}

/// Ethereum RPC client for on-chain reads against the NoxCompute contract.
///
/// Wraps an `INoxCompute` contract instance to verify ACL access and fetch the
/// KMS public key. Also provides ERC-1271 signature verification for Smart
/// Account callers via a separate `IERC1271` contract instance created on demand.
#[derive(Clone, Debug)]
pub struct NoxClient {
    contract: INoxCompute::INoxComputeInstance<RootProvider>,
}

impl NoxClient {
    /// Build a [`NoxClient`] connected to `rpc_url`.
    ///
    /// Connects to the Ethereum node at `rpc_url` and wraps the `INoxCompute`
    /// contract at `contract_address`. Returns [`RpcError::ProviderError`] if
    /// the connection fails.
    pub async fn new(rpc_url: &str, contract_address: Address) -> Result<Self, RpcError> {
        let trimmed_rpc_url = rpc_url.trim_end_matches('/');
        let provider = RootProvider::connect(trimmed_rpc_url)
            .await
            .map_err(|e| RpcError::ProviderError(e.to_string()))?;
        let contract = INoxCompute::new(contract_address, provider);
        Ok(Self { contract })
    }

    /// Fetch the KMS public key from the NoxCompute contract.
    ///
    /// Calls `kmsPublicKey()` on-chain and parses the returned bytes as a
    /// compressed SEC1 public key. Called once at startup to initialise
    /// [`KmsClient`](crate::kms::KmsClient).
    pub async fn kms_public_key(&self) -> Result<PublicKey, RpcError> {
        let result = self
            .contract
            .kmsPublicKey()
            .call()
            .await
            .map_err(RpcError::CallFailure)?;
        PublicKey::from_sec1_bytes(&result).map_err(|e| RpcError::InvalidKey(e.to_string()))
    }

    /// Fetch the on-chain gateway address from the NoxCompute contract.
    ///
    /// Calls `gateway()` on-chain. Used at startup to cross-check the configured
    /// `wallet_key` derives the same address as registered on-chain.
    pub async fn gateway_address(&self) -> Result<Address, RpcError> {
        self.contract
            .gateway()
            .call()
            .await
            .map_err(RpcError::CallFailure)
    }

    /// Verify that `viewer` has read access to `handle` on-chain.
    ///
    /// Calls `isViewer(handle, viewer)` on the NoxCompute contract. Returns
    /// `Ok(true)` when access is granted, `Ok(false)` when it is not. Returns [`RpcError::CallFailure`] if the RPC node is unreachable or
    /// the call fails for any transport reason.
    pub async fn check_access(&self, handle: B256, viewer: Address) -> Result<bool, RpcError> {
        let is_viewer = self
            .contract
            .isViewer(handle, viewer)
            .call()
            .await
            .map_err(RpcError::CallFailure)?;
        Ok(is_viewer)
    }

    /// Verify that `handle` is marked as publicly decryptable on-chain.
    ///
    /// Calls `isPubliclyDecryptable(handle)` on the NoxCompute contract. Returns
    /// `Ok(true)` when the handle is publicly decryptable, `Ok(false)` when it is not.
    /// Returns [`RpcError::CallFailure`] if the RPC node is unreachable or the call fails for any transport reason.
    pub async fn is_publicly_decryptable(&self, handle: B256) -> Result<bool, RpcError> {
        let is_public = self
            .contract
            .isPubliclyDecryptable(handle)
            .call()
            .await
            .map_err(RpcError::CallFailure)?;
        Ok(is_public)
    }

    /// Verify an ERC-1271 signature against a Smart Account contract at `address`.
    ///
    /// Calls `isValidSignature(hash, signature)` on the contract deployed at
    /// `address`. Returns `Ok(true)` if the contract returns the ERC-1271 magic
    /// value (`0x1626ba7e`). Returns `Ok(false)` if the contract returns any other value. Returns
    /// [`RpcError::CallFailure`] if the call itself fails
    /// for any reason (transport error, revert, ABI mismatch, contract not
    /// deployed, …), forwarding the raw alloy error transparently so no
    /// information is lost.
    pub async fn verify_erc1271(
        &self,
        hash: B256,
        signature: &[u8],
        address: Address,
    ) -> Result<bool, RpcError> {
        const MAGIC_VALUE: FixedBytes<4> = FixedBytes([0x16, 0x26, 0xba, 0x7e]);

        let provider = self.contract.provider().clone();
        let contract = IERC1271::new(address, provider);

        match contract
            .isValidSignature(hash, Bytes::from(signature.to_vec()))
            .call()
            .await
        {
            Ok(MAGIC_VALUE) => Ok(true), // valid ERC-1271 signature
            Ok(_) => Ok(false),          // call succeeded but signature is invalid
            Err(alloy::contract::Error::ZeroData(_, _)) => Ok(false), // when called address is not an ERC-1271 contract
            Err(alloy::contract::Error::TransportError(
                alloy::transports::RpcError::ErrorResp(_),
            )) => Ok(false), // when called contract reverts (e.g. due to invalid signature)
            Err(e) => Err(RpcError::CallFailure(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        hex,
        primitives::{address, b256},
    };

    use super::*;

    const RPC_URL: &str = "https://arbitrum-sepolia.drpc.org";
    const BAD_RPC_URL: &str = "https://not-an-rpc-node.invalid";
    const AA_ADDRESS: Address = address!("0xE831ed7F6F79eE19005fF3C5d8Ee3938F1655873");
    const HASH: B256 = b256!("0xf38604494066bb3860ba01ca14f45b0dea9bb90c28b3cc197c7110b2ee15dd2d");
    const SIGNATURE: [u8; 66] = hex!(
        "0x002eb79fe60ed2bf8fdbe98b062be86ce942e7aa2f60a1b34031b4cec0f6c0cfc605a5585d8d2a699c15d35c5fed84c85638a1865e04df49da56a8b9675b49e7481b"
    );

    async fn make_arbitrum_sepolia_client(rpc_url: &str) -> NoxClient {
        NoxClient::new(rpc_url, Address::ZERO).await.unwrap()
    }

    #[tokio::test]
    async fn test_verify_erc1271_rpc_error() {
        let client = make_arbitrum_sepolia_client(BAD_RPC_URL).await;
        let result = client.verify_erc1271(HASH, &SIGNATURE, AA_ADDRESS).await;
        let err = result.expect_err("should fail on invalid RPC URL");
        assert!(
            matches!(err, RpcError::CallFailure(_)),
            "should return CallFailure error on RPC failure"
        );
    }

    #[tokio::test]
    async fn test_verify_erc1271_eoa() {
        let client = make_arbitrum_sepolia_client(RPC_URL).await;
        let eoa = Address::ZERO;
        let result = client.verify_erc1271(HASH, &SIGNATURE, eoa).await;
        let is_valid = result.expect("should not fail on EOA");
        assert!(!is_valid, "should return false for EOA");
    }

    #[tokio::test]
    async fn test_verify_erc1271_non_erc1271_contract() {
        let client = make_arbitrum_sepolia_client(RPC_URL).await;
        let result = client
            .verify_erc1271(
                HASH,
                &SIGNATURE,
                address!("0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d"), // USDC contract on Arbitrum Sepolia, not an ERC-1271 contract
            )
            .await;
        let is_valid = result.expect("should not fail on non-ERC1271 contract");
        assert!(!is_valid, "should return false for non-ERC1271 contract");
    }

    #[tokio::test]
    async fn test_verify_erc1271_erc1271_contract_invalid_signature() {
        let client = make_arbitrum_sepolia_client(RPC_URL).await;
        let result = client.verify_erc1271(HASH, &[0u8; 65], AA_ADDRESS).await;
        let is_valid = result.expect("should not fail on ERC1271 contract");
        assert!(
            !is_valid,
            "should return false for ERC1271 contract with invalid signature"
        );
    }

    #[tokio::test]
    async fn test_verify_erc1271_erc1271_contract_valid_signature() {
        let client = make_arbitrum_sepolia_client(RPC_URL).await;
        let result = client.verify_erc1271(HASH, &SIGNATURE, AA_ADDRESS).await;
        let is_valid = result.expect("should not fail on ERC1271 contract");
        assert!(
            is_valid,
            "should return true for ERC1271 contract with valid signature"
        );
    }
}
