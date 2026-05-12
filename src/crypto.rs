use std::collections::HashMap;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use alloy_primitives::hex;
use alloy_signer_local::PrivateKeySigner;
use hkdf::Hkdf;
use k256::{
    PublicKey,
    ecdh::EphemeralSecret,
    elliptic_curve::{
        rand_core::{OsRng, RngCore},
        sec1::ToEncodedPoint,
    },
};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey};
use sha2::Sha256;
use thiserror::Error;
use tracing::info;

/// HKDF info/context string for key derivation
const ECIES_CONTEXT: &[u8] = b"ECIES:AES_GCM:v1";

#[derive(Debug, Error)]
pub enum Error {
    #[error("AES-GCM error: {0}")]
    AesGcmError(String),
    #[error("ECC error: {0}")]
    EccError(String),
    #[error("ECIES decryption error: {0}")]
    EciesDecryptionError(String),
    #[error("protocol key map must not be empty")]
    EmptyKeyMap,
    #[error("HKDF error: {0}")]
    HkdfError(String),
    #[error("no KMS public key for chain_id {0}")]
    UnknownChain(u32),
    #[error("RSA key generation error: {0}")]
    RsaKeyGenError(String),
    #[error("Signer error: {0}")]
    SignerError(String),
}

/// Result of ECIES encryption
#[derive(Debug, Clone)]
pub struct EciesCiphertext {
    pub ephemeral_pubkey: [u8; 33],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Crypto service owning the KMS protocol keys (one per chain) and the gateway RSA-2048 key pair.
///
/// - `protocol_keys`: map of chain_id → KMS EC public key used to ECIES-encrypt plaintext values.
/// - `rsa_public_hex`: gateway RSA public key sent to the KMS delegate endpoint
///   so the KMS can encrypt the shared secret back to the gateway.
/// - `private`: gateway RSA private key used to RSA-OAEP decrypt that response.
#[derive(Clone)]
pub struct CryptoService {
    protocol_keys: HashMap<u32, PublicKey>,
    private: RsaPrivateKey,
    pub rsa_public_key: String,
}

impl CryptoService {
    /// Initialises the crypto service with a per-chain KMS protocol key map and a fresh RSA-2048 key pair.
    pub fn new(protocol_keys: HashMap<u32, PublicKey>) -> Result<Self, Error> {
        if protocol_keys.is_empty() {
            return Err(Error::EmptyKeyMap);
        }
        let key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| Error::RsaKeyGenError(e.to_string()))?;
        let rsa_public_key = hex::encode_prefixed(
            RsaPublicKey::from(&key)
                .to_public_key_der()
                .map_err(|e| Error::RsaKeyGenError(e.to_string()))?,
        );
        for (chain_id, key) in &protocol_keys {
            let kms_pubkey = &hex::encode(key.to_sec1_bytes());
            info!("KMS public key {kms_pubkey} loaded for chain {chain_id}");
        }
        Ok(Self {
            protocol_keys,
            private: key,
            rsa_public_key,
        })
    }

    /// Encrypts plaintext using ECIES with the KMS protocol key for the given chain.
    pub fn ecies_encrypt(&self, chain_id: u32, plaintext: &[u8]) -> Result<EciesCiphertext, Error> {
        let protocol_key = self
            .protocol_keys
            .get(&chain_id)
            .ok_or(Error::UnknownChain(chain_id))?;
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let shared_secret = ephemeral_secret.diffie_hellman(protocol_key);
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(ECIES_CONTEXT, &mut aes_key)
            .map_err(|e| Error::HkdfError(e.to_string()))?;

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
        let nonce_arr = GenericArray::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_arr, plaintext)
            .map_err(|e| Error::AesGcmError(e.to_string()))?;

        let ephemeral_pubkey = Self::encode_pubkey_compressed(&ephemeral_secret);

        Ok(EciesCiphertext {
            ephemeral_pubkey,
            nonce,
            ciphertext,
        })
    }

    /// Decrypts an ECIES ciphertext.
    ///
    /// RSA-OAEP decrypts `encrypted_shared_secret` to recover the ECDH shared
    /// secret, derives the AES-256-GCM key via HKDF, and decrypts `ciphertext`.
    /// All inputs are `0x`-prefixed hex strings as stored in S3.
    pub fn ecies_decrypt(
        &self,
        ciphertext: &str,
        encrypted_shared_secret: &str,
        nonce: &str,
    ) -> Result<Vec<u8>, Error> {
        let nonce_bytes = hex::decode(nonce).map_err(|e| {
            Error::EciesDecryptionError(format!("Failed to decode nonce hex string: {e}"))
        })?;
        let ciphertext_bytes = hex::decode(ciphertext).map_err(|e| {
            Error::EciesDecryptionError(format!("Failed to decode ciphertext hex string: {e}"))
        })?;
        let encrypted_shared_secret_bytes = hex::decode(encrypted_shared_secret).map_err(|e| {
            Error::EciesDecryptionError(format!(
                "Failed to decode encrypted shared secret hex string: {e}"
            ))
        })?;

        let shared_secret = self
            .private
            .decrypt(Oaep::new::<Sha256>(), &encrypted_shared_secret_bytes)
            .map_err(|e| {
                Error::EciesDecryptionError(format!("Failed to decrypt shared secret: {e}"))
            })?;

        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aes_key = [0u8; 32];
        hkdf.expand(ECIES_CONTEXT, &mut aes_key)
            .map_err(|e| Error::HkdfError(e.to_string()))?;
        let cipher = Aes256Gcm::new(&aes_key.into());

        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext_bytes.as_slice())
            .map_err(|e| Error::AesGcmError(e.to_string()))
    }

    /// Loads an EIP-712 signer from a hex-encoded private key.
    ///
    /// Format invariants (hex, 32 bytes, non-zero) are enforced upstream by
    /// `Config::validate`; this only handles the secp256k1 scalar conversion.
    pub fn load_signer(wallet_key: &str) -> Result<PrivateKeySigner, Error> {
        let bytes: [u8; 32] = hex::decode(wallet_key)
            .map_err(|e| Error::SignerError(format!("wallet_key is not valid hex: {e}")))?
            .try_into()
            .map_err(|v: Vec<u8>| {
                Error::SignerError(format!("wallet_key must be 32 bytes, got {}", v.len()))
            })?;

        let signer = PrivateKeySigner::from_bytes(&bytes.into())
            .map_err(|e| Error::SignerError(format!("invalid secp256k1 key: {e}")))?;

        info!("Loaded signer, address: {}", signer.address());

        Ok(signer)
    }

    /// Encode an EC public key as compressed SEC1 format (33 bytes).
    fn encode_pubkey_compressed(secret: &EphemeralSecret) -> [u8; 33] {
        let encoded = secret.public_key().to_encoded_point(true);
        let bytes = encoded.as_bytes();
        let mut result = [0u8; 33];
        result.copy_from_slice(bytes);
        result
    }
}
