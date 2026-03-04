use aes_gcm::{
    Aes256Gcm,
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
use sha2::Sha256;
use thiserror::Error;
use tracing::info;

/// HKDF info/context string for key derivation
const ECIES_CONTEXT: &[u8] = b"ECIES:AES_GCM:v1";

#[derive(Debug, Error)]
pub enum Error {
    #[error("AES-GCM encryption error: {0}")]
    AesGcmError(String),
    #[error("ECC error: {0}")]
    EccError(String),
    #[error("HKDF error: {0}")]
    HkdfError(String),
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

/// Encrypt plaintext using ECIES with the KMS public key.
pub fn ecies_encrypt(plaintext: &[u8], kms_pubkey: &PublicKey) -> Result<EciesCiphertext, Error> {
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let shared_secret = ephemeral_secret.diffie_hellman(kms_pubkey);
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

    let ephemeral_pubkey = encode_pubkey_compressed(&ephemeral_secret);

    Ok(EciesCiphertext {
        ephemeral_pubkey,
        nonce,
        ciphertext,
    })
}

/// Encode an EC public key as compressed SEC1 format (33 bytes).
fn encode_pubkey_compressed(secret: &EphemeralSecret) -> [u8; 33] {
    let encoded = secret.public_key().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    result
}

/// Loads an EIP-712 signer from a hex-encoded private key.
///
/// Accepts keys with or without `0x` prefix. Fails fast if the key is
/// missing, malformed, or not a valid secp256k1 scalar.
pub fn load_signer(wallet_key: &str) -> Result<PrivateKeySigner, Error> {
    if wallet_key.is_empty() {
        return Err(Error::SignerError(
            "NOX_HANDLE_GATEWAY_SIGNER__WALLET_KEY is not set".to_string(),
        ));
    }

    let bytes = hex::decode(wallet_key)
        .map_err(|e| Error::SignerError(format!("Invalid hex in SIGNER__WALLET_KEY: {e}")))?;

    if bytes.len() != 32 {
        return Err(Error::SignerError(format!(
            "Invalid key length in SIGNER__WALLET_KEY: expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut bytes_array = [0u8; 32];
    bytes_array.copy_from_slice(&bytes);
    let signer = PrivateKeySigner::from_bytes(&bytes_array.into())
        .map_err(|e| Error::SignerError(format!("Invalid key in SIGNER__WALLET_KEY: {e}")))?;

    info!(
        "Loaded signer from environment variable, address: {}",
        signer.address()
    );

    Ok(signer)
}
