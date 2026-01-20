use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
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

use crate::kms::KmsPublicKey;

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
}

/// Result of ECIES encryption
#[derive(Debug, Clone)]
pub struct EciesCiphertext {
    pub ephemeral_pubkey: [u8; 33],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Encrypt plaintext using ECIES with the KMS public key.
pub fn ecies_encrypt(
    plaintext: &[u8],
    kms_pubkey: &KmsPublicKey,
) -> Result<EciesCiphertext, Error> {
    let protocol_key = PublicKey::from_sec1_bytes(kms_pubkey)
        .map_err(|e| Error::EccError(format!("invalid KMS public key: {e}")))?;

    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let shared_secret = ephemeral_secret.diffie_hellman(&protocol_key);
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
