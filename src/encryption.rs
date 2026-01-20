use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use hkdf::Hkdf;
use k256::elliptic_curve::{
    rand_core::{OsRng, RngCore},
    sec1::FromEncodedPoint,
};
use k256::{EncodedPoint, ProjectivePoint, Scalar};
use sha2::Sha256;

use crate::error::AppError;
use crate::kms::KmsPublicKey;

/// HKDF info/context string for key derivation
const ECIES_CONTEXT: &[u8] = b"ECIES:AES_CGM:v1";

/// Result of ECIES encryption
#[derive(Debug, Clone)]
pub struct EciesCiphertext {
    pub ephemeral_pubkey: [u8; 33],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EciesCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(33 + 12 + self.ciphertext.len());
        result.extend_from_slice(&self.ephemeral_pubkey);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result
    }
}

/// Encrypt plaintext using ECIES with the KMS public key.
pub fn encrypt(plaintext: &[u8], kms_pubkey: &KmsPublicKey) -> Result<EciesCiphertext, AppError> {
    let encoded_point = EncodedPoint::from_bytes(kms_pubkey.as_bytes())
        .map_err(|e| AppError::EncryptionError(format!("invalid KMS public key: {e}")))?;

    let kms_point: ProjectivePoint =
        Option::from(ProjectivePoint::from_encoded_point(&encoded_point)).ok_or_else(|| {
            AppError::EncryptionError("KMS public key is not on curve".to_string())
        })?;

    let r = Scalar::generate_biased(&mut OsRng);
    let big_k = ProjectivePoint::GENERATOR * r;
    let shared_secret = kms_point * r;
    let x_coordinate = get_x_coordinate(&shared_secret);
    let aes_key = derive_key_from_x_coordinate(&x_coordinate, ECIES_CONTEXT);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new(&aes_key);
    let nonce_arr = GenericArray::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_arr, plaintext)
        .map_err(|e| AppError::EncryptionError(format!("AES-GCM encryption failed: {e}")))?;

    let ephemeral_pubkey = encode_point_compressed(&big_k);

    Ok(EciesCiphertext {
        ephemeral_pubkey,
        nonce,
        ciphertext,
    })
}

/// Extract X-coordinate from an EC point (32 bytes).
fn get_x_coordinate(point: &ProjectivePoint) -> Vec<u8> {
    let encoded = EncodedPoint::from(point.to_affine());
    encoded
        .x()
        .expect("point should have x coordinate")
        .to_vec()
}

/// Derive AES-256 key using HKDF-SHA256 from the x-coordinate of the shared secret.
fn derive_key_from_x_coordinate(
    ikm: &[u8],
    info: &[u8],
) -> GenericArray<u8, aes_gcm::aead::consts::U32> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .expect("32 bytes is valid HKDF output length");
    GenericArray::from_slice(&okm).to_owned()
}

/// Encode an EC point as compressed SEC1 format (33 bytes).
fn encode_point_compressed(point: &ProjectivePoint) -> [u8; 33] {
    let encoded = EncodedPoint::from(point.to_affine());
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    result
}
