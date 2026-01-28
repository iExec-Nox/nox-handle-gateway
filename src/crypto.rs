use std::path::Path;

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
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
use tracing::{info, warn};

use crate::config::SignerConfig;

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

/// Generates a new random signing key
pub fn generate_sign_key() -> PrivateKeySigner {
    PrivateKeySigner::random()
}

/// Load or create an EIP-712 signer from a keystore file.
///
/// 1. If keystore missing, create wallet and persist to storage
/// 2. Verify file exists with proper permissions (Unix: 0o600)
/// 3. Load keys from file
pub fn load_or_create_signer(config: &SignerConfig) -> Result<PrivateKeySigner, Error> {
    let path = &config.keystore_filename;
    let password = &config.keystore_password;

    if !path.exists() {
        warn!("Keystore file {:?} not found, generating new signer", path);
        let signer = generate_sign_key();
        save_signer_to_keystore(&signer, path, password)?;
    }

    #[cfg(unix)]
    verify_keystore_permissions(path)?;

    load_signer_from_keystore(path, password)
}

/// Loads the signer from an encrypted keystore file
fn load_signer_from_keystore(
    keystore_file: &Path,
    password: &str,
) -> Result<PrivateKeySigner, Error> {
    let signer = PrivateKeySigner::decrypt_keystore(keystore_file, password)
        .map_err(|e| Error::SignerError(format!("Failed to decrypt keystore: {}", e)))?;

    info!(
        "Loaded signer from keystore {:?}, address: {}",
        keystore_file,
        signer.address()
    );

    Ok(signer)
}

/// Saves the signer to an encrypted keystore file
fn save_signer_to_keystore(
    signer: &PrivateKeySigner,
    keystore_file: &Path,
    password: &str,
) -> Result<(), Error> {
    // Get the private key bytes from the signer
    let credential = signer.credential();

    // Get parent directory and filename from the path
    let dir = keystore_file.parent().unwrap_or(Path::new("."));
    let filename = keystore_file
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("gateway_keystore.json");

    // Create directory if needed
    if !dir.exists() && !dir.as_os_str().is_empty() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::SignerError(format!("Failed to create keystore directory: {e}")))?;
    }

    // Encrypt and save the keystore
    PrivateKeySigner::encrypt_keystore(
        dir,
        &mut OsRng,
        credential.to_bytes(),
        password,
        Some(filename),
    )
    .map_err(|e| Error::SignerError(format!("Failed to encrypt keystore: {}", e)))?;

    info!("Signer keystore saved to {:?}", keystore_file);

    // Set file permissions to 600 (owner read/write only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(keystore_file, permissions).map_err(|e| {
            Error::SignerError(format!("Failed to set keystore permissions: {}", e))
        })?;
    }

    Ok(())
}

#[cfg(unix)]
fn verify_keystore_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)
        .map_err(|e| Error::SignerError(format!("Failed to read keystore metadata: {e}")))?;

    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(Error::SignerError(format!(
            "Insecure keystore permissions: {:o} (expected 600)",
            mode
        )));
    }

    Ok(())
}
