use crate::libsignal::protocol::KeyPair;
use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr128BE;
use pbkdf2::pbkdf2_hmac;
use rand::{rng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use wacore_binary::jid::Jid;

#[derive(Debug, Error)]
pub enum PhonePairCryptoError {
    #[error("Failed to generate cryptographic keys: {0}")]
    CryptoError(String),
    #[error("Phone number too short (≤6 digits)")]
    PhoneNumberTooShort,
    #[error("Phone number is not international (starts with 0)")]
    PhoneNumberNotInternational,
    #[error("Invalid phone number format")]
    InvalidPhoneNumber,
}

/// Client types for pairing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PairClientType {
    Unknown = 0,
    Chrome = 1,
    Edge = 2,
    Firefox = 3,
    IE = 4,
    Opera = 5,
    Safari = 6,
    Electron = 7,
    UWP = 8,
    OtherWebClient = 9,
}

impl From<i32> for PairClientType {
    fn from(value: i32) -> Self {
        match value {
            1 => Self::Chrome,
            2 => Self::Edge,
            3 => Self::Firefox,
            4 => Self::IE,
            5 => Self::Opera,
            6 => Self::Safari,
            7 => Self::Electron,
            8 => Self::UWP,
            9 => Self::OtherWebClient,
            _ => Self::Unknown,
        }
    }
}

/// Phone linking cache structure to store ephemeral pairing state
#[derive(Clone)]
pub struct PhoneLinkingCache {
    pub jid: Jid,
    pub key_pair: KeyPair,
    pub linking_code: String,
    pub pairing_ref: String,
}

// Custom base32 encoding used by WhatsApp for linking codes
const LINKING_BASE32_ALPHABET: &[u8; 32] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";

pub fn encode_base32_linking(input: &[u8]) -> String {
    // This implementation matches Go's base32.NewEncoding behavior more closely
    let mut result = String::new();
    let mut buffer = 0u32;
    let mut bits = 0usize;

    for &byte in input {
        buffer = (buffer << 8) | (byte as u32);
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1F) as usize;
            result.push(LINKING_BASE32_ALPHABET[index] as char);
        }
    }

    // Handle remaining bits - this is critical for correct encoding
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(LINKING_BASE32_ALPHABET[index] as char);
    }

    result
}

pub fn generate_companion_ephemeral_key() -> Result<(KeyPair, Vec<u8>, String), PhonePairCryptoError> {
    let mut local_rng = rng();
    let ephemeral_key_pair = KeyPair::generate(&mut local_rng);

    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    let mut linking_code_bytes = [0u8; 5];

    local_rng.fill_bytes(&mut salt);
    local_rng.fill_bytes(&mut iv);
    local_rng.fill_bytes(&mut linking_code_bytes);

    let encoded_linking_code = encode_base32_linking(&linking_code_bytes);
    log::info!("Generated linking code: {} (length: {}) from bytes: {:02X?}", encoded_linking_code, encoded_linking_code.len(), linking_code_bytes);

    let mut link_code_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        encoded_linking_code.as_bytes(),
        &salt,
        131072, // 2<<16 = 2 * 65536 = 131072
        &mut link_code_key,
    );

    let mut encrypted_pubkey = ephemeral_key_pair.public_key.public_key_bytes().to_vec();

    type Aes256Ctr = Ctr128BE<Aes256>;
    let mut cipher = Aes256Ctr::new(&link_code_key.into(), &iv.into());
    cipher.apply_keystream(&mut encrypted_pubkey);

    let mut ephemeral_key = vec![0u8; 80];
    ephemeral_key[0..32].copy_from_slice(&salt);
    ephemeral_key[32..48].copy_from_slice(&iv);
    ephemeral_key[48..80].copy_from_slice(&encrypted_pubkey);

    Ok((ephemeral_key_pair, ephemeral_key, encoded_linking_code))
}

pub fn decrypt_primary_ephemeral_key(
    linking_code: &str,
    wrapped_key: &[u8],
) -> Result<Vec<u8>, PhonePairCryptoError> {
    if wrapped_key.len() != 80 {
        return Err(PhonePairCryptoError::CryptoError("Invalid wrapped key length".to_string()));
    }

    let primary_salt = &wrapped_key[0..32];
    let primary_iv = &wrapped_key[32..48];
    let primary_encrypted_pubkey = &wrapped_key[48..80];

    let mut link_code_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        linking_code.as_bytes(),
        primary_salt,
        131072, // 2<<16 = 2 * 65536 = 131072
        &mut link_code_key,
    );

    let mut primary_decrypted_pubkey = primary_encrypted_pubkey.to_vec();
    type Aes256Ctr = Ctr128BE<Aes256>;
    let mut cipher = Aes256Ctr::new(&link_code_key.into(), primary_iv.into());
    cipher.apply_keystream(&mut primary_decrypted_pubkey);

    Ok(primary_decrypted_pubkey)
}

pub fn encrypt_key_bundle(
    ephemeral_shared_secret: &[u8],
    identity_key: &[u8],
    primary_identity_pub: &[u8],
    adv_secret_random: &[u8],
) -> Result<Vec<u8>, PhonePairCryptoError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, AeadInPlace};
    use aes::cipher::generic_array::GenericArray;
    use hkdf::Hkdf;

    let mut key_bundle_salt = [0u8; 32];
    let mut key_bundle_nonce = [0u8; 12];

    let mut local_rng = rng();
    local_rng.fill_bytes(&mut key_bundle_salt);
    local_rng.fill_bytes(&mut key_bundle_nonce);

    // Prepare key bundle encryption
    let hkdf = Hkdf::<Sha256>::new(Some(&key_bundle_salt), ephemeral_shared_secret);
    let mut key_bundle_encryption_key = [0u8; 32];
    hkdf.expand(b"link_code_pairing_key_bundle_encryption_key", &mut key_bundle_encryption_key)
        .map_err(|e| PhonePairCryptoError::CryptoError(format!("HKDF expand failed: {}", e)))?;

    // Prepare plaintext key bundle
    let mut plaintext_key_bundle = Vec::new();
    plaintext_key_bundle.extend_from_slice(identity_key);
    plaintext_key_bundle.extend_from_slice(primary_identity_pub);
    plaintext_key_bundle.extend_from_slice(adv_secret_random);

    // Encrypt key bundle with AES-GCM
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_bundle_encryption_key));
    let nonce = Nonce::from_slice(&key_bundle_nonce);

    let mut encrypted_key_bundle = plaintext_key_bundle;
    let tag = cipher.encrypt_in_place_detached(nonce, &[], &mut encrypted_key_bundle)
        .map_err(|e| PhonePairCryptoError::CryptoError(format!("AES-GCM encryption failed: {}", e)))?;

    // Combine encrypted data with tag
    encrypted_key_bundle.extend_from_slice(&tag);

    // Create wrapped key bundle
    let mut wrapped_key_bundle = Vec::new();
    wrapped_key_bundle.extend_from_slice(&key_bundle_salt);
    wrapped_key_bundle.extend_from_slice(&key_bundle_nonce);
    wrapped_key_bundle.extend_from_slice(&encrypted_key_bundle);

    Ok(wrapped_key_bundle)
}

pub fn compute_adv_secret(
    ephemeral_shared_secret: &[u8],
    identity_shared_key: &[u8],
    adv_secret_random: &[u8],
) -> Result<[u8; 32], PhonePairCryptoError> {
    use hkdf::Hkdf;

    let mut adv_secret_input = Vec::new();
    adv_secret_input.extend_from_slice(ephemeral_shared_secret);
    adv_secret_input.extend_from_slice(identity_shared_key);
    adv_secret_input.extend_from_slice(adv_secret_random);

    let hkdf_adv = Hkdf::<Sha256>::new(None, &adv_secret_input);
    let mut adv_secret = [0u8; 32];
    hkdf_adv.expand(b"adv_secret", &mut adv_secret)
        .map_err(|e| PhonePairCryptoError::CryptoError(format!("ADV secret HKDF failed: {}", e)))?;

    Ok(adv_secret)
}

/// Validates and normalizes phone number for pairing
pub fn validate_and_normalize_phone(phone: &str) -> Result<String, PhonePairCryptoError> {
    // Remove all non-digit characters
    let normalized: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();

    // Check minimum length (more than 6 digits)
    if normalized.len() <= 6 {
        return Err(PhonePairCryptoError::PhoneNumberTooShort);
    }

    // Check it doesn't start with 0 (must be international format)
    if normalized.starts_with('0') {
        return Err(PhonePairCryptoError::PhoneNumberNotInternational);
    }

    Ok(normalized)
}