use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::error::OAuthError;

type HmacSha256 = Hmac<Sha256>;

/// Helper to create an HMAC instance, resolving trait ambiguity.
fn new_hmac(key: &[u8]) -> Result<HmacSha256, OAuthError> {
    <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| OAuthError::CryptoError(format!("HMAC init failed: {e}")))
}

/// Handles AES-256-GCM encryption for tokens and HMAC signing for state parameters.
pub struct CryptoEngine {
    cipher: Aes256Gcm,
    hmac_key: Vec<u8>,
}

impl CryptoEngine {
    /// Create a new CryptoEngine from base64-encoded keys.
    pub fn new(master_key_b64: &str, hmac_secret_b64: &str) -> Result<Self, OAuthError> {
        let master_key = base64::engine::general_purpose::STANDARD
            .decode(master_key_b64)
            .map_err(|e| OAuthError::CryptoError(format!("Invalid MASTER_KEY base64: {e}")))?;

        if master_key.len() != 32 {
            return Err(OAuthError::CryptoError(format!(
                "MASTER_KEY must be 32 bytes, got {}",
                master_key.len()
            )));
        }

        let hmac_key = base64::engine::general_purpose::STANDARD
            .decode(hmac_secret_b64)
            .map_err(|e| OAuthError::CryptoError(format!("Invalid HMAC_SECRET base64: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&master_key)
            .map_err(|e| OAuthError::CryptoError(format!("Failed to init AES cipher: {e}")))?;

        Ok(Self { cipher, hmac_key })
    }

    /// Encrypt plaintext using AES-256-GCM. Returns base64(nonce || ciphertext).
    pub fn encrypt(&self, plaintext: &str) -> Result<String, OAuthError> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| OAuthError::CryptoError(format!("Encryption failed: {e}")))?;

        // Prepend nonce to ciphertext
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
    }

    /// Decrypt base64(nonce || ciphertext) back to plaintext.
    pub fn decrypt(&self, encrypted_b64: &str) -> Result<String, OAuthError> {
        let combined = base64::engine::general_purpose::STANDARD
            .decode(encrypted_b64)
            .map_err(|e| OAuthError::CryptoError(format!("Invalid base64: {e}")))?;

        if combined.len() < 12 {
            return Err(OAuthError::CryptoError("Ciphertext too short".into()));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| OAuthError::CryptoError(format!("Decryption failed: {e}")))?;

        String::from_utf8(plaintext)
            .map_err(|e| OAuthError::CryptoError(format!("Invalid UTF-8 after decrypt: {e}")))
    }

    /// Sign a state parameter with HMAC-SHA256. Returns base64(hmac || payload).
    pub fn sign_state(&self, payload: &str) -> Result<String, OAuthError> {
        let mut mac = new_hmac(&self.hmac_key)?;
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();

        let mut combined = signature.to_vec();
        combined.extend_from_slice(payload.as_bytes());

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined))
    }

    /// Verify and extract a signed state parameter.
    pub fn verify_state(&self, signed: &str) -> Result<String, OAuthError> {
        let combined = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signed)
            .map_err(|_| OAuthError::InvalidState)?;

        if combined.len() < 32 {
            return Err(OAuthError::InvalidState);
        }

        let (signature, payload_bytes) = combined.split_at(32);

        let mut mac = new_hmac(&self.hmac_key)?;
        mac.update(payload_bytes);
        mac.verify_slice(signature)
            .map_err(|_| OAuthError::InvalidState)?;

        String::from_utf8(payload_bytes.to_vec()).map_err(|_| OAuthError::InvalidState)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> CryptoEngine {
        // 32-byte key for AES-256, base64 encoded
        let key = base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]);
        let hmac = base64::engine::general_purpose::STANDARD.encode([0x43u8; 32]);
        CryptoEngine::new(&key, &hmac).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let engine = test_engine();
        let plaintext = "sk-test-secret-token-12345";
        let encrypted = engine.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = engine.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let engine = test_engine();
        let plaintext = "same-input";
        let a = engine.encrypt(plaintext).unwrap();
        let b = engine.encrypt(plaintext).unwrap();
        // Different nonces → different ciphertexts
        assert_ne!(a, b);
    }

    #[test]
    fn test_state_sign_verify_roundtrip() {
        let engine = test_engine();
        let payload = r#"{"tenant":"org_abc","user":"usr_123","provider":"google"}"#;
        let signed = engine.sign_state(payload).unwrap();
        let verified = engine.verify_state(&signed).unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_state_tamper_detection() {
        let engine = test_engine();
        let signed = engine.sign_state("legit-payload").unwrap();
        // Tamper with the signed data
        let tampered = format!("{}X", signed);
        assert!(engine.verify_state(&tampered).is_err());
    }
}
