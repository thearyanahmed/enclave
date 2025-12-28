//! Signed cookie helpers for session authentication.
//!
//! Uses HMAC-SHA256 to sign session IDs, making cookies tamper-proof.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::SecretString;

type HmacSha256 = Hmac<Sha256>;

/// Signs a session ID with HMAC-SHA256.
///
/// Returns a string in the format `{session_id}.{signature}`.
pub fn sign_session_id(session_id: &str, secret: &SecretString) -> String {
    let signature = compute_hmac(session_id.as_bytes(), secret.expose_secret().as_bytes());
    format!("{}.{}", session_id, hex::encode(signature))
}

/// Verifies a signed cookie value and extracts the session ID.
///
/// Returns `None` if the signature is invalid (tampered).
pub fn verify_signed_cookie(cookie_value: &str, secret: &SecretString) -> Option<String> {
    let (session_id, signature_hex) = cookie_value.rsplit_once('.')?;

    let actual_sig = hex::decode(signature_hex).ok()?;
    let expected_sig = compute_hmac(session_id.as_bytes(), secret.expose_secret().as_bytes());

    if constant_time_eq(&expected_sig, &actual_sig) {
        Some(session_id.to_owned())
    } else {
        log::warn!(target: "enclave_auth::session", "msg=\"session cookie tampered\" cookie_prefix=\"{}...\"", &cookie_value.chars().take(8).collect::<String>());
        None
    }
}

/// Computes HMAC-SHA256.
///
/// # Panics
///
/// This function cannot panic as HMAC accepts keys of any size.
fn compute_hmac(message: &[u8], key: &[u8]) -> Vec<u8> {
    // SAFETY: HmacSha256::new_from_slice only fails if the key is invalid,
    // but HMAC-SHA256 accepts keys of any length, so this cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let secret = SecretString::new("test-secret-key-that-is-long-enough");
        let session_id = "abc123session";

        let signed = sign_session_id(session_id, &secret);
        let verified = verify_signed_cookie(&signed, &secret);

        assert_eq!(verified, Some(session_id.to_owned()));
    }

    #[test]
    fn test_tampered_signature() {
        let secret = SecretString::new("test-secret-key-that-is-long-enough");
        let session_id = "abc123session";

        // Verify normal signing works first
        let signed = sign_session_id(session_id, &secret);
        assert!(verify_signed_cookie(&signed, &secret).is_some());

        // Tamper with the signature
        let tampered = format!("{}.{}", session_id, "0".repeat(64));

        let verified = verify_signed_cookie(&tampered, &secret);
        assert!(verified.is_none());
    }

    #[test]
    fn test_tampered_session_id() {
        let secret = SecretString::new("test-secret-key-that-is-long-enough");
        let session_id = "abc123session";

        let signed = sign_session_id(session_id, &secret);
        // Replace session ID but keep signature
        let signature = signed.rsplit_once('.').unwrap().1;
        let tampered = format!("different_session.{signature}");

        let verified = verify_signed_cookie(&tampered, &secret);
        assert!(verified.is_none());
    }

    #[test]
    fn test_wrong_secret() {
        let secret1 = SecretString::new("secret-key-one-that-is-long-enough");
        let secret2 = SecretString::new("secret-key-two-that-is-long-enough");
        let session_id = "abc123session";

        let signed = sign_session_id(session_id, &secret1);
        let verified = verify_signed_cookie(&signed, &secret2);

        assert!(verified.is_none());
    }

    #[test]
    fn test_malformed_cookie() {
        let secret = SecretString::new("test-secret-key-that-is-long-enough");

        // No separator
        assert!(verify_signed_cookie("noseparator", &secret).is_none());

        // Invalid hex
        assert!(verify_signed_cookie("session.notahexsignature", &secret).is_none());
    }

    #[test]
    fn test_deterministic_signing() {
        let secret = SecretString::new("test-secret-key-that-is-long-enough");
        let session_id = "abc123session";

        let signed1 = sign_session_id(session_id, &secret);
        let signed2 = sign_session_id(session_id, &secret);

        assert_eq!(signed1, signed2);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hello!"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
