//! Attestation Key (AK) public key loading and quote signature verification.
//!
//! Supported AK types:
//!   - RSA (RSASSA-PKCS1-v1_5, hash selectable, default SHA-256)
//!   - ECDSA over NIST P-256 with SHA-256
//!
//! Keys are loaded from PEM SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----").
//! Signature blobs are raw: fixed-length big-endian integer for RSA, and
//! either raw r||s (64 bytes) or DER for ECDSA.

use crate::alg::HashAlg;
use p256::ecdsa::{signature::Verifier as _, Signature as P256Signature};
use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
use rsa::pkcs8::DecodePublicKey;
use thiserror::Error;

#[derive(Debug)]
pub enum AkKey {
    Rsa(rsa::RsaPublicKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
}

#[derive(Debug, Error)]
pub enum AkError {
    #[error("unsupported AK public key format (need RSA or ECDSA P-256 SPKI PEM): {0}")]
    Load(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed signature blob: {0}")]
    MalformedSignature(String),
}

impl AkKey {
    pub fn from_pem(pem: &str) -> Result<Self, AkError> {
        if let Ok(key) = rsa::RsaPublicKey::from_public_key_pem(pem) {
            return Ok(AkKey::Rsa(key));
        }
        if let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_pem(pem) {
            return Ok(AkKey::EcdsaP256(key));
        }
        Err(AkError::Load(
            "neither RSA nor ECDSA P-256 SPKI".to_string(),
        ))
    }

    pub fn kind(&self) -> &'static str {
        match self {
            AkKey::Rsa(_) => "rsa-rsassa",
            AkKey::EcdsaP256(_) => "ecdsa-p256",
        }
    }

    /// Verify `sig` over the marshalled TPMS_ATTEST bytes `msg`.
    pub fn verify(&self, msg: &[u8], sig: &[u8], hash: HashAlg) -> Result<(), AkError> {
        match self {
            AkKey::Rsa(key) => verify_rsa(key, msg, sig, hash),
            AkKey::EcdsaP256(key) => verify_ecdsa(key, msg, sig),
        }
    }
}

fn verify_rsa(
    key: &rsa::RsaPublicKey,
    msg: &[u8],
    sig: &[u8],
    hash: HashAlg,
) -> Result<(), AkError> {
    let sig = rsa::pkcs1v15::Signature::try_from(sig)
        .map_err(|e| AkError::MalformedSignature(e.to_string()))?;
    macro_rules! check {
        ($d:ty) => {
            RsaVerifyingKey::<$d>::new(key.clone()).verify(msg, &sig)
        };
    }
    let res = match hash {
        HashAlg::Sha1 => check!(sha1::Sha1),
        HashAlg::Sha256 => check!(sha2::Sha256),
        HashAlg::Sha384 => check!(sha2::Sha384),
        HashAlg::Sha512 => check!(sha2::Sha512),
    };
    res.map_err(|_| AkError::BadSignature)
}

fn verify_ecdsa(
    key: &p256::ecdsa::VerifyingKey,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), AkError> {
    // Accept raw r||s (TPMT_SIGNATURE TPMS_SIGNATURE_ECDSA marshalled flat)
    // or DER.
    let parsed = if sig.len() == 64 {
        P256Signature::from_slice(sig)
    } else {
        P256Signature::from_der(sig)
    }
    .map_err(|e| AkError::MalformedSignature(e.to_string()))?;
    key.verify(msg, &parsed).map_err(|_| AkError::BadSignature)
}
