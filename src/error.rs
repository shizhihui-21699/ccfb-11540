//! Error types shared across the crate.

use std::io;

/// All failures produced by parsing, replaying or verifying attestation material.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("malformed event log at byte {offset:#x}: {message}")]
    EventLog { offset: usize, message: String },

    #[error("malformed TPM structure at byte {offset:#x}: {message}")]
    Tpm { offset: usize, message: String },

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u16),

    #[error("digest length mismatch for {algorithm:#06x}: expected {expected}, got {actual}")]
    DigestLength {
        algorithm: u16,
        expected: usize,
        actual: usize,
    },

    #[error("PCR index {0} is out of range (valid: 0..=23)")]
    PcrIndexOutOfRange(u32),

    #[error("quote signature verification failed")]
    SignatureVerification,

    #[error("attest magic invalid: expected TPM_GENERATED_VALUE (0xff544347), got {0:#010x}")]
    BadAttestMagic(u16),

    #[error("attest type {0:#06x} is not TPM_ST_ATTEST_QUOTE (0x8018)")]
    NotAQuote(u16),

    #[error("nonce mismatch: expected {expected}, quote carries {actual}")]
    NonceMismatch { expected: String, actual: String },

    #[error("replay attack: nonce {0} was already used in an accepted quote")]
    ReplayedNonce(String),

    #[error("PCR {pcr} ({algorithm:#06x}) mismatch: quote={quote} replay={replay}")]
    PcrMismatch {
        pcr: u32,
        algorithm: u16,
        quote: String,
        replay: String,
    },

    #[error("baseline JSON error: {0}")]
    Baseline(String),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
