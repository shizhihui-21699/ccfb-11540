//! # tpm-ra-verify
//!
//! A library and CLI for TCG measured-boot remote attestation:
//!
//! * parse TCG PC Client event logs (legacy SHA-1 and crypto-agile),
//! * replay every event into per-algorithm PCR banks,
//! * parse and verify TPM 2.0 quotes (AK signature, nonce freshness,
//!   quoted PCR composite digest),
//! * compare the log and PCRs against a trusted JSON baseline and name the
//!   event responsible for any divergence.

pub mod baseline;
pub mod codec;
pub mod error;
pub mod eventlog;
pub mod nonce;
pub mod replay;
pub mod samples;
pub mod tcg;
pub mod tpm;
pub mod tpm_builder;
pub mod verify;

pub use error::{Error, Result};
