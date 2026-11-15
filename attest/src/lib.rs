//! Measured-boot remote attestation verification library.
//!
//! Pipeline:
//! 1. Parse a TCG PC Client crypto-agile event log (`eventlog`).
//! 2. Replay the log per hash bank to compute expected PCR values (`replay`).
//! 3. Parse a TPM2 quote (`TPMS_ATTEST`), check the anti-replay nonce and the
//!    PCR digest against the replayed values (`quote`).
//! 4. Verify the quote signature with the Attestation Key public key (`ak`).
//! 5. Diff the replayed log against a trusted baseline and pinpoint the first
//!    divergent event (`baseline`, `verify`).

pub mod ak;
pub mod alg;
pub mod baseline;
pub mod eventlog;
pub mod fixture;
pub mod quote;
pub mod replay;
pub mod verify;
