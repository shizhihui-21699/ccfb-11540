//! PCR replay: re-run every event's extend operation per hash algorithm and
//! derive the expected PCR values.
//!
//! A TPM2_PCR_Extend computes, for each bank,
//!
//! ```text
//! PCR_new = Hash(PCR_old || digest)
//! ```
//!
//! starting from the all-zero reset value. `EV_NO_ACTION` events are logged but
//! never extended, matching firmware behavior.

use std::collections::BTreeMap;

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{Error, Result};
use crate::eventlog::{EventLog, TaggedDigest};
use crate::tcg::{
    algorithm_name, digest_size, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
    TPM_ALG_SHA512,
};

/// Object-safe hasher so one replay loop drives every supported algorithm.
trait DynHash {
    fn hash(&self, input: &[u8]) -> Vec<u8>;
    fn output_size(&self) -> usize;
}

struct Sha1Hash;
impl DynHash for Sha1Hash {
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Sha1::digest(input).to_vec()
    }
    fn output_size(&self) -> usize {
        20
    }
}

struct Sha256Hash;
impl DynHash for Sha256Hash {
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Sha256::digest(input).to_vec()
    }
    fn output_size(&self) -> usize {
        32
    }
}

struct Sha384Hash;
impl DynHash for Sha384Hash {
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Sha384::digest(input).to_vec()
    }
    fn output_size(&self) -> usize {
        48
    }
}

struct Sha512Hash;
impl DynHash for Sha512Hash {
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Sha512::digest(input).to_vec()
    }
    fn output_size(&self) -> usize {
        64
    }
}

fn hasher_for(algorithm: u16) -> Result<Box<dyn DynHash>> {
    Ok(match algorithm {
        TPM_ALG_SHA1 => Box::new(Sha1Hash),
        TPM_ALG_SHA256 => Box::new(Sha256Hash),
        TPM_ALG_SHA384 => Box::new(Sha384Hash),
        TPM_ALG_SHA512 => Box::new(Sha512Hash),
        other => return Err(Error::UnsupportedAlgorithm(other)),
    })
}

/// One PCR bank: the 24 PCR values of a single hash algorithm.
#[derive(Debug, Clone)]
pub struct PcrBank {
    pub algorithm: u16,
    pub pcrs: BTreeMap<u32, Vec<u8>>,
}

impl PcrBank {
    fn reset(algorithm: u16) -> Result<Self> {
        let size = digest_size(algorithm)
            .ok_or(Error::UnsupportedAlgorithm(algorithm))?;
        Ok(Self {
            algorithm,
            pcrs: (0..=23).map(|i| (i, vec![0u8; size])).collect(),
        })
    }

    pub fn algorithm_name(&self) -> String {
        algorithm_name(self.algorithm)
    }

    pub fn get(&self, pcr: u32) -> &[u8] {
        &self.pcrs[&pcr]
    }
}

/// All banks present in the log, keyed by algorithm id.
#[derive(Debug, Clone)]
pub struct PcrBanks(pub BTreeMap<u16, PcrBank>);

impl PcrBanks {
    pub fn bank(&self, algorithm: u16) -> Option<&PcrBank> {
        self.0.get(&algorithm)
    }

    pub fn algorithms(&self) -> Vec<u16> {
        self.0.keys().copied().collect()
    }
}

/// Replay the whole log: one bank per advertised algorithm, all PCRs reset to
/// zero and extended in event order.
pub fn replay(log: &EventLog) -> Result<PcrBanks> {
    let mut banks = BTreeMap::new();
    for entry in &log.algorithms {
        // Confirm the digest size claimed by the spec event matches the hash.
        let hasher = hasher_for(entry.algorithm)?;
        if hasher.output_size() != entry.digest_size as usize {
            return Err(Error::DigestLength {
                algorithm: entry.algorithm,
                expected: hasher.output_size(),
                actual: entry.digest_size as usize,
            });
        }
        banks.insert(
            entry.algorithm,
            PcrBank::reset(entry.algorithm)?,
        );
    }
    if banks.is_empty() {
        return Err(Error::EventLog {
            offset: 0,
            message: "Spec ID event advertises no hash algorithms".into(),
        });
    }

    let hashers: BTreeMap<u16, Box<dyn DynHash>> = banks
        .keys()
        .map(|alg| Ok((*alg, hasher_for(*alg)?)))
        .collect::<Result<_>>()?;

    for event in log.extending_events() {
        for TaggedDigest { algorithm, digest } in &event.digests {
            let (Some(bank), Some(hasher)) = (
                banks.get_mut(algorithm),
                hashers.get(algorithm),
            ) else {
                return Err(Error::UnsupportedAlgorithm(*algorithm));
            };
            if digest.len() != hasher.output_size() {
                return Err(Error::DigestLength {
                    algorithm: *algorithm,
                    expected: hasher.output_size(),
                    actual: digest.len(),
                });
            }
            let current = bank
                .pcrs
                .get(&event.pcr_index)
                .ok_or(Error::PcrIndexOutOfRange(event.pcr_index))?;
            let mut input = Vec::with_capacity(current.len() + digest.len());
            input.extend_from_slice(current);
            input.extend_from_slice(digest);
            bank.pcrs
                .insert(event.pcr_index, hasher.hash(&input));
        }
    }

    Ok(PcrBanks(banks))
}

/// Extend a single digest into an existing PCR value (helper for tests/tools).
pub fn extend(algorithm: u16, current: &[u8], digest: &[u8]) -> Result<Vec<u8>> {
    let hasher = hasher_for(algorithm)?;
    if current.len() != hasher.output_size() {
        return Err(Error::DigestLength {
            algorithm,
            expected: hasher.output_size(),
            actual: current.len(),
        });
    }
    if digest.len() != hasher.output_size() {
        return Err(Error::DigestLength {
            algorithm,
            expected: hasher.output_size(),
            actual: digest.len(),
        });
    }
    let mut input = Vec::with_capacity(current.len() + digest.len());
    input.extend_from_slice(current);
    input.extend_from_slice(digest);
    Ok(hasher.hash(&input))
}

/// One-shot hash, used when building sample digests and quote composites.
pub fn hash(algorithm: u16, input: &[u8]) -> Result<Vec<u8>> {
    Ok(hasher_for(algorithm)?.hash(input))
}
