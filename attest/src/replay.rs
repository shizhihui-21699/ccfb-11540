//! PCR replay: fold the event log into expected PCR values, one bank per
//! hash algorithm.
//!
//! Extend semantics (TPM 2.0 spec Part 1, "PCR Extend"):
//!   PCR_new = Hash( PCR_old || digest )
//! with every PCR initialized to digest-size zero bytes. EV_NO_ACTION records
//! (e.g. the Spec ID event) are never extended.

use crate::alg::HashAlg;
use crate::eventlog::{EventLog, EV_NO_ACTION};
use std::collections::BTreeMap;

/// PCR index -> PCR value, for one hash bank.
pub type PcrBank = BTreeMap<u32, Vec<u8>>;

/// Replay the log and return expected PCR values per hash bank.
///
/// Only banks listed in `algs` are computed. An event contributes to a bank
/// only if the log recorded a digest for that bank's algorithm.
pub fn replay(log: &EventLog, algs: &[HashAlg]) -> BTreeMap<HashAlg, PcrBank> {
    let mut banks: BTreeMap<HashAlg, PcrBank> = BTreeMap::new();
    for alg in algs {
        banks.insert(*alg, PcrBank::new());
    }

    for event in &log.events {
        if event.event_type == EV_NO_ACTION {
            continue;
        }
        for (alg, digest) in &event.digests {
            let Some(bank) = banks.get_mut(alg) else {
                continue;
            };
            let pcr = bank
                .entry(event.pcr)
                .or_insert_with(|| vec![0u8; alg.digest_size()]);
            let mut buf = std::mem::take(pcr);
            buf.extend_from_slice(digest);
            *pcr = alg.hash(&buf);
        }
    }

    banks
}

/// The digest the TPM puts into `TPMS_QUOTE_INFO.pcrDigest`: hash of the
/// concatenation of the selected PCR values, in selection order, PCR index
/// ascending within each selection. All selections in one quote must use the
/// same hash algorithm (the one the digest is computed with).
pub fn quote_pcr_digest(
    selections: &[(HashAlg, Vec<u32>)],
    banks: &BTreeMap<HashAlg, PcrBank>,
) -> Result<Vec<u8>, String> {
    let alg = selections
        .first()
        .map(|(a, _)| *a)
        .ok_or_else(|| "quote selects no PCRs".to_string())?;
    if selections.iter().any(|(a, _)| *a != alg) {
        return Err("quote PCR selection mixes hash algorithms".to_string());
    }
    let bank = banks
        .get(&alg)
        .ok_or_else(|| format!("no replayed bank for {alg}"))?;

    let mut concat = Vec::new();
    for (_, pcrs) in selections {
        for &idx in pcrs {
            let value = bank.get(&idx).cloned().unwrap_or_else(|| {
                // A PCR never touched by the log reads as all zeros.
                vec![0u8; alg.digest_size()]
            });
            concat.extend_from_slice(&value);
        }
    }
    Ok(alg.hash(&concat))
}
