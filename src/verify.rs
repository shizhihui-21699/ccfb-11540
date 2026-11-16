//! End-to-end verification orchestration: log parse, PCR replay, quote
//! signature, nonce freshness, PCR digest comparison and baseline diffing.

use std::path::Path;

use crate::baseline::{self, Baseline, BaselineReport};
use crate::error::{Error, Result};
use crate::eventlog::EventLog;
use crate::nonce::NonceCache;
use crate::replay;
use crate::tpm::{self, AkPublicKey};

/// Inputs controlling one verification run.
pub struct VerifyInputs<'a> {
    pub log_path: &'a Path,
    pub quote_path: &'a Path,
    /// Optional external AK; when absent the AK embedded in the bundle is used.
    pub ak_path: Option<&'a Path>,
    /// Challenge nonce the caller expected the TPM to echo.
    pub expected_nonce: &'a [u8],
    /// Optional baseline for root-cause comparison.
    pub baseline_path: Option<&'a Path>,
    /// Optional replay-protection cache.
    pub nonce_cache_path: Option<&'a Path>,
}

/// A per-PCR mismatch between the replayed bank and the quote's composite.
#[derive(Debug)]
pub struct QuotePcrMismatch {
    pub algorithm: u16,
    pub pcr: u32,
    pub quote_value: String,
    pub replay_value: String,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub log_events: usize,
    pub extending_events: usize,
    pub algorithms: Vec<u16>,
    pub signature_valid: bool,
    pub nonce_fresh: bool,
    pub nonce_hex: String,
    pub quote_selections: Vec<(u16, Vec<u32>)>,
    pub pcr_match: bool,
    pub pcr_mismatches: Vec<QuotePcrMismatch>,
    /// PCRs extended by the log but not covered by the quote (warnings).
    pub uncovered_extended_pcrs: Vec<(u16, u32)>,
    pub baseline: Option<BaselineReport>,
    pub ok: bool,
}

/// Run every check. Errors are returned for hard structural failures;
/// check failures (signature, nonce, PCR, baseline) are reflected in the
/// report where it is useful to present several at once.
pub fn verify(inputs: VerifyInputs) -> Result<VerifyReport> {
    // --- Parse log and replay ---------------------------------------------
    let log_bytes = std::fs::read(inputs.log_path)?;
    let log = EventLog::parse(&log_bytes)?;
    let banks = replay::replay(&log)?;

    // --- Parse quote and optional external AK -----------------------------
    let quote_bytes = std::fs::read(inputs.quote_path)?;
    let mut bundle = tpm::parse_quote_bundle(&quote_bytes)?;
    if let Some(ak_path) = inputs.ak_path {
        let external = tpm::load_ak_file(ak_path)?;
        assert_same_ak(&bundle.ak, &external)?;
        bundle.ak = external;
    }

    let mut report = VerifyReport {
        log_events: log.events.len(),
        extending_events: log.extending_events().count(),
        algorithms: banks.algorithms(),
        nonce_hex: hex::encode(&bundle.attest.extra_data),
        ..Default::default()
    };
    report.quote_selections = bundle
        .attest
        .pcr_selections
        .iter()
        .map(|s| (s.hash_algorithm, s.selected_pcrs()))
        .collect();

    // --- Nonce anti-replay -------------------------------------------------
    let mut cache = match inputs.nonce_cache_path {
        Some(path) => NonceCache::load(path)?,
        None => NonceCache::default(),
    };
    match cache.check_fresh(inputs.expected_nonce, &bundle.attest.extra_data) {
        Ok(()) => report.nonce_fresh = true,
        Err(e) => {
            report.nonce_fresh = false;
            return Err(e); // Hard failure: nothing after this is trustworthy.
        }
    }

    // --- Signature ---------------------------------------------------------
    match bundle.verify_signature() {
        Ok(()) => report.signature_valid = true,
        Err(e) => {
            report.signature_valid = false;
            return Err(e);
        }
    }

    // --- PCR composite digest ---------------------------------------------
    let (replayed_digest, covered) = tpm::quote_pcr_digest(
        &bundle.attest.pcr_selections,
        |alg, pcr| banks.bank(alg).map(|b| b.get(pcr).to_vec()),
    )?;
    report.pcr_match = replayed_digest == bundle.attest.pcr_digest;
    if !report.pcr_match {
        // Locate the first offending PCR by recomputing the composite one PCR
        // at a time until the digest diverges, then report all PCRs whose
        // values disagree with... the quote has no per-PCR values, so report
        // the point where the composite first changes vs. an incremental
        // replay against the quote's claimed digest is impossible; instead we
        // expose the covered PCRs and their replayed values for triage.
        for (alg, pcr) in &covered {
            let replay_value = hex::encode(
                banks
                    .bank(*alg)
                    .ok_or(Error::UnsupportedAlgorithm(*alg))?
                    .get(*pcr),
            );
            report.pcr_mismatches.push(QuotePcrMismatch {
                algorithm: *alg,
                pcr: *pcr,
                quote_value: "(composite digest)".into(),
                replay_value,
            });
        }
    }

    // Warning: PCRs the firmware extended but the quote did not attest to.
    // Only banks the quote actually speaks are relevant — an sha256-only quote
    // says nothing about, and must not raise noise over, the sha1/sha384 banks.
    let quoted_algorithms: std::collections::HashSet<u16> = bundle
        .attest
        .pcr_selections
        .iter()
        .map(|s| s.hash_algorithm)
        .collect();
    let covered_set: std::collections::HashSet<(u16, u32)> =
        covered.iter().copied().collect();
    for event in log.extending_events() {
        for d in &event.digests {
            if !quoted_algorithms.contains(&d.algorithm) {
                continue;
            }
            let key = (d.algorithm, event.pcr_index);
            if !covered_set.contains(&key) {
                report.uncovered_extended_pcrs.push(key);
            }
        }
    }
    report
        .uncovered_extended_pcrs
        .sort_unstable();
    report.uncovered_extended_pcrs.dedup();

    // --- Baseline root-cause comparison -----------------------------------
    if let Some(path) = inputs.baseline_path {
        let baseline = Baseline::from_json(&std::fs::read(path)?)?;
        report.baseline = Some(baseline::compare(&baseline, &log, &banks));
    }

    let baseline_ok = report
        .baseline
        .as_ref()
        .map(|b| b.ok())
        .unwrap_or(true);
    report.ok = report.signature_valid
        && report.nonce_fresh
        && report.pcr_match
        && baseline_ok;

    // Persist the nonce only after every check has succeeded.
    if report.ok {
        cache.remember(inputs.expected_nonce);
        if let Some(path) = inputs.nonce_cache_path {
            cache.save(path)?;
        }
    }

    Ok(report)
}

fn assert_same_ak(embedded: &AkPublicKey, external: &AkPublicKey) -> Result<()> {
    let same = match (embedded, external) {
        (
            AkPublicKey::Rsa { modulus: m1, .. },
            AkPublicKey::Rsa { modulus: m2, .. },
        ) => m1 == m2,
        (
            AkPublicKey::Ecc {
                public_point: p1, ..
            },
            AkPublicKey::Ecc {
                public_point: p2, ..
            },
        ) => p1 == p2,
        _ => false,
    };
    if same {
        Ok(())
    } else {
        Err(Error::Tpm {
            offset: 0,
            message: "external AK does not match the AK in the quote bundle".into(),
        })
    }
}
