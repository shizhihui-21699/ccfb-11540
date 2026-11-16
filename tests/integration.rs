//! End-to-end behavior: parsing, replay, quote signature verification,
//! nonce anti-replay, PCR mismatch and baseline root-cause attribution.

use tpm_ra_verify::baseline::{compare, Baseline};
use tpm_ra_verify::eventlog::EventLog;
use tpm_ra_verify::nonce::NonceCache;
use tpm_ra_verify::replay::replay;
use tpm_ra_verify::samples::{
    self, build_quote_for, seeded_rng, VALID_NONCE, WRONG_NONCE,
};
use tpm_ra_verify::tcg::{
    TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
};
use tpm_ra_verify::tpm::{parse_quote_bundle, AkPublicKey};
use tpm_ra_verify::tpm_builder::{
    corrupt_signature, generate_ecc_ak, generate_rsa_ak,
};
use tpm_ra_verify::verify::{verify, VerifyInputs};

const ALGS: [u16; 3] = [TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA1];

fn golden() -> samples::BuiltLog {
    samples::build_golden_log(&ALGS).unwrap()
}

// ---------------------------------------------------------------------------
// Event log parsing
// ---------------------------------------------------------------------------

#[test]
fn parses_crypto_agile_log_with_all_banks() {
    let log = golden();
    let parsed = EventLog::parse(&log.bytes).unwrap();
    assert!(!parsed.legacy);
    assert_eq!(parsed.algorithms.len(), 3);
    // First event is the Spec ID Event03 and never extends a PCR.
    assert_eq!(parsed.events[0].digests.len(), 0);
    assert!(!parsed.events[0].extends_pcr);
    assert!(parsed.events[0].spec_id.is_some());
    // StartupLocality is a no-action event with zero digests.
    assert!(!parsed.events[1].extends_pcr);
    // Every extending event carries one digest per advertised algorithm.
    for ev in parsed.events.iter().skip(2) {
        if ev.extends_pcr {
            assert_eq!(ev.digests.len(), 3, "event at {:#x}", ev.offset);
        }
    }
}

#[test]
fn parses_legacy_sha1_log() {
    let built = samples::build_legacy_log().unwrap();
    let parsed = EventLog::parse(&built.bytes).unwrap();
    assert!(parsed.legacy);
    assert_eq!(parsed.algorithms.len(), 1);
    assert_eq!(parsed.algorithms[0].algorithm, TPM_ALG_SHA1);
    assert!(parsed.events.iter().skip(1).all(|e| {
        e.digests.len() == 1 && e.digests[0].algorithm == TPM_ALG_SHA1
    }));
}

#[test]
fn rejects_truncated_log_with_offset() {
    let log = golden();
    let cut = &log.bytes[..log.bytes.len() - 7];
    let err = EventLog::parse(cut).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("malformed event log"), "got: {msg}");
    assert!(msg.contains("byte 0x"), "offset missing: {msg}");
}

#[test]
fn rejects_empty_and_garbage_logs() {
    assert!(EventLog::parse(&[]).is_err());
    // Random bytes are neither a legacy spec event nor an agile Spec ID event.
    let garbage = [0xA5u8; 64];
    assert!(EventLog::parse(&garbage).is_err());
}

#[test]
fn rejects_pcr_index_out_of_range() {
    use tpm_ra_verify::eventlog::{
        build_agile_event, build_spec_id_event, AlgorithmEntry, SpecIdEvent,
        TaggedDigest,
    };
    let spec = SpecIdEvent {
        platform_class: 2,
        spec_version_minor: 0,
        spec_version_major: 2,
        spec_errata: 0,
        algorithms: vec![AlgorithmEntry {
            algorithm: TPM_ALG_SHA256,
            digest_size: 32,
        }],
        vendor_info: Vec::new(),
    };
    let mut bytes = build_spec_id_event(&spec);
    bytes.extend_from_slice(&build_agile_event(
        24, // only 0..=23 are valid
        tpm_ra_verify::tcg::EV_POST_CODE,
        &[TaggedDigest {
            algorithm: TPM_ALG_SHA256,
            digest: vec![0u8; 32],
        }],
        b"x",
    ));
    let err = EventLog::parse(&bytes).unwrap_err();
    assert!(matches!(
        err,
        tpm_ra_verify::Error::PcrIndexOutOfRange(24)
    ));
}

#[test]
fn quote_bundle_rejects_bad_magic() {
    let mut bytes = vec![0u8; 8];
    bytes[..4].copy_from_slice(b"XXXX");
    let err = parse_quote_bundle(&bytes).unwrap_err();
    assert!(err.to_string().contains("not a TQ2! quote bundle"));
}

#[test]
fn rejects_unknown_algorithm() {
    // Craft a spec event advertising an unsupported algorithm id.
    use tpm_ra_verify::eventlog::{build_spec_id_event, AlgorithmEntry, SpecIdEvent};
    let spec = SpecIdEvent {
        platform_class: 2,
        spec_version_minor: 0,
        spec_version_major: 2,
        spec_errata: 0,
        algorithms: vec![AlgorithmEntry {
            algorithm: 0x7777,
            digest_size: 32,
        }],
        vendor_info: Vec::new(),
    };
    let bytes = build_spec_id_event(&spec);
    let err = EventLog::parse(&bytes).unwrap_err();
    assert!(matches!(
        err,
        tpm_ra_verify::Error::UnsupportedAlgorithm(0x7777)
    ));
}

#[test]
fn rejects_digest_with_wrong_length() {
    use tpm_ra_verify::eventlog::{
        build_agile_event, build_spec_id_event, AlgorithmEntry, SpecIdEvent,
        TaggedDigest,
    };
    use tpm_ra_verify::tcg::EV_POST_CODE;
    let spec = SpecIdEvent {
        platform_class: 2,
        spec_version_minor: 0,
        spec_version_major: 2,
        spec_errata: 0,
        algorithms: vec![AlgorithmEntry {
            algorithm: TPM_ALG_SHA256,
            digest_size: 32,
        }],
        vendor_info: Vec::new(),
    };
    let mut bytes = build_spec_id_event(&spec);
    bytes.extend_from_slice(&build_agile_event(
        0,
        EV_POST_CODE,
        &[TaggedDigest {
            algorithm: TPM_ALG_SHA256,
            digest: vec![0u8; 31], // one byte short
        }],
        b"x",
    ));
    let err = EventLog::parse(&bytes).unwrap_err();
    assert!(matches!(
        err,
        tpm_ra_verify::Error::DigestLength { actual: 31, .. }
    ));
}

// ---------------------------------------------------------------------------
// PCR replay
// ---------------------------------------------------------------------------

#[test]
fn replay_is_deterministic_and_banks_agree_on_shared_alg() {
    let log = golden();
    let banks1 = replay(&log.parsed).unwrap();
    let banks2 = replay(&log.parsed).unwrap();
    assert_eq!(
        banks1.bank(TPM_ALG_SHA256).unwrap().get(0),
        banks2.bank(TPM_ALG_SHA256).unwrap().get(0)
    );

    // The legacy SHA-1 log must produce the same SHA-1 PCRs as the agile log's
    // SHA-1 bank: identical event digests, identical extend math.
    let legacy = samples::build_legacy_log().unwrap();
    let legacy_banks = replay(&legacy.parsed).unwrap();
    for pcr in 0..=9u32 {
        assert_eq!(
            banks1.bank(TPM_ALG_SHA1).unwrap().get(pcr),
            legacy_banks.bank(TPM_ALG_SHA1).unwrap().get(pcr),
            "PCR{pcr} differs between agile and legacy"
        );
    }
}

#[test]
fn untouched_pcrs_stay_at_reset() {
    let log = golden();
    let banks = replay(&log.parsed).unwrap();
    let bank = banks.bank(TPM_ALG_SHA256).unwrap();
    assert!(bank.get(8).iter().all(|b| *b == 0));
    assert!(bank.get(10).iter().all(|b| *b == 0));
    assert!(bank.get(23).iter().all(|b| *b == 0));
}

#[test]
fn tampered_event_changes_only_downstream_pcr() {
    let good = replay(&golden().parsed).unwrap();
    let bad_log = samples::build_tampered_log(&ALGS).unwrap();
    let bad = replay(&bad_log.parsed).unwrap();

    // PCR9 holds the kernel cmdline measurement and must diverge.
    assert_ne!(
        good.bank(TPM_ALG_SHA256).unwrap().get(9),
        bad.bank(TPM_ALG_SHA256).unwrap().get(9)
    );
    // Unrelated PCRs must be identical.
    assert_eq!(
        good.bank(TPM_ALG_SHA256).unwrap().get(0),
        bad.bank(TPM_ALG_SHA256).unwrap().get(0)
    );
    assert_eq!(
        good.bank(TPM_ALG_SHA256).unwrap().get(7),
        bad.bank(TPM_ALG_SHA256).unwrap().get(7)
    );
}

// ---------------------------------------------------------------------------
// Quote signature verification (RSA + ECC, multiple hashes)
// ---------------------------------------------------------------------------

#[test]
fn rsa_quote_signature_verifies() {
    let mut rng = seeded_rng();
    let ak = generate_rsa_ak(&mut rng).unwrap();
    let banks = replay(&golden().parsed).unwrap();
    let (bytes, _) =
        build_quote_for(&ak, &mut rng, &banks, TPM_ALG_SHA256, VALID_NONCE).unwrap();
    let bundle = parse_quote_bundle(&bytes).unwrap();
    bundle.verify_signature().unwrap();
    assert_eq!(bundle.attest.extra_data, VALID_NONCE);
}

#[test]
fn ecc_sha384_quote_signature_verifies() {
    let mut rng = seeded_rng();
    let ak = generate_ecc_ak(&mut rng).unwrap();
    let banks = replay(&golden().parsed).unwrap();
    let (bytes, _) =
        build_quote_for(&ak, &mut rng, &banks, TPM_ALG_SHA384, VALID_NONCE).unwrap();
    let bundle = parse_quote_bundle(&bytes).unwrap();
    bundle.verify_signature().unwrap();
    assert!(matches!(bundle.ak, AkPublicKey::Ecc { .. }));
}

#[test]
fn corrupted_signature_is_rejected() {
    let mut rng = seeded_rng();
    let ak = generate_rsa_ak(&mut rng).unwrap();
    let banks = replay(&golden().parsed).unwrap();
    let (mut bytes, _) =
        build_quote_for(&ak, &mut rng, &banks, TPM_ALG_SHA256, VALID_NONCE).unwrap();
    corrupt_signature(&mut bytes);
    let bundle = parse_quote_bundle(&bytes).unwrap();
    assert!(matches!(
        bundle.verify_signature().unwrap_err(),
        tpm_ra_verify::Error::SignatureVerification
    ));
}

#[test]
fn attest_magic_and_type_are_validated() {
    let mut rng = seeded_rng();
    let ak = generate_rsa_ak(&mut rng).unwrap();
    let banks = replay(&golden().parsed).unwrap();
    let (mut bytes, _) =
        build_quote_for(&ak, &mut rng, &banks, TPM_ALG_SHA256, VALID_NONCE).unwrap();
    // Corrupt the attest magic (first two bytes after the bundle magic+length).
    bytes[6] ^= 0xFF;
    let err = parse_quote_bundle(&bytes).unwrap_err();
    assert!(matches!(err, tpm_ra_verify::Error::BadAttestMagic(_)));
}

// ---------------------------------------------------------------------------
// Nonce handling
// ---------------------------------------------------------------------------

#[test]
fn nonce_mismatch_and_replay_are_rejected() {
    let cache = NonceCache::default();
    cache.check_fresh(VALID_NONCE, VALID_NONCE).unwrap();
    assert!(matches!(
        cache.check_fresh(VALID_NONCE, WRONG_NONCE).unwrap_err(),
        tpm_ra_verify::Error::NonceMismatch { .. }
    ));

    let mut cache = NonceCache::default();
    cache.remember(VALID_NONCE);
    assert!(matches!(
        cache.check_fresh(VALID_NONCE, VALID_NONCE).unwrap_err(),
        tpm_ra_verify::Error::ReplayedNonce(_)
    ));
}

#[test]
fn nonce_cache_round_trips_through_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonces.json");
    let mut cache = NonceCache::default();
    cache.remember(VALID_NONCE);
    cache.save(&path).unwrap();

    let reloaded = NonceCache::load(&path).unwrap();
    assert!(matches!(
        reloaded.check_fresh(VALID_NONCE, VALID_NONCE).unwrap_err(),
        tpm_ra_verify::Error::ReplayedNonce(_)
    ));
    assert_eq!(reloaded.len(), 1);
}

// ---------------------------------------------------------------------------
// Full verify() orchestration
// ---------------------------------------------------------------------------

fn write_tmp(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn full_verify_passes_for_golden_chain() {
    let dir = tempfile::tempdir().unwrap();
    let golden = golden();
    let log_path = write_tmp(dir.path(), "log.bin", &golden.bytes);
    let mut rng = seeded_rng();
    let ak = generate_rsa_ak(&mut rng).unwrap();
    let banks = replay(&golden.parsed).unwrap();
    let (quote_bytes, _) =
        build_quote_for(&ak, &mut rng, &banks, TPM_ALG_SHA256, VALID_NONCE).unwrap();
    let quote_path = write_tmp(dir.path(), "q.bin", &quote_bytes);
    let cache_path = dir.path().join("nonces.json");

    let report = verify(VerifyInputs {
        log_path: &log_path,
        quote_path: &quote_path,
        ak_path: None,
        expected_nonce: VALID_NONCE,
        baseline_path: None,
        nonce_cache_path: Some(&cache_path),
    })
    .unwrap();
    assert!(report.ok);
    assert!(report.signature_valid && report.nonce_fresh && report.pcr_match);

    // A second presentation of the same nonce must fail.
    let err = verify(VerifyInputs {
        log_path: &log_path,
        quote_path: &quote_path,
        ak_path: None,
        expected_nonce: VALID_NONCE,
        baseline_path: None,
        nonce_cache_path: Some(&cache_path),
    })
    .unwrap_err();
    assert!(matches!(err, tpm_ra_verify::Error::ReplayedNonce(_)));
}

#[test]
fn full_verify_flags_pcr_mismatch_for_tampered_log() {
    let dir = tempfile::tempdir().unwrap();
    let good = golden();
    let mut rng = seeded_rng();
    let ak = generate_rsa_ak(&mut rng).unwrap();
    let good_banks = replay(&good.parsed).unwrap();
    let (quote_bytes, _) =
        build_quote_for(&ak, &mut rng, &good_banks, TPM_ALG_SHA256, VALID_NONCE).unwrap();

    let tampered = samples::build_tampered_log(&ALGS).unwrap();
    let log_path = write_tmp(dir.path(), "bad.bin", &tampered.bytes);
    let quote_path = write_tmp(dir.path(), "q.bin", &quote_bytes);

    let report = verify(VerifyInputs {
        log_path: &log_path,
        quote_path: &quote_path,
        ak_path: None,
        expected_nonce: VALID_NONCE,
        baseline_path: None,
        nonce_cache_path: None,
    })
    .unwrap();
    assert!(!report.ok);
    assert!(report.signature_valid && report.nonce_fresh);
    assert!(!report.pcr_match);
    // PCR9 is among the covered, failing PCRs.
    assert!(report
        .pcr_mismatches
        .iter()
        .any(|m| m.algorithm == TPM_ALG_SHA256 && m.pcr == 9));
}

#[test]
fn uncovered_pcr_warning_is_scoped_to_quoted_bank() {
    use tpm_ra_verify::tpm::PcrSelection;
    use tpm_ra_verify::tpm_builder::QuoteRequest;

    let dir = tempfile::tempdir().unwrap();
    let golden = golden();
    let log_path = write_tmp(dir.path(), "log.bin", &golden.bytes);
    let banks = replay(&golden.parsed).unwrap();

    // Quote only PCR0..3 in the sha256 bank; the log also extends PCR4..9.
    let mut pcr_select = vec![0u8; 3];
    for pcr in 0u32..4 {
        pcr_select[(pcr / 8) as usize] |= 1 << (pcr % 8);
    }
    let selection = PcrSelection {
        hash_algorithm: TPM_ALG_SHA256,
        pcr_select,
    };
    let (digest, _) = tpm_ra_verify::tpm::quote_pcr_digest(
        std::slice::from_ref(&selection),
        |alg, pcr| banks.bank(alg).map(|b| b.get(pcr).to_vec()),
    )
    .unwrap();

    let mut rng = seeded_rng();
    let ak = generate_rsa_ak(&mut rng).unwrap();
    let public_area = match &ak {
        tpm_ra_verify::tpm_builder::GeneratedAk::Rsa { public_area, .. } => {
            public_area.clone()
        }
        _ => unreachable!(),
    };
    let bundle = tpm_ra_verify::tpm_builder::build_quote(QuoteRequest {
        ak: &ak,
        rng: &mut rng,
        nonce: VALID_NONCE,
        pcr_selections: vec![selection],
        pcr_digest: digest,
        hash_algorithm: TPM_ALG_SHA256,
        clock: 1,
        firmware_version: 1,
    })
    .unwrap();
    let quote_bytes =
        tpm_ra_verify::tpm_builder::serialize_bundle(&bundle, &public_area);
    let quote_path = write_tmp(dir.path(), "q.bin", &quote_bytes);

    let report = verify(VerifyInputs {
        log_path: &log_path,
        quote_path: &quote_path,
        ak_path: None,
        expected_nonce: VALID_NONCE,
        baseline_path: None,
        nonce_cache_path: None,
    })
    .unwrap();
    assert!(report.ok);
    // PCR4,5,7,9 are extended in sha256 but outside the 0..3 selection.
    let warned: std::collections::HashSet<u32> = report
        .uncovered_extended_pcrs
        .iter()
        .filter(|(alg, _)| *alg == TPM_ALG_SHA256)
        .map(|(_, pcr)| *pcr)
        .collect();
    assert!(warned.contains(&9));
    assert!(warned.contains(&4));
    // No foreign-bank noise: every warning is sha256, the only quoted bank.
    assert!(report
        .uncovered_extended_pcrs
        .iter()
        .all(|(alg, _)| *alg == TPM_ALG_SHA256));
}

// ---------------------------------------------------------------------------
// Baseline root-cause attribution
// ---------------------------------------------------------------------------

#[test]
fn baseline_pinpoints_the_tampered_event() {
    let good = golden();
    let good_banks = replay(&good.parsed).unwrap();
    let baseline = Baseline::from_log(&good.parsed, &good_banks, "t", "d");

    let tampered = samples::build_tampered_log(&ALGS).unwrap();
    let bad_banks = replay(&tampered.parsed).unwrap();
    let report = compare(&baseline, &tampered.parsed, &bad_banks);

    assert!(!report.ok());
    // The first divergence must be event #22 (kernel cmdline, PCR9).
    let first = report.differences.first().unwrap();
    assert_eq!(first.sequence(), 22);
    let explanation = first.explain();
    assert!(explanation.contains("event #22"), "got: {explanation}");

    // Final-value view independently flags PCR9 in every bank.
    assert!(report
        .pcr_differences
        .iter()
        .all(|d| d.pcr == 9));
    assert!(report
        .pcr_differences
        .iter()
        .any(|d| d.algorithm == "sha256"));
}

#[test]
fn baseline_json_round_trips_and_matches_golden_log() {
    let good = golden();
    let banks = replay(&good.parsed).unwrap();
    let baseline = Baseline::from_log(&good.parsed, &banks, "t", "d");
    let json = baseline.to_json_pretty().unwrap();
    let restored = Baseline::from_json(json.as_bytes()).unwrap();
    let report = compare(&restored, &good.parsed, &banks);
    assert!(report.ok(), "differences: {:?}", report.differences);
}

#[test]
fn baseline_detects_extra_and_missing_events() {
    let good = golden();
    let banks = replay(&good.parsed).unwrap();
    let baseline = Baseline::from_log(&good.parsed, &banks, "t", "d");

    // Drop the last event from the observed log.
    let mut shortened = good.parsed.clone();
    shortened.events.pop();
    let report = compare(&baseline, &shortened, &banks);
    assert!(report
        .differences
        .iter()
        .any(|d| matches!(
            d,
            tpm_ra_verify::baseline::EventDifference::MissingInLog { .. }
        )));
}
