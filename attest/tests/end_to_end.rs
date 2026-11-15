//! End-to-end tests over spec-conformant fixtures: happy path (RSA + ECDSA),
//! nonce replay protection, signature failure, log/quote inconsistency, and
//! baseline divergence pinpointing.

use mb_attest::ak::AkKey;
use mb_attest::alg::HashAlg;
use mb_attest::baseline::Baseline;
use mb_attest::eventlog;
use mb_attest::fixture;
use mb_attest::quote;
use mb_attest::verify::{verify, DivergenceKind, VerifyInputs};

fn fixtures() -> fixture::FixtureSet {
    fixture::generate(b"challenge-nonce-0123456789abcdef")
}

struct Case {
    log: mb_attest::eventlog::EventLog,
    quote: mb_attest::quote::Quote,
    ak: AkKey,
    nonce: Vec<u8>,
    sig: Vec<u8>,
    baseline: Baseline,
}

impl Case {
    fn good_rsa(f: &fixture::FixtureSet) -> Self {
        Case {
            log: eventlog::parse(&f.log_v1).unwrap(),
            quote: quote::parse(&f.quote_rsa_v1).unwrap(),
            ak: AkKey::from_pem(&f.ak_rsa_pem).unwrap(),
            nonce: f.nonce.clone(),
            sig: f.sig_rsa_v1.clone(),
            baseline: Baseline::from_json(&f.baseline_json).unwrap(),
        }
    }

    fn inputs(&self) -> VerifyInputs<'_> {
        VerifyInputs {
            log: &self.log,
            quote: &self.quote,
            ak: &self.ak,
            nonce: &self.nonce,
            signature: &self.sig,
            sig_hash: HashAlg::Sha256,
            baseline: Some(&self.baseline),
        }
    }
}

#[test]
fn good_attestation_rsa() {
    let f = fixtures();
    let case = Case::good_rsa(&f);
    let report = verify(&case.inputs());
    assert!(report.nonce_ok);
    assert!(report.signature_ok);
    assert!(report.log_matches_quote);
    assert!(report.baseline.as_ref().unwrap().matches());
    assert!(report.attested());
}

#[test]
fn good_attestation_ecdsa() {
    let f = fixtures();
    let case = Case {
        quote: quote::parse(&f.quote_ec_v1).unwrap(),
        ak: AkKey::from_pem(&f.ak_ec_pem).unwrap(),
        sig: f.sig_ec_v1.clone(),
        ..Case::good_rsa(&f)
    };
    let report = verify(&case.inputs());
    assert!(report.signature_ok);
    assert!(report.attested());
}

#[test]
fn wrong_nonce_is_rejected() {
    let f = fixtures();
    let mut case = Case::good_rsa(&f);
    case.nonce = b"different-nonce-entirely!!!!!!!!".to_vec();
    let report = verify(&case.inputs());
    assert!(!report.nonce_ok);
    assert!(!report.attested());
    // Everything else still checks out — the rejection is specifically the nonce.
    assert!(report.signature_ok);
    assert!(report.log_matches_quote);
}

#[test]
fn tampered_signature_is_rejected() {
    let f = fixtures();
    let mut case = Case::good_rsa(&f);
    let n = case.sig.len();
    case.sig[n - 1] ^= 0x01;
    let report = verify(&case.inputs());
    assert!(!report.signature_ok);
    assert!(!report.attested());
}

#[test]
fn quote_over_different_log_is_rejected() {
    // Sign a quote over the v2 PCRs but present the v1 log: replay mismatch.
    let f = fixtures();
    let mut case = Case::good_rsa(&f);
    case.quote = quote::parse(&f.quote_rsa_v2).unwrap();
    case.sig = f.sig_rsa_v2.clone();
    let report = verify(&case.inputs());
    assert!(report.signature_ok); // signature itself is genuine
    assert!(!report.log_matches_quote);
    assert!(!report.attested());
}

#[test]
fn tampered_log_fails_quote_consistency() {
    let f = fixtures();
    let mut case = Case::good_rsa(&f);
    case.log = eventlog::parse(&f.log_tampered).unwrap();
    let report = verify(&case.inputs());
    assert!(report.signature_ok);
    assert!(!report.log_matches_quote);
    assert!(!report.attested());
}

#[test]
fn changed_system_pinpoints_divergent_event() {
    // v2 log + v2 quote: cryptographically consistent, but the initrd event
    // diverges from the baseline.
    let f = fixtures();
    let mut case = Case::good_rsa(&f);
    case.log = eventlog::parse(&f.log_v2).unwrap();
    case.quote = quote::parse(&f.quote_rsa_v2).unwrap();
    case.sig = f.sig_rsa_v2.clone();

    let report = verify(&case.inputs());
    assert!(report.signature_ok);
    assert!(report.log_matches_quote);
    assert!(!report.attested());

    let baseline = report.baseline.as_ref().unwrap();
    assert!(!baseline.matches());

    // PCR 9 must be reported as the mismatching PCR.
    assert!(baseline
        .pcr_mismatches
        .iter()
        .any(|m| m.pcr == 9 && m.alg == HashAlg::Sha256));

    // The divergence must point at the initrd event (last event, PCR 9,
    // EV_IPL) with both expected and actual digests filled in.
    let div = baseline
        .divergences
        .iter()
        .find(|d| d.pcr == 9 && d.alg == HashAlg::Sha256)
        .expect("PCR 9 divergence reported");
    assert_eq!(div.kind, DivergenceKind::DigestMismatch);
    assert_eq!(div.event_type, Some(eventlog::EV_IPL));
    assert!(div.expected_digest.is_some());
    assert!(div.actual_digest.is_some());
    assert_eq!(div.description.as_deref(), Some("Initial RAM disk"));

    // Other PCRs must NOT be flagged.
    assert!(baseline.divergences.iter().all(|d| d.pcr == 9));
    assert!(baseline.pcr_mismatches.iter().all(|m| m.pcr == 9));
}

#[test]
fn quote_parses_tpm2b_wrapped_form() {
    let f = fixtures();
    // Prepend a TPM2B size header; the parser must strip it.
    let mut wrapped = (f.quote_rsa_v1.len() as u16).to_be_bytes().to_vec();
    wrapped.extend_from_slice(&f.quote_rsa_v1);
    let q = quote::parse(&wrapped).unwrap();
    assert_eq!(q.extra_data, f.nonce);
    assert_eq!(q.raw, f.quote_rsa_v1);
}

#[test]
fn legacy_log_is_rejected_with_clear_error() {
    // A legacy (SHA-1-only) log starts directly with a non-SpecID event.
    let mut fake = Vec::new();
    fake.extend_from_slice(&0u32.to_le_bytes()); // pcr
    fake.extend_from_slice(&eventlog::EV_NO_ACTION.to_le_bytes());
    fake.extend_from_slice(&[0u8; 20]);
    fake.extend_from_slice(&4u32.to_le_bytes());
    fake.extend_from_slice(b"fake");
    let err = eventlog::parse(&fake).unwrap_err();
    assert!(matches!(err, eventlog::EventLogError::NotCryptoAgile));
}
