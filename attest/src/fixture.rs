//! Spec-conformant test fixture construction: a synthetic crypto-agile event
//! log, matching TPM2 quotes (RSA and ECDSA AKs), and a trusted baseline.
//!
//! Used by the `gen-fixtures` binary and the integration tests. Everything is
//! serialized by hand exactly per the TCG / TPM2 layouts documented in
//! `eventlog` and `quote`, so the fixtures double as an independent
//! cross-check of the parsers.

use std::collections::BTreeMap;

use p256::ecdsa::{signature::Signer as _, Signature as P256Sig, SigningKey as EcSigningKey};
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::signature::SignatureEncoding;

use crate::alg::HashAlg;
use crate::baseline::{Baseline, BaselineEvent};
use crate::eventlog::*;
use crate::quote::{TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE};
use crate::replay::{quote_pcr_digest, replay, PcrBank};

/// One event to put into a synthetic log; digests are computed as hash(data).
#[derive(Debug, Clone)]
pub struct FixtureEvent {
    pub pcr: u32,
    pub event_type: u32,
    pub data: Vec<u8>,
    pub description: String,
}

/// The canonical fixture event sequence (a plausible measured-boot chain).
pub fn fixture_events_v1() -> Vec<FixtureEvent> {
    vec![
        FixtureEvent {
            pcr: 0,
            event_type: EV_S_CRTM_CONTENTS,
            data: b"CRTM v1.0 boot block".to_vec(),
            description: "Core Root of Trust for Measurement".into(),
        },
        FixtureEvent {
            pcr: 0,
            event_type: EV_EFI_PLATFORM_FIRMWARE_BLOB,
            data: b"firmware volume FV_MAIN".to_vec(),
            description: "Main firmware volume".into(),
        },
        FixtureEvent {
            pcr: 1,
            event_type: EV_POST_CODE,
            data: b"POST code measurements".to_vec(),
            description: "Firmware POST code".into(),
        },
        FixtureEvent {
            pcr: 4,
            event_type: EV_EFI_BOOT_SERVICES_APPLICATION,
            data: b"shimx64.efi + grubx64.efi".to_vec(),
            description: "Bootloader image".into(),
        },
        FixtureEvent {
            pcr: 7,
            event_type: EV_EFI_VARIABLE_DRIVER_CONFIG,
            data: b"SecureBoot=enabled,PK,KEK,db,dbx".to_vec(),
            description: "Secure boot variables".into(),
        },
        FixtureEvent {
            pcr: 7,
            event_type: EV_SEPARATOR,
            data: [0u8; 4].to_vec(),
            description: "Pre-OS separator".into(),
        },
        FixtureEvent {
            pcr: 9,
            event_type: EV_IPL,
            data: b"initrd.img v1 (known good)".to_vec(),
            description: "Initial RAM disk".into(),
        },
    ]
}

/// v2: identical except the initrd changed (simulates an unexpected update
/// or tampering that the TPM faithfully measured).
pub fn fixture_events_v2() -> Vec<FixtureEvent> {
    let mut ev = fixture_events_v1();
    ev.last_mut().unwrap().data = b"initrd.img v2 (UNEXPECTED)".to_vec();
    ev
}

/// Serialize the Spec ID Event03 record (as the log's first event).
fn spec_id_record(algs: &[HashAlg]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"Spec ID Event03\0"); // signature[16]
    data.extend_from_slice(&0u32.to_le_bytes()); // platformClass
    data.push(0); // specVersionMinor
    data.push(2); // specVersionMajor
    data.push(0); // specErrata
    data.push(2); // uintnSize (64-bit firmware)
    data.extend_from_slice(&(algs.len() as u32).to_le_bytes());
    for alg in algs {
        data.extend_from_slice(&alg.tpm_alg_id().to_le_bytes());
        data.extend_from_slice(&(alg.digest_size() as u16).to_le_bytes());
    }
    data.push(0); // vendorInfoSize

    let mut rec = Vec::new();
    rec.extend_from_slice(&0u32.to_le_bytes()); // pcrIndex
    rec.extend_from_slice(&EV_NO_ACTION.to_le_bytes()); // eventType
    rec.extend_from_slice(&[0u8; 20]); // SHA-1 digest (zero by convention)
    rec.extend_from_slice(&(data.len() as u32).to_le_bytes());
    rec.extend_from_slice(&data);
    rec
}

/// Serialize one TCG_PCR_EVENT2 record.
fn event2_record(pcr: u32, event_type: u32, digests: &[(HashAlg, Vec<u8>)], data: &[u8]) -> Vec<u8> {
    let mut rec = Vec::new();
    rec.extend_from_slice(&pcr.to_le_bytes());
    rec.extend_from_slice(&event_type.to_le_bytes());
    rec.extend_from_slice(&(digests.len() as u32).to_le_bytes());
    for (alg, digest) in digests {
        rec.extend_from_slice(&alg.tpm_alg_id().to_le_bytes());
        rec.extend_from_slice(digest);
    }
    rec.extend_from_slice(&(data.len() as u32).to_le_bytes());
    rec.extend_from_slice(data);
    rec
}

/// Build a crypto-agile event log from fixture events.
///
/// If `corrupt` is `Some((event_ordinal, alg))`, that event's digest for
/// `alg` gets its first byte flipped (simulating a log that no longer
/// matches what the TPM measured).
pub fn build_log(
    events: &[FixtureEvent],
    algs: &[HashAlg],
    corrupt: Option<(usize, HashAlg)>,
) -> Vec<u8> {
    let mut log = spec_id_record(algs);
    for (i, ev) in events.iter().enumerate() {
        let digests: Vec<(HashAlg, Vec<u8>)> = algs
            .iter()
            .map(|&alg| {
                let mut d = alg.hash(&ev.data);
                if corrupt == Some((i, alg)) {
                    d[0] ^= 0xFF;
                }
                (alg, d)
            })
            .collect();
        log.extend_from_slice(&event2_record(ev.pcr, ev.event_type, &digests, &ev.data));
    }
    log
}

/// Marshal a TPMS_ATTEST quote over the given PCR selection.
pub fn build_quote(
    banks: &BTreeMap<HashAlg, PcrBank>,
    select_alg: HashAlg,
    select_pcrs: &[u32],
    nonce: &[u8],
) -> Vec<u8> {
    let selections = vec![(select_alg, select_pcrs.to_vec())];
    let pcr_digest = quote_pcr_digest(&selections, banks).expect("fixture digest");

    // PCR selection bitmap: 3 bytes cover PCR 0..23.
    let mut bitmap = [0u8; 3];
    for &p in select_pcrs {
        bitmap[(p / 8) as usize] |= 1 << (p % 8);
    }

    let mut q = Vec::new();
    q.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
    q.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
    // qualifiedSigner: TPM2B_NAME = hash alg id || digest of a fixed label
    let name_alg = HashAlg::Sha256;
    let mut name = name_alg.tpm_alg_id().to_be_bytes().to_vec();
    name.extend_from_slice(&name_alg.hash(b"mb-attest fixture AK"));
    q.extend_from_slice(&(name.len() as u16).to_be_bytes());
    q.extend_from_slice(&name);
    // extraData: the anti-replay nonce
    q.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    q.extend_from_slice(nonce);
    // clockInfo
    q.extend_from_slice(&123_456_789u64.to_be_bytes()); // clock
    q.extend_from_slice(&5u32.to_be_bytes()); // resetCount
    q.extend_from_slice(&1u32.to_be_bytes()); // restartCount
    q.push(1); // safe = YES
    // firmwareVersion
    q.extend_from_slice(&0u64.to_be_bytes());
    // TPMS_QUOTE_INFO
    q.extend_from_slice(&1u32.to_be_bytes()); // one PCR selection
    q.extend_from_slice(&select_alg.tpm_alg_id().to_be_bytes());
    q.push(bitmap.len() as u8);
    q.extend_from_slice(&bitmap);
    q.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
    q.extend_from_slice(&pcr_digest);
    q
}

/// Everything needed to exercise the verifier end to end.
pub struct FixtureSet {
    pub nonce: Vec<u8>,
    pub algs: Vec<HashAlg>,
    pub select_pcrs: Vec<u32>,

    pub log_v1: Vec<u8>,
    /// Same log with one sha256 digest corrupted (log/quote inconsistency).
    pub log_tampered: Vec<u8>,
    /// Log with a different initrd measurement (baseline inconsistency).
    pub log_v2: Vec<u8>,

    pub ak_rsa_pem: String,
    pub ak_ec_pem: String,

    pub quote_rsa_v1: Vec<u8>,
    pub sig_rsa_v1: Vec<u8>,
    pub quote_ec_v1: Vec<u8>,
    pub sig_ec_v1: Vec<u8>,
    pub quote_rsa_v2: Vec<u8>,
    pub sig_rsa_v2: Vec<u8>,

    pub baseline_json: String,
}

pub fn generate(nonce: &[u8]) -> FixtureSet {
    let algs = vec![HashAlg::Sha1, HashAlg::Sha256];
    let select_alg = HashAlg::Sha256;
    let select_pcrs = vec![0u32, 1, 4, 7, 9];

    let events_v1 = fixture_events_v1();
    let events_v2 = fixture_events_v2();

    let log_v1 = build_log(&events_v1, &algs, None);
    // Corrupt the sha256 digest of the bootloader event (ordinal 3).
    let log_tampered = build_log(&events_v1, &algs, Some((3, HashAlg::Sha256)));
    let log_v2 = build_log(&events_v2, &algs, None);

    let parsed_v1 = crate::eventlog::parse(&log_v1).expect("fixture log parses");
    let parsed_v2 = crate::eventlog::parse(&log_v2).expect("fixture log parses");
    let banks_v1 = replay(&parsed_v1, &algs);
    let banks_v2 = replay(&parsed_v2, &algs);

    // Keys.
    let rsa_priv = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
    let rsa_pub = rsa_priv.to_public_key();
    let ak_rsa_pem = rsa_pub
        .to_public_key_pem(LineEnding::LF)
        .expect("rsa pem");
    let ec_signing = EcSigningKey::random(&mut OsRng);
    let ak_ec_pem = ec_signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("ec pem");

    // Quotes.
    let quote_v1 = build_quote(&banks_v1, select_alg, &select_pcrs, nonce);
    let quote_v2 = build_quote(&banks_v2, select_alg, &select_pcrs, nonce);

    let rsa_signing = RsaSigningKey::<sha2::Sha256>::new(rsa_priv);
    let sig_rsa_v1 = rsa_signing.sign(&quote_v1).to_vec();
    let sig_rsa_v2 = rsa_signing.sign(&quote_v2).to_vec();
    let sig_ec_v1: P256Sig = ec_signing.sign(&quote_v1);
    let sig_ec_v1 = sig_ec_v1.to_bytes().to_vec();

    // Baseline from the v1 (known-good) state.
    let baseline = Baseline {
        version: 1,
        name: Some("fixture-golden-v1".into()),
        events: events_v1
            .iter()
            .map(|ev| BaselineEvent {
                pcr: ev.pcr,
                event_type: Some(event_type_name(ev.event_type).to_string()),
                digests: algs
                    .iter()
                    .map(|a| (a.name().to_string(), hex::encode(a.hash(&ev.data))))
                    .collect(),
                description: Some(ev.description.clone()),
            })
            .collect(),
        pcrs: algs
            .iter()
            .map(|&a| {
                let pcrs: BTreeMap<String, String> = banks_v1
                    .get(&a)
                    .expect("bank")
                    .iter()
                    .map(|(p, v)| (p.to_string(), hex::encode(v)))
                    .collect();
                (a.name().to_string(), pcrs)
            })
            .collect(),
    };
    let baseline_json = serde_json::to_string_pretty(&baseline).expect("baseline json");

    FixtureSet {
        nonce: nonce.to_vec(),
        algs,
        select_pcrs,
        log_v1,
        log_tampered,
        log_v2,
        ak_rsa_pem,
        ak_ec_pem,
        quote_rsa_v1: quote_v1.clone(),
        sig_rsa_v1,
        quote_ec_v1: quote_v1,
        sig_ec_v1,
        quote_rsa_v2: quote_v2,
        sig_rsa_v2,
        baseline_json,
    }
}
