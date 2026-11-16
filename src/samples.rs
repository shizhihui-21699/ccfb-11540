//! Deterministic construction of sample measured-boot artifacts.
//!
//! The generated log follows the EDK2/TCG PC Client shape: a Spec ID Event03,
//! a StartupLocality no-action event, then a plausible firmware -> bootloader
//! -> kernel chain spread across PCRs 0..9. Digests are real hashes over the
//! event data so the whole pipeline exercises the actual crypto code paths.

use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::error::Result;
use crate::eventlog::{
    self, AlgorithmEntry, SpecIdEvent, TaggedDigest,
};
use crate::replay::hash;
use crate::tcg::{
    algorithm_name, digest_size, EV_EFI_ACTION, EV_EFI_BOOT_SERVICES_APPLICATION,
    EV_EFI_GPT_EVENT, EV_EFI_VARIABLE_AUTHORITY, EV_EFI_VARIABLE_BOOT,
    EV_EFI_VARIABLE_DRIVER_CONFIG, EV_IPL, EV_NO_ACTION, EV_POST_CODE, EV_SEPARATOR,
    STARTUP_LOCALITY_SIGNATURE, TPM_ALG_SHA1,
};
use crate::tpm::{PcrSelection, QuoteBundle};
use crate::tpm_builder::{self, GeneratedAk, QuoteRequest};

pub const SAMPLE_SEED: [u8; 32] = [0x54u8; 32];
pub const VALID_NONCE: &[u8] = b"remote-attestation-challenge-0001";
pub const REPLAYED_NONCE: &[u8] = VALID_NONCE;
pub const WRONG_NONCE: &[u8] = b"stale-or-forged-challenge-value!!";

/// Which PCRs the sample quote attests to (0..9, the dynamic boot chain).
pub fn sample_selection(algorithm: u16) -> PcrSelection {
    let mut pcr_select = vec![0u8; 3];
    for pcr in 0u32..10 {
        pcr_select[(pcr / 8) as usize] |= 1 << (pcr % 8);
    }
    PcrSelection {
        hash_algorithm: algorithm,
        pcr_select,
    }
}

fn spec_id(algorithms: &[u16]) -> SpecIdEvent {
    SpecIdEvent {
        platform_class: 0x0000_0000_0000_0002, // EFI
        spec_version_minor: 0x00,
        spec_version_major: 0x02,
        spec_errata: 0x00,
        algorithms: algorithms
            .iter()
            .map(|alg| AlgorithmEntry {
                algorithm: *alg,
                digest_size: digest_size(*alg).expect("known alg") as u16,
            })
            .collect(),
        vendor_info: Vec::new(),
    }
}

/// `UEFI_VARIABLE_DATA`: GUID(16) + UnicodeName (u64 len + UTF-16LE) +
/// UnicodeDataLength(u64) + variable data.
fn uefi_variable(guid: &[u8; 16], name: &str, data: &[u8]) -> Vec<u8> {
    let mut w = Vec::new();
    w.extend_from_slice(guid);
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let name_bytes = utf16.len() * 2;
    w.extend_from_slice(&(name_bytes as u64).to_le_bytes());
    for unit in utf16 {
        w.extend_from_slice(&unit.to_le_bytes());
    }
    w.extend_from_slice(&(data.len() as u64).to_le_bytes());
    w.extend_from_slice(data);
    w
}

/// `UEFI_IMAGE_LOAD_EVENT`: at 0x100000, len 0x80000, link addr, then a
/// device-path blob (simplified but length-prefixed like the spec).
fn image_load(data: &[u8]) -> Vec<u8> {
    let mut w = Vec::new();
    w.extend_from_slice(&0x0000_0000_0010_0000u64.to_le_bytes()); // ImageLocationInMemory
    w.extend_from_slice(&0x0000_0000_0008_0000u64.to_le_bytes()); // ImageLengthInMemory
    w.extend_from_slice(&0x0000_0000_0010_0000u64.to_le_bytes()); // ImageLinkTimeAddress
    w.extend_from_slice(&(data.len() as u64).to_le_bytes()); // LengthOfDevicePath
    w.extend_from_slice(data);
    w
}

/// One semantic sample event before serialization: where it extends, its type,
/// and the raw measured bytes (event data). Digests are derived from `data`
/// under every active algorithm.
struct EventSpec {
    pcr: u32,
    ty: u32,
    data: Vec<u8>,
}

fn golden_event_specs() -> Vec<EventSpec> {
    let efi_guid = [0x61u8; 16];
    let sec_guid = [0x62u8; 16];
    let pk_guid = [0x63u8; 16];
    let boot_guid = [0x64u8; 16];
    let dbx_guid = [0x65u8; 16];
    vec![
        // 1: CRTM / POST code into PCR0
        EventSpec {
            pcr: 0,
            ty: EV_POST_CODE,
            data: b"CRTM boot block v1.4 (synthetic sample)".to_vec(),
        },
        // 2: firmware blob measurement, PCR0
        EventSpec {
            pcr: 0,
            ty: EV_POST_CODE,
            data: b"UEFI PEI/DXE firmware volume 0x7F8000".to_vec(),
        },
        // StartupLocality (EV_NO_ACTION) is inserted separately by the builder.
        // 3: separator PCR0..7 (first of the separator waves)
        EventSpec {
            pcr: 0,
            ty: EV_SEPARATOR,
            data: vec![0x00, 0x00, 0x00, 0x04],
        },
        EventSpec {
            pcr: 1,
            ty: EV_SEPARATOR,
            data: vec![0x00, 0x00, 0x00, 0x04],
        },
        EventSpec {
            pcr: 2,
            ty: EV_SEPARATOR,
            data: vec![0x00, 0x00, 0x00, 0x04],
        },
        EventSpec {
            pcr: 3,
            ty: EV_SEPARATOR,
            data: vec![0x00, 0x00, 0x00, 0x04],
        },
        EventSpec {
            pcr: 4,
            ty: EV_SEPARATOR,
            data: vec![0x00, 0x00, 0x00, 0x04],
        },
        EventSpec {
            pcr: 5,
            ty: EV_SEPARATOR,
            data: vec![0x00, 0x00, 0x00, 0x04],
        },
        EventSpec {
            pcr: 6,
            ty: EV_SEPARATOR,
            data: vec![0x00, 0x00, 0x00, 0x04],
        },
        EventSpec {
            pcr: 7,
            ty: EV_SEPARATOR,
            data: vec![0x00, 0x00, 0x00, 0x04],
        },
        // 12: Secure Boot PK variable into PCR7
        EventSpec {
            pcr: 7,
            ty: EV_EFI_VARIABLE_DRIVER_CONFIG,
            data: uefi_variable(&pk_guid, "PK", b"platform-key-cert-der"),
        },
        // 13: dbx into PCR7
        EventSpec {
            pcr: 7,
            ty: EV_EFI_VARIABLE_DRIVER_CONFIG,
            data: uefi_variable(&dbx_guid, "dbx", b"forbidden-signature-db-v3"),
        },
        // 14: Boot order variable into PCR1
        EventSpec {
            pcr: 1,
            ty: EV_EFI_VARIABLE_BOOT,
            data: uefi_variable(&boot_guid, "BootOrder", &[0x00, 0x00, 0x00, 0x01]),
        },
        // 15: Boot#### option
        EventSpec {
            pcr: 1,
            ty: EV_EFI_VARIABLE_BOOT,
            data: uefi_variable(
                &boot_guid,
                "Boot0001",
                b"HD(1,GPT,00112233)/\\EFI\\BOOT\\GRUBAA64.EFI",
            ),
        },
        // 16: GPT partition table into PCR5
        EventSpec {
            pcr: 5,
            ty: EV_EFI_GPT_EVENT,
            data: b"GPT header + 128 partition entries (synthetic)".to_vec(),
        },
        // 17: shim/bootloader image into PCR4
        EventSpec {
            pcr: 4,
            ty: EV_EFI_BOOT_SERVICES_APPLICATION,
            data: image_load(b"\\EFI\\BOOT\\BOOTAA64.EFI device path"),
        },
        // 18: shim verifies grub -> authority event PCR4
        EventSpec {
            pcr: 4,
            ty: EV_EFI_VARIABLE_AUTHORITY,
            data: uefi_variable(&sec_guid, "db", b"shim-Microsoft-UEFI-CA"),
        },
        // 19: grub image PCR4
        EventSpec {
            pcr: 4,
            ty: EV_EFI_BOOT_SERVICES_APPLICATION,
            data: image_load(b"\\EFI\\fedora\\grubaa64.efi device path"),
        },
        // 20: Boot Manager Action / ExitBootServices PCR4/5
        EventSpec {
            pcr: 4,
            ty: EV_EFI_ACTION,
            data: b"Exit Boot Services Invocation".to_vec(),
        },
        EventSpec {
            pcr: 5,
            ty: EV_EFI_ACTION,
            data: b"Exit Boot Services Returned with Success".to_vec(),
        },
        // 22: kernel command line via IPL into PCR9
        EventSpec {
            pcr: 9,
            ty: EV_IPL,
            data: b"console=tty0 root=UUID=deadbeef ro quiet splash".to_vec(),
        },
        // 23: kernel image measurement PCR9
        EventSpec {
            pcr: 9,
            ty: EV_IPL,
            data: b"/boot/vmlinuz-6.6.0-synthetic + initramfs digest".to_vec(),
        },
        // 24: EFI config blob into PCR2
        EventSpec {
            pcr: 2,
            ty: EV_EFI_VARIABLE_DRIVER_CONFIG,
            data: uefi_variable(&efi_guid, "SetupMode", &[0x00, 0x00, 0x00, 0x00]),
        },
    ]
}

/// A built sample: serialized log plus its parsed form for callers.
pub struct BuiltLog {
    pub bytes: Vec<u8>,
    pub parsed: EventLog,
}

// Re-export under the name used throughout.
pub use crate::eventlog::EventLog;

fn digests_for(data: &[u8], algorithms: &[u16]) -> Vec<TaggedDigest> {
    algorithms
        .iter()
        .map(|alg| TaggedDigest {
            algorithm: *alg,
            digest: hash(*alg, data).expect("known alg"),
        })
        .collect()
}

/// Build the golden crypto-agile log for the given algorithm set.
/// StartupLocality is emitted as a second EV_NO_ACTION event right after the
/// spec event, matching real firmware.
pub fn build_golden_log(algorithms: &[u16]) -> Result<BuiltLog> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&eventlog::build_spec_id_event(&spec_id(algorithms)));
    // StartupLocality: locality byte 0, zero digests (as EDK2 writes it).
    let mut locality = STARTUP_LOCALITY_SIGNATURE.to_vec();
    locality.push(0u8);
    bytes.extend_from_slice(&eventlog::build_no_action_event(0, &[], &locality));

    for spec in golden_event_specs() {
        let digests = digests_for(&spec.data, algorithms);
        bytes.extend_from_slice(&eventlog::build_agile_event(
            spec.pcr,
            spec.ty,
            &digests,
            &spec.data,
        ));
    }
    let parsed = EventLog::parse(&bytes)?;
    Ok(BuiltLog { bytes, parsed })
}

/// Tampered variant: flip one byte inside the kernel command-line event data
/// and recompute that event's digests, so the log stays structurally valid but
/// the PCR chain diverges from the baseline.
pub fn build_tampered_log(algorithms: &[u16]) -> Result<BuiltLog> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&eventlog::build_spec_id_event(&spec_id(algorithms)));
    let mut locality = STARTUP_LOCALITY_SIGNATURE.to_vec();
    locality.push(0u8);
    bytes.extend_from_slice(&eventlog::build_no_action_event(0, &[], &locality));

    for spec in golden_event_specs() {
        let mut data = spec.data.clone();
        if spec.pcr == 9 && spec.ty == EV_IPL && data.starts_with(b"console=") {
            // Inject a kernel parameter — the classic measured-boot attack.
            let inject = b" console=ttyS0 init=/bin/evil";
            data.extend_from_slice(inject);
        }
        let digests = digests_for(&data, algorithms);
        bytes.extend_from_slice(&eventlog::build_agile_event(
            spec.pcr,
            spec.ty,
            &digests,
            &data,
        ));
    }
    let parsed = EventLog::parse(&bytes)?;
    Ok(BuiltLog { bytes, parsed })
}

/// Build a legacy SHA-1 only log (TCG 1.2 style): spec event with a SHA-1
/// algorithm block followed by `TCG_PCR_EVENT` entries.
pub fn build_legacy_log() -> Result<BuiltLog> {
    let spec = spec_id(&[TPM_ALG_SHA1]);
    let mut spec_data = Vec::new();
    spec_data.extend_from_slice(crate::tcg::SPEC_ID_SIGNATURE);
    spec_data.extend_from_slice(&spec.platform_class.to_be_bytes());
    spec_data.push(spec.spec_version_minor);
    spec_data.push(spec.spec_version_major);
    spec_data.push(spec.spec_errata);
    spec_data.push(2u8);
    spec_data.extend_from_slice(&0u32.to_be_bytes());
    spec_data.extend_from_slice(&1u32.to_be_bytes());
    spec_data.extend_from_slice(&TPM_ALG_SHA1.to_be_bytes());
    spec_data.extend_from_slice(&20u16.to_be_bytes());
    spec_data.extend_from_slice(&0u32.to_be_bytes()); // vendorInfo length

    let mut bytes =
        eventlog::build_legacy_event(0, EV_NO_ACTION, &[0u8; 20], &spec_data);

    for spec in golden_event_specs().into_iter().filter(|e| e.pcr <= 9) {
        let digest: [u8; 20] = hash(TPM_ALG_SHA1, &spec.data)?
            .try_into()
            .expect("sha1 is 20 bytes");
        bytes.extend_from_slice(&eventlog::build_legacy_event(
            spec.pcr,
            spec.ty,
            &digest,
            &spec.data,
        ));
    }
    let parsed = EventLog::parse(&bytes)?;
    Ok(BuiltLog { bytes, parsed })
}

// ---------------------------------------------------------------------------
// Quote construction over a replayed log
// ---------------------------------------------------------------------------

pub fn seeded_rng() -> StdRng {
    StdRng::from_seed(SAMPLE_SEED)
}

/// Sign a quote over PCRs 0..9 of the given banks, returning the serialized
/// bundle and its parsed form.
pub fn build_quote_for(
    ak: &GeneratedAk,
    rng: &mut StdRng,
    banks: &crate::replay::PcrBanks,
    algorithm: u16,
    nonce: &[u8],
) -> Result<(Vec<u8>, QuoteBundle)> {
    let selection = sample_selection(algorithm);
    let (pcr_digest, _covered) = crate::tpm::quote_pcr_digest(
        std::slice::from_ref(&selection),
        |alg, pcr| banks.bank(alg).map(|b| b.get(pcr).to_vec()),
    )?;
    let public_area = match ak {
        GeneratedAk::Rsa { public_area, .. }
        | GeneratedAk::Ecc { public_area, .. } => public_area.clone(),
    };
    let bundle = tpm_builder::build_quote(QuoteRequest {
        ak,
        rng,
        nonce,
        pcr_selections: vec![selection],
        pcr_digest,
        hash_algorithm: algorithm,
        clock: 0x0001_0000_0000_0042,
        firmware_version: 0x2024_0301_0000_0000,
    })?;
    let bytes = tpm_builder::serialize_bundle(&bundle, &public_area);
    Ok((bytes, bundle))
}

/// Re-export for the binary.
pub fn alg_name(alg: u16) -> String {
    algorithm_name(alg)
}
