//! Parser for TCG PC Client measured boot event logs.
//!
//! Supports both wire formats defined in the TCG PC Client Platform Firmware
//! Profile Specification:
//!
//! * **Crypto-agile** (`TCG_PCR_EVENT2`), identified by an `EV_NO_ACTION`
//!   "Spec ID Event03" carrying the active algorithm/digest-size list.
//! * **Legacy SHA-1** (`TCG_PCR_EVENT`, TCG 1.2 style), single 20-byte digest.
//!
//! The first event decides the format: a legacy parse whose event data starts
//! with `Spec ID Event03` means a legacy stream; otherwise the stream is
//! rewound and parsed as crypto-agile.

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::tcg::{
    digest_size, event_type_name, EV_NO_ACTION, SPEC_ID_SIGNATURE, TPM_ALG_SHA1,
};

/// One digest inside a crypto-agile event: algorithm id plus raw digest bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedDigest {
    pub algorithm: u16,
    pub digest: Vec<u8>,
}

/// Algorithm descriptor from the Spec ID Event03 (`TPMS_SPEC_ID_BLOCK` entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmEntry {
    pub algorithm: u16,
    pub digest_size: u16,
}

/// Parsed contents of the Spec ID Event03 event data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecIdEvent {
    pub platform_class: u32,
    pub spec_version_minor: u8,
    pub spec_version_major: u8,
    pub spec_errata: u8,
    pub algorithms: Vec<AlgorithmEntry>,
    pub vendor_info: Vec<u8>,
}

/// A single parsed event-log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEvent {
    /// Byte offset of the event start in the raw log (for diagnostics).
    pub offset: usize,
    pub pcr_index: u32,
    pub event_type: u32,
    /// Empty for the crypto-agile Spec ID event; one entry for legacy events.
    pub digests: Vec<TaggedDigest>,
    pub event_data: Vec<u8>,
    /// Parsed Spec ID payload when this is the agile/legacy spec event.
    pub spec_id: Option<SpecIdEvent>,
    /// True when this event must be extended into a PCR.
    /// `EV_NO_ACTION` events are never extended.
    pub extends_pcr: bool,
}

impl ParsedEvent {
    pub fn event_type_name(&self) -> String {
        event_type_name(self.event_type)
    }

    /// Digest carried for a given algorithm, if present.
    pub fn digest_for(&self, algorithm: u16) -> Option<&[u8]> {
        self.digests
            .iter()
            .find(|d| d.algorithm == algorithm)
            .map(|d| d.digest.as_slice())
    }
}

/// Result of parsing a complete log.
#[derive(Debug, Clone)]
pub struct EventLog {
    pub events: Vec<ParsedEvent>,
    /// Algorithms advertised by the Spec ID event.
    pub algorithms: Vec<AlgorithmEntry>,
    /// True for a legacy SHA-1 (TCG 1.2 style) log.
    pub legacy: bool,
}

impl EventLog {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.is_empty() {
            return Err(Error::EventLog {
                offset: 0,
                message: "event log is empty".into(),
            });
        }

        // Speculatively parse the first event as a legacy TCG_PCR_EVENT.
        let start = r.checkpoint();
        let legacy_first = parse_legacy_event(&mut r);
        let legacy = match &legacy_first {
            Ok(ev) => ev
                .event_data
                .starts_with(SPEC_ID_SIGNATURE),
            Err(_) => false,
        };

        if legacy {
            // Full legacy SHA-1 stream. First event already consumed.
            let mut events = Vec::new();
            let first = legacy_first?;
            let spec = parse_legacy_spec_id(&first.event_data)?;
            let mut first = first;
            first.spec_id = Some(spec.clone());
            events.push(first);
            while !r.is_empty() {
                events.push(parse_legacy_event(&mut r)?);
            }
            return Ok(EventLog {
                events,
                algorithms: spec.algorithms,
                legacy: true,
            });
        }

        // Crypto-agile stream: rewind and parse TCG_PCR_EVENT2 entries.
        r.restore(start);
        let mut algorithms = Vec::new();
        let mut events = Vec::new();
        let mut first = true;
        while !r.is_empty() {
            let ev = parse_agile_event(&mut r, first, &algorithms)?;
            if first {
                let spec = ev
                    .spec_id
                    .clone()
                    .ok_or_else(|| Error::EventLog {
                        offset: ev.offset,
                        message: "first crypto-agile event is not a Spec ID Event03".into(),
                    })?;
                algorithms = spec.algorithms.clone();
                first = false;
            }
            events.push(ev);
        }
        if first {
            return Err(Error::EventLog {
                offset: 0,
                message: "log contains no events".into(),
            });
        }
        Ok(EventLog {
            events,
            algorithms,
            legacy: false,
        })
    }

    /// Events that actually extend PCRs (everything except EV_NO_ACTION).
    pub fn extending_events(&self) -> impl Iterator<Item = &ParsedEvent> {
        self.events.iter().filter(|e| e.extends_pcr)
    }
}

// ---------------------------------------------------------------------------
// Legacy TCG_PCR_EVENT (SHA-1, TCG 1.2)
// ---------------------------------------------------------------------------

fn parse_legacy_event(r: &mut Reader) -> Result<ParsedEvent> {
    let offset = r.position();
    let pcr_index = r.u32()?;
    let event_type = r.u32()?;
    let digest = r.read_exact(20, "legacy SHA-1 digest")?.to_vec();
    let event_data = r.blob32("legacy event data")?.to_vec();
    validate_pcr(pcr_index, offset)?;

    let is_spec = event_data.starts_with(SPEC_ID_SIGNATURE);
    let spec_id = if is_spec {
        Some(parse_legacy_spec_id(&event_data)?)
    } else {
        None
    };

    Ok(ParsedEvent {
        offset,
        pcr_index,
        event_type,
        digests: vec![TaggedDigest {
            algorithm: TPM_ALG_SHA1,
            digest,
        }],
        event_data,
        spec_id,
        extends_pcr: event_type != EV_NO_ACTION,
    })
}

fn parse_legacy_spec_id(data: &[u8]) -> Result<SpecIdEvent> {
    // A legacy spec event still carries the agile-style Spec ID block after the
    // 16-byte signature, so the on-disk layout is shared from that point on.
    let mut r = Reader::new(data);
    let sig = r.read_exact(16, "Spec ID signature")?;
    if sig != SPEC_ID_SIGNATURE {
        return Err(Error::EventLog {
            offset: 0,
            message: "bad Spec ID signature in legacy event".into(),
        });
    }
    parse_spec_id_block(&mut r)
}

// ---------------------------------------------------------------------------
// Crypto-agile TCG_PCR_EVENT2
// ---------------------------------------------------------------------------

fn parse_agile_event(
    r: &mut Reader,
    first: bool,
    known_algorithms: &[AlgorithmEntry],
) -> Result<ParsedEvent> {
    let offset = r.position();
    let pcr_index = r.u32()?;
    let event_type = r.u32()?;
    validate_pcr(pcr_index, offset)?;
    let digest_count = r.u32()?;

    let mut digests = Vec::new();
    for _ in 0..digest_count {
        let alg = r.u16()?;
        let raw = r.blob16("tagged digest")?;
        // The Spec ID event defines the legal digest size per algorithm.
        let expected = known_algorithms
            .iter()
            .find(|a| a.algorithm == alg)
            .map(|a| a.digest_size as usize)
            .or_else(|| digest_size(alg));
        match expected {
            Some(size) if size == raw.len() => {}
            Some(size) => {
                return Err(Error::DigestLength {
                    algorithm: alg,
                    expected: size,
                    actual: raw.len(),
                })
            }
            None => return Err(Error::UnsupportedAlgorithm(alg)),
        }
        digests.push(TaggedDigest {
            algorithm: alg,
            digest: raw.to_vec(),
        });
    }

    let event_data = r.blob32("event data")?.to_vec();

    let spec_id = if first {
        if event_type != EV_NO_ACTION {
            return Err(Error::EventLog {
                offset,
                message: "first event must be EV_NO_ACTION Spec ID Event03".into(),
            });
        }
        if digest_count != 0 {
            return Err(Error::EventLog {
                offset,
                message: format!("Spec ID Event03 must carry 0 digests, got {digest_count}"),
            });
        }
        if !event_data.starts_with(SPEC_ID_SIGNATURE) {
            return Err(Error::EventLog {
                offset,
                message: "first event data does not start with 'Spec ID Event03'".into(),
            });
        }
        Some(parse_spec_id_event(&event_data)?)
    } else if digest_count == 0 {
        // Zero digests are legal for non-spec EV_NO_ACTION events such as
        // StartupLocality; anything else must carry at least one digest.
        if event_type != EV_NO_ACTION {
            return Err(Error::EventLog {
                offset,
                message: "extending event with zero digests".into(),
            });
        }
        None
    } else {
        None
    };

    Ok(ParsedEvent {
        offset,
        pcr_index,
        event_type,
        digests,
        event_data,
        spec_id,
        extends_pcr: event_type != EV_NO_ACTION,
    })
}

fn parse_spec_id_event(data: &[u8]) -> Result<SpecIdEvent> {
    let mut r = Reader::new(data);
    let sig = r.read_exact(16, "Spec ID signature")?;
    if sig != SPEC_ID_SIGNATURE {
        return Err(Error::EventLog {
            offset: 0,
            message: "bad Spec ID signature".into(),
        });
    }
    parse_spec_id_block(&mut r)
}

/// Shared body of the Spec ID Event03 event data following the 16-byte signature.
fn parse_spec_id_block(r: &mut Reader) -> Result<SpecIdEvent> {
    let platform_class = r.u32()?;
    let spec_version_minor = r.u8()?;
    let spec_version_major = r.u8()?;
    let spec_errata = r.u8()?;
    let uintn_size = r.u8()?;
    if uintn_size != 2 {
        return Err(Error::EventLog {
            offset: r.position(),
            message: format!("unsupported uintnSize {uintn_size}, expected 2"),
        });
    }
    let reserved = r.u32()?;
    if reserved != 0 {
        return Err(Error::EventLog {
            offset: r.position() - 4,
            message: format!("non-zero reserved field in Spec ID event: {reserved:#x}"),
        });
    }
    let number_of_algorithms = r.u32()? as usize;
    let mut algorithms = Vec::with_capacity(number_of_algorithms);
    for _ in 0..number_of_algorithms {
        let algorithm = r.u16()?;
        let advertised_size = r.u16()?;
        // The spec block names the exact hashes firmware will extend with.
        // An algorithm this build cannot hash must be rejected here rather
        // than failing later mid-replay.
        let Some(canonical) = digest_size(algorithm) else {
            return Err(Error::UnsupportedAlgorithm(algorithm));
        };
        if canonical != advertised_size as usize {
            return Err(Error::DigestLength {
                algorithm,
                expected: canonical,
                actual: advertised_size as usize,
            });
        }
        algorithms.push(AlgorithmEntry {
            algorithm,
            digest_size: advertised_size,
        });
    }
    let vendor_info_len = r.u32()? as usize;
    let vendor_info = r.read_exact(vendor_info_len, "vendorInfo")?.to_vec();
    if !r.is_empty() {
        return Err(Error::EventLog {
            offset: r.position(),
            message: "trailing bytes after Spec ID event data".into(),
        });
    }
    Ok(SpecIdEvent {
        platform_class,
        spec_version_minor,
        spec_version_major,
        spec_errata,
        algorithms,
        vendor_info,
    })
}

fn validate_pcr(pcr_index: u32, _offset: usize) -> Result<()> {
    if pcr_index > 23 {
        Err(Error::PcrIndexOutOfRange(pcr_index))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Wire builders (used by the sample generator; kept next to the parser so the
// two never drift apart).
// ---------------------------------------------------------------------------

/// Serialize a crypto-agile Spec ID Event03 (PCR 0, EV_NO_ACTION, zero digests).
pub fn build_spec_id_event(spec: &SpecIdEvent) -> Vec<u8> {
    let mut data = Writer::new();
    data.bytes(SPEC_ID_SIGNATURE); // exactly 16 bytes incl. NUL
    data.u32(spec.platform_class);
    data.u8(spec.spec_version_minor);
    data.u8(spec.spec_version_major);
    data.u8(spec.spec_errata);
    data.u8(2); // uintnSize
    data.u32(0); // reserved
    data.u32(spec.algorithms.len() as u32);
    for a in &spec.algorithms {
        data.u16(a.algorithm);
        data.u16(a.digest_size);
    }
    data.u32(spec.vendor_info.len() as u32);
    data.bytes(&spec.vendor_info);
    let event_data = data.into_bytes();

    let mut w = Writer::new();
    w.u32(0); // PCRIndex
    w.u32(EV_NO_ACTION); // EventType
    w.u32(0); // DigestCount — spec event carries no digests
    w.u32(event_data.len() as u32);
    w.bytes(&event_data);
    w.into_bytes()
}

/// Serialize one crypto-agile `TCG_PCR_EVENT2`.
pub fn build_agile_event(
    pcr_index: u32,
    event_type: u32,
    digests: &[TaggedDigest],
    event_data: &[u8],
) -> Vec<u8> {
    assert_ne!(event_type, EV_NO_ACTION, "use build_no_action_event");
    let mut w = Writer::new();
    w.u32(pcr_index);
    w.u32(event_type);
    w.u32(digests.len() as u32);
    for d in digests {
        w.u16(d.algorithm);
        w.blob16(&d.digest);
    }
    w.u32(event_data.len() as u32);
    w.bytes(event_data);
    w.into_bytes()
}

/// Serialize an `EV_NO_ACTION` event with digests (e.g. StartupLocality, which
/// real firmware logs with a digest count of zero; this covers both shapes).
pub fn build_no_action_event(
    pcr_index: u32,
    digests: &[TaggedDigest],
    event_data: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(pcr_index);
    w.u32(EV_NO_ACTION);
    w.u32(digests.len() as u32);
    for d in digests {
        w.u16(d.algorithm);
        w.blob16(&d.digest);
    }
    w.u32(event_data.len() as u32);
    w.bytes(event_data);
    w.into_bytes()
}

/// Serialize one legacy `TCG_PCR_EVENT` (single SHA-1 digest).
pub fn build_legacy_event(
    pcr_index: u32,
    event_type: u32,
    sha1_digest: &[u8; 20],
    event_data: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(pcr_index);
    w.u32(event_type);
    w.bytes(sha1_digest);
    w.u32(event_data.len() as u32);
    w.bytes(event_data);
    w.into_bytes()
}
