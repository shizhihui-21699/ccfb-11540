//! Parser for the TCG PC Client Platform Firmware Profile event log in
//! "crypto agile" format (TCG_EfiSpecIDEvent / "Spec ID Event03" followed by
//! `TCG_PCR_EVENT2` records), per:
//!   - TCG PC Client Platform Firmware Profile Specification, section 10
//!   - TCG EFI Protocol Specification, section 5.3
//!
//! Log layout (all integers little-endian):
//!
//! ```text
//! TCG_PCClientPCREvent                       <-- first record, legacy shape
//!   pcrIndex        u32                      (always 0)
//!   eventType       u32                      (always EV_NO_ACTION)
//!   digest          [u8; 20]                 (SHA-1, conventionally zero)
//!   eventDataSize   u32
//!   event           TCG_EfiSpecIDEventStruct
//!     signature        [u8; 16] = "Spec ID Event03\0"
//!     platformClass    u32
//!     specVersionMinor u8
//!     specVersionMajor u8
//!     specErrata       u8
//!     uintnSize        u8
//!     numberOfAlgorithms u32
//!     digestSizes[numberOfAlgorithms] { algorithmId u16, digestSize u16 }
//!     vendorInfoSize   u8
//!     vendorInfo       [u8; vendorInfoSize]
//!
//! TCG_PCR_EVENT2 (repeated to end of buffer)
//!   pcrIndex        u32
//!   eventType       u32
//!   digests         TPML_DIGEST_VALUES
//!     count            u32
//!     digests[count]   TPMT_HA { hashAlg u16, digest [u8; digestSize(hashAlg)] }
//!   eventSize       u32
//!   event           [u8; eventSize]
//! ```

use crate::alg::HashAlg;
use thiserror::Error;

pub const EV_PREBOOT_CERT: u32 = 0x0000_0000;
pub const EV_POST_CODE: u32 = 0x0000_0001;
pub const EV_NO_ACTION: u32 = 0x0000_0003;
pub const EV_SEPARATOR: u32 = 0x0000_0004;
pub const EV_ACTION: u32 = 0x0000_0005;
pub const EV_EVENT_TAG: u32 = 0x0000_0006;
pub const EV_S_CRTM_CONTENTS: u32 = 0x0000_0007;
pub const EV_S_CRTM_VERSION: u32 = 0x0000_0008;
pub const EV_CPU_MICROCODE: u32 = 0x0000_0009;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000_000A;
pub const EV_TABLE_OF_DEVICES: u32 = 0x0000_000B;
pub const EV_COMPACT_HASH: u32 = 0x0000_000C;
pub const EV_IPL: u32 = 0x0000_000D;
pub const EV_IPL_PARTITION_DATA: u32 = 0x0000_000E;
pub const EV_NONHOST_CODE: u32 = 0x0000_000F;
pub const EV_NONHOST_CONFIG: u32 = 0x0000_0010;
pub const EV_NONHOST_INFO: u32 = 0x0000_0011;
pub const EV_OMIT_BOOT_DEVICE_EVENTS: u32 = 0x0000_0012;
pub const EV_EFI_EVENT_BASE: u32 = 0x8000_0000;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
pub const EV_EFI_VARIABLE_BOOT: u32 = 0x8000_0002;
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
pub const EV_EFI_BOOT_SERVICES_DRIVER: u32 = 0x8000_0004;
pub const EV_EFI_RUNTIME_SERVICES_DRIVER: u32 = 0x8000_0005;
pub const EV_EFI_GPT_EVENT: u32 = 0x8000_0006;
pub const EV_EFI_ACTION: u32 = 0x8000_0007;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB: u32 = 0x8000_0008;
pub const EV_EFI_HANDOFF_TABLES: u32 = 0x8000_0009;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = 0x8000_000A;
pub const EV_EFI_HANDOFF_TABLES2: u32 = 0x8000_000B;
pub const EV_EFI_VARIABLE_BOOT2: u32 = 0x8000_000C;
pub const EV_EFI_HCRTM_EVENT: u32 = 0x8000_0010;
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E0;
pub const EV_EFI_SPDM_FIRMWARE_BLOB: u32 = 0x8000_00E1;
pub const EV_EFI_SPDM_FIRMWARE_CONFIG: u32 = 0x8000_00E2;

pub fn event_type_name(t: u32) -> &'static str {
    match t {
        EV_PREBOOT_CERT => "EV_PREBOOT_CERT",
        EV_POST_CODE => "EV_POST_CODE",
        EV_NO_ACTION => "EV_NO_ACTION",
        EV_SEPARATOR => "EV_SEPARATOR",
        EV_ACTION => "EV_ACTION",
        EV_EVENT_TAG => "EV_EVENT_TAG",
        EV_S_CRTM_CONTENTS => "EV_S_CRTM_CONTENTS",
        EV_S_CRTM_VERSION => "EV_S_CRTM_VERSION",
        EV_CPU_MICROCODE => "EV_CPU_MICROCODE",
        EV_PLATFORM_CONFIG_FLAGS => "EV_PLATFORM_CONFIG_FLAGS",
        EV_TABLE_OF_DEVICES => "EV_TABLE_OF_DEVICES",
        EV_COMPACT_HASH => "EV_COMPACT_HASH",
        EV_IPL => "EV_IPL",
        EV_IPL_PARTITION_DATA => "EV_IPL_PARTITION_DATA",
        EV_NONHOST_CODE => "EV_NONHOST_CODE",
        EV_NONHOST_CONFIG => "EV_NONHOST_CONFIG",
        EV_NONHOST_INFO => "EV_NONHOST_INFO",
        EV_OMIT_BOOT_DEVICE_EVENTS => "EV_OMIT_BOOT_DEVICE_EVENTS",
        EV_EFI_EVENT_BASE => "EV_EFI_EVENT_BASE",
        EV_EFI_VARIABLE_DRIVER_CONFIG => "EV_EFI_VARIABLE_DRIVER_CONFIG",
        EV_EFI_VARIABLE_BOOT => "EV_EFI_VARIABLE_BOOT",
        EV_EFI_BOOT_SERVICES_APPLICATION => "EV_EFI_BOOT_SERVICES_APPLICATION",
        EV_EFI_BOOT_SERVICES_DRIVER => "EV_EFI_BOOT_SERVICES_DRIVER",
        EV_EFI_RUNTIME_SERVICES_DRIVER => "EV_EFI_RUNTIME_SERVICES_DRIVER",
        EV_EFI_GPT_EVENT => "EV_EFI_GPT_EVENT",
        EV_EFI_ACTION => "EV_EFI_ACTION",
        EV_EFI_PLATFORM_FIRMWARE_BLOB => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        EV_EFI_HANDOFF_TABLES => "EV_EFI_HANDOFF_TABLES",
        EV_EFI_PLATFORM_FIRMWARE_BLOB2 => "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        EV_EFI_HANDOFF_TABLES2 => "EV_EFI_HANDOFF_TABLES2",
        EV_EFI_VARIABLE_BOOT2 => "EV_EFI_VARIABLE_BOOT2",
        EV_EFI_HCRTM_EVENT => "EV_EFI_HCRTM_EVENT",
        EV_EFI_VARIABLE_AUTHORITY => "EV_EFI_VARIABLE_AUTHORITY",
        EV_EFI_SPDM_FIRMWARE_BLOB => "EV_EFI_SPDM_FIRMWARE_BLOB",
        EV_EFI_SPDM_FIRMWARE_CONFIG => "EV_EFI_SPDM_FIRMWARE_CONFIG",
        _ => "EV_UNKNOWN",
    }
}

const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

/// One parsed event-log record. `index` counts from 0 at the Spec ID event.
#[derive(Debug, Clone)]
pub struct Event {
    pub index: usize,
    pub pcr: u32,
    pub event_type: u32,
    /// One digest per hash bank recorded in the log, in log order.
    pub digests: Vec<(HashAlg, Vec<u8>)>,
    pub data: Vec<u8>,
}

impl Event {
    pub fn type_name(&self) -> &'static str {
        event_type_name(self.event_type)
    }

    pub fn digest_for(&self, alg: HashAlg) -> Option<&[u8]> {
        self.digests
            .iter()
            .find(|(a, _)| *a == alg)
            .map(|(_, d)| d.as_slice())
    }
}

/// Contents of the Spec ID Event03 record.
#[derive(Debug, Clone)]
pub struct SpecIdEvent {
    pub platform_class: u32,
    pub spec_version_minor: u8,
    pub spec_version_major: u8,
    pub spec_errata: u8,
    pub uintn_size: u8,
    /// Hash banks declared by the firmware, with their digest sizes.
    pub digest_sizes: Vec<(HashAlg, u16)>,
    pub vendor_info: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EventLog {
    pub spec_id: SpecIdEvent,
    /// All records including the Spec ID event at index 0.
    pub events: Vec<Event>,
}

impl EventLog {
    /// Hash banks declared in the Spec ID event.
    pub fn algorithms(&self) -> Vec<HashAlg> {
        self.spec_id.digest_sizes.iter().map(|(a, _)| *a).collect()
    }

    /// Events that are actually extended into PCRs (EV_NO_ACTION is not).
    pub fn extended_events(&self) -> impl Iterator<Item = &Event> {
        self.events.iter().filter(|e| e.event_type != EV_NO_ACTION)
    }
}

#[derive(Debug, Error)]
pub enum EventLogError {
    #[error("log too short: {0}")]
    Truncated(&'static str),
    #[error("first event is not a Spec ID Event03 record (legacy SHA-1-only format is not supported)")]
    NotCryptoAgile,
    #[error("first event has type {0:#x}, expected EV_NO_ACTION")]
    BadFirstEventType(u32),
    #[error("unknown TPM algorithm id {0:#06x} in Spec ID digestSizes")]
    UnknownSpecAlg(u16),
    #[error("digest size {got} for {alg} does not match expected {want}")]
    BadDigestSize {
        alg: HashAlg,
        got: u16,
        want: usize,
    },
    #[error("event {index}: digest for unknown algorithm id {alg_id:#06x}")]
    UnknownEventAlg { index: usize, alg_id: u16 },
    #[error("event {index}: trailing {remaining} garbage byte(s) at end of log")]
    TrailingBytes { index: usize, remaining: usize },
}

/// Minimal little-endian cursor.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], EventLogError> {
        if self.remaining() < n {
            return Err(EventLogError::Truncated(what));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, EventLogError> {
        Ok(self.take(1, what)?[0])
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16, EventLogError> {
        let b = self.take(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32, EventLogError> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Parse a whole event-log buffer.
pub fn parse(buf: &[u8]) -> Result<EventLog, EventLogError> {
    let mut r = Reader::new(buf);

    // ---- First record: TCG_PCClientPCREvent carrying the Spec ID event ----
    let pcr = r.u32("first pcrIndex")?;
    let event_type = r.u32("first eventType")?;
    if event_type != EV_NO_ACTION {
        return Err(EventLogError::BadFirstEventType(event_type));
    }
    let digest20 = r.take(20, "first digest")?.to_vec();
    let data_size = r.u32("first eventDataSize")? as usize;
    let data = r.take(data_size, "first event data")?.to_vec();

    let spec_id = parse_spec_id(&data)?;

    let spec_event = Event {
        index: 0,
        pcr,
        event_type,
        digests: vec![(HashAlg::Sha1, digest20)],
        data,
    };

    // ---- Remaining records: TCG_PCR_EVENT2 ----
    let mut events = vec![spec_event];
    while r.remaining() > 0 {
        let index = events.len();
        let pcr = r.u32("event pcrIndex")?;
        let event_type = r.u32("event eventType")?;
        let digest_count = r.u32("event digest count")?;
        let mut digests = Vec::with_capacity(digest_count as usize);
        for _ in 0..digest_count {
            let alg_id = r.u16("event digest alg")?;
            let (alg, size) = spec_id
                .digest_sizes
                .iter()
                .find(|(a, _)| a.tpm_alg_id() == alg_id)
                .map(|(a, s)| (*a, *s as usize))
                .ok_or(EventLogError::UnknownEventAlg { index, alg_id })?;
            let digest = r.take(size, "event digest")?.to_vec();
            digests.push((alg, digest));
        }
        let event_size = r.u32("event eventSize")? as usize;
        let data = r.take(event_size, "event data")?.to_vec();
        events.push(Event {
            index,
            pcr,
            event_type,
            digests,
            data,
        });
    }

    Ok(EventLog { spec_id, events })
}

fn parse_spec_id(data: &[u8]) -> Result<SpecIdEvent, EventLogError> {
    if data.len() < 16 || &data[..16] != SPEC_ID_SIGNATURE {
        return Err(EventLogError::NotCryptoAgile);
    }
    let mut r = Reader::new(data);
    let _sig = r.take(16, "spec id signature")?;
    let platform_class = r.u32("platformClass")?;
    let spec_version_minor = r.u8("specVersionMinor")?;
    let spec_version_major = r.u8("specVersionMajor")?;
    let spec_errata = r.u8("specErrata")?;
    let uintn_size = r.u8("uintnSize")?;
    let num_algs = r.u32("numberOfAlgorithms")?;
    let mut digest_sizes = Vec::with_capacity(num_algs as usize);
    for _ in 0..num_algs {
        let alg_id = r.u16("digestSizes alg")?;
        let size = r.u16("digestSizes size")?;
        let alg = HashAlg::from_tpm_alg(alg_id)
            .ok_or(EventLogError::UnknownSpecAlg(alg_id))?;
        let want = alg.digest_size();
        if size as usize != want {
            return Err(EventLogError::BadDigestSize {
                alg,
                got: size,
                want,
            });
        }
        digest_sizes.push((alg, size));
    }
    let vendor_info_size = r.u8("vendorInfoSize")?;
    let vendor_info = r.take(vendor_info_size as usize, "vendorInfo")?.to_vec();

    Ok(SpecIdEvent {
        platform_class,
        spec_version_minor,
        spec_version_major,
        spec_errata,
        uintn_size,
        digest_sizes,
        vendor_info,
    })
}
