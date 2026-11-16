//! TCG / TPM constants from TCG PC Client spec and TPM 2.0 Part 2.

// --- TPM_ALG_ID (TPM 2.0 Part 2, Table 9) ---
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_SHA384: u16 = 0x000C;
pub const TPM_ALG_SHA512: u16 = 0x000D;

// --- TPM_ECC_CURVE ---
pub const TPM_ECC_NIST_P256: u16 = 0x0003;

// --- TPM_ALG_ID for signature/object schemes ---
pub const TPM_ALG_RSASSA: u16 = 0x0014;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_NULL: u16 = 0x0010;

// --- TPM_ALG_ID for public key types ---
pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_ECC: u16 = 0x0023;

// --- TPM_ST ---
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

// --- Magic placed at the start of every attestation structure ---
pub const TPM_GENERATED_VALUE: u16 = 0xFF54;

// --- TPMA_OBJECT bits for a restricted signing AK ---
// sign | decrypt | restricted | fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth
pub const AK_OBJECT_ATTRIBUTES: u32 =
    (1 << 2) | (1 << 17) | (1 << 16) | (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6);
// = 0x00072072

/// Canonical digest sizes; `None` means the size comes from the log's algorithm map.
pub fn digest_size(algorithm: u16) -> Option<usize> {
    match algorithm {
        TPM_ALG_SHA1 => Some(20),
        TPM_ALG_SHA256 => Some(32),
        TPM_ALG_SHA384 => Some(48),
        TPM_ALG_SHA512 => Some(64),
        _ => None,
    }
}

pub fn algorithm_name(algorithm: u16) -> String {
    match algorithm {
        TPM_ALG_SHA1 => "sha1".into(),
        TPM_ALG_SHA256 => "sha256".into(),
        TPM_ALG_SHA384 => "sha384".into(),
        TPM_ALG_SHA512 => "sha512".into(),
        other => format!("alg_{other:04x}"),
    }
}

// --- TCG event types (TCG PC Client Spec, Table 10) ---
pub const EV_PREBOOT_CERT: u32 = 0x0000_0000;
pub const EV_POST_CODE: u32 = 0x0000_0001;
pub const EV_UNUSED: u32 = 0x0000_0002;
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
// EFI event types
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
pub const EV_EFI_HCRTM_EVENT: u32 = 0x8000_0010;
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E0;
pub const EV_EFI_SPDM_FIRMWARE_BLOB: u32 = 0x8000_00E1;
pub const EV_EFI_SPDM_FIRMWARE_CONFIG: u32 = 0x8000_00E2;

pub fn event_type_name(ty: u32) -> String {
    let name = match ty {
        EV_PREBOOT_CERT => "EV_PREBOOT_CERT",
        EV_POST_CODE => "EV_POST_CODE",
        EV_UNUSED => "EV_UNUSED",
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
        EV_EFI_VARIABLE_DRIVER_CONFIG => "EV_EFI_VARIABLE_DRIVER_CONFIG",
        EV_EFI_VARIABLE_BOOT => "EV_EFI_VARIABLE_BOOT",
        EV_EFI_BOOT_SERVICES_APPLICATION => "EV_EFI_BOOT_SERVICES_APPLICATION",
        EV_EFI_BOOT_SERVICES_DRIVER => "EV_EFI_BOOT_SERVICES_DRIVER",
        EV_EFI_RUNTIME_SERVICES_DRIVER => "EV_EFI_RUNTIME_SERVICES_DRIVER",
        EV_EFI_GPT_EVENT => "EV_EFI_GPT_EVENT",
        EV_EFI_ACTION => "EV_EFI_ACTION",
        EV_EFI_PLATFORM_FIRMWARE_BLOB => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        EV_EFI_HANDOFF_TABLES => "EV_EFI_HANDOFF_TABLES",
        EV_EFI_HCRTM_EVENT => "EV_EFI_HCRTM_EVENT",
        EV_EFI_VARIABLE_AUTHORITY => "EV_EFI_VARIABLE_AUTHORITY",
        EV_EFI_SPDM_FIRMWARE_BLOB => "EV_EFI_SPDM_FIRMWARE_BLOB",
        EV_EFI_SPDM_FIRMWARE_CONFIG => "EV_EFI_SPDM_FIRMWARE_CONFIG",
        _other if ty >= EV_EFI_EVENT_BASE => "EV_EFI_UNKNOWN",
        _ => "EV_UNKNOWN",
    };
    name.to_string()
}

/// Signature string carried by the Spec ID Event03 — 16 bytes, NUL padded.
pub const SPEC_ID_SIGNATURE: &[u8] = b"Spec ID Event03\0";

/// Signature carried by the StartupLocality EV_NO_ACTION event (16 bytes, NUL padded).
pub const STARTUP_LOCALITY_SIGNATURE: &[u8] = b"StartupLocality\0";
