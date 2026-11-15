//! TPM hash algorithm identifiers and dispatch.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Hash algorithms supported for PCR banks (TPM_ALG_ID subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub const ALL: [HashAlg; 4] = [
        HashAlg::Sha1,
        HashAlg::Sha256,
        HashAlg::Sha384,
        HashAlg::Sha512,
    ];

    /// TPM_ALG_ID -> HashAlg (TPM 2.0 spec Part 2, table 9).
    pub fn from_tpm_alg(id: u16) -> Option<Self> {
        match id {
            0x0004 => Some(Self::Sha1),
            0x000B => Some(Self::Sha256),
            0x000C => Some(Self::Sha384),
            0x000D => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn tpm_alg_id(self) -> u16 {
        match self {
            Self::Sha1 => 0x0004,
            Self::Sha256 => 0x000B,
            Self::Sha384 => 0x000C,
            Self::Sha512 => 0x000D,
        }
    }

    pub fn digest_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

impl std::fmt::Display for HashAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
