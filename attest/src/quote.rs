//! TPM2 quote (`TPMS_ATTEST` with `TPMS_QUOTE_INFO`) parsing and checking.
//!
//! All TPM wire-format integers are BIG-endian (unlike the event log, which
//! is little-endian). Relevant structures (TPM 2.0 spec Part 2):
//!
//! ```text
//! TPMS_ATTEST
//!   magic           TPM_GENERATED (u32)  = 0xFF544347 ("ÿTCG")
//!   type            TPMI_ST_ATTEST (u16) = TPM_ST_ATTEST_QUOTE = 0x8018
//!   qualifiedSigner TPM2B_NAME   (u16 size + bytes)
//!   extraData       TPM2B_DATA   (u16 size + bytes)   <-- anti-replay nonce
//!   clockInfo       TPMS_CLOCK_INFO
//!     clock           u64
//!     resetCount      u32
//!     restartCount    u32
//!     safe            u8 (TPMI_YES_NO)
//!   firmwareVersion u64
//!   attested        TPMS_QUOTE_INFO
//!     pcrSelect  TPML_PCR_SELECTION
//!       count        u32
//!       pcrSelections[count] TPMS_PCR_SELECTION
//!         hash         u16 (TPMI_ALG_HASH)
//!         sizeofSelect u8
//!         pcrSelect    [u8; sizeofSelect]   (bit i set => PCR i selected)
//!     pcrDigest  TPM2B_DIGEST (u16 size + bytes)
//! ```
//!
//! The signature produced by TPM2_Quote covers the marshalled TPMS_ATTEST
//! bytes (i.e. the contents of the returned TPM2B_ATTEST, without its own
//! 2-byte size header).

use crate::alg::HashAlg;
use thiserror::Error;

pub const TPM_GENERATED_VALUE: u32 = 0xFF54_5447; // 0xFF 'T' 'C' 'G'
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

#[derive(Debug, Clone)]
pub struct Quote {
    pub qualified_signer: Vec<u8>,
    /// Qualifying data — must equal the challenger-supplied nonce.
    pub extra_data: Vec<u8>,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    pub firmware_version: u64,
    /// (hash alg, selected PCR indices ascending) per selection entry.
    pub pcr_select: Vec<(HashAlg, Vec<u32>)>,
    pub pcr_digest: Vec<u8>,
    /// The exact signed bytes (marshalled TPMS_ATTEST).
    pub raw: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum QuoteError {
    #[error("quote truncated: {0}")]
    Truncated(&'static str),
    #[error("bad magic {0:#010x}, expected TPM_GENERATED_VALUE 0xff544347")]
    BadMagic(u32),
    #[error("attestation type {0:#06x} is not TPM_ST_ATTEST_QUOTE (0x8018)")]
    NotAQuote(u16),
    #[error("unknown hash algorithm id {0:#06x} in PCR selection")]
    UnknownHashAlg(u16),
    #[error("trailing {0} byte(s) after TPMS_ATTEST")]
    Trailing(usize),
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], QuoteError> {
        if self.remaining() < n {
            return Err(QuoteError::Truncated(what));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self, what: &'static str) -> Result<u8, QuoteError> {
        Ok(self.take(1, what)?[0])
    }
    fn u16(&mut self, what: &'static str) -> Result<u16, QuoteError> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self, what: &'static str) -> Result<u32, QuoteError> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self, what: &'static str) -> Result<u64, QuoteError> {
        let b = self.take(8, what)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    fn tpm2b(&mut self, what: &'static str) -> Result<&'a [u8], QuoteError> {
        let n = self.u16(what)? as usize;
        self.take(n, what)
    }
}

/// Parse a quote blob. Accepts either a raw marshalled TPMS_ATTEST or a
/// TPM2B_ATTEST (2-byte size prefix + TPMS_ATTEST).
pub fn parse(buf: &[u8]) -> Result<Quote, QuoteError> {
    // Strip a TPM2B size header if one is present.
    let body = if buf.len() >= 2 && u16::from_be_bytes([buf[0], buf[1]]) as usize == buf.len() - 2
    {
        &buf[2..]
    } else {
        buf
    };

    let mut r = Reader::new(body);

    let magic = r.u32("magic")?;
    if magic != TPM_GENERATED_VALUE {
        return Err(QuoteError::BadMagic(magic));
    }
    let st = r.u16("attestation type")?;
    if st != TPM_ST_ATTEST_QUOTE {
        return Err(QuoteError::NotAQuote(st));
    }
    let qualified_signer = r.tpm2b("qualifiedSigner")?.to_vec();
    let extra_data = r.tpm2b("extraData")?.to_vec();
    let clock = r.u64("clockInfo.clock")?;
    let reset_count = r.u32("clockInfo.resetCount")?;
    let restart_count = r.u32("clockInfo.restartCount")?;
    let safe = r.u8("clockInfo.safe")? != 0;
    let firmware_version = r.u64("firmwareVersion")?;

    // TPMS_QUOTE_INFO
    let sel_count = r.u32("pcrSelect.count")?;
    let mut pcr_select = Vec::with_capacity(sel_count as usize);
    for _ in 0..sel_count {
        let hash_id = r.u16("pcrSelection.hash")?;
        let alg =
            HashAlg::from_tpm_alg(hash_id).ok_or(QuoteError::UnknownHashAlg(hash_id))?;
        let sizeof_select = r.u8("pcrSelection.sizeofSelect")?;
        let bitmap = r.take(sizeof_select as usize, "pcrSelection.pcrSelect")?;
        let mut pcrs = Vec::new();
        for (byte_i, byte) in bitmap.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    pcrs.push((byte_i * 8 + bit) as u32);
                }
            }
        }
        pcr_select.push((alg, pcrs));
    }
    let pcr_digest = r.tpm2b("pcrDigest")?.to_vec();

    if r.remaining() != 0 {
        return Err(QuoteError::Trailing(r.remaining()));
    }

    Ok(Quote {
        qualified_signer,
        extra_data,
        clock,
        reset_count,
        restart_count,
        safe,
        firmware_version,
        pcr_select,
        pcr_digest,
        raw: body.to_vec(),
    })
}

/// Constant-time equality for the nonce check (avoids leaking where a
/// mismatch occurred, though the nonce itself is not secret).
pub fn nonce_matches(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(actual.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
