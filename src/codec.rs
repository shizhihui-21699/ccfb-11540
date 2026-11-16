//! Minimal big-endian byte reader/writer for TCG event-log and TPM wire structures.
//!
//! Both formats encode integers and length prefixes in network byte order, so one
//! codec serves both. Every read carries the absolute stream offset, which lets
//! parse errors point at the exact byte of the malformed field.

use crate::error::{Error, Result};

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        if self.remaining() < n {
            Err(Error::EventLog {
                offset: self.pos,
                message: format!("unexpected end of data while reading {what} (need {n} bytes, have {})", self.remaining()),
            })
        } else {
            let s = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            Ok(s)
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1, "U8")?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let s = self.take(2, "U16")?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let s = self.take(4, "U32")?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn u64_be(&mut self) -> Result<u64> {
        let s = self.take(8, "U64")?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    /// Read a TPM2B-style blob: `u16` length prefix followed by that many bytes.
    pub fn blob16(&mut self, what: &str) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len, what)
    }

    /// Read a TCG `u32`-prefixed blob (event data).
    pub fn blob32(&mut self, what: &str) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len, what)
    }

    pub fn read_exact(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        self.take(n, what)
    }

    /// Snapshot used to rewind after a speculative parse attempt.
    pub fn checkpoint(&self) -> usize {
        self.pos
    }

    pub fn restore(&mut self, pos: usize) {
        self.pos = pos;
    }
}

#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64_be(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// TPM2B: `u16` length prefix + payload.
    pub fn blob16(&mut self, v: &[u8]) {
        self.u16(v.len() as u16);
        self.bytes(v);
    }
}
