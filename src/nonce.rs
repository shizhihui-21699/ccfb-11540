//! Nonce anti-replay: a quote is fresh only when its nonce equals the caller's
//! expected challenge *and* has never appeared in an earlier accepted quote.
//!
//! Accepted nonces are persisted in a JSON cache so the protection survives
//! process restarts. Writes happen only after every other check has passed, so
//! a rejected quote never poisons the cache.

use std::collections::BTreeSet;
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct NonceCache {
    /// Hex-encoded nonces of quotes that were accepted in the past.
    #[serde(default)]
    seen: BTreeSet<String>,
}

impl NonceCache {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Verify freshness: nonce must match the challenge and be unseen.
    /// Returns an error without mutating state on failure.
    pub fn check_fresh(&self, expected: &[u8], quote_nonce: &[u8]) -> Result<()> {
        if expected != quote_nonce {
            return Err(Error::NonceMismatch {
                expected: hex::encode(expected),
                actual: hex::encode(quote_nonce),
            });
        }
        let key = hex::encode(expected);
        if self.seen.contains(&key) {
            return Err(Error::ReplayedNonce(key));
        }
        Ok(())
    }

    /// Record a nonce after the whole verification has succeeded.
    pub fn remember(&mut self, nonce: &[u8]) {
        self.seen.insert(hex::encode(nonce));
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Write atomically: temp file in the same directory, then rename.
        let tmp = path.with_extension("nonce-tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
