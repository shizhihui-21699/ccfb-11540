//! Trusted baseline ("golden measurement") file format.
//!
//! JSON, versioned. Two complementary sections:
//!
//! ```json
//! {
//!   "version": 1,
//!   "name": "ubuntu-24.04-shim15.8-golden",
//!   "events": [
//!     {
//!       "pcr": 0,
//!       "event_type": "EV_S_CRTM_CONTENTS",
//!       "digests": { "sha1": "…hex…", "sha256": "…hex…" },
//!       "description": "CRTM / BIOS boot block"
//!     }
//!   ],
//!   "pcrs": {
//!     "sha256": { "0": "…hex…", "7": "…hex…" }
//!   }
//! }
//! ```
//!
//! - `events` lists every event expected to be extended, in log order
//!   (EV_NO_ACTION records such as the Spec ID event are excluded). Used to
//!   pinpoint the first divergent event when a PCR mismatches.
//! - `pcrs` gives the expected final PCR values per bank. It may be a subset
//!   of banks/PCRs; only listed entries are checked. It is redundant with
//!   `events` but allows a quick check and tolerates baselines where the
//!   event list is unavailable.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::alg::HashAlg;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub events: Vec<BaselineEvent>,
    /// alg name -> (pcr index as string) -> hex digest
    #[serde(default)]
    pub pcrs: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEvent {
    pub pcr: u32,
    #[serde(default)]
    pub event_type: Option<String>,
    /// alg name -> hex digest
    pub digests: BTreeMap<String, String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("baseline JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported baseline version {0} (expected 1)")]
    Version(u32),
    #[error("baseline references unknown hash algorithm '{0}'")]
    UnknownAlg(String),
    #[error("baseline entry has bad hex: {0}")]
    Hex(String),
}

impl Baseline {
    pub fn from_json(s: &str) -> Result<Self, BaselineError> {
        let b: Baseline = serde_json::from_str(s)?;
        if b.version != 1 {
            return Err(BaselineError::Version(b.version));
        }
        // Validate algorithm names and hex eagerly so typos surface at load.
        for (alg, pcrs) in &b.pcrs {
            let alg = HashAlg::from_name(alg)
                .ok_or_else(|| BaselineError::UnknownAlg(alg.clone()))?;
            for v in pcrs.values() {
                let d = hex::decode(v).map_err(|e| BaselineError::Hex(e.to_string()))?;
                if d.len() != alg.digest_size() {
                    return Err(BaselineError::Hex(format!(
                        "{alg} PCR value has {} bytes, expected {}",
                        d.len(),
                        alg.digest_size()
                    )));
                }
            }
        }
        for ev in &b.events {
            for (name, v) in &ev.digests {
                let alg = HashAlg::from_name(name)
                    .ok_or_else(|| BaselineError::UnknownAlg(name.clone()))?;
                let d = hex::decode(v).map_err(|e| BaselineError::Hex(e.to_string()))?;
                if d.len() != alg.digest_size() {
                    return Err(BaselineError::Hex(format!(
                        "{name} event digest has {} bytes, expected {}",
                        d.len(),
                        alg.digest_size()
                    )));
                }
            }
        }
        Ok(b)
    }

    /// Expected final value of one PCR in one bank, if listed.
    pub fn expected_pcr(&self, alg: HashAlg, pcr: u32) -> Option<Vec<u8>> {
        self.pcrs
            .get(alg.name())?
            .get(&pcr.to_string())
            .and_then(|h| hex::decode(h).ok())
    }
}
