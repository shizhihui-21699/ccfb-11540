//! Trusted baseline: a signed-off snapshot of what a good measured boot log
//! must look like, plus the comparison logic that pinpoints the diverging event.
//!
//! Baseline file format (JSON, versioned via `schema_version`):
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "created_at": "2026-11-17T08:00:00Z",
//!   "description": "golden fleet boot chain",
//!   "log_format": "crypto-agile",
//!   "algorithms": [{"algorithm": 11, "name": "sha256", "digest_size": 32}],
//!   "pcr_banks": {
//!     "sha256": {"0": "00..", "7": "ab.."}
//!   },
//!   "events": [
//!     {
//!       "sequence": 1,
//!       "pcr": 0,
//!       "event_type": 1,
//!       "event_type_name": "EV_POST_CODE",
//!       "digests": {"sha256": "hex.."},
//!       "event_data_hex": "hex..",
//!       "extends_pcr": true
//!     }
//!   ]
//! }
//! ```
//!
//! Comparison is positional (event order is part of the trust chain): the
//! first position whose PCR, type, digest or data differs is reported together
//! with both the expected and observed value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::eventlog::{EventLog, ParsedEvent};
use crate::replay::PcrBanks;
use crate::tcg::algorithm_name;

pub const BASELINE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineAlgorithm {
    pub algorithm: u16,
    pub name: String,
    pub digest_size: u16,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineEvent {
    pub sequence: usize,
    pub pcr: u32,
    pub event_type: u32,
    pub event_type_name: String,
    /// Algorithm name -> hex digest.
    pub digests: BTreeMap<String, String>,
    #[serde(with = "hex_serde")]
    pub event_data: Vec<u8>,
    pub extends_pcr: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: u32,
    pub created_at: String,
    #[serde(default)]
    pub description: String,
    pub log_format: String,
    pub algorithms: Vec<BaselineAlgorithm>,
    /// Algorithm name -> (PCR index -> hex value), only touched PCRs recorded.
    pub pcr_banks: BTreeMap<String, BTreeMap<u32, String>>,
    pub events: Vec<BaselineEvent>,
}

impl Baseline {
    /// Build a baseline from a log that the operator trusts and its replayed
    /// PCR banks. The timestamp is supplied (no wall-clock access in libraries
    /// that may be used by reproducible tests).
    pub fn from_log(log: &EventLog, banks: &PcrBanks, created_at: &str, description: &str) -> Self {
        let algorithms = log
            .algorithms
            .iter()
            .map(|a| BaselineAlgorithm {
                algorithm: a.algorithm,
                name: algorithm_name(a.algorithm),
                digest_size: a.digest_size,
            })
            .collect();

        let mut pcr_banks = BTreeMap::new();
        for (alg, bank) in &banks.0 {
            let mut pcrs = BTreeMap::new();
            for (pcr, value) in &bank.pcrs {
                // Only record PCRs that differ from reset, plus record zero PCRs
                // explicitly when at least one event touched the bank elsewhere:
                // simplest correct choice is to record every PCR.
                pcrs.insert(*pcr, hex::encode(value));
            }
            pcr_banks.insert(algorithm_name(*alg), pcrs);
        }

        let events = log
            .events
            .iter()
            .enumerate()
            .map(|(i, e)| BaselineEvent {
                sequence: i,
                pcr: e.pcr_index,
                event_type: e.event_type,
                event_type_name: e.event_type_name(),
                digests: e
                    .digests
                    .iter()
                    .map(|d| (algorithm_name(d.algorithm), hex::encode(&d.digest)))
                    .collect(),
                event_data: e.event_data.clone(),
                extends_pcr: e.extends_pcr,
            })
            .collect();

        Baseline {
            schema_version: BASELINE_SCHEMA_VERSION,
            created_at: created_at.to_string(),
            description: description.to_string(),
            log_format: if log.legacy {
                "legacy-sha1".into()
            } else {
                "crypto-agile".into()
            },
            algorithms,
            pcr_banks,
            events,
        }
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let baseline: Baseline = serde_json::from_slice(bytes)?;
        if baseline.schema_version != BASELINE_SCHEMA_VERSION {
            return Err(Error::Baseline(format!(
                "unsupported schema_version {}, expected {}",
                baseline.schema_version, BASELINE_SCHEMA_VERSION
            )));
        }
        Ok(baseline)
    }
}

/// One concrete field-level difference found at a single event position.
#[derive(Debug, PartialEq, Eq)]
pub enum EventDifference {
    MissingInLog {
        sequence: usize,
    },
    ExtraInLog {
        sequence: usize,
        observed: ParsedEventSnapshot,
    },
    PcrChanged {
        sequence: usize,
        expected: u32,
        observed: u32,
    },
    EventTypeChanged {
        sequence: usize,
        expected: (u32, String),
        observed: (u32, String),
    },
    DigestChanged {
        sequence: usize,
        algorithm: String,
        expected: String,
        observed: String,
    },
    DigestMissing {
        sequence: usize,
        algorithm: String,
        expected: String,
    },
    DigestUnexpected {
        sequence: usize,
        algorithm: String,
        observed: String,
    },
    EventDataChanged {
        sequence: usize,
        expected_hex: String,
        observed_hex: String,
    },
    ExtendFlagChanged {
        sequence: usize,
        expected: bool,
        observed: bool,
    },
}

/// Serializable-ish snapshot for reporting extra events.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedEventSnapshot {
    pub pcr: u32,
    pub event_type: u32,
    pub event_type_name: String,
}

impl EventDifference {
    pub fn sequence(&self) -> usize {
        match self {
            EventDifference::MissingInLog { sequence }
            | EventDifference::ExtraInLog { sequence, .. }
            | EventDifference::PcrChanged { sequence, .. }
            | EventDifference::EventTypeChanged { sequence, .. }
            | EventDifference::DigestChanged { sequence, .. }
            | EventDifference::DigestMissing { sequence, .. }
            | EventDifference::DigestUnexpected { sequence, .. }
            | EventDifference::EventDataChanged { sequence, .. }
            | EventDifference::ExtendFlagChanged { sequence, .. } => *sequence,
        }
    }

    /// Human-readable explanation naming the offending event.
    pub fn explain(&self) -> String {
        match self {
            EventDifference::MissingInLog { sequence } => {
                format!("event #{sequence} exists in baseline but is missing from the log")
            }
            EventDifference::ExtraInLog { sequence, observed } => {
                format!(
                    "event #{sequence} ({}, PCR {}) appears in the log but not in the baseline",
                    observed.event_type_name, observed.pcr
                )
            }
            EventDifference::PcrChanged {
                sequence,
                expected,
                observed,
            } => format!("event #{sequence} targets PCR {observed}, baseline expects PCR {expected}"),
            EventDifference::EventTypeChanged {
                sequence,
                expected,
                observed,
            } => format!(
                "event #{sequence} has type {} ({:#010x}), baseline expects {} ({:#010x})",
                observed.1, observed.0, expected.1, expected.0
            ),
            EventDifference::DigestChanged {
                sequence,
                algorithm,
                expected,
                observed,
            } => format!(
                "event #{sequence} {algorithm} digest differs: observed {observed} baseline {expected}"
            ),
            EventDifference::DigestMissing {
                sequence,
                algorithm,
                expected,
            } => format!(
                "event #{sequence} is missing its {algorithm} digest (baseline {expected})"
            ),
            EventDifference::DigestUnexpected {
                sequence,
                algorithm,
                observed,
            } => format!(
                "event #{sequence} carries an unexpected {algorithm} digest {observed}"
            ),
            EventDifference::EventDataChanged {
                sequence,
                expected_hex,
                observed_hex,
            } => format!(
                "event #{sequence} event data differs: observed {observed_hex} baseline {expected_hex}"
            ),
            EventDifference::ExtendFlagChanged {
                sequence,
                expected,
                observed,
            } => format!(
                "event #{sequence} extend flag is {observed}, baseline expects {expected}"
            ),
        }
    }
}

/// Result of a baseline comparison.
#[derive(Debug, Default)]
pub struct BaselineReport {
    pub differences: Vec<EventDifference>,
    /// Final PCR values that diverge from the baseline.
    pub pcr_differences: Vec<PcrBaselineDifference>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PcrBaselineDifference {
    pub algorithm: String,
    pub pcr: u32,
    pub expected: String,
    pub observed: String,
}

impl BaselineReport {
    pub fn ok(&self) -> bool {
        self.differences.is_empty() && self.pcr_differences.is_empty()
    }
}

/// Compare a parsed log + replayed PCRs against the trusted baseline.
pub fn compare(baseline: &Baseline, log: &EventLog, banks: &PcrBanks) -> BaselineReport {
    let mut report = BaselineReport::default();

    let observed_count = log.events.len();
    let expected_count = baseline.events.len();
    let common = observed_count.min(expected_count);

    for i in 0..common {
        let expected = &baseline.events[i];
        let observed = &log.events[i];
        compare_one(expected, observed, &mut report);
    }
    if expected_count > observed_count {
        for e in &baseline.events[common..] {
            report
                .differences
                .push(EventDifference::MissingInLog {
                    sequence: e.sequence,
                });
        }
    }
    if observed_count > expected_count {
        for (i, observed) in log.events.iter().enumerate().skip(common) {
            report.differences.push(EventDifference::ExtraInLog {
                sequence: i,
                observed: ParsedEventSnapshot {
                    pcr: observed.pcr_index,
                    event_type: observed.event_type,
                    event_type_name: observed.event_type_name(),
                },
            });
        }
    }

    // PCR-level cross-check against the recorded final values.
    for (alg_name, expected_pcrs) in &baseline.pcr_banks {
        let Some(alg_id) = baseline
            .algorithms
            .iter()
            .find(|a| &a.name == alg_name)
            .map(|a| a.algorithm)
        else {
            continue;
        };
        let Some(bank) = banks.bank(alg_id) else {
            for (pcr, expected) in expected_pcrs {
                report.pcr_differences.push(PcrBaselineDifference {
                    algorithm: alg_name.clone(),
                    pcr: *pcr,
                    expected: expected.clone(),
                    observed: "<bank absent>".into(),
                });
            }
            continue;
        };
        for (pcr, expected_hex) in expected_pcrs {
            let observed_hex = hex::encode(bank.get(*pcr));
            if &observed_hex != expected_hex {
                report.pcr_differences.push(PcrBaselineDifference {
                    algorithm: alg_name.clone(),
                    pcr: *pcr,
                    expected: expected_hex.clone(),
                    observed: observed_hex,
                });
            }
        }
    }

    report
}

fn compare_one(
    expected: &BaselineEvent,
    observed: &ParsedEvent,
    report: &mut BaselineReport,
) {
    let seq = expected.sequence;
    if expected.pcr != observed.pcr_index {
        report.differences.push(EventDifference::PcrChanged {
            sequence: seq,
            expected: expected.pcr,
            observed: observed.pcr_index,
        });
    }
    if expected.event_type != observed.event_type {
        report
            .differences
            .push(EventDifference::EventTypeChanged {
                sequence: seq,
                expected: (expected.event_type, expected.event_type_name.clone()),
                observed: (observed.event_type, observed.event_type_name()),
            });
    }
    if expected.extends_pcr != observed.extends_pcr {
        report.differences.push(EventDifference::ExtendFlagChanged {
            sequence: seq,
            expected: expected.extends_pcr,
            observed: observed.extends_pcr,
        });
    }

    // Digest maps compared both directions.
    let observed_map: BTreeMap<_, _> = observed
        .digests
        .iter()
        .map(|d| (algorithm_name(d.algorithm), hex::encode(&d.digest)))
        .collect();
    for (alg, expected_hex) in &expected.digests {
        match observed_map.get(alg) {
            Some(observed_hex) if observed_hex != expected_hex => {
                report.differences.push(EventDifference::DigestChanged {
                    sequence: seq,
                    algorithm: alg.clone(),
                    expected: expected_hex.clone(),
                    observed: observed_hex.clone(),
                });
            }
            None => report.differences.push(EventDifference::DigestMissing {
                sequence: seq,
                algorithm: alg.clone(),
                expected: expected_hex.clone(),
            }),
            _ => {}
        }
    }
    for (alg, observed_hex) in &observed_map {
        if !expected.digests.contains_key(alg) {
            report
                .differences
                .push(EventDifference::DigestUnexpected {
                    sequence: seq,
                    algorithm: alg.clone(),
                    observed: observed_hex.clone(),
                });
        }
    }

    if expected.event_data != observed.event_data {
        report
            .differences
            .push(EventDifference::EventDataChanged {
                sequence: seq,
                expected_hex: hex::encode(&expected.event_data),
                observed_hex: hex::encode(&observed.event_data),
            });
    }
}

/// Hex encoding for the `event_data` byte field inside JSON.
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(text.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}
