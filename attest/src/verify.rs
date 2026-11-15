//! End-to-end attestation verification: nonce, AK signature, log replay vs
//! quote PCR digest, and trusted-baseline diff with first-divergence
//! pinpointing.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::ak::AkKey;
use crate::alg::HashAlg;
use crate::baseline::Baseline;
use crate::eventlog::{event_type_name, EventLog};
use crate::quote::{nonce_matches, Quote};
use crate::replay::{quote_pcr_digest, replay, PcrBank};

#[derive(Debug)]
pub struct PcrMismatch {
    pub alg: HashAlg,
    pub pcr: u32,
    pub expected: Vec<u8>,
    pub actual: Vec<u8>,
}

/// The first event (per PCR bank) where the log diverges from the baseline.
#[derive(Debug)]
pub struct Divergence {
    pub alg: HashAlg,
    pub pcr: u32,
    /// Index into the full event log (`Event::index`).
    pub log_index: Option<usize>,
    /// Ordinal among events extended into this PCR.
    pub ordinal_in_pcr: usize,
    pub event_type: Option<u32>,
    pub expected_digest: Option<Vec<u8>>,
    pub actual_digest: Option<Vec<u8>>,
    pub description: Option<String>,
    pub kind: DivergenceKind,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DivergenceKind {
    /// Same position, different digest.
    DigestMismatch,
    /// Log has more events for this PCR than the baseline.
    UnexpectedEvent,
    /// Baseline has more events for this PCR than the log.
    MissingEvent,
}

#[derive(Debug)]
pub struct BaselineOutcome {
    /// Final-PCR mismatches against the baseline's `pcrs` section.
    pub pcr_mismatches: Vec<PcrMismatch>,
    /// First divergence per (PCR, bank) against the baseline's `events`.
    pub divergences: Vec<Divergence>,
}

impl BaselineOutcome {
    pub fn matches(&self) -> bool {
        self.pcr_mismatches.is_empty() && self.divergences.is_empty()
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub nonce_ok: bool,
    pub signature_ok: bool,
    pub log_matches_quote: bool,
    pub quote_pcr_digest: Vec<u8>,
    pub replayed_pcr_digest: Option<Vec<u8>>,
    pub replayed: BTreeMap<HashAlg, PcrBank>,
    pub baseline: Option<BaselineOutcome>,
}

impl VerifyReport {
    /// Overall attestation verdict: quote authentic, log consistent with the
    /// TPM, and (if a baseline was supplied) system state matches the baseline.
    pub fn attested(&self) -> bool {
        self.nonce_ok
            && self.signature_ok
            && self.log_matches_quote
            && self.baseline.as_ref().is_none_or(BaselineOutcome::matches)
    }
}

pub struct VerifyInputs<'a> {
    pub log: &'a EventLog,
    pub quote: &'a Quote,
    pub ak: &'a AkKey,
    pub nonce: &'a [u8],
    pub signature: &'a [u8],
    pub sig_hash: HashAlg,
    pub baseline: Option<&'a Baseline>,
}

pub fn verify(input: &VerifyInputs) -> VerifyReport {
    let nonce_ok = nonce_matches(input.nonce, &input.quote.extra_data);
    let signature_ok = input
        .ak
        .verify(&input.quote.raw, input.signature, input.sig_hash)
        .is_ok();

    // Replay every bank the log declares, plus any bank the quote selects.
    let mut algs = input.log.algorithms();
    for (alg, _) in &input.quote.pcr_select {
        if !algs.contains(alg) {
            algs.push(*alg);
        }
    }
    let replayed = replay(input.log, &algs);

    let replayed_digest = quote_pcr_digest(&input.quote.pcr_select, &replayed).ok();
    let log_matches_quote = replayed_digest
        .as_ref()
        .is_some_and(|d| nonce_matches(d, &input.quote.pcr_digest));

    let baseline = input.baseline.map(|b| check_baseline(input.log, &replayed, b));

    VerifyReport {
        nonce_ok,
        signature_ok,
        log_matches_quote,
        quote_pcr_digest: input.quote.pcr_digest.clone(),
        replayed_pcr_digest: replayed_digest,
        replayed,
        baseline,
    }
}

fn check_baseline(
    log: &EventLog,
    replayed: &BTreeMap<HashAlg, PcrBank>,
    baseline: &Baseline,
) -> BaselineOutcome {
    // 1. Final PCR values.
    let mut pcr_mismatches = Vec::new();
    for (alg_name, pcrs) in &baseline.pcrs {
        let Some(alg) = HashAlg::from_name(alg_name) else {
            continue; // already validated at load
        };
        for (pcr_str, expected_hex) in pcrs {
            let Ok(pcr) = pcr_str.parse::<u32>() else { continue };
            let Some(expected) = hex::decode(expected_hex).ok() else { continue };
            let actual = replayed
                .get(&alg)
                .and_then(|b| b.get(&pcr))
                .cloned()
                .unwrap_or_else(|| vec![0u8; alg.digest_size()]);
            if actual != expected {
                pcr_mismatches.push(PcrMismatch {
                    alg,
                    pcr,
                    expected,
                    actual,
                });
            }
        }
    }

    // 2. Per-event walk to locate divergence.
    let divergences = find_divergences(log, baseline);

    BaselineOutcome {
        pcr_mismatches,
        divergences,
    }
}

/// Walk baseline events and log events in lockstep per (PCR, bank) and report
/// the first divergence in each.
pub fn find_divergences(log: &EventLog, baseline: &Baseline) -> Vec<Divergence> {
    let mut out = Vec::new();
    if baseline.events.is_empty() {
        return out;
    }

    // PCRs involved on either side.
    let mut pcrs: Vec<u32> = baseline.events.iter().map(|e| e.pcr).collect();
    pcrs.extend(log.extended_events().map(|e| e.pcr));
    pcrs.sort_unstable();
    pcrs.dedup();

    // Log events extended into each PCR, in log order.
    let log_extended: Vec<&crate::eventlog::Event> = log.extended_events().collect();

    for pcr in pcrs {
        let base_events: Vec<&crate::baseline::BaselineEvent> = baseline
            .events
            .iter()
            .filter(|e| e.pcr == pcr)
            .collect();
        let log_events: Vec<&&crate::eventlog::Event> = log_extended
            .iter()
            .filter(|e| e.pcr == pcr)
            .collect();

        // Which banks does the baseline specify for this PCR?
        let mut algs: Vec<HashAlg> = base_events
            .iter()
            .flat_map(|e| e.digests.keys().filter_map(|n| HashAlg::from_name(n)))
            .collect();
        algs.sort();
        algs.dedup();

        for alg in algs {
            let n = base_events.len().max(log_events.len());
            for i in 0..n {
                let base_ev = base_events.get(i);
                let log_ev = log_events.get(i);
                match (base_ev, log_ev) {
                    (Some(b), Some(l)) => {
                        let expected = b
                            .digests
                            .get(alg.name())
                            .and_then(|h| hex::decode(h).ok());
                        let actual = l.digest_for(alg).map(|d| d.to_vec());
                        if let (Some(exp), Some(act)) = (&expected, &actual) {
                            if exp != act {
                                out.push(Divergence {
                                    alg,
                                    pcr,
                                    log_index: Some(l.index),
                                    ordinal_in_pcr: i,
                                    event_type: Some(l.event_type),
                                    expected_digest: expected,
                                    actual_digest: actual,
                                    description: b.description.clone(),
                                    kind: DivergenceKind::DigestMismatch,
                                });
                                break; // first divergence for this (pcr, alg)
                            }
                        }
                    }
                    (Some(b), None) => {
                        out.push(Divergence {
                            alg,
                            pcr,
                            log_index: None,
                            ordinal_in_pcr: i,
                            event_type: None,
                            expected_digest: b
                                .digests
                                .get(alg.name())
                                .and_then(|h| hex::decode(h).ok()),
                            actual_digest: None,
                            description: b.description.clone(),
                            kind: DivergenceKind::MissingEvent,
                        });
                        break;
                    }
                    (None, Some(l)) => {
                        out.push(Divergence {
                            alg,
                            pcr,
                            log_index: Some(l.index),
                            ordinal_in_pcr: i,
                            event_type: Some(l.event_type),
                            expected_digest: None,
                            actual_digest: l.digest_for(alg).map(|d| d.to_vec()),
                            description: None,
                            kind: DivergenceKind::UnexpectedEvent,
                        });
                        break;
                    }
                    (None, None) => unreachable!(),
                }
            }
        }
    }

    out.sort_by_key(|d| (d.pcr, d.alg));
    out
}

/// Human-readable rendering for the CLI.
pub fn render_report(report: &VerifyReport) -> String {
    let mut s = String::new();
    let mark = |ok: bool| if ok { "OK  " } else { "FAIL" };

    writeln!(s, "== Attestation checks ==").unwrap();
    writeln!(s, "[{}] anti-replay nonce (quote extraData)", mark(report.nonce_ok)).unwrap();
    writeln!(s, "[{}] quote signature (AK public key)", mark(report.signature_ok)).unwrap();
    writeln!(
        s,
        "[{}] event log replay == quote PCR digest",
        mark(report.log_matches_quote)
    )
    .unwrap();
    if !report.log_matches_quote {
        if let Some(d) = &report.replayed_pcr_digest {
            writeln!(s, "       quote pcrDigest:    {}", hex::encode(&report.quote_pcr_digest)).unwrap();
            writeln!(s, "       replayed pcrDigest: {}", hex::encode(d)).unwrap();
        }
    }

    if let Some(b) = &report.baseline {
        writeln!(s, "== Baseline comparison ==").unwrap();
        if b.matches() {
            writeln!(s, "[OK  ] system state matches trusted baseline").unwrap();
        } else {
            for m in &b.pcr_mismatches {
                writeln!(
                    s,
                    "[FAIL] PCR {} ({}): expected {}, replayed {}",
                    m.pcr,
                    m.alg,
                    hex::encode(&m.expected),
                    hex::encode(&m.actual)
                )
                .unwrap();
            }
            for d in &b.divergences {
                let idx = d
                    .log_index
                    .map(|i| format!("log event #{i}"))
                    .unwrap_or_else(|| "not present in log".to_string());
                let ty = d
                    .event_type
                    .map(event_type_name)
                    .unwrap_or("EV_UNKNOWN");
                match d.kind {
                    DivergenceKind::DigestMismatch => writeln!(
                        s,
                        "[FAIL] first divergent event in PCR {} ({}): {} ({}), ordinal {} in PCR",
                        d.pcr, d.alg, idx, ty, d.ordinal_in_pcr
                    )
                    .unwrap(),
                    DivergenceKind::UnexpectedEvent => writeln!(
                        s,
                        "[FAIL] unexpected event in PCR {} ({}): {} ({}), ordinal {} — not in baseline",
                        d.pcr, d.alg, idx, ty, d.ordinal_in_pcr
                    )
                    .unwrap(),
                    DivergenceKind::MissingEvent => writeln!(
                        s,
                        "[FAIL] baseline event missing from log in PCR {} ({}), ordinal {}",
                        d.pcr, d.alg, d.ordinal_in_pcr
                    )
                    .unwrap(),
                }
                if let Some(desc) = &d.description {
                    writeln!(s, "       baseline description: {desc}").unwrap();
                }
                if let Some(e) = &d.expected_digest {
                    writeln!(s, "       expected digest: {}", hex::encode(e)).unwrap();
                }
                if let Some(a) = &d.actual_digest {
                    writeln!(s, "       actual digest:   {}", hex::encode(a)).unwrap();
                }
            }
        }
    }

    writeln!(
        s,
        "== Verdict: {} ==",
        if report.attested() { "ATTESTED" } else { "REJECTED" }
    )
    .unwrap();
    s
}
