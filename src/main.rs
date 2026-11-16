//! `tpm-ra-verify` command line.
//!
//! Subcommands:
//!   parse     <log>                                  decode and print events
//!   replay    <log>                                  replay PCRs and print banks
//!   baseline  <log> --out <file> [--desc ...]        emit a trusted baseline
//!   verify    <log> <quote> --nonce <hex|@file|text> [--ak <file>]
//!                      [--baseline <file>] [--nonce-cache <file>] [--json]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tpm_ra_verify::baseline::Baseline;
use tpm_ra_verify::error::Error;
use tpm_ra_verify::eventlog::EventLog;
use tpm_ra_verify::replay::replay;
use tpm_ra_verify::tcg::algorithm_name;
use tpm_ra_verify::verify::{self, VerifyInputs};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, Error> {
    let (cmd, rest) = match args.split_first() {
        Some((_, rest)) if !rest.is_empty() => (&rest[0], &rest[1..]),
        _ => {
            print_usage();
            return Ok(ExitCode::from(2));
        }
    };
    match cmd.as_str() {
        "parse" => cmd_parse(rest),
        "replay" => cmd_replay(rest),
        "baseline" => cmd_baseline(rest),
        "verify" => cmd_verify(rest),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            print_usage();
            Ok(ExitCode::from(2))
        }
    }
}

fn print_usage() {
    eprintln!(
        "tpm-ra-verify — TCG measured-boot event log / TPM quote verifier\n\
         \n\
         USAGE:\n  \
         tpm-ra-verify parse <log>\n  \
         tpm-ra-verify replay <log>\n  \
         tpm-ra-verify baseline <log> --out <file> [--desc TEXT]\n  \
         tpm-ra-verify verify <log> <quote> --nonce <hex|@path|text>\n    \
         [--ak <file>] [--baseline <file>] [--nonce-cache <file>] [--json]\n"
    );
}

// ---------------------------------------------------------------------------
// parse
// ---------------------------------------------------------------------------

fn cmd_parse(args: &[String]) -> Result<ExitCode, Error> {
    let log_path = required_positional(args, 0, "parse <log>")?;
    let bytes = std::fs::read(log_path)?;
    let log = EventLog::parse(&bytes)?;

    println!(
        "log format : {}\nevents     : {}\nalgorithms : {}",
        if log.legacy { "legacy SHA-1" } else { "crypto-agile" },
        log.events.len(),
        log.algorithms
            .iter()
            .map(|a| format!(
                "{}({}B)",
                algorithm_name(a.algorithm),
                a.digest_size
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for (i, ev) in log.events.iter().enumerate() {
        println!("\n[{i:3}] offset={:#06x} PCR{:2} {:30} {}",
            ev.offset, ev.pcr_index, ev.event_type_name(),
            if ev.extends_pcr { "EXTEND" } else { "no-action" });
        for d in &ev.digests {
            println!(
                "        {:7} {}",
                algorithm_name(d.algorithm),
                hex::encode(&d.digest)
            );
        }
        let preview: String = ev
            .event_data
            .iter()
            .take(48)
            .map(|b| if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            })
            .collect();
        println!(
            "        data[{}]: {preview}{}",
            ev.event_data.len(),
            if ev.event_data.len() > 48 { "…" } else { "" }
        );
        if let Some(spec) = &ev.spec_id {
            println!(
                "        SpecID: class={:#x} ver {}.{} errata {} algs={}",
                spec.platform_class,
                spec.spec_version_major,
                spec.spec_version_minor,
                spec.spec_errata,
                spec.algorithms.len()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

fn cmd_replay(args: &[String]) -> Result<ExitCode, Error> {
    let log_path = required_positional(args, 0, "replay <log>")?;
    let log = EventLog::parse(&std::fs::read(log_path)?)?;
    let banks = replay(&log)?;

    for alg in banks.algorithms() {
        let bank = banks.bank(alg).expect("present");
        println!("bank {}", algorithm_name(alg));
        for pcr in 0..=23u32 {
            let value = bank.get(pcr);
            // Collapse never-extended PCRs visually but always print the value.
            let touched = value.iter().any(|b| *b != 0);
            println!(
                "  PCR{pcr:2}: {} {}",
                hex::encode(value),
                if touched { "" } else { "(reset)" }
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// baseline
// ---------------------------------------------------------------------------

fn cmd_baseline(args: &[String]) -> Result<ExitCode, Error> {
    let log_path = required_positional(args, 0, "baseline <log>")?;
    let out = flag_value(args, "--out")?.ok_or_else(|| Error::Baseline(
        "--out <file> is required".into(),
    ))?;
    let desc = flag_value(args, "--desc")?.unwrap_or_else(|| "trusted baseline".into());

    let log = EventLog::parse(&std::fs::read(log_path)?)?;
    let banks = replay(&log)?;
    let created_at = now_utc();
    let baseline = Baseline::from_log(&log, &banks, &created_at, &desc);
    std::fs::write(&out, baseline.to_json_pretty()?)?;
    println!(
        "wrote baseline with {} events and {} banks to {}",
        baseline.events.len(),
        baseline.pcr_banks.len(),
        Path::new(&out).display()
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

struct VerifyFlags {
    log: PathBuf,
    quote: PathBuf,
    nonce: Vec<u8>,
    ak: Option<PathBuf>,
    baseline: Option<PathBuf>,
    nonce_cache: Option<PathBuf>,
    json: bool,
}

fn cmd_verify(args: &[String]) -> Result<ExitCode, Error> {
    let log = PathBuf::from(required_positional(args, 0, "verify <log> <quote>")?);
    let quote = PathBuf::from(required_positional(args, 1, "verify <log> <quote>")?);
    let nonce_text = flag_value(args, "--nonce")?
        .ok_or_else(|| Error::Baseline("--nonce is required".into()))?;
    let nonce = parse_nonce(&nonce_text)?;

    let flags = VerifyFlags {
        log,
        quote,
        nonce,
        ak: flag_value(args, "--ak")?.map(PathBuf::from),
        baseline: flag_value(args, "--baseline")?.map(PathBuf::from),
        nonce_cache: flag_value(args, "--nonce-cache")?.map(PathBuf::from),
        json: args.iter().any(|a| a == "--json"),
    };

    let report = verify::verify(VerifyInputs {
        log_path: &flags.log,
        quote_path: &flags.quote,
        ak_path: flags.ak.as_deref(),
        expected_nonce: &flags.nonce,
        baseline_path: flags.baseline.as_deref(),
        nonce_cache_path: flags.nonce_cache.as_deref(),
    })?;

    if flags.json {
        print_verify_json(&report)?;
    } else {
        print_verify_text(&report);
    }

    if report.ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn print_verify_text(report: &tpm_ra_verify::verify::VerifyReport) {
    println!("== TCG measured boot verification ==");
    println!(
        "events parsed        : {} ({} extend PCRs)",
        report.log_events, report.extending_events
    );
    println!(
        "algorithms           : {}",
        report
            .algorithms
            .iter()
            .map(|a| algorithm_name(*a))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "quote selections     : {}",
        report
            .quote_selections
            .iter()
            .map(|(alg, pcrs)| {
                format!(
                    "{}: PCR{}",
                    algorithm_name(*alg),
                    pcrs.iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    );
    println!("nonce                : {}", report.nonce_hex);
    println!("nonce fresh          : {}", yes(report.nonce_fresh));
    println!("AK signature valid   : {}", yes(report.signature_valid));
    println!("PCR composite match  : {}", yes(report.pcr_match));
    if !report.pcr_mismatches.is_empty() {
        println!("  replayed PCR values covered by the failing composite:");
        for m in &report.pcr_mismatches {
            println!(
                "    {} PCR{:2} = {}",
                algorithm_name(m.algorithm),
                m.pcr,
                m.replay_value
            );
        }
    }
    if !report.uncovered_extended_pcrs.is_empty() {
        println!(
            "warning             : {} extended PCRs are not covered by the quote",
            report.uncovered_extended_pcrs.len()
        );
    }

    if let Some(baseline) = &report.baseline {
        println!("\n== Baseline comparison ==");
        if baseline.ok() {
            println!("log and final PCRs match the trusted baseline");
        } else {
            for d in &baseline.differences {
                println!("DIVERGENCE: {}", d.explain());
            }
            for p in &baseline.pcr_differences {
                println!(
                    "PCR DIVERGENCE: {} PCR{} observed {} baseline {}",
                    p.algorithm, p.pcr, p.observed, p.expected
                );
            }
        }
    }

    println!("\nRESULT: {}", if report.ok { "PASS" } else { "FAIL" });
}

fn print_verify_json(report: &tpm_ra_verify::verify::VerifyReport) -> Result<(), Error> {
    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        ok: bool,
        log_events: usize,
        extending_events: usize,
        algorithms: Vec<String>,
        signature_valid: bool,
        nonce_fresh: bool,
        nonce_hex: &'a str,
        pcr_match: bool,
        pcr_mismatches: Vec<JsonPcr<'a>>,
        uncovered_extended_pcrs: Vec<(String, u32)>,
        baseline_differences: Vec<String>,
        baseline_pcr_differences: Vec<String>,
    }
    #[derive(serde::Serialize)]
    struct JsonPcr<'a> {
        algorithm: String,
        pcr: u32,
        replay_value: &'a str,
    }

    let (bd, bp): (Vec<_>, Vec<_>) = match &report.baseline {
        Some(b) => (
            b.differences.iter().map(|d| d.explain()).collect(),
            b.pcr_differences
                .iter()
                .map(|p| {
                    format!(
                        "{} PCR{} observed {} baseline {}",
                        p.algorithm, p.pcr, p.observed, p.expected
                    )
                })
                .collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };

    let out = JsonOut {
        ok: report.ok,
        log_events: report.log_events,
        extending_events: report.extending_events,
        algorithms: report
            .algorithms
            .iter()
            .map(|a| algorithm_name(*a))
            .collect(),
        signature_valid: report.signature_valid,
        nonce_fresh: report.nonce_fresh,
        nonce_hex: &report.nonce_hex,
        pcr_match: report.pcr_match,
        pcr_mismatches: report
            .pcr_mismatches
            .iter()
            .map(|m| JsonPcr {
                algorithm: algorithm_name(m.algorithm),
                pcr: m.pcr,
                replay_value: &m.replay_value,
            })
            .collect(),
        uncovered_extended_pcrs: report
            .uncovered_extended_pcrs
            .iter()
            .map(|(alg, pcr)| (algorithm_name(*alg), *pcr))
            .collect(),
        baseline_differences: bd,
        baseline_pcr_differences: bp,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Small CLI helpers
// ---------------------------------------------------------------------------

fn required_positional(args: &[String], idx: usize, usage: &str) -> Result<String, Error> {
    args.iter()
        .filter(|a| !a.starts_with("--"))
        .nth(idx)
        .cloned()
        .ok_or_else(|| Error::Baseline(format!("missing argument; usage: {usage}")))
}

fn flag_value(args: &[String], flag: &str) -> Result<Option<String>, Error> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == flag {
            return Ok(Some(iter.next().cloned().ok_or_else(|| {
                Error::Baseline(format!("{flag} requires a value"))
            })?));
        }
    }
    Ok(None)
}

/// Nonce input forms:
///   `@path`        -> raw bytes read from file (e.g. samples/nonce.txt)
///   `0x....` / hex -> decoded hex
///   anything else  -> used verbatim as ASCII bytes
fn parse_nonce(text: &str) -> Result<Vec<u8>, Error> {
    if let Some(path) = text.strip_prefix('@') {
        return Ok(std::fs::read(path)?);
    }
    if let Some(hex_part) = text.strip_prefix("0x") {
        return hex::decode(hex_part)
            .map_err(|e| Error::Baseline(format!("bad hex nonce: {e}")));
    }
    if is_likely_hex(text) {
        if let Ok(bytes) = hex::decode(text) {
            return Ok(bytes);
        }
    }
    Ok(text.as_bytes().to_vec())
}

fn is_likely_hex(text: &str) -> bool {
    text.len().is_multiple_of(2)
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        && text.len() >= 16
}

fn yes(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "NO"
    }
}

/// UTC timestamp without pulling in a chrono dependency.
fn now_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_utc(secs)
}

fn format_unix_utc(secs: u64) -> String {
    // Civil-time conversion (Howard Hinnant's algorithm), valid for dates
    // after 1970-01-01.
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}
