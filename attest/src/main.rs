//! mb-attest: measured-boot remote attestation verifier.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use mb_attest::ak::AkKey;
use mb_attest::alg::HashAlg;
use mb_attest::baseline::Baseline;
use mb_attest::verify::{render_report, verify, VerifyInputs};

#[derive(Parser)]
#[command(
    name = "mb-attest",
    about = "Measured-boot attestation: TCG event log replay, TPM quote verification, baseline diff"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dump a parsed event log in human-readable form.
    ShowLog {
        /// Event log file (crypto-agile / "Spec ID Event03" format).
        #[arg(long)]
        log: PathBuf,
    },
    /// Replay the event log and print expected PCR values per bank.
    Replay {
        #[arg(long)]
        log: PathBuf,
        /// Restrict to one hash bank (default: all banks in the log).
        #[arg(long)]
        alg: Option<String>,
    },
    /// Full attestation verification.
    Verify {
        #[arg(long)]
        log: PathBuf,
        /// TPMS_ATTEST quote blob (raw or TPM2B_ATTEST wrapped).
        #[arg(long)]
        quote: PathBuf,
        /// Quote signature (raw RSA signature, or raw r||s / DER for ECDSA).
        #[arg(long)]
        sig: PathBuf,
        /// AK public key, PEM SubjectPublicKeyInfo.
        #[arg(long)]
        ak: PathBuf,
        /// Anti-replay nonce: hex string, or @path to a binary file.
        #[arg(long)]
        nonce: String,
        /// Trusted baseline JSON.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Hash algorithm of the quote signature.
        #[arg(long, default_value = "sha256")]
        sig_hash: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.cmd {
        Cmd::ShowLog { log } => show_log(&log),
        Cmd::Replay { log, alg } => replay_cmd(&log, alg),
        Cmd::Verify {
            log,
            quote,
            sig,
            ak,
            nonce,
            baseline,
            sig_hash,
        } => verify_cmd(&log, &quote, &sig, &ak, &nonce, baseline, &sig_hash),
    }
}

fn show_log(path: &PathBuf) -> anyhow::Result<ExitCode> {
    let buf = fs::read(path)?;
    let log = mb_attest::eventlog::parse(&buf)?;
    let spec = &log.spec_id;
    println!(
        "Spec ID Event03: spec {}.{} errata {}, platformClass {:#x}, uintnSize {}",
        spec.spec_version_major,
        spec.spec_version_minor,
        spec.spec_errata,
        spec.platform_class,
        spec.uintn_size
    );
    let banks: Vec<String> = spec
        .digest_sizes
        .iter()
        .map(|(a, s)| format!("{}({}B)", a, s))
        .collect();
    println!("hash banks: {}", banks.join(", "));
    println!();
    for ev in &log.events {
        println!(
            "#{:03} PCR {:2} {:<38} data[{}]",
            ev.index,
            ev.pcr,
            ev.type_name(),
            ev.data.len()
        );
        for (alg, digest) in &ev.digests {
            println!("      {:<7} {}", alg, hex::encode(digest));
        }
        if !ev.data.is_empty() && ev.index > 0 {
            let preview: String = ev
                .data
                .iter()
                .take(48)
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            println!("      data:   {preview}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn replay_cmd(path: &PathBuf, alg: Option<String>) -> anyhow::Result<ExitCode> {
    let buf = fs::read(path)?;
    let log = mb_attest::eventlog::parse(&buf)?;
    let algs = match &alg {
        Some(name) => vec![HashAlg::from_name(name)
            .ok_or_else(|| anyhow::anyhow!("unknown hash algorithm '{name}'"))?],
        None => log.algorithms(),
    };
    let banks = mb_attest::replay::replay(&log, &algs);
    for (alg, bank) in &banks {
        println!("bank {alg}:");
        for (pcr, value) in bank {
            println!("  PCR {:2}: {}", pcr, hex::encode(value));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn verify_cmd(
    log_path: &PathBuf,
    quote_path: &PathBuf,
    sig_path: &PathBuf,
    ak_path: &PathBuf,
    nonce: &str,
    baseline_path: Option<PathBuf>,
    sig_hash: &str,
) -> anyhow::Result<ExitCode> {
    let log = mb_attest::eventlog::parse(&fs::read(log_path)?)?;
    let quote = mb_attest::quote::parse(&fs::read(quote_path)?)?;
    let sig = fs::read(sig_path)?;
    let ak_pem = fs::read_to_string(ak_path)?;
    let ak = AkKey::from_pem(&ak_pem)?;
    let nonce_bytes = if let Some(p) = nonce.strip_prefix('@') {
        fs::read(p)?
    } else {
        hex::decode(nonce)?
    };
    let sig_hash = HashAlg::from_name(sig_hash)
        .ok_or_else(|| anyhow::anyhow!("unknown sig hash '{sig_hash}'"))?;
    let baseline = match baseline_path {
        Some(p) => Some(Baseline::from_json(&fs::read_to_string(p)?)?),
        None => None,
    };

    eprintln!("AK type: {}", ak.kind());
    let report = verify(&VerifyInputs {
        log: &log,
        quote: &quote,
        ak: &ak,
        nonce: &nonce_bytes,
        signature: &sig,
        sig_hash,
        baseline: baseline.as_ref(),
    });
    print!("{}", render_report(&report));

    Ok(if report.attested() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
