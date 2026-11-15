//! Generate spec-conformant test fixtures: event logs, TPM quotes, AK keys
//! and a trusted baseline, in a directory.

use std::fs;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(about = "Generate measured-boot attestation test fixtures")]
struct Args {
    /// Output directory (created if missing).
    #[arg(long)]
    out: PathBuf,
    /// Nonce to embed in the quotes (hex). Random 32 bytes if omitted.
    #[arg(long)]
    nonce: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let nonce = match &args.nonce {
        Some(h) => hex::decode(h)?,
        None => {
            use rand::RngCore;
            let mut n = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut n);
            n
        }
    };

    let f = mb_attest::fixture::generate(&nonce);
    fs::create_dir_all(&args.out)?;
    let w = |name: &str, data: &[u8]| -> anyhow::Result<()> {
        fs::write(args.out.join(name), data)?;
        println!("wrote {name}");
        Ok(())
    };

    w("eventlog.bin", &f.log_v1)?;
    w("eventlog-tampered.bin", &f.log_tampered)?;
    w("eventlog-v2.bin", &f.log_v2)?;
    w("quote-rsa.bin", &f.quote_rsa_v1)?;
    w("quote-rsa.bin.sig", &f.sig_rsa_v1)?;
    w("quote-ec.bin", &f.quote_ec_v1)?;
    w("quote-ec.bin.sig", &f.sig_ec_v1)?;
    w("quote-rsa-v2.bin", &f.quote_rsa_v2)?;
    w("quote-rsa-v2.bin.sig", &f.sig_rsa_v2)?;
    w("ak-rsa.pem", f.ak_rsa_pem.as_bytes())?;
    w("ak-ec.pem", f.ak_ec_pem.as_bytes())?;
    w("baseline.json", f.baseline_json.as_bytes())?;
    w("nonce.hex", hex::encode(&f.nonce).as_bytes())?;

    println!("\nScenarios:");
    println!("  good:      eventlog.bin          + quote-rsa.bin / quote-ec.bin  -> ATTESTED");
    println!("  tampered:  eventlog-tampered.bin + quote-rsa.bin                 -> log != quote");
    println!("  changed:   eventlog-v2.bin       + quote-rsa-v2.bin              -> baseline mismatch (PCR 9)");
    Ok(())
}
