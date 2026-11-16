//! Generate deterministic sample artifacts under `samples/`:
//!
//! ```text
//! samples/
//!   golden.log                 crypto-agile log (sha256 + sha384 + sha1 banks)
//!   golden-tampered.log        same shape, kernel cmdline injection
//!   legacy-sha1.log            TCG 1.2 style single-SHA1 log
//!   baseline.json              trusted baseline derived from the golden log
//!   ak-rsa/                    RSA-2048 AK (TPM2B_PUBLIC + PEM)
//!   ak-ecc/                    NIST P-256 AK (TPM2B_PUBLIC + PEM)
//!   quote-rsa-sha256.quote     valid RSA/SHA-256 quote over the golden log
//!   quote-ecc-sha384.quote     valid ECDSA/SHA-384 quote over the golden log
//!   quote-bad-signature.quote  structurally valid, signature corrupted
//!   quote-wrong-nonce.quote    valid signature, stale nonce
//!   nonce.txt                  the nonce a verifier must supply
//! ```

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use tpm_ra_verify::baseline::Baseline;
use tpm_ra_verify::replay::replay;
use tpm_ra_verify::samples::{
    self, build_quote_for, seeded_rng, VALID_NONCE, WRONG_NONCE,
};
use tpm_ra_verify::tcg::{TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384};
use tpm_ra_verify::tpm_builder::{corrupt_signature, generate_ecc_ak, generate_rsa_ak};

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let root = PathBuf::from("samples");
    fs::create_dir_all(&root)?;
    let rsa_dir = root.join("ak-rsa");
    let ecc_dir = root.join("ak-ecc");
    fs::create_dir_all(&rsa_dir)?;
    fs::create_dir_all(&ecc_dir)?;

    let mut rng = seeded_rng();
    let rsa_ak = generate_rsa_ak(&mut rng)?;
    let ecc_ak = generate_ecc_ak(&mut rng)?;

    // --- Logs ---------------------------------------------------------------
    let algorithms = [TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA1];
    let golden = samples::build_golden_log(&algorithms)?;
    let tampered = samples::build_tampered_log(&algorithms)?;
    let legacy = samples::build_legacy_log()?;
    fs::write(root.join("golden.log"), &golden.bytes)?;
    fs::write(root.join("golden-tampered.log"), &tampered.bytes)?;
    fs::write(root.join("legacy-sha1.log"), &legacy.bytes)?;

    let banks = replay(&golden.parsed)?;

    // --- Baseline -----------------------------------------------------------
    let baseline = Baseline::from_log(
        &golden.parsed,
        &banks,
        "2026-11-17T00:00:00Z",
        "golden synthetic measured-boot chain (PCR0..9)",
    );
    fs::write(root.join("baseline.json"), baseline.to_json_pretty()?)?;

    // --- AK files -----------------------------------------------------------
    fs::write(rsa_dir.join("ak.tpm2b_public"), rsa_ak.tpm2b_public())?;
    fs::write(rsa_dir.join("ak.pem"), rsa_ak.pem()?)?;
    fs::write(ecc_dir.join("ak.tpm2b_public"), ecc_ak.tpm2b_public())?;
    fs::write(ecc_dir.join("ak.pem"), ecc_ak.pem()?)?;

    // --- Quotes -------------------------------------------------------------
    let (rsa_quote, _) =
        build_quote_for(&rsa_ak, &mut rng, &banks, TPM_ALG_SHA256, VALID_NONCE)?;
    fs::write(root.join("quote-rsa-sha256.quote"), &rsa_quote)?;

    let (ecc_quote, _) =
        build_quote_for(&ecc_ak, &mut rng, &banks, TPM_ALG_SHA384, VALID_NONCE)?;
    fs::write(root.join("quote-ecc-sha384.quote"), &ecc_quote)?;

    let mut bad_sig = rsa_quote.clone();
    corrupt_signature(&mut bad_sig);
    fs::write(root.join("quote-bad-signature.quote"), &bad_sig)?;

    let (wrong_nonce_quote, _) =
        build_quote_for(&rsa_ak, &mut rng, &banks, TPM_ALG_SHA256, WRONG_NONCE)?;
    fs::write(root.join("quote-wrong-nonce.quote"), &wrong_nonce_quote)?;

    fs::write(root.join("nonce.txt"), VALID_NONCE)?;

    println!("Generated sample artifacts in {}/", root.display());
    println!("  golden events: {}", golden.parsed.events.len());
    println!("  nonce: {}", String::from_utf8_lossy(VALID_NONCE));
    Ok(())
}
