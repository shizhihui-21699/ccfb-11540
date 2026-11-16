//! Builders for synthetic but spec-conformant TPM material: AK key pairs,
//! `TPMS_ATTEST` payloads, signatures and quote bundles.
//!
//! Everything is deterministic when seeded through `StdRng::from_seed`, so the
//! sample generator produces byte-stable artifacts for the test suite.

use p256::ecdsa::SigningKey as EccSigningKey;
use pkcs8::EncodePublicKey as _;
use rsa::pkcs1v15::{Signature as RsaSig, SigningKey as RsaSigningKey};
use rsa::signature::RandomizedSigner as RsaRandomSigner;
use rsa::signature::SignatureEncoding as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::codec::Writer;
use crate::error::{Error, Result};
use crate::replay::hash;
use crate::tcg::{
    AK_OBJECT_ATTRIBUTES, TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_NULL, TPM_ALG_RSA,
    TPM_ALG_RSASSA, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ECC_NIST_P256,
    TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use crate::tpm::{
    AkPublicKey, Attest, ClockInfo, PcrSelection, QuoteBundle, SignatureScheme,
    QUOTE_BUNDLE_MAGIC,
};

/// An AK with enough private material to sign quotes. The RSA private key is
/// much larger than the P-256 one, so box it to keep both enum variants at a
/// similar size.
#[allow(clippy::large_enum_variant)]
pub enum GeneratedAk {
    Rsa {
        private: Box<RsaPrivateKey>,
        public: AkPublicKey,
        public_area: Vec<u8>,
    },
    Ecc {
        private: EccSigningKey,
        public: AkPublicKey,
        public_area: Vec<u8>,
    },
}

impl GeneratedAk {
    pub fn public(&self) -> &AkPublicKey {
        match self {
            GeneratedAk::Rsa { public, .. } | GeneratedAk::Ecc { public, .. } => public,
        }
    }

    /// Marshalled TPM2B_PUBLIC (u16 length + TPMT_PUBLIC).
    pub fn tpm2b_public(&self) -> Vec<u8> {
        let inner = match self {
            GeneratedAk::Rsa { public_area, .. }
            | GeneratedAk::Ecc { public_area, .. } => public_area,
        };
        let mut w = Writer::new();
        w.blob16(inner);
        w.into_bytes()
    }

    /// PEM SubjectPublicKeyInfo for external tooling.
    pub fn pem(&self) -> Result<String> {
        match self {
            GeneratedAk::Rsa { private, .. } => {
                let pub_key = RsaPublicKey::from(private.as_ref());
                pub_key
                    .to_public_key_pem(pkcs8::LineEnding::LF)
                    .map_err(|e| Error::Tpm {
                        offset: 0,
                        message: format!("PEM encode failed: {e}"),
                    })
            }
            GeneratedAk::Ecc { private, .. } => {
                let pub_key = private.verifying_key();
                pub_key
                    .to_public_key_pem(pkcs8::LineEnding::LF)
                    .map_err(|e| Error::Tpm {
                        offset: 0,
                        message: format!("PEM encode failed: {e}"),
                    })
            }
        }
    }
}

pub fn generate_rsa_ak(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Result<GeneratedAk> {
    let private = RsaPrivateKey::new(rng, 2048).map_err(|e| Error::Tpm {
        offset: 0,
        message: format!("RSA key generation failed: {e}"),
    })?;
    let public_part = RsaPublicKey::from(&private);
    let modulus = public_part.n().to_bytes_be();
    let exponent = crate::tpm::biguint_to_u32(public_part.e())?;

    let ak = AkPublicKey::Rsa {
        name_algorithm: TPM_ALG_SHA256,
        object_attributes: AK_OBJECT_ATTRIBUTES,
        auth_policy: Vec::new(),
        scheme_hash: TPM_ALG_NULL,
        modulus: modulus.clone(),
        exponent,
    };
    let public_area = marshal_rsa_public_area(&ak)?;
    Ok(GeneratedAk::Rsa {
        private: Box::new(private),
        public: ak,
        public_area,
    })
}

pub fn generate_ecc_ak(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Result<GeneratedAk> {
    let private = EccSigningKey::random(rng);
    let point = private.verifying_key().to_encoded_point(false);
    let mut public_point = Vec::with_capacity(64);
    public_point.extend_from_slice(point.x().expect("uncompressed point has x"));
    public_point.extend_from_slice(point.y().expect("uncompressed point has y"));

    let ak = AkPublicKey::Ecc {
        name_algorithm: TPM_ALG_SHA256,
        object_attributes: AK_OBJECT_ATTRIBUTES,
        auth_policy: Vec::new(),
        scheme_hash: TPM_ALG_NULL,
        curve_id: TPM_ECC_NIST_P256,
        public_point,
    };
    let public_area = marshal_ecc_public_area(&ak)?;
    Ok(GeneratedAk::Ecc {
        private,
        public: ak,
        public_area,
    })
}

fn marshal_rsa_public_area(ak: &AkPublicKey) -> Result<Vec<u8>> {
    let AkPublicKey::Rsa {
        name_algorithm,
        object_attributes,
        auth_policy,
        scheme_hash,
        modulus,
        exponent,
    } = ak
    else {
        panic!("marshal_rsa_public_area called on ECC key");
    };
    let mut w = Writer::new();
    w.u16(TPM_ALG_RSA);
    w.u16(*name_algorithm);
    w.u32(*object_attributes);
    w.blob16(auth_policy);
    w.u16(TPM_ALG_RSASSA);
    w.u16(*scheme_hash);
    w.u16((modulus.len() * 8) as u16);
    w.u32(*exponent);
    w.blob16(modulus); // unique = modulus
    Ok(w.into_bytes())
}

fn marshal_ecc_public_area(ak: &AkPublicKey) -> Result<Vec<u8>> {
    let AkPublicKey::Ecc {
        name_algorithm,
        object_attributes,
        auth_policy,
        scheme_hash,
        curve_id,
        public_point,
    } = ak
    else {
        panic!("marshal_ecc_public_area called on RSA key");
    };
    assert_eq!(public_point.len(), 64);
    let mut w = Writer::new();
    w.u16(TPM_ALG_ECC);
    w.u16(*name_algorithm);
    w.u32(*object_attributes);
    w.blob16(auth_policy);
    w.u16(TPM_ALG_ECDSA);
    w.u16(*scheme_hash);
    w.u16(*curve_id);
    w.u16(TPM_ALG_NULL); // kdfScheme
    w.u16(TPM_ALG_NULL); // kdf hashAlg
    w.blob16(&public_point[..32]); // unique.x
    w.blob16(&public_point[32..]); // unique.y
    Ok(w.into_bytes())
}

/// TPM Name: nameAlg || hash(nameAlg, marshalled TPMT_PUBLIC).
fn object_name(ak: &AkPublicKey, public_area: &[u8]) -> Result<Vec<u8>> {
    let name_alg = ak.name_algorithm();
    let mut name = Vec::new();
    name.extend_from_slice(&name_alg.to_be_bytes());
    name.extend_from_slice(&hash(name_alg, public_area)?);
    Ok(name)
}

fn marshal_attest(attest: &Attest) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(TPM_GENERATED_VALUE);
    w.u16(TPM_ST_ATTEST_QUOTE);
    w.blob16(&attest.qualified_signer);
    w.blob16(&attest.extra_data);
    w.u64_be(attest.clock_info.clock);
    w.u32(attest.clock_info.reset_count);
    w.u32(attest.clock_info.restart_count);
    w.u8(if attest.clock_info.safe { 1 } else { 0 });
    w.u64_be(attest.firmware_version);
    w.u32(attest.pcr_selections.len() as u32);
    for s in &attest.pcr_selections {
        s.marshal(&mut w);
    }
    w.blob16(&attest.pcr_digest);
    Ok(w.into_bytes())
}

fn sign_tpm2b(
    ak: &GeneratedAk,
    hash_algorithm: u16,
    tpm2b: &[u8],
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<SignatureScheme> {
    if !matches!(
        hash_algorithm,
        TPM_ALG_SHA256 | TPM_ALG_SHA384
    ) {
        return Err(Error::UnsupportedAlgorithm(hash_algorithm));
    }
    match ak {
        GeneratedAk::Rsa { private, .. } => {
            let signature: RsaSig = match hash_algorithm {
                TPM_ALG_SHA256 => {
                    RsaSigningKey::<sha2::Sha256>::new((**private).clone())
                        .sign_with_rng(rng, tpm2b)
                }
                TPM_ALG_SHA384 => {
                    RsaSigningKey::<sha2::Sha384>::new((**private).clone())
                        .sign_with_rng(rng, tpm2b)
                }
                _ => unreachable!(),
            };
            Ok(SignatureScheme::RsaSsa {
                hash_algorithm,
                sig: signature.to_bytes().to_vec(),
            })
        }
        GeneratedAk::Ecc { private, .. } => {
            let signature = sign_ecdsa_with_hash(private, hash_algorithm, tpm2b, rng)?;
            let (r, s) = signature.split_bytes();
            Ok(SignatureScheme::Ecdsa {
                hash_algorithm,
                r: trim_zeros(&r).to_vec(),
                s: trim_zeros(&s).to_vec(),
            })
        }
    }
}

/// ECDSA over an arbitrary supported hash. The high-level `SigningKey` API is
/// fixed to SHA-256, so signing goes through the randomized prehash hazmat
/// trait, matching a TPM's RNG-driven ECDSA rather than deterministic RFC6979.
fn sign_ecdsa_with_hash(
    key: &EccSigningKey,
    hash_algorithm: u16,
    message: &[u8],
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<p256::ecdsa::Signature> {
    use p256::ecdsa::signature::hazmat::RandomizedPrehashSigner;
    let prehashed = hash(hash_algorithm, message)?;
    key.sign_prehash_with_rng(rng, &prehashed)
        .map_err(|_| Error::Tpm {
            offset: 0,
            message: "ECDSA signing failed".into(),
        })
}

fn trim_zeros(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < b.len() - 1 && b[i] == 0 {
        i += 1;
    }
    &b[i..]
}

fn marshal_signature(sig: &SignatureScheme) -> Vec<u8> {
    let mut w = Writer::new();
    match sig {
        SignatureScheme::RsaSsa {
            hash_algorithm,
            sig,
        } => {
            w.u16(TPM_ALG_RSASSA);
            w.u16(*hash_algorithm);
            w.blob16(sig);
        }
        SignatureScheme::Ecdsa {
            hash_algorithm,
            r,
            s,
        } => {
            w.u16(TPM_ALG_ECDSA);
            w.u16(*hash_algorithm);
            w.blob16(r);
            w.blob16(s);
        }
    }
    w.into_bytes()
}

/// Everything needed to build a quote, minus PCR values (supplied by the caller
/// via `pcr_digest`).
pub struct QuoteRequest<'a, R: rand_core::RngCore + rand_core::CryptoRng> {
    pub ak: &'a GeneratedAk,
    pub rng: &'a mut R,
    pub nonce: &'a [u8],
    pub pcr_selections: Vec<PcrSelection>,
    pub pcr_digest: Vec<u8>,
    pub hash_algorithm: u16,
    pub clock: u64,
    pub firmware_version: u64,
}

/// Produce a fully signed, serializable quote bundle.
pub fn build_quote<R: rand_core::RngCore + rand_core::CryptoRng>(
    req: QuoteRequest<R>,
) -> Result<QuoteBundle> {
    let public_area = match req.ak {
        GeneratedAk::Rsa { public_area, .. }
        | GeneratedAk::Ecc { public_area, .. } => public_area.clone(),
    };
    let qualified_signer = object_name(req.ak.public(), &public_area)?;

    let attest = Attest {
        qualified_signer,
        extra_data: req.nonce.to_vec(),
        clock_info: ClockInfo {
            clock: req.clock,
            reset_count: 1,
            restart_count: 0,
            safe: true,
        },
        firmware_version: req.firmware_version,
        pcr_selections: req.pcr_selections,
        pcr_digest: req.pcr_digest,
    };

    let attest_payload = marshal_attest(&attest)?;
    let mut attest_tpm2b = Vec::with_capacity(2 + attest_payload.len());
    attest_tpm2b.extend_from_slice(&(attest_payload.len() as u16).to_be_bytes());
    attest_tpm2b.extend_from_slice(&attest_payload);

    let signature = sign_tpm2b(req.ak, req.hash_algorithm, &attest_tpm2b, req.rng)?;

    Ok(QuoteBundle {
        attest_raw: attest_payload,
        attest,
        signature,
        ak: req.ak.public().clone(),
    })
}

/// Serialize a quote bundle into the `.quote` container format.
pub fn serialize_bundle(bundle: &QuoteBundle, public_area: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(QUOTE_BUNDLE_MAGIC);
    w.blob16(&bundle.attest_raw);
    w.blob16(&marshal_signature(&bundle.signature));
    // The container stores the TPMT_PUBLIC (without its TPM2B prefix); the
    // parser wraps it back into TPM2B_PUBLIC semantics.
    w.blob16(public_area);
    w.into_bytes()
}

/// Flip one byte of a signature to produce an invalid bundle for tests.
pub fn corrupt_signature(bundle_bytes: &mut [u8]) {
    // Skip magic(4)+attest length prefix(2); corrupt inside the signature blob.
    let attest_len = u16::from_be_bytes([bundle_bytes[4], bundle_bytes[5]]) as usize;
    let sig_len_off = 6 + attest_len;
    let sig_len = u16::from_be_bytes([
        bundle_bytes[sig_len_off],
        bundle_bytes[sig_len_off + 1],
    ]) as usize;
    let sig_data_off = sig_len_off + 2 + 2; // past sigAlg+hashAlg
    let idx = sig_data_off + sig_len.saturating_sub(4);
    bundle_bytes[idx] ^= 0x80;
}
