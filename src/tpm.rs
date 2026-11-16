//! TPM 2.0 quote handling: parse the attestation structure, signature and AK
//! public key, verify the signature and reconstruct the quoted PCR digest.
//!
//! The on-disk `.quote` bundle used by this tool is a small container:
//!
//! ```text
//! magic "TQ2!" (4 bytes)
//! u16be len  | TPM2B_ATTEST  (attest, marshalled per TPM 2.0 Part 2)
//! u16be len  | TPMT_SIGNATURE
//! u16be len  | TPM2B_PUBLIC  (the AK, so a bundle is self-contained)
//! ```
//!
//! Only the AK schemes a real attestation key uses are accepted:
//! RSASSA (with a declared signing hash) and ECDSA on NIST P-256.

use pkcs8::DecodePublicKey as _;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifier};
use sha2::{Sha256 as RsaSha256, Sha384 as RsaSha384, Sha512 as RsaSha512};
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, RsaPublicKey};
use p256::ecdsa::signature::Verifier as EcdsaVerifierTrait;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifier};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey as P256PublicKey};

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::tcg::{
    digest_size, AK_OBJECT_ATTRIBUTES, TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_NULL,
    TPM_ALG_RSA, TPM_ALG_RSASSA, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
    TPM_ALG_SHA512, TPM_ECC_NIST_P256, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};

/// Magic prefix of a `.quote` bundle file.
pub const QUOTE_BUNDLE_MAGIC: &[u8; 4] = b"TQ2!";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    pub hash_algorithm: u16,
    /// Raw selection bitmap; byte i selects PCRs 8i..8i+8, LSB = PCR 8i.
    pub pcr_select: Vec<u8>,
}

impl PcrSelection {
    pub fn contains(&self, pcr: u32) -> bool {
        let byte = (pcr / 8) as usize;
        let bit = pcr % 8;
        self.pcr_select
            .get(byte)
            .map(|b| (b >> bit) & 1 == 1)
            .unwrap_or(false)
    }

    pub fn selected_pcrs(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for (i, b) in self.pcr_select.iter().enumerate() {
            for bit in 0..8 {
                if (b >> bit) & 1 == 1 {
                    out.push((i * 8 + bit) as u32);
                }
            }
        }
        out
    }

    pub(crate) fn marshal(&self, w: &mut Writer) {
        w.u16(self.hash_algorithm);
        // TPMS_PCR_SELECTION: sizeofSelect is the byte length of pcrSelect.
        w.u8(self.pcr_select.len() as u8);
        w.bytes(&self.pcr_select);
    }
}

/// Parsed `TPMS_ATTEST` (the payload of `TPM2B_ATTEST`).
#[derive(Debug, Clone)]
pub struct Attest {
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock_info: ClockInfo,
    pub firmware_version: u64,
    pub pcr_selections: Vec<PcrSelection>,
    pub pcr_digest: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}

#[derive(Debug, Clone)]
pub enum SignatureScheme {
    RsaSsa { hash_algorithm: u16, sig: Vec<u8> },
    Ecdsa {
        hash_algorithm: u16,
        r: Vec<u8>,
        s: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub enum AkPublicKey {
    Rsa {
        name_algorithm: u16,
        object_attributes: u32,
        auth_policy: Vec<u8>,
        /// RSASSA scheme hash embedded in the key (may be TPM_ALG_NULL).
        scheme_hash: u16,
        modulus: Vec<u8>,
        exponent: u32,
    },
    Ecc {
        name_algorithm: u16,
        object_attributes: u32,
        auth_policy: Vec<u8>,
        scheme_hash: u16,
        curve_id: u16,
        /// Uncompressed point Qx || Qy, 64 bytes for P-256.
        public_point: Vec<u8>,
    },
}

impl AkPublicKey {
    /// Name hash declared on the key object.
    pub fn name_algorithm(&self) -> u16 {
        match self {
            AkPublicKey::Rsa { name_algorithm, .. }
            | AkPublicKey::Ecc { name_algorithm, .. } => *name_algorithm,
        }
    }

    /// Signing-scheme hash; for a TPM key with ALG_NULL the per-signature
    /// `hashAlg` field is authoritative.
    pub fn scheme_hash(&self) -> u16 {
        match self {
            AkPublicKey::Rsa { scheme_hash, .. }
            | AkPublicKey::Ecc { scheme_hash, .. } => *scheme_hash,
        }
    }
}

/// A fully parsed quote bundle.
#[derive(Debug, Clone)]
pub struct QuoteBundle {
    /// Raw `TPM2B_ATTEST` bytes — the exact message that was signed.
    pub attest_raw: Vec<u8>,
    pub attest: Attest,
    pub signature: SignatureScheme,
    pub ak: AkPublicKey,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub fn parse_quote_bundle(bytes: &[u8]) -> Result<QuoteBundle> {
    let mut outer = Reader::new(bytes);
    let magic = outer.read_exact(4, "bundle magic")?;
    if magic != QUOTE_BUNDLE_MAGIC {
        return Err(Error::Tpm {
            offset: 0,
            message: "not a TQ2! quote bundle (bad magic)".into(),
        });
    }
    let attest_raw = outer.blob16("TPM2B_ATTEST")?.to_vec();
    let sig_raw = outer.blob16("TPMT_SIGNATURE")?.to_vec();
    let pub_raw = outer.blob16("TPM2B_PUBLIC")?.to_vec();
    if !outer.is_empty() {
        return Err(Error::Tpm {
            offset: outer.position(),
            message: "trailing bytes after quote bundle".into(),
        });
    }

    let attest = parse_attest(&attest_raw)?;
    let signature = parse_signature(&sig_raw)?;
    let ak = parse_public(&pub_raw)?;
    Ok(QuoteBundle {
        attest_raw,
        attest,
        signature,
        ak,
    })
}

fn parse_attest(raw: &[u8]) -> Result<Attest> {
    let mut r = Reader::new(raw);
    let magic = r.u16()?;
    if magic != TPM_GENERATED_VALUE {
        return Err(Error::BadAttestMagic(magic));
    }
    let st = r.u16()?;
    if st != TPM_ST_ATTEST_QUOTE {
        return Err(Error::NotAQuote(st));
    }
    let qualified_signer = r.blob16("qualifiedSigner")?.to_vec();
    let extra_data = r.blob16("nonce/extraData")?.to_vec();
    let clock = r.u64_be()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    let safe = r.u8()? != 0;
    let firmware_version = r.u64_be()?;

    let count = r.u32()? as usize;
    let mut pcr_selections = Vec::with_capacity(count);
    for _ in 0..count {
        let hash_algorithm = r.u16()?;
        let sizeof_select = r.u8()?;
        let pcr_select = r.read_exact(sizeof_select as usize, "pcrSelect")?.to_vec();
        pcr_selections.push(PcrSelection {
            hash_algorithm,
            pcr_select,
        });
    }
    let pcr_digest = r.blob16("pcrDigest")?.to_vec();
    if !r.is_empty() {
        return Err(Error::Tpm {
            offset: r.position(),
            message: "trailing bytes in TPMS_ATTEST".into(),
        });
    }
    Ok(Attest {
        qualified_signer,
        extra_data,
        clock_info: ClockInfo {
            clock,
            reset_count,
            restart_count,
            safe,
        },
        firmware_version,
        pcr_selections,
        pcr_digest,
    })
}

fn parse_signature(raw: &[u8]) -> Result<SignatureScheme> {
    let mut r = Reader::new(raw);
    let alg = r.u16()?;
    let hash_algorithm = r.u16()?;
    check_hash_alg(hash_algorithm)?;
    match alg {
        TPM_ALG_RSASSA => {
            let sig = r.blob16("RSA signature")?.to_vec();
            if !r.is_empty() {
                return Err(tpm_trailing(r.position()));
            }
            Ok(SignatureScheme::RsaSsa { hash_algorithm, sig })
        }
        TPM_ALG_ECDSA => {
            let r_bytes = r.blob16("ECDSA r")?;
            let s_bytes = r.blob16("ECDSA s")?;
            if !r.is_empty() {
                return Err(tpm_trailing(r.position()));
            }
            if r_bytes.len() > 32 || s_bytes.len() > 32 {
                return Err(Error::Tpm {
                    offset: 0,
                    message: "P-256 signature component exceeds 32 bytes".into(),
                });
            }
            Ok(SignatureScheme::Ecdsa {
                hash_algorithm,
                r: r_bytes.to_vec(),
                s: s_bytes.to_vec(),
            })
        }
        other => Err(Error::Tpm {
            offset: 0,
            message: format!("unsupported signature algorithm {other:#06x}"),
        }),
    }
}

fn parse_public(raw: &[u8]) -> Result<AkPublicKey> {
    let mut r = Reader::new(raw);
    let type_alg = r.u16()?;
    let name_algorithm = r.u16()?;
    check_hash_alg(name_algorithm)?;
    let object_attributes = r.u32()?;
    let auth_policy = r.blob16("authPolicy")?.to_vec();

    if object_attributes & AK_OBJECT_ATTRIBUTES != AK_OBJECT_ATTRIBUTES {
        return Err(Error::Tpm {
            offset: 0,
            message: format!(
                "AK object attributes {object_attributes:#010x} missing restricted/sign/fixed bits"
            ),
        });
    }

    match type_alg {
        TPM_ALG_RSA => {
            let scheme = r.u16()?;
            if scheme != TPM_ALG_RSASSA && scheme != TPM_ALG_NULL {
                return Err(Error::Tpm {
                    offset: 0,
                    message: format!("RSA AK uses unsupported scheme {scheme:#06x}"),
                });
            }
            let scheme_hash = r.u16()?;
            if scheme_hash != TPM_ALG_NULL {
                check_hash_alg(scheme_hash)?;
            }
            let key_bits = r.u16()?;
            if key_bits % 8 != 0 {
                return Err(Error::Tpm {
                    offset: 0,
                    message: "non-byte-aligned RSA keyBits".into(),
                });
            }
            let exponent_raw = r.u32()?;
            let exponent = if exponent_raw == 0 { 65537 } else { exponent_raw };
            let modulus = r.blob16("RSA modulus")?.to_vec();
            if modulus.len() != key_bits as usize / 8 {
                return Err(Error::Tpm {
                    offset: 0,
                    message: format!(
                        "modulus length {} != keyBits/8 {}",
                        modulus.len(),
                        key_bits as usize / 8
                    ),
                });
            }
            if !r.is_empty() {
                return Err(tpm_trailing(r.position()));
            }
            Ok(AkPublicKey::Rsa {
                name_algorithm,
                object_attributes,
                auth_policy,
                scheme_hash,
                modulus,
                exponent,
            })
        }
        TPM_ALG_ECC => {
            let scheme = r.u16()?;
            if scheme != TPM_ALG_ECDSA && scheme != TPM_ALG_NULL {
                return Err(Error::Tpm {
                    offset: 0,
                    message: format!("ECC AK uses unsupported scheme {scheme:#06x}"),
                });
            }
            let scheme_hash = r.u16()?;
            if scheme_hash != TPM_ALG_NULL {
                check_hash_alg(scheme_hash)?;
            }
            let curve_id = r.u16()?;
            if curve_id != TPM_ECC_NIST_P256 {
                return Err(Error::Tpm {
                    offset: 0,
                    message: format!("unsupported ECC curve {curve_id:#06x} (only NIST P-256)"),
                });
            }
            // TPMU_PUBLIC_PARMS: kdfScheme for ECC keys.
            let kdf = r.u16()?;
            if kdf != TPM_ALG_NULL {
                return Err(Error::Tpm {
                    offset: 0,
                    message: format!("unexpected ECC KDF scheme {kdf:#06x}"),
                });
            }
            let kdf_hash = r.u16()?;
            if kdf_hash != TPM_ALG_NULL {
                return Err(Error::Tpm {
                    offset: 0,
                    message: "ECC KDF hashAlg must be TPM_ALG_NULL".into(),
                });
            }
            let qx = r.blob16("ECC Qx")?;
            let qy = r.blob16("ECC Qy")?;
            if qx.len() != 32 || qy.len() != 32 {
                return Err(Error::Tpm {
                    offset: 0,
                    message: "P-256 point coordinates must be 32 bytes each".into(),
                });
            }
            let mut public_point = Vec::with_capacity(64);
            public_point.extend_from_slice(qx);
            public_point.extend_from_slice(qy);
            if !r.is_empty() {
                return Err(tpm_trailing(r.position()));
            }
            Ok(AkPublicKey::Ecc {
                name_algorithm,
                object_attributes,
                auth_policy,
                scheme_hash,
                curve_id,
                public_point,
            })
        }
        other => Err(Error::Tpm {
            offset: 0,
            message: format!("unsupported AK key type {other:#06x}"),
        }),
    }
}

fn check_hash_alg(alg: u16) -> Result<()> {
    match alg {
        TPM_ALG_SHA1 | TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512 => Ok(()),
        other => Err(Error::UnsupportedAlgorithm(other)),
    }
}

/// Convert an RSA exponent into a `u32`; TPM exponents are at most 32 bits.
pub(crate) fn biguint_to_u32(value: &rsa::BigUint) -> Result<u32> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 4 {
        return Err(Error::Tpm {
            offset: 0,
            message: "RSA exponent exceeds 32 bits".into(),
        });
    }
    let mut tmp = [0u8; 4];
    tmp[4 - bytes.len()..].copy_from_slice(&bytes);
    Ok(u32::from_be_bytes(tmp))
}

fn tpm_trailing(offset: usize) -> Error {
    Error::Tpm {
        offset,
        message: "trailing bytes in TPM structure".into(),
    }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

impl QuoteBundle {
    /// Verify the AK signature over the exact `TPM2B_ATTEST` contents.
    /// The signed message is the marshalled TPM2B (u16 length + payload),
    /// matching how a real TPM signs over the entire TPM2B buffer.
    pub fn verify_signature(&self) -> Result<()> {
        // Resolve the effective signing hash: per-signature hashAlg wins,
        // but reject contradictions with a hash fixed on the key object.
        let key_hash = self.ak.scheme_hash();
        let sig_hash = match &self.signature {
            SignatureScheme::RsaSsa { hash_algorithm, .. }
            | SignatureScheme::Ecdsa { hash_algorithm, .. } => *hash_algorithm,
        };
        if key_hash != TPM_ALG_NULL && key_hash != sig_hash {
            return Err(Error::Tpm {
                offset: 0,
                message: format!(
                    "signature hash {sig_hash:#06x} contradicts AK scheme hash {key_hash:#06x}"
                ),
            });
        }

        let mut tpm2b = Vec::with_capacity(2 + self.attest_raw.len());
        tpm2b.extend_from_slice(&(self.attest_raw.len() as u16).to_be_bytes());
        tpm2b.extend_from_slice(&self.attest_raw);

        match (&self.ak, &self.signature) {
            (
                AkPublicKey::Rsa {
                    modulus, exponent, ..
                },
                SignatureScheme::RsaSsa { sig, .. },
            ) => {
                let n = BigUint::from_bytes_be(modulus);
                let e = BigUint::from(*exponent);
                let key = RsaPublicKey::new(n, e).map_err(|err| Error::Tpm {
                    offset: 0,
                    message: format!("invalid RSA public key: {err}"),
                })?;
                let signature = RsaSignature::try_from(sig.as_slice()).map_err(|_| {
                    Error::Tpm {
                        offset: 0,
                        message: "malformed RSA signature".into(),
                    }
                })?;
                match sig_hash {
                    TPM_ALG_SHA256 => RsaVerifier::<RsaSha256>::new(key)
                        .verify(&tpm2b, &signature)
                        .map_err(|_| Error::SignatureVerification),
                    TPM_ALG_SHA384 => RsaVerifier::<RsaSha384>::new(key)
                        .verify(&tpm2b, &signature)
                        .map_err(|_| Error::SignatureVerification),
                    TPM_ALG_SHA512 => RsaVerifier::<RsaSha512>::new(key)
                        .verify(&tpm2b, &signature)
                        .map_err(|_| Error::SignatureVerification),
                    TPM_ALG_SHA1 => Err(Error::Tpm {
                        offset: 0,
                        message: "RSA-SHA1 verification is not enabled".into(),
                    }),
                    other => Err(Error::UnsupportedAlgorithm(other)),
                }
            }
            (
                AkPublicKey::Ecc { public_point, .. },
                SignatureScheme::Ecdsa { r, s, .. },
            ) => {
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(public_point);
                let encoded = EncodedPoint::from_bytes(&point).map_err(|err| Error::Tpm {
                    offset: 0,
                    message: format!("invalid EC point: {err}"),
                })?;
                let option_key = P256PublicKey::from_encoded_point(&encoded);
                if option_key.is_none().into() {
                    return Err(Error::Tpm {
                        offset: 0,
                        message: "EC point is not on the P-256 curve".into(),
                    });
                }
                let verifier = EcdsaVerifier::from(&option_key.unwrap());

                let mut fixed = [0u8; 64];
                if r.len() > 32 || s.len() > 32 {
                    return Err(Error::Tpm {
                        offset: 0,
                        message: "malformed ECDSA signature component".into(),
                    });
                }
                fixed[32 - r.len()..32].copy_from_slice(r);
                fixed[64 - s.len()..64].copy_from_slice(s);
                let signature = EcdsaSignature::from_slice(&fixed).map_err(|err| {
                    Error::Tpm {
                        offset: 0,
                        message: format!("malformed ECDSA signature: {err}"),
                    }
                })?;
                match sig_hash {
                    // Verify over the explicit digest: a TPM quote names its own
                    // hash, so the prehash path handles SHA-256/384/512 uniformly
                    // instead of the verifier's fixed SHA-256 message path.
                    TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512 => {
                        use p256::ecdsa::signature::hazmat::PrehashVerifier;
                        let prehash = crate::replay::hash(sig_hash, &tpm2b)?;
                        verifier
                            .verify_prehash(&prehash, &signature)
                            .map_err(|_| Error::SignatureVerification)
                    }
                    TPM_ALG_SHA1 => Err(Error::Tpm {
                        offset: 0,
                        message: "ECDSA-SHA1 verification is not enabled".into(),
                    }),
                    other => Err(Error::UnsupportedAlgorithm(other)),
                }
            }
            _ => Err(Error::Tpm {
                offset: 0,
                message: "AK type and signature scheme do not match".into(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// PEM / DER AK loading (PKCS#8 SubjectPublicKeyInfo)
// ---------------------------------------------------------------------------

/// Load an AK from either a TPM2B_PUBLIC blob or a PEM/DER public key file.
pub fn load_ak_file(path: &std::path::Path) -> Result<AkPublicKey> {
    let bytes = std::fs::read(path)?;
    if bytes.starts_with(QUOTE_BUNDLE_MAGIC) {
        return Err(Error::Tpm {
            offset: 0,
            message: "expected an AK file, got a quote bundle".into(),
        });
    }
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text.contains("-----BEGIN") {
            return ak_from_pem(text);
        }
    }
    // Raw TPM2B_PUBLIC.
    let mut r = Reader::new(&bytes);
    let inner = r.blob16("TPM2B_PUBLIC")?;
    if !r.is_empty() {
        return Err(Error::Tpm {
            offset: r.position(),
            message: "trailing bytes in AK blob".into(),
        });
    }
    parse_public(inner)
}

fn ak_from_pem(text: &str) -> Result<AkPublicKey> {
    // Try RSA first, then P-256. Attributes unknown for an external key: mark
    // it with the standard AK bit set so downstream checks behave the same.
    if let Ok(rsa_key) = RsaPublicKey::from_public_key_pem(text) {
        let modulus = rsa_key.n().to_bytes_be();
        let exponent = biguint_to_u32(rsa_key.e())?;
        return Ok(AkPublicKey::Rsa {
            name_algorithm: TPM_ALG_SHA256,
            object_attributes: AK_OBJECT_ATTRIBUTES,
            auth_policy: Vec::new(),
            scheme_hash: TPM_ALG_NULL,
            modulus,
            exponent,
        });
    }
    if let Ok(ec_key) = P256PublicKey::from_public_key_pem(text) {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let point = ec_key.to_encoded_point(false);
        let x = point.x().ok_or_else(|| Error::Tpm {
            offset: 0,
            message: "PEM EC key has no x coordinate".into(),
        })?;
        let y = point.y().ok_or_else(|| Error::Tpm {
            offset: 0,
            message: "PEM EC key has no y coordinate".into(),
        })?;
        let mut public_point = Vec::with_capacity(64);
        public_point.extend_from_slice(x);
        public_point.extend_from_slice(y);
        return Ok(AkPublicKey::Ecc {
            name_algorithm: TPM_ALG_SHA256,
            object_attributes: AK_OBJECT_ATTRIBUTES,
            auth_policy: Vec::new(),
            scheme_hash: TPM_ALG_NULL,
            curve_id: TPM_ECC_NIST_P256,
            public_point,
        });
    }
    Err(Error::Tpm {
        offset: 0,
        message: "PEM is neither an RSA nor a P-256 public key".into(),
    })
}

// ---------------------------------------------------------------------------
// PCR composite digest (the value a TPM places in pcrDigest)
// ---------------------------------------------------------------------------

/// (hash algorithm, PCR index) pairs naming one PCR inside a quote.
pub type PcrRef = (u16, u32);
/// A reconstructed composite digest plus the PCRs that went into it.
pub type CompositeDigest = (Vec<u8>, Vec<PcrRef>);

/// Reconstruct the digest over `TPML_PCR_SELECTION` + concatenated PCR values,
/// which the TPM stores in `pcrDigest` (TPM 2.0 Part 2, TPMS_QUOTE_INFO).
pub fn quote_pcr_digest(
    selections: &[PcrSelection],
    lookup: impl Fn(u16, u32) -> Option<Vec<u8>>,
) -> Result<CompositeDigest> {
    if selections.is_empty() {
        return Err(Error::Tpm {
            offset: 0,
            message: "quote contains no PCR selections".into(),
        });
    }
    let hash_algorithm = selections[0].hash_algorithm;
    for s in selections {
        if s.hash_algorithm != hash_algorithm {
            return Err(Error::Tpm {
                offset: 0,
                message: "all quote PCR selections must share one hash algorithm".into(),
            });
        }
        check_hash_alg(s.hash_algorithm)?;
    }

    let mut w = Writer::new();
    w.u32(selections.len() as u32);
    let mut covered = Vec::new();
    let mut pcr_values = Vec::new();
    for s in selections {
        s.marshal(&mut w);
        for pcr in s.selected_pcrs() {
            let value = lookup(s.hash_algorithm, pcr).ok_or(Error::Tpm {
                offset: 0,
                message: format!("replayed bank has no PCR {pcr}"),
            })?;
            pcr_values.extend_from_slice(&value);
            covered.push((s.hash_algorithm, pcr));
        }
    }
    let expected_size = digest_size(hash_algorithm).ok_or(Error::UnsupportedAlgorithm(hash_algorithm))?;
    let mut to_hash = w.into_bytes();
    to_hash.extend_from_slice(&pcr_values);
    let digest = crate::replay::hash(hash_algorithm, &to_hash)?;
    debug_assert_eq!(digest.len(), expected_size);
    Ok((digest, covered))
}
