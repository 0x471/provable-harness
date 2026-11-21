//! Pure-Rust (RustCrypto) implementations of the `rustls-webpki` signature
//! verification algorithms, mirroring the `ring`-backed set in
//! `rustls_webpki::ring` (0.103) so certificate validation can run where `ring`
//! cannot be built, e.g. inside the SP1 zkVM.
//!
//! This is trust-critical code (it decides whether a server certificate chain
//! and the TLS handshake signature are valid). It is kept small, mirrors ring's
//! acceptance rules, and is differentially tested against ring in
//! `tests/differential.rs`.
//!
//! Supported (same `AlgorithmIdentifier`s as rustls-webpki's ring set):
//! - ECDSA P-256 / P-384 with SHA-256 / SHA-384, ASN.1 DER signatures,
//!   uncompressed public keys only (as ring);
//! - RSA PKCS#1 v1.5 with SHA-256 / 384 / 512, 2048..=8192-bit moduli, including
//!   the "absent parameters" AlgorithmIdentifier encodings;
//! - RSA-PSS with SHA-256 / 384 / 512 (salt length = digest length, MGF1 with
//!   the same digest), rsaEncryption ("legacy") keys, 2048..=8192 bits.
//!
//! Deliberately NOT supported (fail closed): Ed25519, P-521, the
//! `RSA_PKCS1_3072_8192_SHA384` duplicate entry.

use rustls_pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Clone, Copy, Debug)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

fn prehash(h: Hash, msg: &[u8]) -> Vec<u8> {
    match h {
        Hash::Sha256 => Sha256::digest(msg).to_vec(),
        Hash::Sha384 => Sha384::digest(msg).to_vec(),
        Hash::Sha512 => Sha512::digest(msg).to_vec(),
    }
}

// ---------------------------------------------------------------- ECDSA ----

#[derive(Clone, Copy, Debug)]
enum Curve {
    P256,
    P384,
}

#[derive(Debug)]
struct Ecdsa {
    curve: Curve,
    hash: Hash,
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for Ecdsa {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        let digest = prehash(self.hash, message);
        match self.curve {
            Curve::P256 => {
                // ring accepts only uncompressed points (0x04 || X || Y).
                if public_key.len() != 65 || public_key[0] != 0x04 {
                    return Err(InvalidSignature);
                }
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let sig =
                    p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(&digest, &sig).map_err(|_| InvalidSignature)
            }
            Curve::P384 => {
                if public_key.len() != 97 || public_key[0] != 0x04 {
                    return Err(InvalidSignature);
                }
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let sig =
                    p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(&digest, &sig).map_err(|_| InvalidSignature)
            }
        }
    }
}

pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &Ecdsa {
    curve: Curve::P256,
    hash: Hash::Sha256,
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
};
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &Ecdsa {
    curve: Curve::P256,
    hash: Hash::Sha384,
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
};
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &Ecdsa {
    curve: Curve::P384,
    hash: Hash::Sha256,
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
};
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &Ecdsa {
    curve: Curve::P384,
    hash: Hash::Sha384,
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
};

// ------------------------------------------------------------------ RSA ----

const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 8192;

#[derive(Clone, Copy, Debug)]
enum Padding {
    Pkcs1,
    Pss,
}

#[derive(Debug)]
struct Rsa {
    padding: Padding,
    hash: Hash,
    signature_alg_id: AlgorithmIdentifier,
}

/// Parse a PKCS#1 `RSAPublicKey` with ring's acceptance rules: modulus of
/// 2048..=8192 bits, odd public exponent >= 3 (and the rsa crate's upper bound).
fn rsa_public_key(der: &[u8]) -> Result<rsa::RsaPublicKey, InvalidSignature> {
    use rsa::pkcs1::der::Decode;
    use rsa::traits::PublicKeyParts;
    let parsed = rsa::pkcs1::RsaPublicKey::from_der(der).map_err(|_| InvalidSignature)?;
    let n = rsa::BigUint::from_bytes_be(parsed.modulus.as_bytes());
    let e = rsa::BigUint::from_bytes_be(parsed.public_exponent.as_bytes());
    let bits = n.bits();
    if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
        return Err(InvalidSignature);
    }
    let e_is_odd = parsed.public_exponent.as_bytes().last().is_some_and(|b| b & 1 == 1);
    if e < rsa::BigUint::from(3u8) || !e_is_odd {
        return Err(InvalidSignature);
    }
    let key = rsa::RsaPublicKey::new_with_max_size(n, e, RSA_MAX_BITS)
        .map_err(|_| InvalidSignature)?;
    debug_assert!(key.n().bits() == bits);
    Ok(key)
}

impl SignatureVerificationAlgorithm for Rsa {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use rsa::traits::PublicKeyParts;
        let key = rsa_public_key(public_key)?;
        // The signature must be exactly the modulus length (ring rejects others).
        if signature.len() != key.size() {
            return Err(InvalidSignature);
        }
        let digest = prehash(self.hash, message);
        let res = match (self.padding, self.hash) {
            (Padding::Pkcs1, Hash::Sha256) => key.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest, signature),
            (Padding::Pkcs1, Hash::Sha384) => key.verify(rsa::Pkcs1v15Sign::new::<Sha384>(), &digest, signature),
            (Padding::Pkcs1, Hash::Sha512) => key.verify(rsa::Pkcs1v15Sign::new::<Sha512>(), &digest, signature),
            (Padding::Pss, Hash::Sha256) => key.verify(rsa::Pss::new::<Sha256>(), &digest, signature),
            (Padding::Pss, Hash::Sha384) => key.verify(rsa::Pss::new::<Sha384>(), &digest, signature),
            (Padding::Pss, Hash::Sha512) => key.verify(rsa::Pss::new::<Sha512>(), &digest, signature),
        };
        res.map_err(|_| InvalidSignature)
    }
}

// AlgorithmIdentifier contents without the NULL parameters (some CAs emit these).
const RSA_PKCS1_SHA256_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);
const RSA_PKCS1_SHA384_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
]);
const RSA_PKCS1_SHA512_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
]);

pub static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pkcs1,
    hash: Hash::Sha256,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
};
pub static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pkcs1,
    hash: Hash::Sha384,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
};
pub static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pkcs1,
    hash: Hash::Sha512,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
};
pub static RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pkcs1,
    hash: Hash::Sha256,
    signature_alg_id: RSA_PKCS1_SHA256_ABSENT_PARAMS,
};
pub static RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pkcs1,
    hash: Hash::Sha384,
    signature_alg_id: RSA_PKCS1_SHA384_ABSENT_PARAMS,
};
pub static RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pkcs1,
    hash: Hash::Sha512,
    signature_alg_id: RSA_PKCS1_SHA512_ABSENT_PARAMS,
};
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pss,
    hash: Hash::Sha256,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
};
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pss,
    hash: Hash::Sha384,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
};
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &dyn SignatureVerificationAlgorithm = &Rsa {
    padding: Padding::Pss,
    hash: Hash::Sha512,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
};

/// Drop-in replacement for `rustls_webpki::ALL_VERIFICATION_ALGS` (ring build),
/// minus the unsupported entries listed in the crate docs.
pub static ALL_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];
