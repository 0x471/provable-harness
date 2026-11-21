//! Differential tests: every decision of the RustCrypto algorithms must equal
//! the decision of rustls-webpki's ring-backed algorithms.

use std::time::Duration;

use ph_webpki_algs as ours;
use rustls_pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};
use webpki::ring as theirs;

type Alg = &'static dyn SignatureVerificationAlgorithm;

fn pairs() -> Vec<(&'static str, Alg, Alg)> {
    vec![
        ("ECDSA_P256_SHA256", ours::ECDSA_P256_SHA256, theirs::ECDSA_P256_SHA256),
        ("ECDSA_P256_SHA384", ours::ECDSA_P256_SHA384, theirs::ECDSA_P256_SHA384),
        ("ECDSA_P384_SHA256", ours::ECDSA_P384_SHA256, theirs::ECDSA_P384_SHA256),
        ("ECDSA_P384_SHA384", ours::ECDSA_P384_SHA384, theirs::ECDSA_P384_SHA384),
        ("RSA_PKCS1_SHA256", ours::RSA_PKCS1_2048_8192_SHA256, theirs::RSA_PKCS1_2048_8192_SHA256),
        ("RSA_PKCS1_SHA384", ours::RSA_PKCS1_2048_8192_SHA384, theirs::RSA_PKCS1_2048_8192_SHA384),
        ("RSA_PKCS1_SHA512", ours::RSA_PKCS1_2048_8192_SHA512, theirs::RSA_PKCS1_2048_8192_SHA512),
        ("RSA_PKCS1_SHA256_ABSENT", ours::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS, theirs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS),
        ("RSA_PKCS1_SHA384_ABSENT", ours::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS, theirs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS),
        ("RSA_PKCS1_SHA512_ABSENT", ours::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS, theirs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS),
        ("RSA_PSS_SHA256", ours::RSA_PSS_2048_8192_SHA256_LEGACY_KEY, theirs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        ("RSA_PSS_SHA384", ours::RSA_PSS_2048_8192_SHA384_LEGACY_KEY, theirs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        ("RSA_PSS_SHA512", ours::RSA_PSS_2048_8192_SHA512_LEGACY_KEY, theirs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
    ]
}

#[test]
fn algorithm_identifiers_match_ring() {
    for (name, o, t) in pairs() {
        assert_eq!(o.public_key_alg_id(), t.public_key_alg_id(), "{name} public key id");
        assert_eq!(o.signature_alg_id(), t.signature_alg_id(), "{name} signature id");
    }
}

/// Run (public_key, message, signature) through every algorithm pair and assert
/// identical accept/reject decisions. Returns how many algorithms accepted.
fn same_decisions(pk: &[u8], msg: &[u8], sig: &[u8]) -> usize {
    let mut accepted = 0;
    for (name, o, t) in pairs() {
        let a = o.verify_signature(pk, msg, sig).is_ok();
        let b = t.verify_signature(pk, msg, sig).is_ok();
        assert_eq!(a, b, "{name}: ours={a} ring={b}");
        accepted += a as usize;
    }
    accepted
}

fn tampered(v: &[u8], i: usize) -> Vec<u8> {
    let mut v = v.to_vec();
    let i = i % v.len();
    v[i] ^= 0x01;
    v
}

#[test]
fn ecdsa_random_vectors() {
    use ecdsa_sig::*;
    let mut rng = rand::thread_rng();
    for i in 0..40usize {
        let msg: Vec<u8> = (0..(i * 7 % 200) + 1).map(|j| (j * 31 + i) as u8).collect();
        for (pk, sigs) in [p256_case(&mut rng, &msg), p384_case(&mut rng, &msg)] {
            for sig in &sigs {
                assert_eq!(same_decisions(&pk, &msg, sig), 1, "exactly one alg accepts");
                same_decisions(&pk, &tampered(&msg, i), sig);
                same_decisions(&pk, &msg, &tampered(sig, i * 3 + 8));
                same_decisions(&tampered(&pk, i + 1), &msg, sig);
            }
        }
    }
}

mod ecdsa_sig {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256, Sha384};

    /// Returns the uncompressed public key and DER signatures for SHA-256 and SHA-384.
    pub fn p256_case(rng: &mut (impl rand::RngCore + rand::CryptoRng), msg: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let sk = p256::ecdsa::SigningKey::random(rng);
        let pk = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let s1: p256::ecdsa::Signature = sk.sign_prehash(&Sha256::digest(msg)).unwrap();
        let s2: p256::ecdsa::Signature = sk.sign_prehash(&Sha384::digest(msg)).unwrap();
        (pk, vec![s1.to_der().as_bytes().to_vec(), s2.to_der().as_bytes().to_vec()])
    }

    pub fn p384_case(rng: &mut (impl rand::RngCore + rand::CryptoRng), msg: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let sk = p384::ecdsa::SigningKey::random(rng);
        let pk = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let s1: p384::ecdsa::Signature = sk.sign_prehash(&Sha256::digest(msg)).unwrap();
        let s2: p384::ecdsa::Signature = sk.sign_prehash(&Sha384::digest(msg)).unwrap();
        (pk, vec![s1.to_der().as_bytes().to_vec(), s2.to_der().as_bytes().to_vec()])
    }
}

#[test]
fn ecdsa_encoding_edge_cases() {
    let mut rng = rand::thread_rng();
    let msg = b"edge cases";
    let (pk, sigs) = ecdsa_sig::p256_case(&mut rng, msg);
    // Compressed public key: ring rejects, so must we.
    let compressed = {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        p256::PublicKey::from_sec1_bytes(&pk).unwrap().to_encoded_point(true).as_bytes().to_vec()
    };
    assert_eq!(same_decisions(&compressed, msg, &sigs[0]), 0);
    // High-S form of a valid signature: whatever ring decides, we decide the same.
    let sig = p256::ecdsa::Signature::from_der(&sigs[0]).unwrap();
    let (r, s) = sig.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r, -*s).unwrap();
    same_decisions(&pk, msg, high.to_der().as_bytes());
    // Raw (r||s) instead of DER, empty, and trailing garbage.
    same_decisions(&pk, msg, &sig.to_bytes());
    same_decisions(&pk, msg, &[]);
    let mut trailing = sigs[0].clone();
    trailing.push(0);
    same_decisions(&pk, msg, &trailing);
}

mod rsa_sig {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::{Pkcs1v15Sign, Pss, RsaPrivateKey};
    use sha2::{Digest, Sha256, Sha384, Sha512};

    pub fn key(bits: usize) -> (RsaPrivateKey, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let sk = RsaPrivateKey::new(&mut rng, bits).unwrap();
        let pk = sk.to_public_key().to_pkcs1_der().unwrap().as_bytes().to_vec();
        (sk, pk)
    }

    pub fn signatures(sk: &RsaPrivateKey, msg: &[u8]) -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        vec![
            sk.sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(msg)).unwrap(),
            sk.sign(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(msg)).unwrap(),
            sk.sign(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(msg)).unwrap(),
            sk.sign_with_rng(&mut rng, Pss::new::<Sha256>(), &Sha256::digest(msg)).unwrap(),
            sk.sign_with_rng(&mut rng, Pss::new::<Sha384>(), &Sha384::digest(msg)).unwrap(),
            sk.sign_with_rng(&mut rng, Pss::new::<Sha512>(), &Sha512::digest(msg)).unwrap(),
        ]
    }

    pub fn pss_wrong_salt(sk: &RsaPrivateKey, msg: &[u8]) -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        vec![
            sk.sign_with_rng(&mut rng, Pss::new_with_salt::<Sha256>(0), &Sha256::digest(msg)).unwrap(),
            sk.sign_with_rng(&mut rng, Pss::new_with_salt::<Sha256>(20), &Sha256::digest(msg)).unwrap(),
        ]
    }
}

#[test]
fn rsa_random_vectors() {
    let (sk, pk) = rsa_sig::key(2048);
    for i in 0..6usize {
        let msg: Vec<u8> = (0..(i * 37 + 1)).map(|j| (j ^ i) as u8).collect();
        let sigs = rsa_sig::signatures(&sk, &msg);
        for (k, sig) in sigs.iter().enumerate() {
            // PKCS#1 sigs are accepted by the plain and ABSENT_PARAMS variants (2 algs),
            // PSS sigs by exactly one.
            let expect = if k < 3 { 2 } else { 1 };
            assert_eq!(same_decisions(&pk, &msg, sig), expect, "sig #{k}");
            same_decisions(&pk, &tampered(&msg, i), sig);
            same_decisions(&pk, &msg, &tampered(sig, i * 13 + 5));
        }
        for sig in rsa_sig::pss_wrong_salt(&sk, &msg) {
            same_decisions(&pk, &msg, &sig);
        }
        // Signature length != modulus length.
        let mut short = sigs[0].clone();
        short.remove(0);
        same_decisions(&pk, &msg, &short);
    }
}

#[test]
fn rsa_key_size_bounds() {
    use rsa::{Pkcs1v15Sign, Pss};
    use sha2::{Digest, Sha256};
    let (sk, pk) = rsa_sig::key(1024);
    let msg = b"short key";
    let d = Sha256::digest(msg);
    let sigs = [
        sk.sign(Pkcs1v15Sign::new::<Sha256>(), &d).unwrap(),
        sk.sign_with_rng(&mut rand::thread_rng(), Pss::new::<Sha256>(), &d).unwrap(),
    ];
    for sig in &sigs {
        assert_eq!(same_decisions(&pk, msg, sig), 0, "1024-bit keys are rejected");
    }
    let (sk, pk) = rsa_sig::key(3072);
    for sig in rsa_sig::signatures(&sk, msg).iter().take(1) {
        assert_eq!(same_decisions(&pk, msg, sig), 2);
    }
}

// ---- real certificate chains -------------------------------------------------

fn chains() -> Vec<(String, Vec<Vec<u8>>)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/chains");
    let mut out = vec![];
    let mut hosts: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    hosts.sort();
    for h in hosts {
        let mut certs = vec![];
        for i in 1.. {
            match std::fs::read(root.join(&h).join(format!("{i}.der"))) {
                Ok(c) => certs.push(c),
                Err(_) => break,
            }
        }
        out.push((h, certs));
    }
    out
}

fn captured_at() -> UnixTime {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/chains/CAPTURED_AT");
    let secs: u64 = std::fs::read_to_string(root).unwrap().trim().parse().unwrap();
    UnixTime::since_unix_epoch(Duration::from_secs(secs))
}

fn verify_chain(certs: &[Vec<u8>], host: &str, algs: &[Alg]) -> Result<(), String> {
    let leaf = CertificateDer::from(certs[0].as_slice());
    let ee = webpki::EndEntityCert::try_from(&leaf).map_err(|e| e.to_string())?;
    let inter: Vec<_> = certs[1..].iter().map(|c| CertificateDer::from(c.as_slice())).collect();
    ee.verify_for_usage(
        algs,
        webpki_roots::TLS_SERVER_ROOTS,
        &inter,
        captured_at(),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|e| e.to_string())?;
    let name = ServerName::try_from(host).unwrap();
    ee.verify_is_valid_for_subject_name(&name).map_err(|e| e.to_string())
}

#[test]
fn real_chains_same_decisions() {
    let all = chains();
    assert!(all.len() >= 8, "expected captured chains");
    for (host, certs) in &all {
        let ring_res = verify_chain(certs, host, webpki::ALL_VERIFICATION_ALGS);
        let our_res = verify_chain(certs, host, ours::ALL_VERIFICATION_ALGS);
        assert!(ring_res.is_ok(), "{host}: ring rejects the captured chain: {ring_res:?}");
        assert_eq!(our_res, ring_res, "{host}");

        // Tamper with the last bytes (signature value) of each certificate.
        for k in 0..certs.len() {
            let mut bad = certs.clone();
            let n = bad[k].len();
            bad[k][n - 3] ^= 0x01;
            let r = verify_chain(&bad, host, webpki::ALL_VERIFICATION_ALGS).is_ok();
            let o = verify_chain(&bad, host, ours::ALL_VERIFICATION_ALGS).is_ok();
            assert_eq!(o, r, "{host}: tampered cert #{k}");
        }
        // Wrong host name.
        let r = verify_chain(certs, "evil.example", webpki::ALL_VERIFICATION_ALGS).is_ok();
        let o = verify_chain(certs, "evil.example", ours::ALL_VERIFICATION_ALGS).is_ok();
        assert!(!r && !o);
    }
}
