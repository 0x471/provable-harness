#![no_main]
//! Differential: the guest's RustCrypto signature algorithms (webpki-algs) must
//! accept and reject exactly what rustls-webpki's ring algorithms do, for every
//! algorithm, on arbitrary (public key, message, signature) triples. Accepting
//! something ring rejects would let a forged TLS handshake signature through.
//! Input: [pk_len u16 BE][pk][msg_len u16 BE][msg][sig].
use libfuzzer_sys::fuzz_target;
use ph_webpki_algs as ours;
use rustls_pki_types::SignatureVerificationAlgorithm;
use webpki::ring as theirs;

type Alg = &'static dyn SignatureVerificationAlgorithm;

fn take<'a>(d: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = u16::from_be_bytes([*d.first()?, *d.get(1)?]) as usize;
    let v = d.get(2..2 + n)?;
    *d = &d[2 + n..];
    Some(v)
}

fuzz_target!(|data: &[u8]| {
    let mut d = data;
    let (Some(pk), Some(msg)) = (take(&mut d), take(&mut d)) else { return };
    let sig = d;
    let pairs: [(&str, Alg, Alg); 13] = [
        ("P256_SHA256", ours::ECDSA_P256_SHA256, theirs::ECDSA_P256_SHA256),
        ("P256_SHA384", ours::ECDSA_P256_SHA384, theirs::ECDSA_P256_SHA384),
        ("P384_SHA256", ours::ECDSA_P384_SHA256, theirs::ECDSA_P384_SHA256),
        ("P384_SHA384", ours::ECDSA_P384_SHA384, theirs::ECDSA_P384_SHA384),
        ("PKCS1_SHA256", ours::RSA_PKCS1_2048_8192_SHA256, theirs::RSA_PKCS1_2048_8192_SHA256),
        ("PKCS1_SHA384", ours::RSA_PKCS1_2048_8192_SHA384, theirs::RSA_PKCS1_2048_8192_SHA384),
        ("PKCS1_SHA512", ours::RSA_PKCS1_2048_8192_SHA512, theirs::RSA_PKCS1_2048_8192_SHA512),
        ("PKCS1_SHA256_ABSENT", ours::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS, theirs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS),
        ("PKCS1_SHA384_ABSENT", ours::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS, theirs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS),
        ("PKCS1_SHA512_ABSENT", ours::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS, theirs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS),
        ("PSS_SHA256", ours::RSA_PSS_2048_8192_SHA256_LEGACY_KEY, theirs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        ("PSS_SHA384", ours::RSA_PSS_2048_8192_SHA384_LEGACY_KEY, theirs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        ("PSS_SHA512", ours::RSA_PSS_2048_8192_SHA512_LEGACY_KEY, theirs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
    ];
    for (name, o, t) in pairs {
        let a = o.verify_signature(pk, msg, sig).is_ok();
        let b = t.verify_signature(pk, msg, sig).is_ok();
        assert_eq!(a, b, "{name}: ours={a} ring={b}");
    }
});
