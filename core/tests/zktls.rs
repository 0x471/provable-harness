//! zkTLS verification against a TLSNotary presentation recorded with this
//! repository's own stack (`ph-zktls dev`): real MPC-TLS (TLS 1.2) to the mock
//! Messages API under a throwaway dev CA (`fixtures/mock-ca.der`), notarized by
//! the ph notary with the demo key `[7; 32]` and slot `model 4242...42 0`. The
//! request carries the fake key `mock-api-key-0000`. Nothing in it is secret or
//! identifying.
//!
//! The tests re-sign the same attestation header under other signature schemes
//! (upstream `secp256k1`, `secp256k1eth`): those are valid TLSNotary
//! presentations, but the harness must accept only the ph notary scheme.

use ph_core::anthropic::{check_request, parse_http_response};
use ph_core::zktls::{
    check_slot, crypto_provider, ph_notary_signed_message, verify_model_exchange, verify_presentation,
    PH_NOTARY_SIG_ALG_ID,
};
use ph_core::{NotaryKey, Slot, TlsRoots, ZkTlsConfig};

const FIXTURE: &[u8] = include_bytes!("fixtures/mock-anthropic.presentation.tlsn");
const MOCK_CA: &[u8] = include_bytes!("fixtures/mock-ca.der");
/// The exact request body that was notarized (built like `anthropic::request_body`).
const BODY: &str = r#"{"model":"claude-haiku-5-5","max_tokens":64,"system":"You are a test agent.","messages":[{"role":"user","content":"Reply with exactly: pong"}],"metadata":{"user_id":"ph-4242424242424242424242424242424242424242424242424242424242424242-0"}}"#;
const NOTARY_SECRET: [u8; 32] = [7; 32];
/// k256 public key of the demo notary (secret = [7; 32]).
const NOTARY: &str = "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";
/// A time at which the captured public chains in webpki-algs/tests/chains are valid.
const NOTARIZED_AT: u64 = 1795191252;

/// Replace the attestation signature. Bincode layout of a Presentation starts
/// with AttestationProof.signature = { alg: u8, data: Vec<u8> }, then the header.
fn resigned(alg: u8, sign: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    assert_eq!(FIXTURE[0], PH_NOTARY_SIG_ALG_ID, "fixture is signed with the ph scheme");
    let sig_len = u64::from_le_bytes(FIXTURE[1..9].try_into().unwrap()) as usize;
    let rest = &FIXTURE[9 + sig_len..];
    let header: tlsn_attestation::Header = bincode::deserialize(rest).unwrap();
    let sig = sign(&bcs::to_bytes(&header).unwrap());
    let mut out = vec![alg];
    out.extend_from_slice(&(sig.len() as u64).to_le_bytes());
    out.extend_from_slice(&sig);
    out.extend_from_slice(rest);
    out
}

fn ph_sign(key: &[u8; 32], header: &[u8]) -> Vec<u8> {
    use k256::ecdsa::signature::Signer as _;
    let sk = k256::ecdsa::SigningKey::from_bytes(key.into()).unwrap();
    let sig: k256::ecdsa::Signature = sk.sign(&ph_notary_signed_message(header));
    sig.to_vec()
}

fn fixture() -> Vec<u8> {
    FIXTURE.to_vec()
}

fn cfg(roots: TlsRoots) -> ZkTlsConfig {
    ZkTlsConfig {
        notary: NotaryKey {
            alg: "k256".into(),
            key: ph_core::hash::from_hex(NOTARY).unwrap(),
        },
        host: "test-server.io".into(),
        roots,
        model: "claude-haiku-5-5".into(),
        max_tokens: 64,
    }
}

fn pinned() -> ZkTlsConfig {
    cfg(TlsRoots::Custom(vec![MOCK_CA.to_vec()]))
}

fn chain_cert(host: &str, i: usize) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../webpki-algs/tests/chains/{host}/{i}.der",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn presentation_verifies_with_its_pinned_root() {
    let c = pinned();
    let x = verify_presentation(&crypto_provider(&c).unwrap(), &c.notary, &c.host, &fixture()).unwrap();
    assert!(x.sent.starts_with(b"POST /v1/messages HTTP/1.1\r\nhost: test-server.io\r\n"));
    let (status, body) = parse_http_response(&x.recv).unwrap();
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("pong"));
}

#[test]
fn unrelated_roots_are_rejected() {
    // The dev CA is not a Mozilla root, and an unrelated real root does not anchor it.
    for roots in [TlsRoots::Mozilla, TlsRoots::Custom(vec![chain_cert("letsencrypt.org", 4)])] {
        let c = cfg(roots);
        let e = verify_presentation(&crypto_provider(&c).unwrap(), &c.notary, &c.host, &fixture()).unwrap_err();
        assert!(e.contains("does not verify"), "{e}");
    }
}

#[test]
fn wrong_notary_or_host_is_rejected() {
    let mut c = pinned();
    c.notary.key[5] ^= 1;
    let e = verify_presentation(&crypto_provider(&c).unwrap(), &c.notary, &c.host, &fixture()).unwrap_err();
    assert!(e.contains("pinned notary"), "{e}");

    let mut c = pinned();
    c.host = "test-server.io.evil.example".into();
    let e = verify_presentation(&crypto_provider(&c).unwrap(), &c.notary, &c.host, &fixture()).unwrap_err();
    assert!(e.contains("different server"), "{e}");
}

#[test]
fn any_byte_flip_is_rejected() {
    let c = pinned();
    let p = crypto_provider(&c).unwrap();
    // Flip bytes across the whole presentation (header, signature, certs, transcript).
    let fx = fixture();
    let orig = verify_presentation(&p, &c.notary, &c.host, &fx).unwrap();
    let mut rejected = 0;
    let step = fx.len() / 97;
    let mut tried = 0;
    for i in (0..fx.len()).step_by(step.max(1)) {
        tried += 1;
        let mut b = fx.clone();
        b[i] ^= 0x01;
        if verify_presentation(&p, &c.notary, &c.host, &b).is_err() {
            rejected += 1;
        } else {
            // A flip may land in bytes that do not affect meaning, but it must
            // never change what is reported as authenticated.
            let x = verify_presentation(&p, &c.notary, &c.host, &b).unwrap();
            assert_eq!((x.time, &x.sent, &x.recv), (orig.time, &orig.sent, &orig.recv), "flip at {i}");
        }
    }
    assert!(rejected * 10 > tried * 8, "only {rejected} of {tried} flips rejected");
}

#[test]
fn model_level_checks_bind_slot_and_request() {
    let c = pinned();
    let p = crypto_provider(&c).unwrap();
    let slot = Slot::model(&[0x42; 32], 0);
    // The genuine exchange passes every model-level check.
    let (reply, _) = verify_model_exchange(&p, &c, &fixture(), BODY, &slot, false).unwrap();
    assert_eq!(reply.text, "pong");
    let x = verify_presentation(&p, &c.notary, &c.host, &fixture()).unwrap();
    check_slot(&x, &slot).unwrap();
    check_request(&x.sent, &c.host, BODY).unwrap();
    // Another (session, step), or a request the harness did not build, is rejected.
    for other in [Slot::model(&[0x42; 32], 1), Slot::model(&[0x43; 32], 0), Slot::tool(&[0x42; 32], 0)] {
        let e = verify_model_exchange(&p, &c, &fixture(), BODY, &other, false).unwrap_err();
        assert!(e.contains("not bound to slot"), "{e}");
    }
    assert!(verify_model_exchange(&p, &c, &fixture(), "{}", &slot, false).is_err());
    // A config pinning another model rejects the reply.
    let mut m = pinned();
    m.model = "claude-other".into();
    assert!(verify_model_exchange(&p, &m, &fixture(), BODY, &slot, false).is_err());
}

#[test]
fn only_the_ph_notary_scheme_is_accepted() {
    use tlsn_attestation::signing::{Secp256k1EthSigner, Secp256k1Signer, Signer};
    use tlsn_core::webpki::{CertificateDer, RootCertStore, ServerCertVerifier};
    let c = pinned();
    let p = crypto_provider(&c).unwrap();
    let ph_core::TlsRoots::Custom(roots) = &c.roots else { panic!("the fixture pins the mock CA") };
    let upstream = tlsn_attestation::CryptoProvider {
        cert: ServerCertVerifier::new(&RootCertStore { roots: roots.iter().map(|r| CertificateDer(r.clone())).collect() })
            .unwrap(),
        ..Default::default()
    };
    // Same key, other schemes. Each is a valid TLSNotary presentation...
    let plain = resigned(1, |h| Secp256k1Signer::new(&NOTARY_SECRET).unwrap().sign(h).unwrap().data);
    let eth = resigned(3, |h| Secp256k1EthSigner::new(&NOTARY_SECRET).unwrap().sign(h).unwrap().data);
    for (name, bytes) in [("secp256k1 (upstream notary)", plain), ("secp256k1eth", eth)] {
        let pres: tlsn_attestation::presentation::Presentation = bincode::deserialize(&bytes).unwrap();
        pres.verify(&upstream).unwrap_or_else(|e| panic!("{name} should verify under upstream rules: {e}"));
        // ...but the harness's provider refuses every scheme but the ph one.
        let e = verify_presentation(&p, &c.notary, &c.host, &bytes).unwrap_err();
        assert!(e.contains("only the ph notary signature scheme"), "{name}: {e}");
    }
    // Re-signing under the ph scheme with the right key reproduces an accepted presentation.
    let again = resigned(PH_NOTARY_SIG_ALG_ID, |h| ph_sign(&NOTARY_SECRET, h));
    verify_presentation(&p, &c.notary, &c.host, &again).unwrap();
    // The ph scheme with another key, or the ph domain dropped, is rejected.
    let other = resigned(PH_NOTARY_SIG_ALG_ID, |h| ph_sign(&[8; 32], h));
    assert!(verify_presentation(&p, &c.notary, &c.host, &other).unwrap_err().contains("does not verify"));
    let undomained = resigned(PH_NOTARY_SIG_ALG_ID, |h| {
        use k256::ecdsa::signature::Signer as _;
        let sk = k256::ecdsa::SigningKey::from_bytes((&NOTARY_SECRET).into()).unwrap();
        let sig: k256::ecdsa::Signature = sk.sign(h);
        sig.to_vec()
    });
    assert!(verify_presentation(&p, &c.notary, &c.host, &undomained).unwrap_err().contains("does not verify"));
}

// ---- verified-chain cache (vendor/tlsn/core/src/webpki.rs) -------------------

mod chain_cache {
    use tlsn_core::connection::ServerName;
    use tlsn_core::webpki::{CertificateDer, ServerCertVerifier};

    fn anthropic_chain() -> (CertificateDer, Vec<CertificateDer>) {
        let c = |i| CertificateDer(super::chain_cert("api.anthropic.com", i));
        (c(1), vec![c(2), c(3)])
    }

    fn name(s: &str) -> ServerName {
        ServerName::Dns(s.try_into().unwrap())
    }

    /// Smallest t in [lo, hi] with `ok(t) == want_at_hi` (ok is a step function there).
    fn boundary(lo: u64, hi: u64, ok: impl Fn(u64) -> bool) -> u64 {
        let (mut a, mut b) = (lo, hi);
        let want = ok(hi);
        assert_ne!(ok(lo), want);
        while b - a > 1 {
            let m = a + (b - a) / 2;
            if ok(m) == want { b = m } else { a = m }
        }
        b
    }

    /// A synthetic chain whose intermediate expires (2026-12-01) before the leaf
    /// does (2027-06-01), and whose leaf starts (2026-06-01) after it: a cache
    /// that kept only the leaf's window would accept the chain after the
    /// intermediate expired. (The real fixture chain cannot show that: its
    /// leaf's window lies inside every other certificate's.)
    #[test]
    fn cache_keeps_every_certificates_window() {
        use tlsn_core::webpki::RootCertStore;
        let der = |n: &str| {
            let p = format!("{}/tests/fixtures/window-{n}.der", env!("CARGO_MANIFEST_DIR"));
            CertificateDer(std::fs::read(p).unwrap())
        };
        let (leaf, inter) = (der("leaf"), vec![der("inter")]);
        let verifier = || ServerCertVerifier::new(&RootCertStore { roots: vec![der("root")] }).unwrap();
        let host = name("test.example");
        const DAY: u64 = 86_400;
        let jan26 = 1_767_225_600;
        let (mar26, jun26, jul26) = (jan26 + 59 * DAY, jan26 + 151 * DAY, jan26 + 181 * DAY);
        let (dec26, jan27) = (jan26 + 334 * DAY, jan26 + 365 * DAY);
        let fresh = verifier();
        let ok = |t| fresh.verify_server_cert_uncached(&leaf, &inter, &host, t).is_ok();
        assert!(ok(jul26));
        assert!(!ok(mar26), "the leaf is not valid yet");
        assert!(!ok(jan27), "the intermediate has expired, the leaf has not");
        let cached = verifier();
        cached.verify_server_cert(&leaf, &inter, &host, jul26).unwrap();
        for t in [0, mar26, jun26 - 1, jun26, jul26, dec26 - 1, dec26, dec26 + 1, jan27, 4_000_000_000] {
            assert_eq!(cached.verify_server_cert(&leaf, &inter, &host, t).is_ok(), ok(t), "t={t}");
        }
    }

    #[test]
    fn cached_and_uncached_decisions_agree() {
        let (leaf, inter) = anthropic_chain();
        let host = name("api.anthropic.com");
        let fresh = ServerCertVerifier::mozilla();
        let ok = |t: u64| fresh.verify_server_cert_uncached(&leaf, &inter, &host, t).is_ok();
        let t0 = super::NOTARIZED_AT;
        assert!(ok(t0), "fixture chain must be valid at the notarized time");
        // The chain's real validity window, found with the uncached verifier.
        let first_valid = boundary(0, t0, ok);
        let last_valid = boundary(t0, u64::MAX / 2, |t| !ok(t)) - 1;
        assert!(first_valid < t0 && t0 < last_valid);

        let probes = [
            0, first_valid - 1, first_valid, first_valid + 1, t0, last_valid - 1, last_valid,
            last_valid + 1, last_valid + 86_400 * 365,
        ];
        // Warm the cache at t0, then every probe must match a fresh, uncached answer.
        let cached = ServerCertVerifier::mozilla();
        cached.verify_server_cert(&leaf, &inter, &host, t0).unwrap();
        for t in probes {
            let a = cached.verify_server_cert(&leaf, &inter, &host, t).is_ok();
            assert_eq!(a, ok(t), "cached vs uncached disagree at t={t}");
        }
        // Warmed caches never widen acceptance for another name or another chain.
        assert!(cached.verify_server_cert(&leaf, &inter, &name("evil.example.com"), t0).is_err());
        let mut tampered = inter.clone();
        let n = tampered[0].0.len();
        tampered[0].0[n - 5] ^= 1; // inside the intermediate's signature
        assert!(cached.verify_server_cert(&leaf, &tampered, &host, t0).is_err());
        assert!(cached.verify_server_cert(&leaf, &inter[..1], &host, t0).is_ok() == ok_with(&leaf, &inter[..1], &host, t0));
        // A rejection is never cached as an acceptance.
        let cold = ServerCertVerifier::mozilla();
        assert!(cold.verify_server_cert(&leaf, &inter, &host, last_valid + 1).is_err());
        assert!(cold.verify_server_cert(&leaf, &inter, &host, last_valid + 1).is_err());
    }

    fn ok_with(leaf: &CertificateDer, inter: &[CertificateDer], host: &ServerName, t: u64) -> bool {
        ServerCertVerifier::mozilla().verify_server_cert_uncached(leaf, inter, host, t).is_ok()
    }
}
