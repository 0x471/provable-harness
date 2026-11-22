//! Seed beacon and pre-registration: an eval seed nobody can choose.
//!
//! Without an interactive verifier, the operator could run many seeds and
//! publish the best (seed shopping). Instead:
//!
//! 1. The operator publishes a pre-registration (`ph eval prereg`): the suite
//!    hash, pinned model and notary (`model_auth_hash`), the harness program vk,
//!    and a *future* drand quicknet round R.
//! 2. When round R is out, `ph eval seed --prereg` fetches it, checks its BLS
//!    signature against the pinned quicknet key, and derives
//!    `seed = H(BEACON_SEED, H(prereg), R, randomness_R)`.
//! 3. `ph eval verify --prereg --beacon` re-checks the signature, re-derives the
//!    seed, checks the pre-registration against the proof, and checks that
//!    every notarized TLS time is after round R was published (the runs
//!    happened after the seed existed).
//!
//! The pinned notary time-stamps the pre-registration (`PH-PREREG`): it journals
//! it and signs a receipt, which `ph eval verify` requires to predate round R.
//! The notary's session log lists every pre-registration it saw, so with
//! `--notary-log` a verifier also sees whether the operator pre-registered the
//! same suite more than once and kept the round it liked (seed shopping).

use anyhow::{anyhow, bail, Context, Result};
use drand_verify::{derive_randomness, G2PubkeyRfc, Pubkey};
use ph_core::hash::{domain, from_hex, to_hex, Digest, Hasher};
use serde::{Deserialize, Serialize};

/// drand quicknet (League of Entropy), scheme bls-unchained-g1-rfc9380.
pub const QUICKNET_CHAIN: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
pub const QUICKNET_PUBKEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
pub const QUICKNET_GENESIS: u64 = 1692803367;
pub const QUICKNET_PERIOD: u64 = 3;

pub fn round_time(round: u64) -> u64 {
    QUICKNET_GENESIS + (round.max(1) - 1) * QUICKNET_PERIOD
}

pub fn round_at(t: u64) -> u64 {
    t.saturating_sub(QUICKNET_GENESIS) / QUICKNET_PERIOD + 1
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Prereg {
    pub suite_name: String,
    pub suite_hash: String,
    pub model_id: String,
    /// `ModelAuth::hash()`: pins the model, the API host, the notary key and roots.
    pub model_auth_hash: String,
    /// Harness program vk the proof will be for.
    pub program_vk: String,
    pub beacon_chain: String,
    pub beacon_round: u64,
    /// Earliest time the beacon round can exist (unix seconds).
    pub beacon_time: u64,
    /// The notary's time-stamp; not part of `hash()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<PreregReceipt>,
}

/// A notary-signed time-stamp of a pre-registration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreregReceipt {
    /// Notary clock (unix seconds).
    pub time: u64,
    /// k256 ECDSA signature (hex) over `ph_core::notary_log::prereg_receipt_digest`.
    pub signature: String,
}

impl PreregReceipt {
    /// Check the receipt for `p` against the pinned notary key.
    pub fn verify(&self, p: &Prereg, notary: &ph_core::NotaryKey) -> Result<()> {
        let suite = ph_core::hash::from_hex32(&p.suite_hash).ok_or_else(|| anyhow!("bad suite hash"))?;
        let sig = from_hex(&self.signature).ok_or_else(|| anyhow!("receipt signature is not hex"))?;
        ph_core::notary_log::verify_prereg_receipt(notary, &suite, &p.hash(), self.time, &sig).map_err(|e| anyhow!(e))
    }
}

/// Ask the notary at `addr` to time-stamp a pre-registration.
pub fn notarize_prereg(addr: &str, token: Option<&str>, p: &Prereg) -> Result<PreregReceipt> {
    use std::io::{BufRead, Write};
    let mut s = std::net::TcpStream::connect(addr).with_context(|| format!("connecting to the notary at {addr}"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut msg = String::new();
    if let Some(t) = token {
        msg.push_str(&format!("PH-AUTH {t}\n"));
    }
    msg.push_str(&format!("PH-PREREG {} {}\n", p.suite_hash, to_hex(&p.hash())));
    s.write_all(msg.as_bytes())?;
    let mut line = String::new();
    std::io::BufReader::new(&s).read_line(&mut line)?;
    let mut it = line.trim_end().split(' ');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some("OK"), Some(time), Some(sig), None) => Ok(PreregReceipt {
            time: time.parse().context("receipt time")?,
            signature: sig.to_string(),
        }),
        _ => bail!("notary: {}", line.trim_end()),
    }
}

impl Prereg {
    pub fn hash(&self) -> Digest {
        let mut h = Hasher::new(domain::EVAL_PREREG);
        h.str(&self.suite_name)
            .str(&self.suite_hash)
            .str(&self.model_id)
            .str(&self.model_auth_hash)
            .str(&self.program_vk)
            .str(&self.beacon_chain)
            .u64(self.beacon_round)
            .u64(self.beacon_time);
        h.finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Beacon {
    pub round: u64,
    pub signature: String,
    pub randomness: String,
}

/// Check a quicknet beacon and return its randomness.
pub fn verify_beacon(b: &Beacon) -> Result<[u8; 32]> {
    let pk: [u8; 96] = from_hex(QUICKNET_PUBKEY).and_then(|v| v.try_into().ok()).expect("valid constant");
    let pk = G2PubkeyRfc::from_fixed(pk).map_err(|e| anyhow!("quicknet key: {e:?}"))?;
    let sig = from_hex(&b.signature).ok_or_else(|| anyhow!("beacon signature is not hex"))?;
    if !pk.verify(b.round, &[], &sig).map_err(|e| anyhow!("beacon: {e:?}"))? {
        bail!("beacon signature for round {} does not verify against drand quicknet", b.round);
    }
    let r = derive_randomness(&sig);
    if to_hex(&r) != b.randomness {
        bail!("beacon randomness is not sha256(signature)");
    }
    Ok(r)
}

pub fn fetch_beacon(round: u64) -> Result<Beacon> {
    let url = format!("https://api.drand.sh/{QUICKNET_CHAIN}/public/{round}");
    let b: Beacon = ureq::get(&url)
        .call()
        .with_context(|| format!("fetching drand round {round}"))?
        .into_json()?;
    if b.round != round {
        bail!("drand returned round {} for {round}", b.round);
    }
    verify_beacon(&b)?;
    Ok(b)
}

pub fn seed_from(prereg: &Prereg, b: &Beacon) -> Result<Digest> {
    if prereg.beacon_chain != QUICKNET_CHAIN || b.round != prereg.beacon_round {
        bail!("beacon is not the pre-registered round");
    }
    if prereg.beacon_time != round_time(prereg.beacon_round) {
        bail!("pre-registration beacon_time does not match its round");
    }
    let r = verify_beacon(b)?;
    let mut h = Hasher::new(domain::BEACON_SEED);
    h.digest(&prereg.hash()).u64(b.round).digest(&r);
    Ok(h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real quicknet beacon (round 34165327, fetched 2026-11-21).
    fn real() -> Beacon {
        Beacon {
            round: 34165327,
            signature: "a560e8121f5e4f4e612e10108b8126269ca26c2c74ae89de9ec0d93d8d9614af05ba8683ba5ac6acbefab1bd557cbfe4".into(),
            randomness: "ef84af6358358cb3e7dbd9cb3b7a1588a741dceee58291d30800a6f05cd2436d".into(),
        }
    }

    #[test]
    fn beacon_verification() {
        verify_beacon(&real()).unwrap();
        let mut b = real();
        b.round += 1;
        assert!(verify_beacon(&b).is_err(), "signature is bound to the round");
        let mut b = real();
        b.randomness = "00".repeat(32);
        assert!(verify_beacon(&b).is_err());
        let mut b = real();
        b.signature.replace_range(0..2, "a4");
        assert!(verify_beacon(&b).is_err());
        assert_eq!(round_at(round_time(34165327)), 34165327);
    }

    #[test]
    fn seed_binds_prereg_and_round() {
        let p = Prereg {
            suite_name: "s".into(),
            suite_hash: "00".repeat(32),
            model_id: "m".into(),
            model_auth_hash: "11".repeat(32),
            program_vk: "0x00".into(),
            beacon_chain: QUICKNET_CHAIN.into(),
            beacon_round: 34165327,
            beacon_time: round_time(34165327),
            receipt: None,
        };
        let s = seed_from(&p, &real()).unwrap();
        // The notary's receipt is not part of what it time-stamps.
        let mut r = p.clone();
        r.receipt = Some(PreregReceipt { time: 1, signature: "00".into() });
        assert_eq!(r.hash(), p.hash());
        let mut q = p.clone();
        q.suite_hash = "01".repeat(32);
        assert_ne!(seed_from(&q, &real()).unwrap(), s);
        let mut q = p.clone();
        q.beacon_round += 1;
        assert!(seed_from(&q, &real()).is_err());
    }
}
