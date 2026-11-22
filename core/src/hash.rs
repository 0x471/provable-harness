//! Domain-separated, injective hashing.
//!
//! Every hashed object is encoded as: `len(domain) || domain || fields...`, where
//! every variable-length field is prefixed with its length as a little-endian u64
//! and fixed-size fields (digests, integers, bools) are written raw. For a fixed
//! domain the field layout is fixed, so the encoding is prefix-free and two
//! different objects can only collide if SHA-256 collides.

use sha2::{Digest as _, Sha256};

/// A SHA-256 digest.
pub type Digest = [u8; 32];

/// Domain tags. Each one is used for exactly one object type.
pub mod domain {
    pub const TEXT: &str = "ph/v1/text";
    pub const CTX_GENESIS: &str = "ph/v1/context-genesis";
    pub const CTX_MESSAGE: &str = "ph/v1/context-message";
    pub const MODEL_REQUEST: &str = "ph/v1/model-request";
    pub const MODEL_RESPONSE: &str = "ph/v1/model-response";
    pub const MODEL_ATTESTATION: &str = "ph/v1/model-attestation";
    pub const TOOL_CALL: &str = "ph/v1/tool-call";
    pub const TOOL_RESULT: &str = "ph/v1/tool-result";
    pub const TOOL_ATTESTATION: &str = "ph/v1/tool-attestation";
    pub const POLICY: &str = "ph/v1/policy";
    pub const WORKSPACE: &str = "ph/v1/workspace";
    pub const ACTION_GENESIS: &str = "ph/v1/action-genesis";
    pub const ACTION: &str = "ph/v1/action";
    pub const ACTION_SALT: &str = "ph/v1/action-salt";
    pub const CTX_GENESIS_TOOLS: &str = "ph/v1/ctx-genesis-native-tools";
    pub const TOOL_MODE: &str = "ph/v1/tool-mode";
    pub const EVAL_PREREG: &str = "ph/v1/eval-preregistration";
    pub const BEACON_SEED: &str = "ph/v1/beacon-seed";
    pub const ACTION_FIELD: &str = "ph/v1/action-field";
    pub const MODEL_AUTH: &str = "ph/v1/model-auth";
    pub const TOOL_AUTH: &str = "ph/v1/tool-auth";
    pub const EVAL_SPEC: &str = "ph/v1/eval-spec";
    pub const EVAL_SUITE: &str = "ph/v1/eval-suite";
    pub const EVAL_SESSION: &str = "ph/v1/eval-session";
    pub const NOTARY_LOG: &str = "ph/v1/notary-session-log";
    pub const CLAIM_SALT: &str = "ph/v1/claim-salt";
    pub const SALTED: &str = "ph/v1/salted-commitment";
    pub const NOTARY_PREREG: &str = "ph/v1/notary-prereg-receipt";
}

pub struct Hasher(Sha256);

impl Hasher {
    pub fn new(domain: &str) -> Self {
        let mut h = Self(Sha256::new());
        h.bytes(domain.as_bytes());
        h
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.update((b.len() as u64).to_le_bytes());
        self.0.update(b);
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.update(v.to_le_bytes());
        self
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.update([v]);
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }

    pub fn digest(&mut self, d: &Digest) -> &mut Self {
        self.0.update(d);
        self
    }

    /// A list of strings: count, then each string length-prefixed.
    pub fn strs<S: AsRef<str>>(&mut self, items: &[S]) -> &mut Self {
        self.u64(items.len() as u64);
        for s in items {
            self.str(s.as_ref());
        }
        self
    }

    pub fn finish(self) -> Digest {
        self.0.finalize().into()
    }
}

/// Hash of a standalone text (system prompt, task, final answer, ...).
pub fn text_hash(s: &str) -> Digest {
    let mut h = Hasher::new(domain::TEXT);
    h.str(s);
    h.finish()
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s).as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.chunks(2)
        .map(|p| Some(nibble(p[0])? << 4 | nibble(p[1])?))
        .collect()
}

pub fn from_hex32(s: &str) -> Option<[u8; 32]> {
    from_hex(s)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_prevents_concatenation_ambiguity() {
        let mut a = Hasher::new("t");
        a.str("ab").str("c");
        let mut b = Hasher::new("t");
        b.str("a").str("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn domains_separate() {
        let mut a = Hasher::new(domain::TEXT);
        a.str("x");
        let mut b = Hasher::new(domain::MODEL_RESPONSE);
        b.str("x");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn hex_roundtrip() {
        let d = text_hash("hello");
        assert_eq!(from_hex32(&to_hex(&d)), Some(d));
        assert_eq!(from_hex("0xAbC0"), Some(vec![0xab, 0xc0]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }
}
