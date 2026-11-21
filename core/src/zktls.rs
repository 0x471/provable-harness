//! zkTLS attestation: a TLSNotary presentation of an HTTPS exchange replaces a
//! trusted signer, for model calls (instead of the gateway) and for `http_get` /
//! `http_post` tool calls (instead of the tool oracle).
//!
//! What a valid presentation establishes (given an honest, non-colluding notary):
//! the server that holds a WebPKI certificate for `host` (as of the notarized
//! time) received exactly these request bytes and sent exactly these response
//! bytes over TLS 1.2.
//!
//! Checks performed here (all of them are needed; see docs/ZKTLS.md):
//! 1. the attestation is signed by the pinned notary key, under the pinned
//!    signature scheme;
//! 2. the server identity proof is present and names `host`, with a certificate
//!    chain valid at the attested time under the configured root store;
//! 3. the transcript is present and *complete* (no redacted bytes in either
//!    direction): redacted bytes are prover-chosen and could hide an injected
//!    second request, so nothing is redacted (the API key is protected by keeping
//!    the presentation inside the private witness instead);
//! 4. the attestation carries exactly one extension, written by the notary: the
//!    (kind, session, step-or-seq) slot it consumed before the exchange. This
//!    binds the presentation to one model step / tool call; the notary never
//!    issues two attestations for one slot, so nothing can be re-sampled;
//! 5. the request equals the bytes rebuilt from the harness's own state
//!    (`anthropic::check_request` / `http::tool_request`);
//! 6. the response is one well-framed HTTP/1.1 response (model: a `200` with a
//!    text assistant message from the requested model; tool: any status).

use serde::{Deserialize, Serialize};
use tlsn_attestation::presentation::Presentation;
use tlsn_attestation::signing::{
    KeyAlgId, SignatureAlgId, SignatureError, SignatureVerifier, VerifyingKey,
};
/// Re-exported so callers can hold a provider without naming the vendored crate.
pub use tlsn_attestation::CryptoProvider;
use tlsn_core::connection::{ServerName, TlsVersion};
use tlsn_core::webpki::{CertificateDer, RootCertStore, ServerCertVerifier};

use crate::anthropic::{check_request, model_matches, parse_http_response, parse_reply, ApiReply};
use crate::hash::{domain, to_hex, Digest, Hasher};
use crate::protocol::{ToolCall, ToolResult};

/// Which certificate roots the guest trusts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsRoots {
    /// The Mozilla root set compiled into the harness program (webpki-roots).
    Mozilla,
    /// An explicit list of DER root certificates (e.g. a pinned subset, or a test CA).
    Custom(Vec<Vec<u8>>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotaryKey {
    /// TLSNotary key algorithm name: "k256" or "p256".
    pub alg: String,
    /// Encoded public key (SEC1 compressed, 33 bytes).
    pub key: Vec<u8>,
}

impl NotaryKey {
    /// The one attestation signature scheme accepted for this key.
    ///
    /// TLSNotary accepts several schemes per key type (e.g. `secp256k1` and the
    /// Keccak-prehashed `secp256k1eth` for k256 keys), and any TLSNotary notary
    /// holding the same key could sign plain `secp256k1` attestations without
    /// enforcing our one-reply-per-(session, step) rule. So the guest accepts
    /// only the ph notary scheme, which signs under a ph-specific domain.
    pub fn signature_alg(&self) -> Option<SignatureAlgId> {
        match self.alg.as_str() {
            "k256" => Some(ph_notary_sig_alg()),
            _ => None,
        }
    }
}

/// TLSNotary signature-algorithm id of the ph notary scheme (ids >= 128 are for
/// private use).
pub const PH_NOTARY_SIG_ALG_ID: u8 = 0xA1;

/// Prefix signed in front of the canonical (BCS) attestation-header bytes.
/// Signing `DOMAIN || header` means no signature made by a generic TLSNotary
/// notary (which signs the bare header) can be accepted, even with the same key.
pub const PH_NOTARY_SIG_DOMAIN: &[u8] = b"provable-harness/notary-attestation/v1\0";

pub fn ph_notary_sig_alg() -> SignatureAlgId {
    SignatureAlgId::new(PH_NOTARY_SIG_ALG_ID)
}

/// The bytes the ph notary signs (ECDSA secp256k1 with SHA-256 over these).
pub fn ph_notary_signed_message(header: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PH_NOTARY_SIG_DOMAIN.len() + header.len());
    m.extend_from_slice(PH_NOTARY_SIG_DOMAIN);
    m.extend_from_slice(header);
    m
}

/// Verifier for the ph notary scheme. The notary side is `ph-zktls`.
pub struct PhNotaryVerifier;

impl SignatureVerifier for PhNotaryVerifier {
    fn alg_id(&self) -> SignatureAlgId {
        ph_notary_sig_alg()
    }

    fn verify(&self, key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
        use k256::ecdsa::signature::Verifier as _;
        if key.alg != KeyAlgId::K256 {
            return Err(SignatureError::from_str("ph notary key must be k256"));
        }
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&key.data)
            .map_err(|_| SignatureError::from_str("invalid k256 key"))?;
        let sig = k256::ecdsa::Signature::from_slice(sig)
            .map_err(|_| SignatureError::from_str("invalid secp256k1 signature"))?;
        vk.verify(&ph_notary_signed_message(msg), &sig)
            .map_err(|_| SignatureError::from_str("ph notary signature verification failed"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkTlsConfig {
    pub notary: NotaryKey,
    /// DNS name the certificate must be valid for, e.g. "api.anthropic.com".
    pub host: String,
    pub roots: TlsRoots,
    /// Anthropic model id requested in every call.
    pub model: String,
    pub max_tokens: u32,
}

/// Upper bound on `max_tokens` in zkTLS mode. The MPC-TLS receive limit
/// (`ph-zktls` `MAX_RECV`, 32 KiB) must hold the response headers (~1-2 KiB)
/// plus the JSON reply, whose escaping can expand the text.
pub const MAX_TOKENS: u32 = 2048;

/// How model replies are authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelAuth {
    /// A trusted gateway's Ed25519 signature over (request hash, response hash).
    Gateway { key: [u8; 32] },
    /// A TLSNotary presentation of the HTTPS exchange with the model API.
    ZkTls(ZkTlsConfig),
}

impl ModelAuth {
    pub fn hash(&self) -> Digest {
        let mut h = Hasher::new(domain::MODEL_AUTH);
        match self {
            ModelAuth::Gateway { key } => {
                h.u8(1).digest(key);
            }
            ModelAuth::ZkTls(c) => {
                h.u8(2)
                    .str(&c.notary.alg)
                    .bytes(&c.notary.key)
                    .str(&c.host);
                match &c.roots {
                    TlsRoots::Mozilla => {
                        h.u8(1);
                    }
                    TlsRoots::Custom(roots) => {
                        h.u8(2).u64(roots.len() as u64);
                        for r in roots {
                            h.bytes(r);
                        }
                    }
                }
                h.str(&c.model).u64(c.max_tokens as u64);
            }
        }
        h.finish()
    }

    pub fn validate(&self) -> Result<(), String> {
        if let ModelAuth::ZkTls(c) = self {
            if c.host.is_empty() || c.model.is_empty() || c.max_tokens == 0 {
                return Err("zktls config: empty host/model or zero max_tokens".into());
            }
            if c.max_tokens > MAX_TOKENS {
                return Err(format!(
                    "zktls config: max_tokens above {MAX_TOKENS} risks replies larger than the MPC-TLS receive limit"
                ));
            }
            if c.model.ends_with("-latest") {
                return Err("zktls config: pin a model id, not a -latest alias (the API reports the resolved id)".into());
            }
            c.notary.validate()?;
            validate_roots(&c.roots)?;
        }
        Ok(())
    }
}

impl NotaryKey {
    pub fn validate(&self) -> Result<(), String> {
        if self.signature_alg().is_none() {
            return Err("zktls config: notary key alg must be k256".into());
        }
        if self.key.len() != 33 || !matches!(self.key[0], 2 | 3) {
            return Err("zktls config: notary key must be a compressed SEC1 point".into());
        }
        Ok(())
    }
}

fn validate_roots(r: &TlsRoots) -> Result<(), String> {
    if let TlsRoots::Custom(r) = r {
        if r.is_empty() {
            return Err("zktls config: empty custom root list".into());
        }
    }
    Ok(())
}

fn hash_notary_and_roots(h: &mut Hasher, notary: &NotaryKey, roots: &TlsRoots) {
    h.str(&notary.alg).bytes(&notary.key);
    match roots {
        TlsRoots::Mozilla => {
            h.u8(1);
        }
        TlsRoots::Custom(roots) => {
            h.u8(2).u64(roots.len() as u64);
            for r in roots {
                h.bytes(r);
            }
        }
    }
}

/// zkTLS for the `http_get` / `http_post` tools: any `https://` host the policy
/// allows, authenticated by its WebPKI certificate under `roots`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolTlsConfig {
    pub notary: NotaryKey,
    pub roots: TlsRoots,
}

/// How results of the external tools (`http_get`, `http_post`) are authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolAuth {
    /// A trusted oracle's Ed25519 signature over (call hash, result hash).
    Oracle { key: [u8; 32] },
    /// A TLSNotary presentation of the HTTPS exchange with the target server.
    ZkTls(ToolTlsConfig),
    /// A fixed, published world answered inside the proof (evaluations): the
    /// results are exactly the committed fixture, no evidence is needed.
    Fixture(crate::eval::World),
}

impl ToolAuth {
    pub fn hash(&self) -> Digest {
        let mut h = Hasher::new(domain::TOOL_AUTH);
        match self {
            ToolAuth::Oracle { key } => {
                h.u8(1).digest(key);
            }
            ToolAuth::ZkTls(c) => {
                h.u8(2);
                hash_notary_and_roots(&mut h, &c.notary, &c.roots);
            }
            ToolAuth::Fixture(world) => {
                h.u8(3);
                world.hash_into(&mut h);
            }
        }
        h.finish()
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            ToolAuth::Oracle { .. } => {}
            ToolAuth::ZkTls(c) => {
                c.notary.validate()?;
                validate_roots(&c.roots)?;
            }
            ToolAuth::Fixture(world) => world.validate()?,
        }
        Ok(())
    }
}

/// Build the TLSNotary crypto provider for a root set (once per session:
/// parsing custom roots is not free inside the zkVM).
pub fn provider_for_roots(roots: &TlsRoots) -> Result<CryptoProvider, String> {
    let mut p = match roots {
        TlsRoots::Mozilla => CryptoProvider::default(),
        TlsRoots::Custom(roots) => CryptoProvider {
            cert: ServerCertVerifier::new(&RootCertStore {
                roots: roots.iter().map(|r| CertificateDer(r.clone())).collect(),
            })
            .map_err(|e| format!("bad custom root: {e}"))?,
            ..Default::default()
        },
    };
    p.signature.set_verifier(Box::new(PhNotaryVerifier));
    Ok(p)
}

pub fn crypto_provider(c: &ZkTlsConfig) -> Result<CryptoProvider, String> {
    provider_for_roots(&c.roots)
}

// ---------------------------------------------------------------------- slots --

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SlotKind {
    Model,
    Tool,
}

/// One unit the notary rations: a model step or an external tool call of one
/// session. Text form (intent lines, journal, attestation extension):
/// `<model|tool> <64 lowercase hex> <n>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot {
    pub kind: SlotKind,
    pub session: Digest,
    pub n: u64,
}

/// Id of the notary-written attestation extension that names the slot.
pub const SLOT_EXTENSION_ID: &[u8] = b"provable-harness/slot";

impl Slot {
    pub fn model(session: &Digest, step: u32) -> Self {
        Slot { kind: SlotKind::Model, session: *session, n: step as u64 }
    }

    pub fn tool(session: &Digest, seq: u64) -> Self {
        Slot { kind: SlotKind::Tool, session: *session, n: seq }
    }

    pub fn to_text(&self) -> String {
        let kind = match self.kind {
            SlotKind::Model => "model",
            SlotKind::Tool => "tool",
        };
        format!("{kind} {} {}", to_hex(&self.session), self.n)
    }

    /// Strict inverse of `to_text` (one canonical spelling per slot).
    pub fn parse_text(s: &str) -> Option<Slot> {
        let mut it = s.split(' ');
        let kind = match it.next()? {
            "model" => SlotKind::Model,
            "tool" => SlotKind::Tool,
            _ => return None,
        };
        let hex = it.next()?;
        let n = it.next()?;
        if it.next().is_some() || hex.len() != 64 {
            return None;
        }
        let mut session = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let nib = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            };
            session[i] = nib(pair[0])? << 4 | nib(pair[1])?;
        }
        if n.is_empty() || n.len() > 20 || !n.bytes().all(|b| b.is_ascii_digit()) || (n.len() > 1 && n.starts_with('0')) {
            return None;
        }
        let n: u64 = n.parse().ok()?;
        if kind == SlotKind::Model && n > u32::MAX as u64 {
            return None;
        }
        Some(Slot { kind, session, n })
    }

    pub fn extension_value(&self) -> Vec<u8> {
        format!("ph-slot-v1 {}", self.to_text()).into_bytes()
    }
}

// --------------------------------------------------------------- verification --

/// The authenticated plaintext of a notarized TLS session.
#[derive(Clone, Debug)]
pub struct TlsExchange {
    pub time: u64,
    pub sent: Vec<u8>,
    pub recv: Vec<u8>,
    /// Notary-signed attestation extensions as (id, value).
    pub extensions: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Checks 1-3: notary key and scheme, server identity, complete transcript.
pub fn verify_presentation(
    provider: &CryptoProvider,
    notary: &NotaryKey,
    host: &str,
    bytes: &[u8],
) -> Result<TlsExchange, String> {
    let p: Presentation =
        bincode::deserialize(bytes).map_err(|e| format!("malformed presentation: {e}"))?;
    let vk = p.verifying_key();
    if vk.alg.to_string() != notary.alg || vk.data != notary.key {
        return Err("presentation is not signed by the pinned notary".into());
    }
    let out = p
        .verify(provider)
        .map_err(|e| format!("presentation does not verify: {e}"))?;
    if Some(out.attestation.signature.alg) != notary.signature_alg() {
        return Err("attestation uses a signature scheme other than the pinned one".into());
    }
    match &out.server_name {
        Some(ServerName::Dns(name)) if name.as_str() == host => {}
        Some(_) => return Err("presentation is for a different server".into()),
        None => return Err("presentation has no server identity proof".into()),
    }
    if out.connection_info.version != TlsVersion::V1_2 {
        return Err("unsupported TLS version".into());
    }
    let t = out.transcript.ok_or("presentation has no transcript")?;
    if !t.is_complete() {
        return Err("transcript has redacted bytes; full disclosure is required".into());
    }
    let len = &out.connection_info.transcript_length;
    let sent = t
        .sent_unsafe(len.sent as usize)
        .map_err(|e| format!("sent length: {e}"))?;
    let recv = t
        .received_unsafe(len.received as usize)
        .map_err(|e| format!("received length: {e}"))?;
    Ok(TlsExchange {
        time: out.connection_info.time,
        sent,
        recv,
        extensions: out.extensions.into_iter().map(|e| (e.id, e.value)).collect(),
    })
}

/// Check 4: the attestation names exactly this slot and nothing else.
pub fn check_slot(x: &TlsExchange, slot: &Slot) -> Result<(), String> {
    match x.extensions.as_slice() {
        [(id, value)] if id.as_slice() == SLOT_EXTENSION_ID && *value == slot.extension_value() => Ok(()),
        _ => Err(format!("attestation is not bound to slot {}", slot.to_text())),
    }
}

/// Checks 1-6 for one model step. `expected_body` is rebuilt by the caller from
/// the harness state (never taken from the presentation).
pub fn verify_model_exchange(
    provider: &CryptoProvider,
    c: &ZkTlsConfig,
    bytes: &[u8],
    expected_body: &str,
    slot: &Slot,
    native: bool,
) -> Result<(ApiReply, u64), String> {
    let x = verify_presentation(provider, &c.notary, &c.host, bytes)?;
    check_slot(&x, slot)?;
    check_request(&x.sent, &c.host, expected_body)?;
    let (status, body) = parse_http_response(&x.recv)?;
    if status != 200 {
        return Err(format!("model API answered HTTP {status}"));
    }
    let reply = parse_reply(&body, native)?;
    if !model_matches(&c.model, &reply.model) {
        return Err(format!(
            "reply is from model {}, not {}",
            reply.model, c.model
        ));
    }
    Ok((reply, x.time))
}

/// Checks 1-6 for one `http_get` / `http_post` call. The request bytes and the
/// slot come from the call (harness state), never from the presentation.
pub fn verify_tool_exchange(
    provider: &CryptoProvider,
    c: &ToolTlsConfig,
    call: &ToolCall,
    bytes: &[u8],
) -> Result<(ToolResult, u64), String> {
    let (url, request) = crate::http::tool_request(call)?;
    let x = verify_presentation(provider, &c.notary, &url.host, bytes)?;
    check_slot(&x, &Slot::tool(&call.session_id, call.seq))?;
    if x.sent != request {
        return Err("notarized request differs from the tool call".into());
    }
    let result = crate::http::tool_result(&x.recv)?;
    Ok((result, x.time))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ZkTlsConfig {
        let mut key = vec![2u8];
        key.extend([1u8; 32]);
        ZkTlsConfig {
            notary: NotaryKey { alg: "k256".into(), key },
            host: "api.anthropic.com".into(),
            roots: TlsRoots::Mozilla,
            model: "claude-haiku-5-5".into(),
            max_tokens: 1024,
        }
    }

    #[test]
    fn slot_text_is_canonical() {
        let sid = [0xabu8; 32];
        for slot in [Slot::model(&sid, 0), Slot::model(&sid, u32::MAX), Slot::tool(&sid, u64::MAX)] {
            assert_eq!(Slot::parse_text(&slot.to_text()), Some(slot));
        }
        assert_eq!(Slot::tool(&sid, 7).to_text(), format!("tool {} 7", "ab".repeat(32)));
        let hex = "ab".repeat(32);
        for bad in [
            format!("tool {hex} 07"), format!("tool {} 7", "AB".repeat(32)), format!("tool {hex}  7"),
            format!("tool {hex} 7 "), format!("Tool {hex} 7"), format!("model {hex} 4294967296"),
            format!("tool {hex} 18446744073709551616"), format!("tool {hex} -1"), format!("tool {} 7", &hex[..62]),
            format!("tool {hex} 7\n"),
        ] {
            assert_eq!(Slot::parse_text(&bad), None, "{bad}");
        }
        assert_ne!(Slot::model(&sid, 3).extension_value(), Slot::tool(&sid, 3).extension_value());
    }

    #[test]
    fn tool_auth_hash_and_validation() {
        let c = cfg();
        let t = ToolAuth::ZkTls(ToolTlsConfig { notary: c.notary.clone(), roots: TlsRoots::Mozilla });
        t.validate().unwrap();
        let o = ToolAuth::Oracle { key: [1; 32] };
        assert_ne!(t.hash(), o.hash());
        let t2 = ToolAuth::ZkTls(ToolTlsConfig { notary: c.notary.clone(), roots: TlsRoots::Custom(vec![vec![1]]) });
        assert_ne!(t.hash(), t2.hash());
        assert!(ToolAuth::ZkTls(ToolTlsConfig { notary: c.notary, roots: TlsRoots::Custom(vec![]) }).validate().is_err());
    }

    #[test]
    fn config_validation() {
        let ok = |c: ZkTlsConfig| ModelAuth::ZkTls(c).validate();
        ok(cfg()).unwrap();
        let mut c = cfg();
        c.max_tokens = MAX_TOKENS + 1;
        assert!(ok(c).unwrap_err().contains("max_tokens"));
        let mut c = cfg();
        c.model = "claude-haiku-latest".into();
        assert!(ok(c).unwrap_err().contains("-latest"));
        let mut c = cfg();
        c.notary.alg = "p256".into();
        assert!(ok(c).is_err());
        let mut c = cfg();
        c.notary.key[0] = 4;
        assert!(ok(c).is_err());
        let mut c = cfg();
        c.notary.key.pop();
        assert!(ok(c).is_err());
        let mut c = cfg();
        c.roots = TlsRoots::Custom(vec![]);
        assert!(ok(c).is_err());
    }
}
