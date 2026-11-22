//! MPC-TLS notarization of model API calls and HTTPS tool calls for the
//! provable harness.
//!
//! Roles:
//! - **notary** (trusted not to collude with the operator): runs the TLSNotary
//!   verifier side of MPC-TLS and signs an attestation that carries, as a
//!   notary-written extension, the slot (`ph_core::Slot`: model step or tool
//!   call of one session) it rationed.
//!
//!   Anti re-roll: before MPC-TLS starts, the prover announces
//!   `PH-INTENT <model|tool> <session hex> <n>\n`; the notary marks that slot
//!   consumed immediately (journaled). The prover sees the response plaintext
//!   before the notary signs, so recording the slot only at signing time would let
//!   it abort and retry until it likes the response.
//!   - model slots: the prover must disclose the request tail
//!     `,"metadata":{"user_id":"ph-<session>-<step>"}}` (checked against the
//!     intent) and the response status prefix; the slot is released only after a
//!     completed exchange with a non-200 status (e.g. 529), so the call can be
//!     retried;
//!   - tool slots: nothing is disclosed (the notary learns neither URL nor
//!     data); every completed exchange keeps the slot, whatever the status (a 404
//!     is a legitimate tool result).
//! - **prover** (operator side, holds the API key): sends the exact request bytes
//!   (`ph_core::anthropic::http_request`, `ph_core::http::tool_request`) and
//!   builds a presentation that discloses the whole transcript (consumed privately
//!   by the zkVM guest).
//! - **mock servers**: TLS 1.2 stand-ins for the Messages API and for websites,
//!   for offline tests.

use std::collections::HashSet;
use std::future::IntoFuture;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;

use ph_core::notary_log::PreregRecord;
use ph_core::zktls::SLOT_EXTENSION_ID;
use ph_core::{Slot, SlotKind};
use tlsn::{
    attestation::{
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
        signing::{
            KeyAlgId, Signature, SignatureAlgId, SignatureError, SignatureVerifier, Signer,
            VerifyingKey,
        },
        Attestation, AttestationConfig, CryptoProvider, Extension,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{CertBinding, ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::ProverOutput,
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
    Session,
};

/// MPC-TLS limits. Sent data dominates MPC cost; harness requests carry the
/// whole conversation, so allow 32 KiB.
pub const MAX_SENT: usize = 1 << 15;
/// Must cover `ph_core::zktls::MAX_TOKENS` worth of reply plus headers.
pub const MAX_RECV: usize = 1 << 15;

const TAIL_PREFIX: &[u8] = b",\"metadata\":{\"user_id\":\"ph-";
const STATUS_LEN: usize = 12; // "HTTP/1.1 200"

/// Trusted roots for the TLS server certificate.
#[derive(Clone, Debug)]
pub enum Roots {
    Mozilla,
    Ca(Vec<u8>),
}

impl Roots {
    pub fn store(&self) -> RootCertStore {
        match self {
            Roots::Mozilla => RootCertStore::mozilla(),
            Roots::Ca(der) => RootCertStore {
                roots: vec![CertificateDer(der.clone())],
            },
        }
    }

    pub fn to_ph(&self) -> ph_core::TlsRoots {
        match self {
            Roots::Mozilla => ph_core::TlsRoots::Mozilla,
            Roots::Ca(der) => ph_core::TlsRoots::Custom(vec![der.clone()]),
        }
    }
}

/// Parse the model request tail the notary sees into its slot.
pub fn parse_tail(tail: &[u8]) -> Option<Slot> {
    let rest = tail.strip_prefix(TAIL_PREFIX)?;
    let rest = std::str::from_utf8(rest.strip_suffix(b"\"}}")?).ok()?;
    let (hex, step) = rest.split_once('-')?;
    // `Slot::parse_text` is strict: 64 lowercase hex, canonical decimal <= u32.
    Slot::parse_text(&format!("model {hex} {step}"))
}

fn short(slot: &Slot) -> String {
    let t = slot.to_text();
    let mut it = t.split(' ');
    let (kind, hex, n) = (it.next().unwrap_or(""), it.next().unwrap_or(""), it.next().unwrap_or(""));
    format!("{kind} {}.. #{n}", &hex[..8.min(hex.len())])
}

// ------------------------------------------------------------------ notary --

/// (session, step) slots that were announced and not released.
///
/// With a journal, every change is appended and `fsync`ed *before* the notary
/// acts on it (before answering `OK`, before forgetting a released slot), so a
/// restart cannot re-open a slot: re-opening one would allow re-rolls. Without a
/// journal (`default()`, tests and `dev`), state is lost on restart.
#[derive(Default)]
pub struct NotaryState {
    inner: Mutex<StateInner>,
}

#[derive(Default)]
struct StateInner {
    consumed: HashSet<Slot>,
    journal: Option<std::fs::File>,
}

/// First line of a journal: format version and the notary key it belongs to.
/// v3 added `D` records (attestation signed), v4 `P` records (pre-registrations).
/// Older journals are refused: start a new journal with a new notary key (a
/// fresh journal under the old key would allow re-rolls).
const JOURNAL_HEADER: &str = "PH-NOTARY-JOURNAL v4";

fn journal_line(op: u8, slot: &Slot) -> Vec<u8> {
    format!("{} {}\n", op as char, slot.to_text()).into_bytes()
}

fn prereg_line(p: &PreregRecord) -> Vec<u8> {
    format!("P {} {} {}\n", p.suite, p.prereg, p.time).into_bytes()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

enum Record {
    Slot(u8, Slot),
    Prereg(PreregRecord),
}

fn parse_journal_line(line: &[u8]) -> Option<Record> {
    let (&op, rest) = line.split_first()?;
    if rest.first() != Some(&b' ') {
        return None;
    }
    let text = std::str::from_utf8(&rest[1..]).ok()?;
    match op {
        b'C' | b'R' | b'D' => Some(Record::Slot(op, Slot::parse_text(text)?)),
        b'P' => {
            let mut it = text.split(' ');
            let (suite, prereg, time) = (it.next()?, it.next()?, it.next()?);
            if it.next().is_some() || !is_hex64(suite) || !is_hex64(prereg) {
                return None;
            }
            let time: u64 = time.parse().ok().filter(|_| !time.starts_with('0') || time == "0")?;
            Some(Record::Prereg(PreregRecord { suite: suite.into(), prereg: prereg.into(), time }))
        }
        _ => None,
    }
}

/// What a journal holds: the consumed slots, each slot's event history (e.g.
/// "CD", "CDRCD", "C") and the pre-registrations in order.
#[derive(Default)]
struct Journal {
    consumed: HashSet<Slot>,
    histories: std::collections::BTreeMap<Slot, String>,
    preregs: Vec<PreregRecord>,
}

/// Replay the complete records of a journal (`data` up to and including its
/// last newline; the first line is the header).
fn replay_journal(data: &[u8], key_line: &[u8], path: &std::path::Path) -> Result<Journal> {
    let mut j = Journal::default();
    // Strip the final newline so every remaining segment is one record (an
    // empty segment, i.e. a blank line, is malformed).
    let Some(records) = data.strip_suffix(b"\n") else {
        return Ok(j);
    };
    let mut lines = records.split(|&b| b == b'\n').enumerate();
    if let Some((_, first)) = lines.next() {
        if first != key_line {
            bail!(
                "notary journal {} belongs to another notary key or format version (this build writes {JOURNAL_HEADER})",
                path.display()
            );
        }
    }
    for (n, line) in lines {
        let (op, slot) = match parse_journal_line(line) {
            Some(Record::Slot(op, slot)) => (op, slot),
            Some(Record::Prereg(p)) => {
                j.preregs.push(p);
                continue;
            }
            None => bail!("notary journal line {}: malformed", n + 1),
        };
        let ok = match op {
            b'C' => j.consumed.insert(slot),
            b'R' => j.consumed.remove(&slot),
            // D (attestation signed) only for a currently consumed slot.
            _ => j.consumed.contains(&slot),
        };
        if !ok {
            bail!("notary journal line {}: inconsistent with earlier lines", n + 1);
        }
        j.histories.entry(slot).or_default().push(op as char);
    }
    Ok(j)
}

fn journal_key_line(notary_key: &[u8]) -> Vec<u8> {
    format!("{JOURNAL_HEADER} {}", hex::encode(notary_key)).into_bytes()
}

/// Read a journal without taking its lock (the running notary holds it): each
/// slot's event history and the pre-registrations. A torn last line is ignored
/// (it was never acted on).
fn read_journal(path: &std::path::Path, notary_key: &[u8]) -> Result<Journal> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let complete = data.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    if complete == 0 {
        bail!("journal {} is empty", path.display());
    }
    replay_journal(&data[..complete], &journal_key_line(notary_key), path)
}

pub fn read_journal_histories(
    path: &std::path::Path,
    notary_key: &[u8],
) -> Result<std::collections::BTreeMap<Slot, String>> {
    Ok(read_journal(path, notary_key)?.histories)
}

impl NotaryState {
    /// Open (or create) a journal and replay it. A torn last line (crash during
    /// an append, before its `fsync` returned and so before the notary acted on
    /// it) is dropped; any other malformed or inconsistent line is an error.
    ///
    /// The first line, `PH-NOTARY-JOURNAL v3 <notary public key hex>`, binds the
    /// journal to one notary key (a journal is only meaningful for the key whose
    /// signatures it rations) and to this record format.
    pub fn open(path: &std::path::Path, notary_key: &[u8]) -> Result<Self> {
        use std::io::{Read, Seek};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .with_context(|| format!("opening notary journal {}", path.display()))?;
        // Two notaries sharing one journal would each keep a stale in-memory
        // view and could both accept the same slot.
        file.try_lock().map_err(|e| {
            anyhow!("notary journal {} is in use by another process: {e}", path.display())
        })?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        let complete = data.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        if complete != data.len() {
            file.set_len(complete as u64)?;
            file.sync_all()?;
        }
        file.seek(std::io::SeekFrom::End(0))?;
        let key_line = journal_key_line(notary_key);
        if complete == 0 {
            use std::io::Write;
            file.write_all(&key_line)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        let consumed = replay_journal(&data[..complete], &key_line, path)?.consumed;
        Ok(Self {
            inner: Mutex::new(StateInner {
                consumed,
                journal: Some(file),
            }),
        })
    }

    /// Record a pre-registration with the notary's clock, *before* the receipt
    /// is sent. Every session log lists it.
    pub fn record_prereg(&self, p: &PreregRecord) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if let Some(f) = g.journal.as_mut() {
            use std::io::Write;
            f.write_all(&prereg_line(p))?;
            f.sync_data()?;
        }
        Ok(())
    }

    /// Mark `slot` consumed. Ok(false) if it already was. On a journal write
    /// error the slot is not marked and the error is returned (the caller must
    /// refuse the session).
    pub fn try_consume(&self, slot: &Slot) -> Result<bool> {
        let mut g = self.inner.lock().unwrap();
        if g.consumed.contains(slot) {
            return Ok(false);
        }
        if let Some(f) = g.journal.as_mut() {
            use std::io::Write;
            f.write_all(&journal_line(b'C', slot))?;
            f.sync_data()?;
        }
        g.consumed.insert(*slot);
        Ok(true)
    }

    /// Release `slot` (completed exchange with a non-200 status). On a journal
    /// write error the slot stays consumed (fail closed).
    pub fn release(&self, slot: &Slot) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if !g.consumed.contains(slot) {
            return Ok(());
        }
        if let Some(f) = g.journal.as_mut() {
            use std::io::Write;
            f.write_all(&journal_line(b'R', slot))?;
            f.sync_data()?;
        }
        g.consumed.remove(slot);
        Ok(())
    }

    /// Record that an attestation for `slot` was signed, *before* it is sent: a
    /// crash in between shows as "signed" (a visible missing run), never as an
    /// unrecorded attestation. On a journal write error the attestation must not
    /// be sent.
    pub fn mark_signed(&self, slot: &Slot) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if !g.consumed.contains(slot) {
            bail!("slot {} is not consumed", short(slot));
        }
        if let Some(f) = g.journal.as_mut() {
            use std::io::Write;
            f.write_all(&journal_line(b'D', slot))?;
            f.sync_data()?;
        }
        Ok(())
    }

    pub fn is_consumed(&self, slot: &Slot) -> bool {
        self.inner.lock().unwrap().consumed.contains(slot)
    }
}

const INTENT_PREFIX: &[u8] = b"PH-INTENT ";
/// Longest opening line (`PH-AUTH`, `PH-INTENT` or `PH-PREREG`, which holds two
/// hashes).
const LINE_MAX: usize = 256;

fn intent_line(slot: &Slot) -> Vec<u8> {
    format!("PH-INTENT {}\n", slot.to_text()).into_bytes()
}

fn parse_intent(line: &[u8]) -> Option<Slot> {
    let rest = line.strip_prefix(INTENT_PREFIX)?;
    Slot::parse_text(std::str::from_utf8(rest).ok()?)
}

/// Read one line byte by byte (so no TLSNotary bytes are consumed).
async fn read_line<S: AsyncRead + Unpin>(socket: &mut S) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut line = Vec::new();
    loop {
        let b = socket.read_u8().await?;
        if b == b'\n' {
            return Ok(line);
        }
        line.push(b);
        if line.len() > LINE_MAX {
            bail!("opening line too long");
        }
    }
}

const AUTH_PREFIX: &[u8] = b"PH-AUTH ";

/// Operators allowed to request notarizations (empty: anyone may).
#[derive(Clone, Default)]
pub struct NotaryAccess {
    tokens: Vec<Vec<u8>>,
}

impl NotaryAccess {
    pub fn open() -> Self {
        Self::default()
    }

    /// One token per line (blank lines ignored); each at least 16 bytes.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let tokens: Vec<Vec<u8>> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| l.as_bytes().to_vec())
            .collect();
        if tokens.is_empty() || tokens.iter().any(|t| t.len() < 16) {
            bail!("{}: tokens must be at least 16 bytes", path.display());
        }
        Ok(Self { tokens })
    }

    fn required(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// Constant-time in the token contents.
    fn allows(&self, presented: &[u8]) -> bool {
        self.tokens.iter().fold(false, |any, t| {
            let same_len = t.len() == presented.len();
            let diff = t.iter().zip(presented).fold(0u8, |d, (a, b)| d | (a ^ b));
            any | (same_len & (diff == 0))
        })
    }
}

const PREREG_PREFIX: &[u8] = b"PH-PREREG ";

/// What a connection asks for.
enum Opening {
    /// Notarize one exchange under this slot.
    Intent(Slot),
    /// Time-stamp an eval pre-registration: (suite hash, pre-registration hash).
    Prereg([u8; 32], [u8; 32]),
}

fn parse_prereg(line: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let rest = std::str::from_utf8(line.strip_prefix(PREREG_PREFIX)?).ok()?;
    let (suite, prereg) = rest.split_once(' ')?;
    if !is_hex64(suite) || !is_hex64(prereg) {
        return None;
    }
    Some((ph_core::hash::from_hex32(suite)?, ph_core::hash::from_hex32(prereg)?))
}

/// Read the optional `PH-AUTH <token>` line and the request line.
async fn read_opening<S: AsyncRead + Unpin>(socket: &mut S, access: &NotaryAccess) -> Result<Opening> {
    let mut line = read_line(socket).await?;
    let mut authed = !access.required();
    if let Some(token) = line.strip_prefix(AUTH_PREFIX) {
        authed |= access.allows(token);
        line = read_line(socket).await?;
    }
    if !authed {
        bail!("operator not authorized");
    }
    if let Some((suite, prereg)) = parse_prereg(&line) {
        return Ok(Opening::Prereg(suite, prereg));
    }
    parse_intent(&line).map(Opening::Intent).ok_or_else(|| anyhow!("malformed intent line"))
}

/// Journal a pre-registration with the notary's clock, then sign the receipt:
/// `OK <time> <signature hex>`.
fn prereg_receipt(state: &NotaryState, secret: &[u8; 32], suite: &[u8; 32], prereg: &[u8; 32]) -> Result<String> {
    use k256::ecdsa::signature::Signer as _;
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    state.record_prereg(&PreregRecord {
        suite: hex::encode(suite),
        prereg: hex::encode(prereg),
        time,
    })?;
    let sk = k256::ecdsa::SigningKey::from_bytes(secret.into())?;
    let sig: k256::ecdsa::Signature = sk.sign(&ph_core::notary_log::prereg_receipt_digest(suite, prereg, time));
    Ok(format!("OK {time} {}\n", hex::encode(sig.to_vec())))
}

/// Largest attestation request the notary reads (a real one is a few KB).
const MAX_ATTESTATION_REQUEST: usize = 1 << 20;

/// Time allowed for the opening lines, and for the whole MPC-TLS exchange.
pub const OPENING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

pub fn notary_public_key(secret: &[u8; 32]) -> Result<Vec<u8>> {
    let sk = k256::ecdsa::SigningKey::from_bytes(secret.into())?;
    Ok(sk.verifying_key().to_encoded_point(true).as_bytes().to_vec())
}

fn ph_sig_alg() -> SignatureAlgId {
    SignatureAlgId::new(ph_core::zktls::PH_NOTARY_SIG_ALG_ID)
}

/// The ph notary's attestation signer: ECDSA secp256k1 / SHA-256 over
/// `PH_NOTARY_SIG_DOMAIN || header` (see `ph_core::zktls`). A generic TLSNotary
/// notary signs the bare header, so its signatures never count for the harness,
/// even if it shares this key.
pub struct PhNotarySigner(k256::ecdsa::SigningKey);

impl PhNotarySigner {
    pub fn new(secret: &[u8; 32]) -> Result<Self> {
        Ok(Self(k256::ecdsa::SigningKey::from_bytes(secret.into())?))
    }
}

impl Signer for PhNotarySigner {
    fn alg_id(&self) -> SignatureAlgId {
        ph_sig_alg()
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        use k256::ecdsa::signature::Signer as _;
        let sig: k256::ecdsa::Signature =
            self.0.sign(&ph_core::zktls::ph_notary_signed_message(msg));
        Ok(Signature {
            alg: ph_sig_alg(),
            data: sig.to_vec(),
        })
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            alg: KeyAlgId::K256,
            data: self.0.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
        }
    }
}

/// Prover-side check of the notary's signature (same scheme as the guest's).
struct PhNotaryVerifier;

impl SignatureVerifier for PhNotaryVerifier {
    fn alg_id(&self) -> SignatureAlgId {
        ph_sig_alg()
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
        vk.verify(&ph_core::zktls::ph_notary_signed_message(msg), &sig)
            .map_err(|_| SignatureError::from_str("ph notary signature verification failed"))
    }
}

fn prover_crypto_provider() -> CryptoProvider {
    let mut p = CryptoProvider::default();
    p.signature.set_verifier(Box::new(PhNotaryVerifier));
    p
}

/// Serve one prover connection. Signs an attestation (bound to the announced
/// slot) only if the slot is still free and, for model slots, the disclosed
/// request tail names the same slot.
pub async fn notary_session<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    mut socket: S,
    secret: [u8; 32],
    roots: RootCertStore,
    state: Arc<NotaryState>,
    access: Arc<NotaryAccess>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let intent = match tokio::time::timeout(OPENING_TIMEOUT, read_opening(&mut socket, &access)).await {
        Ok(Ok(Opening::Intent(slot))) => slot,
        Ok(Ok(Opening::Prereg(suite, prereg))) => {
            let reply = match prereg_receipt(&state, &secret, &suite, &prereg) {
                Ok(r) => r,
                Err(e) => format!("REFUSED notary state unavailable: {e:#}\n"),
            };
            socket.write_all(reply.as_bytes()).await?;
            eprintln!("[notary] pre-registration {}.. for suite {}..", &hex::encode(prereg)[..8], &hex::encode(suite)[..8]);
            return Ok(());
        }
        Ok(Err(e)) => {
            let _ = socket.write_all(format!("REFUSED {e}\n").as_bytes()).await;
            return Err(e);
        }
        Err(_) => bail!("opening timed out"),
    };
    let refusal = match state.try_consume(&intent) {
        Ok(true) => None,
        Ok(false) => Some(format!("slot {} was already used (no re-rolls)", short(&intent))),
        Err(e) => Some(format!("notary state unavailable: {e:#}")),
    };
    if let Some(reason) = refusal {
        socket.write_all(format!("REFUSED {reason}\n").as_bytes()).await?;
        bail!(reason);
    }
    socket.write_all(b"OK\n").await?;
    // From here on the slot stays consumed unless a model exchange completes
    // with a non-200 status.
    // A timeout burns the slot, like any other abort.
    let result = match tokio::time::timeout(
        SESSION_TIMEOUT,
        notary_mpc(socket, secret, roots, &intent, &state),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(anyhow!("MPC-TLS session timed out")),
    };
    if let (Ok(false), SlotKind::Model) = (&result, intent.kind) {
        if let Err(e) = state.release(&intent) {
            eprintln!("[notary] could not release slot (stays consumed): {e:#}");
        }
    }
    result.map(|_| ())
}

/// Returns Ok(false) only for a model exchange whose status was not 200 (the
/// caller then releases the slot); Ok(true) otherwise.
async fn notary_mpc<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    secret: [u8; 32],
    roots: RootCertStore,
    intent: &Slot,
    state: &NotaryState,
) -> Result<bool> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let verifier = match handle
        .new_verifier(VerifierConfig::builder().root_store(roots).build()?)?
        .commit()
        .await?
    {
        VerifierCommitStart::Mpc(v) => v.accept().await?.run().await?,
        VerifierCommitStart::Proxy(v) => {
            v.reject(Some("MPC-TLS only")).await?;
            bail!("prover requested proxy mode");
        }
    };
    let (
        VerifierOutput {
            transcript,
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    // --- model slots: disclosed request tail and response status ---
    let (ok, status_text) = match intent.kind {
        SlotKind::Tool => (true, "-".to_string()),
        SlotKind::Model => {
            let t = transcript.ok_or_else(|| anyhow!("prover disclosed nothing"))?;
            let (len_s, len_r) = (t.len_sent(), t.len_received());
            let sent_idx = t.sent_authed();
            let tail_len = sent_idx.len();
            if tail_len == 0 || sent_idx.end() != Some(len_s) || sent_idx.min() != Some(len_s - tail_len) {
                bail!("prover must disclose exactly one contiguous request tail");
            }
            let sent = t.sent_unsafe(len_s)?;
            let disclosed = parse_tail(&sent[len_s - tail_len..])
                .ok_or_else(|| anyhow!("disclosed request tail is not a ph session binding"))?;
            if disclosed != *intent {
                bail!("disclosed session binding does not match the announced intent");
            }
            let recv_idx = t.received_authed();
            if recv_idx.len() != STATUS_LEN || recv_idx.min() != Some(0) || recv_idx.end() != Some(STATUS_LEN) {
                bail!("prover must disclose exactly the response status prefix");
            }
            let recv = t.received_unsafe(len_r)?;
            let status = &recv[..STATUS_LEN];
            if !status.starts_with(b"HTTP/1.1 ") || !status[9..].iter().all(u8::is_ascii_digit) {
                bail!("disclosed response prefix is not an HTTP/1.1 status line");
            }
            (&status[9..] == b"200", String::from_utf8_lossy(&status[9..]).into_owned())
        }
    };

    let app_len = |recs: &[tlsn::transcript::Record]| -> usize {
        recs.iter()
            .filter(|r| matches!(r.typ, ContentType::ApplicationData))
            .map(|r| r.ciphertext.len())
            .sum()
    };
    let sent_len = app_len(tls_transcript.sent());
    let recv_len = app_len(tls_transcript.recv());

    handle.close();
    let mut socket = driver_task.await??;
    let mut req_bytes = Vec::new();
    (&mut socket).take(MAX_ATTESTATION_REQUEST as u64 + 1).read_to_end(&mut req_bytes).await?;
    if req_bytes.len() > MAX_ATTESTATION_REQUEST {
        bail!("attestation request larger than {MAX_ATTESTATION_REQUEST} bytes");
    }
    let request: AttestationRequest = bincode::deserialize(&req_bytes)?;

    let mut provider = CryptoProvider::default();
    provider
        .signer
        .set_signer(Box::new(PhNotarySigner::new(&secret)?));
    // Only the ph scheme; the default config also rejects all extensions.
    let mut acb = AttestationConfig::builder();
    acb.supported_signature_algs(vec![ph_sig_alg()]);
    let att_config = acb.build()?;
    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        bail!("unsupported certificate binding");
    };
    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments)
        // Written by the notary itself (prover-requested extensions are refused
        // by the default config): the slot this attestation was rationed under.
        .extension(Extension {
            id: SLOT_EXTENSION_ID.to_vec(),
            value: intent.extension_value(),
        });
    let attestation = builder.build(&provider)?;
    state.mark_signed(intent)?;
    socket.write_all(&bincode::serialize(&attestation)?).await?;
    socket.close().await?;
    eprintln!("[notary] signed: slot {} status {status_text}", short(intent));
    Ok(ok)
}

/// Build and sign the session log for `sessions` (hex) from a journal.
pub fn signed_session_log(
    journal: &std::path::Path,
    secret: &[u8; 32],
    sessions: &[String],
    now: u64,
) -> Result<ph_core::notary_log::SessionLog> {
    use k256::ecdsa::signature::Signer as _;
    let key = notary_public_key(secret)?;
    let Journal { histories, preregs, .. } = read_journal(journal, &key)?;
    let mut sessions: Vec<String> = sessions.to_vec();
    sessions.sort();
    sessions.dedup();
    for s in &sessions {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            bail!("session ids must be 64 lowercase hex characters");
        }
    }
    let mut slots: Vec<ph_core::notary_log::SlotHistory> = histories
        .into_iter()
        .filter(|(slot, _)| sessions.contains(&ph_core::hash::to_hex(&slot.session)))
        .map(|(slot, events)| ph_core::notary_log::SlotHistory { slot: slot.to_text(), events })
        .collect();
    slots.sort_by(|a, b| a.slot.cmp(&b.slot));
    let mut log = ph_core::notary_log::SessionLog {
        notary_key: key,
        generated_at: now,
        sessions,
        slots,
        preregs,
        signature: vec![],
    };
    let sk = k256::ecdsa::SigningKey::from_bytes(secret.into())?;
    let sig: k256::ecdsa::Signature = sk.sign(&log.digest());
    log.signature = sig.to_vec();
    Ok(log)
}

// ------------------------------------------------------------------ prover --

pub struct Target {
    /// TCP address to connect to, e.g. "api.anthropic.com:443" or "127.0.0.1:7443".
    pub addr: String,
    /// DNS name for SNI and certificate validation, e.g. "api.anthropic.com".
    pub server_name: String,
    pub roots: Roots,
}

/// Notarize a model call: the slot is read from the request's `user_id` tail.
pub async fn notarize(notary_addr: &str, target: &Target, request: Vec<u8>) -> Result<Vec<u8>> {
    let tail_start = request
        .windows(TAIL_PREFIX.len())
        .rposition(|w| w == TAIL_PREFIX)
        .ok_or_else(|| anyhow!("request has no session binding tail"))?;
    let slot = parse_tail(&request[tail_start..])
        .ok_or_else(|| anyhow!("request tail is not a ph session binding"))?;
    notarize_slot(notary_addr, target, request, slot, Some(tail_start)).await
}

/// Notarize an HTTPS tool call under its (session, seq) slot. Nothing is
/// disclosed to the notary.
pub async fn notarize_tool(
    notary_addr: &str,
    target: &Target,
    request: Vec<u8>,
    slot: Slot,
) -> Result<Vec<u8>> {
    if slot.kind != SlotKind::Tool {
        bail!("not a tool slot");
    }
    notarize_slot(notary_addr, target, request, slot, None).await
}

/// Send `request` (exact bytes) over MPC-TLS under `slot` and return a
/// full-disclosure presentation (bincode). `model_tail`: start of the
/// `user_id` tail to disclose, together with the status prefix (model slots).
async fn notarize_slot(
    notary_addr: &str,
    target: &Target,
    request: Vec<u8>,
    slot: Slot,
    model_tail: Option<usize>,
) -> Result<Vec<u8>> {
    if request.len() > MAX_SENT {
        bail!("request is {} bytes, above the {MAX_SENT} MPC-TLS limit", request.len());
    }
    let mut notary = tokio::net::TcpStream::connect(notary_addr)
        .await
        .with_context(|| format!("connecting to notary {notary_addr}"))?;
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if let Ok(token) = std::env::var("PH_NOTARY_TOKEN") {
            notary.write_all(format!("PH-AUTH {token}\n").as_bytes()).await?;
        }
        notary.write_all(&intent_line(&slot)).await?;
        let mut reply = Vec::new();
        loop {
            let b = notary.read_u8().await.context("notary closed during intent")?;
            if b == b'\n' || reply.len() > 256 {
                break;
            }
            reply.push(b);
        }
        if reply != b"OK" {
            bail!("notary refused: {}", String::from_utf8_lossy(&reply));
        }
    }
    let session = Session::new(notary.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT)
                .max_recv_data(MAX_RECV)
                .build()?,
        )
        .await?;
    let tcp = tokio::net::TcpStream::connect(&target.addr)
        .await
        .with_context(|| format!("connecting to {}", target.addr))?;
    tcp.set_nodelay(true)?;
    let server_name = ServerName::Dns(target.server_name.as_str().try_into()?);
    let (mut tls, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(server_name.clone())
            .root_store(target.roots.store())
            .build()?,
        tcp.compat(),
    )?;
    let prover_task = tokio::spawn(prover.into_future());
    tls.write_all(&request).await?;
    tls.flush().await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    let _ = tls.close().await;
    let mut prover = prover_task.await??;

    let sent_len = prover.transcript().sent().len();
    let recv_len = prover.transcript().received().len();
    if sent_len != request.len() || recv_len < STATUS_LEN {
        bail!("unexpected transcript lengths (sent {sent_len}, received {recv_len})");
    }

    let mut cb = TranscriptCommitConfig::builder(prover.transcript());
    cb.commit_sent(&(0..sent_len))?;
    cb.commit_recv(&(0..recv_len))?;
    let commit = cb.build()?;
    let mut rcb = RequestConfig::builder();
    rcb.signature_alg(ph_sig_alg());
    rcb.transcript_commit(commit);
    let request_config = rcb.build()?;

    // Model slots: disclose only the session-binding tail and the status prefix.
    // Tool slots: disclose nothing.
    let mut pcb = ProveConfig::builder(prover.transcript());
    if let Some(c) = request_config.transcript_commit() {
        pcb.transcript_commit(c.clone());
    }
    if let Some(tail_start) = model_tail {
        pcb.reveal_sent(tail_start..sent_len)?;
        pcb.reveal_recv(0..STATUS_LEN)?;
    }
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&pcb.build()?).await?;
    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut ab = AttestationRequest::builder(&request_config);
    ab.server_name(server_name)
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .ok_or_else(|| anyhow!("no server cert chain"))?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .ok_or_else(|| anyhow!("no server signature"))?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (att_request, secrets) = ab.build(&CryptoProvider::default())?;

    handle.close();
    let mut socket = driver_task.await??;
    socket.write_all(&bincode::serialize(&att_request)?).await?;
    socket.close().await?;
    let mut att_bytes = Vec::new();
    socket.read_to_end(&mut att_bytes).await?;
    if att_bytes.is_empty() {
        bail!("notary refused to sign (see notary log)");
    }
    let attestation: Attestation = bincode::deserialize(&att_bytes)?;
    att_request.validate(&attestation, &prover_crypto_provider())?;

    // Full-disclosure presentation for the (private) zkVM witness.
    let mut tb = secrets.transcript_proof_builder();
    tb.reveal_sent(&(0..sent_len))?;
    tb.reveal_recv(&(0..recv_len))?;
    let transcript_proof = tb.build()?;
    let provider = CryptoProvider::default();
    let mut pb = attestation.presentation_builder(&provider);
    pb.identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation: Presentation = pb.build()?;
    Ok(bincode::serialize(&presentation)?)
}

// ------------------------------------------------------------- mock server --

/// A TLS 1.2 stand-in for the Messages API, using the TLSNotary test-server
/// certificate (`test-server.io`, signed by the fixture CA). Replies are picked
/// by the step number in `metadata.user_id`.
///
/// Test hook: a reply of the form `!529:<text>` answers the first request for
/// that step with `529 overloaded` and later requests with `<text>`, to exercise
/// the notary's slot release and the host's retry.
pub async fn mock_server(listener: tokio::net::TcpListener, replies: Arc<Vec<String>>) -> Result<()> {
    let attempts: Arc<Mutex<std::collections::HashMap<usize, u32>>> = Arc::default();
    use futures_rustls::{
        pki_types::{CertificateDer as RCert, PrivateKeyDer},
        rustls::ServerConfig,
        TlsAcceptor,
    };
    use tlsn_server_fixture_certs::{SERVER_CERT_DER, SERVER_KEY_DER};
    let config = ServerConfig::builder_with_provider(Arc::new(
        futures_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&futures_rustls::rustls::version::TLS12])?
    .with_no_client_auth()
    .with_single_cert(
        vec![RCert::from(SERVER_CERT_DER.to_vec())],
        PrivateKeyDer::Pkcs8(SERVER_KEY_DER.to_vec().into()),
    )?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let replies = replies.clone();
        let attempts = attempts.clone();
        tokio::spawn(async move {
            if let Err(e) = mock_connection(acceptor, tcp, replies, attempts).await {
                eprintln!("[mock] connection error: {e:#}");
            }
        });
    }
}

async fn mock_connection(
    acceptor: futures_rustls::TlsAcceptor,
    tcp: tokio::net::TcpStream,
    replies: Arc<Vec<String>>,
    attempts: Arc<Mutex<std::collections::HashMap<usize, u32>>>,
) -> Result<()> {
    let mut tls = acceptor.accept(tcp.compat()).await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head_end, body_len) = loop {
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            bail!("client closed before sending a full request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_string();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .ok_or_else(|| anyhow!("no content-length"))?
                .trim()
                .parse::<usize>()?;
            break (i + 4, len);
        }
    };
    while buf.len() < head_end + body_len {
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            bail!("truncated body");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let req: serde_json::Value = serde_json::from_slice(&buf[head_end..head_end + body_len])?;
    let model = req["model"].as_str().unwrap_or("unknown").to_string();
    let user_id = req["metadata"]["user_id"].as_str().unwrap_or("");
    let step: usize = user_id.rsplit('-').next().unwrap_or("").parse().unwrap_or(usize::MAX);
    let attempt = {
        let mut a = attempts.lock().unwrap();
        let n = a.entry(step).or_insert(0);
        *n += 1;
        *n
    };
    let reply = replies.get(step).map(|r| match r.strip_prefix("!529:") {
        Some(text) if attempt == 1 => Err(text),
        Some(text) => Ok(text),
        None => Ok(r.as_str()),
    });
    let (status, body) = match reply {
        Some(Err(_)) => (
            "529 Overloaded",
            serde_json::json!({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}})
                .to_string(),
        ),
        Some(Ok(text)) => (
            "200 OK",
            serde_json::json!({
                "id": format!("msg_mock_{step}"),
                "type": "message",
                "role": "assistant",
                "model": model,
                // A scripted reply that is a JSON array is used as the content
                // blocks themselves (native tool use); anything else is text.
                "content": match serde_json::from_str::<serde_json::Value>(text) {
                    Ok(v @ serde_json::Value::Array(_)) => v,
                    _ => serde_json::json!([{"type": "text", "text": text}]),
                },
                "stop_reason": if text.contains("\"tool_use\"") { "tool_use" } else { "end_turn" },
                "stop_sequence": null,
                "usage": {"input_tokens": body_len / 4, "output_tokens": text.len() / 4},
            })
            .to_string(),
        ),
        None => (
            "400 Bad Request",
            serde_json::json!({"type": "error", "error": {"type": "invalid_request_error", "message": "no scripted reply"}})
                .to_string(),
        ),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(resp.as_bytes()).await?;
    tls.flush().await?;
    tls.close().await?;
    Ok(())
}

// ---------------------------------------------------------------- mock web --

/// A throwaway PKI for offline zkTLS tool tests: a fresh CA and one ECDSA P-256
/// leaf certificate whose SANs are all the mock hosts. The CA's DER is what the
/// verifier pins (`TlsRoots::Custom`); it is never trusted anywhere else.
pub struct DevWebPki {
    pub ca_der: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub hosts: Vec<String>,
}

pub fn dev_web_pki(hosts: &[String]) -> Result<DevWebPki> {
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    if hosts.is_empty() {
        bail!("no hosts for the dev web PKI");
    }
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.distinguished_name.push(DnType::CommonName, "provable-harness dev CA (tests only)");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.not_before = date_time_ymd(2025, 1, 1);
    ca.not_after = date_time_ymd(2035, 1, 1);
    let ca_cert = ca.self_signed(&ca_key)?;

    let leaf_key = KeyPair::generate()?;
    let mut leaf = CertificateParams::new(hosts.to_vec())?;
    leaf.distinguished_name.push(DnType::CommonName, hosts[0].clone());
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.not_before = date_time_ymd(2025, 1, 1);
    leaf.not_after = date_time_ymd(2035, 1, 1);
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key)?;
    Ok(DevWebPki {
        ca_der: ca_cert.der().to_vec(),
        cert_der: leaf_cert.der().to_vec(),
        key_der: leaf_key.serialize_der(),
        hosts: hosts.to_vec(),
    })
}

/// The fixture "internet": exact `https://` URL -> response body, as in a
/// scenario's `world.json` (`{"get": {...}, "post": {...}}`).
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct MockWorld {
    #[serde(default)]
    pub get: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub post: std::collections::BTreeMap<String, String>,
}

impl MockWorld {
    /// Every host named by the world's URLs (all must be valid `https://` URLs).
    pub fn hosts(&self) -> Result<Vec<String>> {
        let mut hosts = std::collections::BTreeSet::new();
        for url in self.get.keys().chain(self.post.keys()) {
            let u = ph_core::http::parse_https_url(url).map_err(|e| anyhow!("world url {url}: {e}"))?;
            hosts.insert(u.host);
        }
        Ok(hosts.into_iter().collect())
    }
}

/// A TLS 1.2 mock of the world's websites. GET answers 200 with the mapped body
/// (Content-Length framing); POST answers 202 with the mapped body (chunked
/// framing, to exercise that path); unknown URLs get 404.
pub async fn mock_web_server(
    listener: tokio::net::TcpListener,
    pki: Arc<DevWebPki>,
    world: Arc<MockWorld>,
) -> Result<()> {
    use futures_rustls::{
        pki_types::{CertificateDer as RCert, PrivateKeyDer},
        rustls::ServerConfig,
        TlsAcceptor,
    };
    let config = ServerConfig::builder_with_provider(Arc::new(
        futures_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&futures_rustls::rustls::version::TLS12])?
    .with_no_client_auth()
    .with_single_cert(
        vec![RCert::from(pki.cert_der.clone())],
        PrivateKeyDer::Pkcs8(pki.key_der.clone().into()),
    )?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    loop {
        let (tcp, _) = listener.accept().await?;
        let (acceptor, world) = (acceptor.clone(), world.clone());
        tokio::spawn(async move {
            if let Err(e) = mock_web_connection(acceptor, tcp, world).await {
                eprintln!("[web] connection error: {e:#}");
            }
        });
    }
}

async fn mock_web_connection(
    acceptor: futures_rustls::TlsAcceptor,
    tcp: tokio::net::TcpStream,
    world: Arc<MockWorld>,
) -> Result<()> {
    let mut tls = acceptor.accept(tcp.compat()).await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            bail!("client closed before sending a full request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end - 4]).to_string();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split(' ');
    let (method, target) = (request_line.next().unwrap_or(""), request_line.next().unwrap_or(""));
    let mut host = "";
    let mut body_len = 0usize;
    for l in lines {
        if let Some(v) = l.strip_prefix("host: ") {
            host = v;
        } else if let Some(v) = l.strip_prefix("content-length: ") {
            body_len = v.trim().parse()?;
        }
    }
    while buf.len() < head_end + body_len {
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            bail!("truncated body");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let url = format!("https://{host}{target}");
    let resp: Vec<u8> = match (method, world.get.get(&url), world.post.get(&url)) {
        ("GET", Some(body), _) => format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
        ("POST", _, Some(body)) => {
            // Two chunks (split on bytes; empty chunks would end the body early).
            let mut r = b"HTTP/1.1 202 Accepted\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n".to_vec();
            let bytes = body.as_bytes();
            let (a, b) = bytes.split_at(bytes.len() / 2);
            for part in [a, b] {
                if !part.is_empty() {
                    r.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                    r.extend_from_slice(part);
                    r.extend_from_slice(b"\r\n");
                }
            }
            r.extend_from_slice(b"0\r\n\r\n");
            r
        }
        _ => b"HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: 13\r\nconnection: close\r\n\r\n404 not found".to_vec(),
    };
    tls.write_all(&resp).await?;
    tls.flush().await?;
    tls.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{intent_line, parse_intent, parse_tail, NotaryState};
    use ph_core::Slot;

    fn tmp_journal(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ph-notary-{}-{name}.log", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn journal_survives_restart() {
        let path = tmp_journal("restart");
        let (a, b) = (Slot::model(&[0xaa; 32], 1), Slot::tool(&[0xbb; 32], 2));
        // Same session and number, other kind: an independent slot.
        let a_tool = Slot::tool(&[0xaa; 32], 1);
        {
            let s = NotaryState::open(&path, &[2u8; 33]).unwrap();
            assert!(s.try_consume(&a).unwrap());
            assert!(!s.try_consume(&a).unwrap());
            assert!(s.try_consume(&a_tool).unwrap());
            assert!(s.try_consume(&b).unwrap());
            s.release(&b).unwrap();
        }
        let s = NotaryState::open(&path, &[2u8; 33]).unwrap();
        assert!(NotaryState::open(&path, &[2u8; 33]).is_err(), "journal must be exclusively locked");
        assert!(s.is_consumed(&a) && s.is_consumed(&a_tool), "consumed slots stay consumed after restart");
        assert!(!s.is_consumed(&b), "released slot must stay released");
        assert!(!s.try_consume(&a).unwrap());
        assert!(s.try_consume(&b).unwrap());
        drop(s);
        // A torn final append is dropped; later appends stay well-formed.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"C tool cc"))
            .unwrap();
        let s = NotaryState::open(&path, &[2u8; 33]).unwrap();
        let c = Slot::tool(&[0xcc; 32], 3);
        assert!(s.try_consume(&c).unwrap());
        drop(s);
        let s = NotaryState::open(&path, &[2u8; 33]).unwrap();
        assert!(s.is_consumed(&a) && s.is_consumed(&b) && s.is_consumed(&c));
        drop(s);
        assert!(NotaryState::open(&path, &[3u8; 33]).is_err(), "journal is bound to its notary key");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_journal_is_rejected() {
        let hex = "ab".repeat(32);
        let header = format!("{} {}\n", super::JOURNAL_HEADER, "02".repeat(33));
        // Control: a well-formed journal with every record kind opens, and its
        // histories read back (so the cases below fail for their own reason).
        let good = format!("C model {hex} 1\nD model {hex} 1\nR model {hex} 1\nC model {hex} 1\nD model {hex} 1\nC tool {hex} 2\nP {hex} {hex} 1795300000\n");
        let path = tmp_journal("good");
        std::fs::write(&path, format!("{header}{good}")).unwrap();
        drop(NotaryState::open(&path, &[2u8; 33]).unwrap());
        let h = super::read_journal_histories(&path, &[2u8; 33]).unwrap();
        assert_eq!(h[&Slot::model(&[0xab; 32], 1)], "CDRCD");
        assert_eq!(h[&Slot::tool(&[0xab; 32], 2)], "C");
        assert_eq!(super::read_journal(&path, &[2u8; 33]).unwrap().preregs.len(), 1);
        assert!(super::read_journal_histories(&path, &[3u8; 33]).is_err());
        let _ = std::fs::remove_file(&path);
        for (with_header, bad) in [
            (true, format!("C model {hex} 1\n\nC model {hex} 2\n")),
            (true, format!("X model {hex} 1\n")),
            (true, format!("C model {hex} 1\nC model {hex} 1\n")),
            (true, format!("R tool {hex} 1\n")),
            (true, format!("C model {hex} 01\n")),
            (true, format!("C {hex} 1\n")),
            // D only for a consumed slot.
            (true, format!("D model {hex} 1\n")),
            (true, format!("C model {hex} 1\nR model {hex} 1\nD model {hex} 1\n")),
            // Pre-registrations: two hashes and a decimal time.
            (true, format!("P {hex} {hex}\n")),
            (true, format!("P {hex} {hex} 01\n")),
            (true, format!("P {hex} {} 1\n", "AB".repeat(32))),
            (true, format!("P {hex} {hex} 1 2\n")),
            // Old journals are refused rather than misread (v2 has no D records).
            (false, format!("K {}\nC {hex} 1\n", "02".repeat(33))),
            (false, format!("PH-NOTARY-JOURNAL v2 {}\nC model {hex} 1\n", "02".repeat(33))),
            (false, format!("PH-NOTARY-JOURNAL v3 {}\nC model {hex} 1\n", "02".repeat(33))),
        ] {
            let path = tmp_journal("corrupt");
            let text = if with_header { format!("{header}{bad}") } else { bad.clone() };
            std::fs::write(&path, text).unwrap();
            assert!(NotaryState::open(&path, &[2u8; 33]).is_err(), "{bad:?}");
            let _ = std::fs::remove_file(&path);
        }
    }

    /// A pre-registration receipt verifies under the notary key with ph-core's
    /// check, and the session log lists every pre-registration.
    #[test]
    fn prereg_receipt_and_log() {
        let path = tmp_journal("prereg");
        let secret = [7u8; 32];
        let key = super::notary_public_key(&secret).unwrap();
        let state = NotaryState::open(&path, &key).unwrap();
        let (suite, prereg) = ([1u8; 32], [2u8; 32]);
        let reply = super::prereg_receipt(&state, &secret, &suite, &prereg).unwrap();
        let mut it = reply.trim_end().split(' ');
        assert_eq!(it.next(), Some("OK"));
        let time: u64 = it.next().unwrap().parse().unwrap();
        let sig = hex::decode(it.next().unwrap()).unwrap();
        let pinned = ph_core::NotaryKey { alg: "k256".into(), key: key.clone() };
        let v = |s: &[u8; 32], p: &[u8; 32], t| ph_core::notary_log::verify_prereg_receipt(&pinned, s, p, t, &sig);
        assert!(v(&suite, &prereg, time).is_ok());
        assert!(v(&suite, &prereg, time - 1).is_err());
        assert!(v(&prereg, &suite, time).is_err());
        drop(state);
        let log = super::signed_session_log(&path, &secret, &["ab".repeat(32)], time).unwrap();
        assert!(log.verify(&pinned).is_ok());
        assert_eq!(log.preregs.len(), 1);
        assert_eq!((log.preregs[0].suite.as_str(), log.preregs[0].time), (hex::encode(suite).as_str(), time));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn intent_roundtrip() {
        for slot in [Slot::model(&[0x0f; 32], 7), Slot::tool(&[0x0f; 32], u64::MAX)] {
            let line = intent_line(&slot);
            assert!(line.len() <= super::LINE_MAX + 1);
            assert_eq!(parse_intent(&line[..line.len() - 1]), Some(slot));
        }
        let hex = "0f".repeat(32);
        for bad in [
            format!("PH-INTENT model {hex} 07"),
            format!("PH-INTENT model {} 1", "0F".repeat(32)),
            format!("PH-INTENT {hex} 1"),
            "PH-INTENT tool x 1".to_string(),
        ] {
            assert_eq!(parse_intent(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn tail_parsing() {
        let hex = "ab".repeat(32);
        let ok = format!(",\"metadata\":{{\"user_id\":\"ph-{hex}-12\"}}}}");
        assert_eq!(parse_tail(ok.as_bytes()), Some(Slot::model(&[0xab; 32], 12)));
        for bad in [
            format!(",\"metadata\":{{\"user_id\":\"ph-{hex}-012\"}}}}"),
            format!(",\"metadata\":{{\"user_id\":\"ph-{hex}-\"}}}}"),
            format!(",\"metadata\":{{\"user_id\":\"ph-{}-1\"}}}}", "AB".repeat(32)),
            format!(",\"metadata\":{{\"user_id\":\"ph-{hex}-1\"}}}} "),
            format!("x,\"metadata\":{{\"user_id\":\"ph-{hex}-1\"}}}}"),
            format!(",\"metadata\":{{\"user_id\":\"ph-{hex}-4294967296\"}}}}"),
        ] {
            assert_eq!(parse_tail(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn tail_matches_ph_core_body() {
        let sid = [0x5au8; 32];
        let body = ph_core::anthropic::request_body("m", 8, "s", "", &[], &sid, 3);
        let start = body.rfind(",\"metadata\"").unwrap();
        assert_eq!(parse_tail(&body.as_bytes()[start..]), Some(Slot::model(&sid, 3)));
    }
}
