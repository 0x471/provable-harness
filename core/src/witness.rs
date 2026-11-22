//! Witness replay: the backends used inside the zkVM.
//!
//! The witness is fully adversarial (the operator produces it). It contains only
//! *responses* (model texts, tool results) plus signatures. Every request digest
//! that a signature is checked against is computed by the harness from its own
//! state, never read from the witness.

use std::cell::RefCell;
use std::rc::Rc;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::anthropic::request_body;
use crate::protocol::{
    model_attestation_digest, model_response_hash, tool_attestation_digest, ModelQuery, ToolCall,
    ToolResult,
};
use crate::zktls::{
    crypto_provider, provider_for_roots, verify_model_exchange, verify_tool_exchange, ModelAuth,
    Slot, ToolAuth, ToolTlsConfig, ZkTlsConfig,
};
use crate::hash::Digest;
use crate::session::{run_session, SessionInput, SessionOutput};
use crate::{HarnessError, ModelBackend, ToolBackend};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedText {
    pub text: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedToolResult {
    pub result: ToolResult,
    pub signature: Vec<u8>,
}

/// Evidence for one model reply; its kind must match `SessionInput::model_auth`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelEvidence {
    /// Gateway mode: reply text + Ed25519 signature.
    Signed(SignedText),
    /// zkTLS mode: a bincode-encoded TLSNotary presentation (full disclosure,
    /// including the API key: the witness must stay private).
    Tls(Vec<u8>),
}

/// Evidence for one external tool call; its kind must match `SessionInput::tool_auth`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolEvidence {
    /// Oracle mode: the result + Ed25519 signature.
    Signed(SignedToolResult),
    /// zkTLS mode: a bincode-encoded TLSNotary presentation of the exchange with
    /// the target server (full disclosure); the result is derived from it.
    Tls(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    /// `FORMAT_VERSION` of the build that wrote it (first field, so readers can
    /// check it before decoding the rest).
    pub version: u32,
    pub input: SessionInput,
    /// Private seed salting the action log's commitments.
    pub blind: Digest,
    pub model_responses: Vec<ModelEvidence>,
    pub tool_results: Vec<ToolEvidence>,
}

impl Witness {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("witness serialization cannot fail")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        crate::check_format_prefix(b, 0)?;
        bincode::deserialize(b).map_err(|e| format!("malformed witness: {e}"))
    }
}

pub fn verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, HarnessError> {
    VerifyingKey::from_bytes(bytes)
        .map_err(|e| HarnessError::InvalidInput(format!("bad public key: {e}")))
}

/// Strict Ed25519 verification (rejects non-canonical and small-order inputs).
pub fn verify_signature(key: &VerifyingKey, digest: &Digest, sig: &[u8]) -> Result<(), String> {
    let sig = Signature::from_slice(sig).map_err(|e| format!("malformed signature: {e}"))?;
    key.verify_strict(digest, &sig)
        .map_err(|_| "invalid signature".to_string())
}

pub fn sign_digest(key: &SigningKey, digest: &Digest) -> Vec<u8> {
    key.sign(digest).to_bytes().to_vec()
}

enum ModelVerifier {
    Gateway(VerifyingKey),
    ZkTls {
        config: ZkTlsConfig,
        provider: Rc<tlsn_attestation::CryptoProvider>,
    },
}

pub struct WitnessModel {
    verifier: ModelVerifier,
    responses: std::vec::IntoIter<ModelEvidence>,
    times: Option<(u64, u64)>,
    truncated: bool,
}

impl WitnessModel {
    pub fn new(auth: &ModelAuth, responses: Vec<ModelEvidence>) -> Result<Self, HarnessError> {
        Self::with_provider(auth, Self::shared_provider(auth)?, responses)
    }

    /// The crypto provider for `auth` (zkTLS only), to share between sessions:
    /// it carries the verified-chain cache.
    pub fn shared_provider(
        auth: &ModelAuth,
    ) -> Result<Option<Rc<tlsn_attestation::CryptoProvider>>, HarnessError> {
        Ok(match auth {
            ModelAuth::Gateway { .. } => None,
            ModelAuth::ZkTls(c) => Some(Rc::new(crypto_provider(c).map_err(HarnessError::InvalidInput)?)),
        })
    }

    /// `provider` must come from `shared_provider` for the same `auth`.
    pub fn with_provider(
        auth: &ModelAuth,
        provider: Option<Rc<tlsn_attestation::CryptoProvider>>,
        responses: Vec<ModelEvidence>,
    ) -> Result<Self, HarnessError> {
        let verifier = match (auth, provider) {
            (ModelAuth::Gateway { key }, _) => ModelVerifier::Gateway(verifying_key(key)?),
            (ModelAuth::ZkTls(c), Some(provider)) => ModelVerifier::ZkTls {
                provider,
                config: c.clone(),
            },
            (ModelAuth::ZkTls(_), None) => {
                return Err(HarnessError::InvalidInput("zkTLS model auth needs a provider".into()))
            }
        };
        Ok(Self {
            verifier,
            responses: responses.into_iter(),
            times: None,
            truncated: false,
        })
    }
}

/// Verify one zkTLS model step and return the reply text, the notarized time,
/// and whether the reply stopped at `max_tokens`. Shared by the replay backend
/// and the host's live backend.
pub fn verify_zktls_step(
    provider: &tlsn_attestation::CryptoProvider,
    config: &ZkTlsConfig,
    q: &ModelQuery<'_>,
    presentation: &[u8],
) -> Result<(String, u64, bool), HarnessError> {
    let body = request_body(
        &config.model,
        config.max_tokens,
        q.system_prompt,
        q.tools,
        q.messages,
        q.session_id,
        q.step,
    );
    let slot = Slot::model(q.session_id, q.step);
    let (reply, time) = verify_model_exchange(provider, config, presentation, &body, &slot, !q.tools.is_empty())
        .map_err(|e| HarnessError::Attestation(format!("zkTLS model reply for step {}: {e}", q.step)))?;
    Ok((reply.text, time, reply.stop_reason == "max_tokens"))
}

pub fn widen(range: Option<(u64, u64)>, t: u64) -> Option<(u64, u64)> {
    Some(match range {
        None => (t, t),
        Some((a, b)) => (a.min(t), b.max(t)),
    })
}

impl ModelBackend for WitnessModel {
    fn complete(&mut self, q: &ModelQuery<'_>) -> Result<String, HarnessError> {
        let r = self.responses.next().ok_or_else(|| {
            HarnessError::Witness(format!("no model response for step {}", q.step))
        })?;
        self.truncated = false;
        match (&self.verifier, r) {
            (ModelVerifier::Gateway(key), ModelEvidence::Signed(r)) => {
                let digest =
                    model_attestation_digest(&q.request_hash, &model_response_hash(&r.text));
                verify_signature(key, &digest, &r.signature).map_err(|e| {
                    HarnessError::Attestation(format!("model response for step {}: {e}", q.step))
                })?;
                Ok(r.text)
            }
            (ModelVerifier::ZkTls { config, provider }, ModelEvidence::Tls(bytes)) => {
                let (text, time, truncated) = verify_zktls_step(provider, config, q, &bytes)?;
                self.times = widen(self.times, time);
                self.truncated = truncated;
                Ok(text)
            }
            _ => Err(HarnessError::Witness(format!(
                "model evidence for step {} does not match the session's model_auth",
                q.step
            ))),
        }
    }

    fn attested_time_range(&self) -> Option<(u64, u64)> {
        self.times
    }

    fn truncated(&self) -> bool {
        self.truncated
    }

    fn finish(&mut self) -> Result<(), HarnessError> {
        match self.responses.len() {
            0 => Ok(()),
            n => Err(HarnessError::Witness(format!("{n} unused model responses"))),
        }
    }
}

enum ToolVerifier {
    Oracle(VerifyingKey),
    Fixture(crate::eval::World),
    ZkTls {
        config: ToolTlsConfig,
        provider: tlsn_attestation::CryptoProvider,
    },
}

pub struct WitnessTools {
    verifier: ToolVerifier,
    results: std::vec::IntoIter<ToolEvidence>,
    times: Option<(u64, u64)>,
}

impl WitnessTools {
    pub fn new(auth: &ToolAuth, results: Vec<ToolEvidence>) -> Result<Self, HarnessError> {
        let verifier = match auth {
            ToolAuth::Oracle { key } => ToolVerifier::Oracle(verifying_key(key)?),
            ToolAuth::ZkTls(c) => ToolVerifier::ZkTls {
                provider: provider_for_roots(&c.roots).map_err(HarnessError::InvalidInput)?,
                config: c.clone(),
            },
            ToolAuth::Fixture(world) => ToolVerifier::Fixture(world.clone()),
        };
        Ok(Self {
            verifier,
            results: results.into_iter(),
            times: None,
        })
    }
}

/// Verify one zkTLS tool call and return its result and notarized time.
/// Shared by the replay backend and the host's live backend.
pub fn verify_tool_step(
    provider: &tlsn_attestation::CryptoProvider,
    config: &ToolTlsConfig,
    call: &ToolCall,
    presentation: &[u8],
) -> Result<(ToolResult, u64), HarnessError> {
    verify_tool_exchange(provider, config, call, presentation).map_err(|e| {
        HarnessError::Attestation(format!(
            "zkTLS tool result for external call #{} ({}): {e}",
            call.seq, call.tool
        ))
    })
}

impl ToolBackend for WitnessTools {
    fn call(&mut self, call: &ToolCall) -> Result<ToolResult, HarnessError> {
        // Fixture results come from the committed world itself, not the witness.
        if let ToolVerifier::Fixture(world) = &mut self.verifier {
            return Ok(world.respond(call));
        }
        let r = self.results.next().ok_or_else(|| {
            HarnessError::Witness(format!("no tool result for external call #{}", call.seq))
        })?;
        match (&self.verifier, r) {
            (ToolVerifier::Oracle(key), ToolEvidence::Signed(r)) => {
                let digest = tool_attestation_digest(&call.hash(), &r.result.hash());
                verify_signature(key, &digest, &r.signature).map_err(|e| {
                    HarnessError::Attestation(format!(
                        "tool result for external call #{} ({}): {e}",
                        call.seq, call.tool
                    ))
                })?;
                Ok(r.result)
            }
            (ToolVerifier::ZkTls { config, provider }, ToolEvidence::Tls(bytes)) => {
                let (result, time) = verify_tool_step(provider, config, call, &bytes)?;
                self.times = widen(self.times, time);
                Ok(result)
            }
            _ => Err(HarnessError::Witness(format!(
                "tool evidence for external call #{} does not match the session's tool_auth",
                call.seq
            ))),
        }
    }

    fn attested_time_range(&self) -> Option<(u64, u64)> {
        self.times
    }

    fn finish(&mut self) -> Result<(), HarnessError> {
        match self.results.len() {
            0 => Ok(()),
            n => Err(HarnessError::Witness(format!("{n} unused tool results"))),
        }
    }

    fn fixture_world(&self) -> Option<crate::eval::World> {
        match &self.verifier {
            ToolVerifier::Fixture(world) => Some(world.clone()),
            _ => None,
        }
    }
}

/// What the zkVM guest runs: replay the session from the witness, checking
/// every attestation, and return the claim to commit.
pub fn verify_witness(w: &Witness) -> Result<SessionOutput, HarnessError> {
    let mut model = WitnessModel::new(&w.input.model_auth, w.model_responses.clone())?;
    let tools = Rc::new(RefCell::new(WitnessTools::new(
        &w.input.tool_auth,
        w.tool_results.clone(),
    )?));
    if w.version != crate::FORMAT_VERSION {
        return Err(HarnessError::Witness(format!(
            "witness format v{} (this harness reads v{})",
            w.version,
            crate::FORMAT_VERSION
        )));
    }
    run_session(&w.input, &w.blind, &mut model, tools)
}
