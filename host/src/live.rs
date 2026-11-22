//! Live backends used by the operator's host: talk to the gateway / oracle or
//! the MPC-TLS proxy, check each attestation immediately with the guest's own
//! code (the guest re-checks it), and record the witness.

use std::cell::RefCell;
use std::rc::Rc;

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use ph_core::hash::from_hex;
use ph_core::protocol::{
    model_attestation_digest, model_response_hash, tool_attestation_digest,
};
use ph_core::anthropic::parse_http_response;
use ph_core::witness::{verify_signature, verify_tool_step, verify_zktls_step, verifying_key, widen};
use ph_core::zktls::{crypto_provider, provider_for_roots, verify_presentation};
use ph_core::{
    HarnessError, ModelAuth, ModelBackend, ModelEvidence, ModelQuery, SessionInput,
    SessionOutput, SignedText, SignedToolResult, ToolAuth, ToolBackend, ToolCall, ToolEvidence,
    ToolResult, ToolTlsConfig, Witness, ZkTlsConfig,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::services::{ModelReply, ToolReply};

fn post<T: Serialize, R: DeserializeOwned>(url: &str, body: &T) -> Result<R, HarnessError> {
    match ureq::post(url).send_json(body) {
        Ok(resp) => resp
            .into_json::<R>()
            .map_err(|e| HarnessError::Backend(format!("{url}: bad response: {e}"))),
        Err(ureq::Error::Status(code, resp)) => Err(HarnessError::Backend(format!(
            "{url}: HTTP {code}: {}",
            resp.into_string().unwrap_or_default()
        ))),
        Err(e) => Err(HarnessError::Backend(format!("{url}: {e}"))),
    }
}

fn decode_sig(hex: &str) -> Result<Vec<u8>, HarnessError> {
    from_hex(hex).ok_or_else(|| HarnessError::Backend("signature is not hex".into()))
}

pub struct LiveModel {
    url: String,
    key: VerifyingKey,
    pub recorded: Vec<ModelEvidence>,
}

impl ModelBackend for LiveModel {
    fn complete(&mut self, q: &ModelQuery<'_>) -> Result<String, HarnessError> {
        let reply: ModelReply = post(&format!("{}/v1/model", self.url), &q.to_request())?;
        let sig = decode_sig(&reply.signature)?;
        let digest = model_attestation_digest(&q.request_hash, &model_response_hash(&reply.text));
        verify_signature(&self.key, &digest, &sig)
            .map_err(|e| HarnessError::Attestation(format!("gateway step {}: {e}", q.step)))?;
        self.recorded.push(ModelEvidence::Signed(SignedText {
            text: reply.text.clone(),
            signature: sig,
        }));
        Ok(reply.text)
    }
}

/// zkTLS mode: the operator's MPC-TLS proxy calls the model API with a notary
/// and returns a presentation; it is verified here with exactly the guest's code.
pub struct LiveZkTlsModel {
    proxy: String,
    config: ZkTlsConfig,
    provider: ph_core::zktls::CryptoProvider,
    pub recorded: Vec<ModelEvidence>,
    times: Option<(u64, u64)>,
    truncated: bool,
}

/// Overloaded / rate-limited / server errors worth retrying.
const RETRYABLE: [u16; 6] = [429, 500, 502, 503, 504, 529];
const MAX_RETRIES: u32 = 4;

#[derive(serde::Deserialize)]
struct NotarizeReply {
    presentation: String,
}

impl ModelBackend for LiveZkTlsModel {
    fn complete(&mut self, q: &ModelQuery<'_>) -> Result<String, HarnessError> {
        let c = &self.config;
        let body = ph_core::anthropic::request_body(
            &c.model,
            c.max_tokens,
            q.system_prompt,
            q.tools,
            q.messages,
            q.session_id,
            q.step,
        );
        // The notary releases a (session, step) slot after an authenticated
        // non-200 exchange, so transient API errors can be retried. Anything
        // else (MPC failure, abort) burns the slot and ends the session.
        let mut attempt = 0u32;
        let bytes = loop {
            let reply: NotarizeReply = post(
                &format!("{}/v1/notarize", self.proxy),
                &serde_json::json!({ "body": body }),
            )?;
            let bytes = from_hex(&reply.presentation)
                .ok_or_else(|| HarnessError::Backend("presentation is not hex".into()))?;
            let status = verify_presentation(&self.provider, &c.notary, &c.host, &bytes)
                .and_then(|x| parse_http_response(&x.recv))
                .map(|(status, _)| status)
                .map_err(|e| HarnessError::Attestation(format!("zkTLS step {}: {e}", q.step)))?;
            if !RETRYABLE.contains(&status) || attempt >= MAX_RETRIES {
                break bytes;
            }
            attempt += 1;
            let wait = std::time::Duration::from_secs(1 << attempt);
            eprintln!("[zktls] step {}: API answered {status}; retry {attempt}/{MAX_RETRIES} in {wait:?}", q.step);
            std::thread::sleep(wait);
        };
        let (text, time, truncated) = verify_zktls_step(&self.provider, c, q, &bytes)?;
        self.times = widen(self.times, time);
        self.truncated = truncated;
        eprintln!(
            "[zktls] step {} notarized: {} presentation bytes, time {time}",
            q.step,
            bytes.len()
        );
        self.recorded.push(ModelEvidence::Tls(bytes));
        Ok(text)
    }

    fn attested_time_range(&self) -> Option<(u64, u64)> {
        self.times
    }

    fn truncated(&self) -> bool {
        self.truncated
    }
}

pub struct LiveTools {
    url: String,
    key: VerifyingKey,
    pub recorded: Vec<ToolEvidence>,
}

impl ToolBackend for LiveTools {
    fn call(&mut self, call: &ToolCall) -> Result<ToolResult, HarnessError> {
        let reply: ToolReply = post(&format!("{}/v1/tool", self.url), call)?;
        let sig = decode_sig(&reply.signature)?;
        let digest = tool_attestation_digest(&call.hash(), &reply.result.hash());
        verify_signature(&self.key, &digest, &sig)
            .map_err(|e| HarnessError::Attestation(format!("oracle call #{}: {e}", call.seq)))?;
        self.recorded.push(ToolEvidence::Signed(SignedToolResult {
            result: reply.result.clone(),
            signature: sig,
        }));
        Ok(reply.result)
    }
}

/// zkTLS tool mode: the operator's MPC-TLS proxy fetches the URL with a notary
/// (`/v1/fetch`) and returns a presentation; it is verified here with exactly
/// the guest's code. Any failure (proxy, notary refusal, verification) is fatal:
/// the call's slot is consumed, so it cannot be retried within the session.
pub struct LiveZkTlsTools {
    proxy: String,
    config: ToolTlsConfig,
    provider: ph_core::zktls::CryptoProvider,
    pub recorded: Vec<ToolEvidence>,
    times: Option<(u64, u64)>,
}

impl ToolBackend for LiveZkTlsTools {
    fn call(&mut self, call: &ToolCall) -> Result<ToolResult, HarnessError> {
        let reply: NotarizeReply = post(&format!("{}/v1/fetch", self.proxy), call)?;
        let bytes = from_hex(&reply.presentation)
            .ok_or_else(|| HarnessError::Backend("presentation is not hex".into()))?;
        let (result, time) = verify_tool_step(&self.provider, &self.config, call, &bytes)?;
        self.times = widen(self.times, time);
        eprintln!(
            "[zktls] tool call #{} ({}) notarized: {} presentation bytes, ok={}",
            call.seq,
            call.tool,
            bytes.len(),
            result.ok
        );
        self.recorded.push(ToolEvidence::Tls(bytes));
        Ok(result)
    }

    fn attested_time_range(&self) -> Option<(u64, u64)> {
        self.times
    }
}

/// Run the session against live services and return its output plus the witness.
/// `zktls_proxy` is required when `input.model_auth` is zkTLS, `zktls_tool_proxy`
/// when `input.tool_auth` is zkTLS.
pub fn run_live(
    input: &SessionInput,
    services_url: &str,
    zktls_proxy: Option<&str>,
    zktls_tool_proxy: Option<&str>,
) -> Result<(SessionOutput, Witness)> {
    type Recorded = Box<dyn Fn() -> Vec<ToolEvidence>>;
    let (tools, recorded_tools): (Rc<RefCell<dyn ToolBackend>>, Recorded) = match &input.tool_auth {
        ToolAuth::Oracle { key } => {
            let t = Rc::new(RefCell::new(LiveTools {
                url: services_url.to_string(),
                key: verifying_key(key)?,
                recorded: vec![],
            }));
            let r = t.clone();
            (t, Box::new(move || r.borrow().recorded.clone()))
        }
        ToolAuth::Fixture(world) => {
            // Answered from the committed world, exactly as the guest does.
            let t = Rc::new(RefCell::new(ph_core::eval::FixtureTools::new(world.clone())));
            (t, Box::new(Vec::new))
        }
        ToolAuth::ZkTls(config) => {
            let proxy = zktls_tool_proxy
                .ok_or_else(|| anyhow::anyhow!("zkTLS tool auth needs --zktls-tool-proxy"))?;
            let t = Rc::new(RefCell::new(LiveZkTlsTools {
                proxy: proxy.to_string(),
                provider: provider_for_roots(&config.roots).map_err(|e| anyhow::anyhow!(e))?,
                config: config.clone(),
                recorded: vec![],
                times: None,
            }));
            let r = t.clone();
            (t, Box::new(move || r.borrow().recorded.clone()))
        }
    };
    let mut blind = [0u8; 32];
    getrandom::getrandom(&mut blind).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let (out, recorded) = match &input.model_auth {
        ModelAuth::Gateway { key } => {
            let mut model = LiveModel {
                url: services_url.to_string(),
                key: verifying_key(key)?,
                recorded: vec![],
            };
            let out = ph_core::run_session(input, &blind, &mut model, tools.clone())?;
            (out, model.recorded)
        }
        ModelAuth::ZkTls(config) => {
            let proxy = zktls_proxy
                .ok_or_else(|| anyhow::anyhow!("zkTLS model auth needs --zktls-proxy"))?;
            let mut model = LiveZkTlsModel {
                proxy: proxy.to_string(),
                provider: crypto_provider(config).map_err(|e| anyhow::anyhow!(e))?,
                config: config.clone(),
                recorded: vec![],
                times: None,
                truncated: false,
            };
            let out = ph_core::run_session(input, &blind, &mut model, tools.clone())?;
            (out, model.recorded)
        }
    };
    let witness = Witness {
        version: ph_core::FORMAT_VERSION,
        blind,
        input: input.clone(),
        model_responses: recorded,
        tool_results: recorded_tools(),
    };
    Ok((out, witness))
}
