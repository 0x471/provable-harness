//! Wire objects exchanged with the model gateway and the tool oracle, and the
//! exact digests that those parties sign.
//!
//! Context hashing is a chain so its cost is linear in the transcript length:
//!
//! ```text
//! c_0     = H(CTX_GENESIS, session_id, model_id, system_prompt)
//! c_{k+1} = H(CTX_MESSAGE, c_k, role, content)
//! req_k   = H(MODEL_REQUEST, c_k, step)
//! ```
//!
//! The gateway receives the full request in the clear, recomputes `req_k` with
//! these same functions, and signs `H(MODEL_ATTESTATION, req_k, H(MODEL_RESPONSE, text))`.
//! Inside the zkVM the harness recomputes `req_k` from its *own* state, so a
//! signature only verifies if the model saw exactly the context the harness built.

use serde::{Deserialize, Serialize};

use crate::hash::{domain, Digest, Hasher};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    User,
    Assistant,
    /// Output of a code-mode script, fed back to the model.
    Tool,
    /// Native tool use: an assistant turn as a canonical JSON array of content
    /// blocks (text, thinking, tool_use), echoed verbatim to the API.
    AssistantBlocks,
    /// Native tool use: the `tool_result` blocks answering the previous turn's
    /// `tool_use` blocks, as a canonical JSON array (a `user` turn in the API).
    ToolResults,
}

impl Role {
    pub fn tag(self) -> u8 {
        match self {
            Role::User => 1,
            Role::Assistant => 2,
            Role::Tool => 3,
            Role::AssistantBlocks => 4,
            Role::ToolResults => 5,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
            Role::AssistantBlocks => "assistant_blocks",
            Role::ToolResults => "tool_results",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

/// First link of the context chain. `tools` is the canonical native tool
/// definitions (empty in code mode, which keeps the original genesis).
pub fn context_genesis(session_id: &Digest, model_id: &str, system_prompt: &str, tools: &str) -> Digest {
    if tools.is_empty() {
        let mut h = Hasher::new(domain::CTX_GENESIS);
        h.digest(session_id).str(model_id).str(system_prompt);
        return h.finish();
    }
    let mut h = Hasher::new(domain::CTX_GENESIS_TOOLS);
    h.digest(session_id).str(model_id).str(system_prompt).str(tools);
    h.finish()
}

pub fn context_append(prev: &Digest, msg: &Message) -> Digest {
    let mut h = Hasher::new(domain::CTX_MESSAGE);
    h.digest(prev).u8(msg.role.tag()).str(&msg.content);
    h.finish()
}

pub fn context_hash(
    session_id: &Digest,
    model_id: &str,
    system_prompt: &str,
    tools: &str,
    messages: &[Message],
) -> Digest {
    messages.iter().fold(
        context_genesis(session_id, model_id, system_prompt, tools),
        |c, m| context_append(&c, m),
    )
}

pub fn model_request_hash(context: &Digest, step: u32) -> Digest {
    let mut h = Hasher::new(domain::MODEL_REQUEST);
    h.digest(context).u64(step as u64);
    h.finish()
}

pub fn model_response_hash(text: &str) -> Digest {
    let mut h = Hasher::new(domain::MODEL_RESPONSE);
    h.str(text);
    h.finish()
}

/// The full request as sent to the model gateway.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRequest {
    pub session_id: Digest,
    pub model_id: String,
    pub system_prompt: String,
    /// Canonical native tool definitions (empty in code mode).
    #[serde(default)]
    pub tools: String,
    pub messages: Vec<Message>,
    pub step: u32,
}

impl ModelRequest {
    pub fn request_hash(&self) -> Digest {
        let ctx = context_hash(
            &self.session_id,
            &self.model_id,
            &self.system_prompt,
            &self.tools,
            &self.messages,
        );
        model_request_hash(&ctx, self.step)
    }
}

/// Borrowed view of a model request handed to a [`crate::ModelBackend`].
/// `request_hash` is computed by the harness, never taken from the witness.
pub struct ModelQuery<'a> {
    pub session_id: &'a Digest,
    pub model_id: &'a str,
    pub system_prompt: &'a str,
    /// Canonical native tool definitions (empty in code mode).
    pub tools: &'a str,
    pub messages: &'a [Message],
    pub step: u32,
    pub request_hash: Digest,
}

impl ModelQuery<'_> {
    pub fn to_request(&self) -> ModelRequest {
        ModelRequest {
            session_id: *self.session_id,
            model_id: self.model_id.to_string(),
            system_prompt: self.system_prompt.to_string(),
            tools: self.tools.to_string(),
            messages: self.messages.to_vec(),
            step: self.step,
        }
    }
}

/// An external tool invocation. `seq` is the per-session external call counter,
/// so every attestation is unique to one (session, position) and cannot be
/// replayed into another session or another position of the same session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub session_id: Digest,
    pub seq: u64,
    pub tool: String,
    pub args: Vec<String>,
}

impl ToolCall {
    pub fn hash(&self) -> Digest {
        let mut h = Hasher::new(domain::TOOL_CALL);
        h.digest(&self.session_id)
            .u64(self.seq)
            .str(&self.tool)
            .strs(&self.args);
        h.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult {
    /// `false` when the tool reports an error (e.g. HTTP 404); `output` then holds the message.
    pub ok: bool,
    pub output: String,
}

impl ToolResult {
    pub fn hash(&self) -> Digest {
        let mut h = Hasher::new(domain::TOOL_RESULT);
        h.bool(self.ok).str(&self.output);
        h.finish()
    }
}

/// Digest the model gateway signs.
pub fn model_attestation_digest(request_hash: &Digest, response_hash: &Digest) -> Digest {
    let mut h = Hasher::new(domain::MODEL_ATTESTATION);
    h.digest(request_hash).digest(response_hash);
    h.finish()
}

/// Digest the tool oracle signs.
pub fn tool_attestation_digest(call_hash: &Digest, result_hash: &Digest) -> Digest {
    let mut h = Hasher::new(domain::TOOL_ATTESTATION);
    h.digest(call_hash).digest(result_hash);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(role: Role, c: &str) -> Message {
        Message {
            role,
            content: c.into(),
        }
    }

    #[test]
    fn request_hash_matches_incremental_chain() {
        let sid = [7u8; 32];
        let msgs = vec![msg(Role::User, "task"), msg(Role::Assistant, "hi")];
        let req = ModelRequest {
            session_id: sid,
            model_id: "m".into(),
            system_prompt: "sys".into(),
            tools: String::new(),
            messages: msgs.clone(),
            step: 1,
        };
        let mut c = context_genesis(&sid, "m", "sys", "");
        for m in &msgs {
            c = context_append(&c, m);
        }
        assert_eq!(req.request_hash(), model_request_hash(&c, 1));
    }

    #[test]
    fn role_is_bound() {
        let sid = [0u8; 32];
        let a = context_hash(&sid, "m", "s", "", &[msg(Role::User, "x")]);
        let b = context_hash(&sid, "m", "s", "", &[msg(Role::Tool, "x")]);
        assert_ne!(a, b);
        // Native tool definitions are bound into the context (and code mode
        // keeps the original genesis).
        let t = context_hash(&sid, "m", "s", "[{\"name\":\"x\"}]", &[msg(Role::User, "x")]);
        assert_ne!(a, t);
        let c = context_hash(&sid, "m", "s", "", &[msg(Role::AssistantBlocks, "x")]);
        let d = context_hash(&sid, "m", "s", "", &[msg(Role::Assistant, "x")]);
        assert_ne!(c, d);
    }

    #[test]
    fn tool_call_binds_seq_and_session() {
        let c = ToolCall {
            session_id: [1; 32],
            seq: 0,
            tool: "http_get".into(),
            args: vec!["u".into()],
        };
        let mut c2 = c.clone();
        c2.seq = 1;
        let mut c3 = c.clone();
        c3.session_id = [2; 32];
        assert_ne!(c.hash(), c2.hash());
        assert_ne!(c.hash(), c3.hash());
    }
}
