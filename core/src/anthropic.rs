//! Anthropic Messages API wire format, as used by the zkTLS model backend.
//!
//! Both the operator's prover (which sends the request over MPC-TLS) and the
//! zkVM guest (which checks the notarized transcript) use these functions, so the
//! request bytes are fully determined by the harness state:
//!
//! - the JSON body is written by a fixed canonical writer (not serde_json), so
//!   host and guest builds can never disagree on escaping or field order;
//! - the HTTP request has a fixed template; the only free bytes are the API key,
//!   which must match `[A-Za-z0-9_-]{8,256}` and so cannot inject header or
//!   body boundaries;
//! - responses are parsed strictly: exactly one `HTTP/1.1 200` response, one
//!   unambiguous framing (Content-Length XOR chunked), nothing trailing.
//!
//! The body ends with `"metadata":{"user_id":"ph-<session hex>-<step>"}}`, which
//! binds every request to one (session, step). The notary sees only this tail
//! and refuses to notarize the same (session, step) twice with a 200 response,
//! so an operator cannot re-sample the model and keep the reply it prefers.

use core::fmt::Write as _;

use crate::hash::{to_hex, Digest};
use crate::protocol::{Message, Role};

pub const API_PATH: &str = "/v1/messages";
pub const API_VERSION: &str = "2023-06-01";

/// `ph-<64 hex>-<step>`; also what the notary parses from the request tail.
pub fn user_id(session_id: &Digest, step: u32) -> String {
    format!("ph-{}-{}", to_hex(session_id), step)
}

/// JSON string literal with the minimal RFC 8259 escape set.
pub fn json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Canonical JSON for a parsed value: object keys sorted (explicitly, so the
/// output does not depend on serde_json's map features), strings through
/// `json_string`, numbers in serde_json's shortest round-trip form.
pub fn json_value(out: &mut String, v: &serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let _ = write!(out, "{n}");
        }
        Value::String(s) => json_string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_value(out, x);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_string(out, k);
                out.push(':');
                json_value(out, &m[k]);
            }
            out.push('}');
        }
    }
}

/// One content block of a native-mode assistant turn.
#[derive(Clone, Debug, PartialEq)]
pub enum Block {
    Text(String),
    Thinking { thinking: String, signature: String },
    RedactedThinking(String),
    ToolUse { id: String, name: String, input: serde_json::Value },
}

fn str_field<'a>(b: &'a serde_json::Value, k: &str) -> Result<&'a str, String> {
    b.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("content block without string field {k}"))
}

/// Parse API content blocks (native mode). Unknown block types are rejected.
pub fn parse_blocks(blocks: &[serde_json::Value]) -> Result<Vec<Block>, String> {
    blocks
        .iter()
        .map(|b| match b.get("type").and_then(|t| t.as_str()) {
            Some("text") => Ok(Block::Text(str_field(b, "text")?.to_string())),
            Some("thinking") => Ok(Block::Thinking {
                thinking: str_field(b, "thinking")?.to_string(),
                signature: str_field(b, "signature")?.to_string(),
            }),
            Some("redacted_thinking") => Ok(Block::RedactedThinking(str_field(b, "data")?.to_string())),
            Some("tool_use") => {
                let input = b.get("input").cloned().unwrap_or(serde_json::Value::Null);
                if !input.is_object() {
                    return Err("tool_use input is not an object".into());
                }
                Ok(Block::ToolUse {
                    id: str_field(b, "id")?.to_string(),
                    name: str_field(b, "name")?.to_string(),
                    input,
                })
            }
            _ => Err("reply contains an unsupported content block".into()),
        })
        .collect()
}

/// Canonical JSON array of blocks: the exact `content` of the assistant turn
/// that the harness echoes back (thinking blocks verbatim, as the API requires
/// when tools are used).
pub fn blocks_json(blocks: &[Block]) -> String {
    let mut out = String::from("[");
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match b {
            Block::Text(t) => {
                out.push_str("{\"type\":\"text\",\"text\":");
                json_string(&mut out, t);
            }
            Block::Thinking { thinking, signature } => {
                out.push_str("{\"type\":\"thinking\",\"thinking\":");
                json_string(&mut out, thinking);
                out.push_str(",\"signature\":");
                json_string(&mut out, signature);
            }
            Block::RedactedThinking(d) => {
                out.push_str("{\"type\":\"redacted_thinking\",\"data\":");
                json_string(&mut out, d);
            }
            Block::ToolUse { id, name, input } => {
                out.push_str("{\"type\":\"tool_use\",\"id\":");
                json_string(&mut out, id);
                out.push_str(",\"name\":");
                json_string(&mut out, name);
                out.push_str(",\"input\":");
                json_value(&mut out, input);
            }
        }
        out.push('}');
    }
    out.push(']');
    out
}

/// Parse a canonical blocks array produced by `blocks_json` (or a scripted
/// reply in that format) back into blocks.
pub fn blocks_of(canonical: &str) -> Result<Vec<Block>, String> {
    match serde_json::from_str::<serde_json::Value>(canonical) {
        Ok(serde_json::Value::Array(a)) => parse_blocks(&a),
        _ => Err("native-mode reply is not a JSON array of content blocks".into()),
    }
}

/// One `tool_result` block answering a `tool_use`.
pub fn tool_result_block(out: &mut String, tool_use_id: &str, content: &str, is_error: bool) {
    out.push_str("{\"type\":\"tool_result\",\"tool_use_id\":");
    json_string(out, tool_use_id);
    out.push_str(",\"content\":");
    json_string(out, content);
    if is_error {
        out.push_str(",\"is_error\":true");
    }
    out.push('}');
}

/// The Messages API request body for one harness step.
///
/// Harness roles map onto the API's alternating user/assistant turns: the task
/// and every tool (script) result are `user` turns. The harness loop always
/// produces user, assistant, tool, assistant, tool, ... so alternation holds.
/// `tools` is the canonical native tool definitions (a JSON array; empty in
/// code mode, where the body has no `tools` field).
pub fn request_body(
    model: &str,
    max_tokens: u32,
    system: &str,
    tools: &str,
    messages: &[Message],
    session_id: &Digest,
    step: u32,
) -> String {
    let mut b = String::with_capacity(256 + system.len() + messages.iter().map(|m| m.content.len() + 32).sum::<usize>());
    b.push_str("{\"model\":");
    json_string(&mut b, model);
    let _ = write!(b, ",\"max_tokens\":{max_tokens},\"system\":");
    json_string(&mut b, system);
    if !tools.is_empty() {
        b.push_str(",\"tools\":");
        b.push_str(tools);
    }
    b.push_str(",\"messages\":[");
    for (i, m) in messages.iter().enumerate() {
        if i > 0 {
            b.push(',');
        }
        let role = match m.role {
            Role::Assistant | Role::AssistantBlocks => "assistant",
            Role::User | Role::Tool | Role::ToolResults => "user",
        };
        b.push_str("{\"role\":\"");
        b.push_str(role);
        b.push_str("\",\"content\":");
        match m.role {
            // Canonical block arrays built by the harness itself.
            Role::AssistantBlocks | Role::ToolResults => b.push_str(&m.content),
            _ => json_string(&mut b, &m.content),
        }
        b.push('}');
    }
    b.push_str("],\"metadata\":{\"user_id\":");
    json_string(&mut b, &user_id(session_id, step));
    b.push_str("}}");
    b
}

fn request_prefix(host: &str) -> String {
    format!("POST {API_PATH} HTTP/1.1\r\nhost: {host}\r\nx-api-key: ")
}

fn request_suffix(body: &str) -> String {
    format!(
        "\r\nanthropic-version: {API_VERSION}\r\ncontent-type: application/json\r\naccept-encoding: identity\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
}

pub fn valid_api_key(key: &[u8]) -> bool {
    (8..=256).contains(&key.len())
        && key
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

/// The exact HTTP/1.1 request bytes sent to the API.
pub fn http_request(host: &str, api_key: &str, body: &str) -> Result<Vec<u8>, String> {
    if !valid_api_key(api_key.as_bytes()) {
        return Err("api key must match [A-Za-z0-9_-]{8,256}".into());
    }
    let mut r = request_prefix(host).into_bytes();
    r.extend_from_slice(api_key.as_bytes());
    r.extend_from_slice(request_suffix(body).as_bytes());
    Ok(r)
}

/// Check that `sent` is exactly `http_request(host, <some valid key>, body)`.
pub fn check_request(sent: &[u8], host: &str, body: &str) -> Result<(), String> {
    let prefix = request_prefix(host);
    let suffix = request_suffix(body);
    if sent.len() < prefix.len() + suffix.len() {
        return Err("request too short".into());
    }
    if !sent.starts_with(prefix.as_bytes()) {
        return Err("request line / host / header order differs from the template".into());
    }
    if !sent.ends_with(suffix.as_bytes()) {
        return Err("request headers or body differ from the harness context".into());
    }
    let key = &sent[prefix.len()..sent.len() - suffix.len()];
    if !valid_api_key(key) {
        return Err("api key field is not [A-Za-z0-9_-]{8,256}".into());
    }
    Ok(())
}

/// A successful Messages API reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiReply {
    pub text: String,
    pub model: String,
    pub stop_reason: String,
}

/// Strict HTTP/1.1 response framing (see `http::parse_response`). Returns
/// (status, body). Interim 1xx responses are not skipped: the notary decides
/// slot release from the first status line (see `http::parse_response`).
pub fn parse_http_response(recv: &[u8]) -> Result<(u16, Vec<u8>), String> {
    crate::http::parse_response(recv, false).map(|r| (r.status, r.body))
}

/// Parse a Messages API success body.
///
/// `text` blocks are concatenated into the reply. `thinking` / `redacted_thinking`
/// blocks are skipped: current models think by default (on some, thinking cannot
/// be disabled), the API returns those blocks with the reasoning omitted or
/// encrypted, and the harness never feeds them back. Any other block type (e.g.
/// `tool_use`, server-tool results) is rejected: the request declares no tools,
/// so such a block means the exchange is not what the harness asked for.
///
/// In native tool mode (`native`), every supported block is kept and `text` is
/// the canonical blocks array (`blocks_json`) instead.
pub fn parse_reply(body: &[u8], native: bool) -> Result<ApiReply, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("reply is not JSON: {e}"))?;
    let field = |k: &str| v.get(k).and_then(|x| x.as_str());
    if field("type") != Some("message") || field("role") != Some("assistant") {
        return Err("reply is not an assistant message".into());
    }
    let blocks = v
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or("reply has no content array")?;
    if native {
        return Ok(ApiReply {
            text: blocks_json(&parse_blocks(blocks)?),
            model: field("model").ok_or("reply has no model")?.to_string(),
            stop_reason: field("stop_reason").unwrap_or("").to_string(),
        });
    }
    let mut text = String::new();
    for b in blocks {
        match b.get("type").and_then(|t| t.as_str()) {
            Some("text") => {}
            Some("thinking") | Some("redacted_thinking") => continue,
            _ => return Err("reply contains a content block other than text or thinking".into()),
        }
        text.push_str(
            b.get("text")
                .and_then(|t| t.as_str())
                .ok_or("text block without text")?,
        );
    }
    Ok(ApiReply {
        text,
        model: field("model").ok_or("reply has no model")?.to_string(),
        stop_reason: field("stop_reason").unwrap_or("").to_string(),
    })
}

/// The response model must be the requested one, or a dated snapshot of it.
pub fn model_matches(requested: &str, served: &str) -> bool {
    served == requested
        || served
            .strip_prefix(requested)
            .is_some_and(|rest| rest.starts_with('-') && rest[1..].bytes().all(|b| b.is_ascii_digit()) && rest.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs() -> Vec<Message> {
        vec![
            Message { role: Role::User, content: "task \"q\"\n".into() },
            Message { role: Role::Assistant, content: "```rhai\n1\n```".into() },
            Message { role: Role::Tool, content: "[code-mode result]\tok\u{1}\u{e9}".into() },
        ]
    }

    #[test]
    fn body_is_valid_json_with_expected_shape() {
        let sid = [0xabu8; 32];
        let b = request_body("claude-x", 512, "sys", "", &msgs(), &sid, 1);
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["model"], "claude-x");
        assert_eq!(v["max_tokens"], 512);
        assert_eq!(v["messages"][0]["content"], "task \"q\"\n");
        assert_eq!(v["messages"][1]["role"], "assistant");
        assert_eq!(v["messages"][2]["role"], "user");
        assert_eq!(v["messages"][2]["content"], "[code-mode result]\tok\u{1}\u{e9}");
        assert_eq!(v["metadata"]["user_id"], user_id(&sid, 1));
        assert!(b.ends_with(&format!(",\"metadata\":{{\"user_id\":\"{}\"}}}}", user_id(&sid, 1))));
    }

    #[test]
    fn request_template_roundtrip_and_injection() {
        let body = "{\"a\":1}";
        let req = http_request("api.anthropic.com", "sk-ant-api03-AbC_d-123", body).unwrap();
        check_request(&req, "api.anthropic.com", body).unwrap();
        assert!(check_request(&req, "evil.com", body).is_err());
        assert!(check_request(&req, "api.anthropic.com", "{\"a\":2}").is_err());
        // Keys that could inject header/body boundaries are rejected on both sides.
        for bad in ["short", "sk-ant\r\ncontent-length: 5\r\n\r\nHELLO", "sk ant 1234567", "sk-ant:12345678"] {
            assert!(http_request("h", bad, body).is_err(), "{bad:?}");
            let mut forged = request_prefix("h").into_bytes();
            forged.extend_from_slice(bad.as_bytes());
            forged.extend_from_slice(request_suffix(body).as_bytes());
            assert!(check_request(&forged, "h", body).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn response_framing() {
        let json = br#"{"type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}"#;
        let mut cl = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", json.len()).into_bytes();
        cl.extend_from_slice(json);
        let (s, b) = parse_http_response(&cl).unwrap();
        assert_eq!(s, 200);
        assert_eq!(parse_reply(&b, false).unwrap().text, "hi");

        let mut trailing = cl.clone();
        trailing.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        assert!(parse_http_response(&trailing).is_err());

        let mut ch = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        ch.extend_from_slice(format!("{:x}\r\n", 10).as_bytes());
        ch.extend_from_slice(&json[..10]);
        ch.extend_from_slice(b"\r\n");
        ch.extend_from_slice(format!("{:x}\r\n", json.len() - 10).as_bytes());
        ch.extend_from_slice(&json[10..]);
        ch.extend_from_slice(b"\r\n0\r\n\r\n");
        let (_, b2) = parse_http_response(&ch).unwrap();
        assert_eq!(b2, json.to_vec());

        for bad in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nhi"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nhi",
            b"HTTP/1.1 200 OK\r\n\r\nhi",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=1\r\nhi\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Trailer: 1\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi",
            b"HTTP/1.1 200 OK\r\n Folded: x\r\nContent-Length: 2\r\n\r\nhi",
        ] {
            assert!(parse_http_response(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn reply_parsing() {
        assert!(parse_reply(br#"{"type":"error","error":{"type":"x"}}"#, false).is_err());
        assert!(parse_reply(br#"{"type":"message","role":"assistant","model":"m","content":[{"type":"tool_use","id":"x"}]}"#, false).is_err());
        assert!(parse_reply(br#"{"type":"message","role":"assistant","model":"m","content":[{"type":"server_tool_use","id":"x"}]}"#, false).is_err());
        assert!(parse_reply(br#"{"type":"message","role":"assistant","model":"m","content":[{"type":"text"}]}"#, false).is_err());
        // Thinking blocks (reasoning omitted by default, or redacted) are skipped.
        let t = parse_reply(br#"{"type":"message","role":"assistant","model":"m","content":[{"type":"thinking","thinking":"","signature":"EqQBCkYIARgC"},{"type":"redacted_thinking","data":"abc"},{"type":"text","text":"hi"}],"stop_reason":"end_turn"}"#, false).unwrap();
        assert_eq!(t.text, "hi");
        let r = parse_reply(br#"{"type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}],"stop_reason":"max_tokens"}"#, false).unwrap();
        assert_eq!((r.text.as_str(), r.stop_reason.as_str()), ("ab", "max_tokens"));
        assert!(model_matches("claude-x", "claude-x"));
        assert!(model_matches("claude-x", "claude-x-20261001"));
        assert!(!model_matches("claude-x", "claude-x-evil"));
        assert!(!model_matches("claude-x", "claude-x-"));
        assert!(!model_matches("claude-x", "claude-xl"));
    }
}
