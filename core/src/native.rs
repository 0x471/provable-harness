//! Native tool use: the model calls declared tools through the Messages API's
//! `tool_use` blocks instead of writing a code-mode script.
//!
//! Each declared tool is *bound* to one harness action, so it goes through the
//! same runtime policy check, budgets, taint tracking, action log and backends
//! as a code-mode call:
//!
//! - `read_file { param, prefix }`: read `prefix + input[param]` from the workspace;
//! - `http_get { url, query }`: GET `url`, with the listed input fields appended
//!   as a query string (`?k=v&...`, in the listed order, values percent-encoded);
//! - `http_post { url }`: POST the tool input, as canonical JSON, to `url`.
//!
//! The tool definitions are part of the session configuration (committed in the
//! claim as `tool_mode_hash`) and of every request (`tools`), so the model sees
//! exactly the published tools.

use serde::{Deserialize, Serialize};

use crate::anthropic::{json_string, json_value};
use crate::hash::{domain, Digest, Hasher};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolMode {
    /// The model replies with a ```rhai script (code mode).
    #[default]
    Code,
    /// The model calls these tools natively.
    Native(Vec<NativeTool>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeTool {
    pub name: String,
    pub description: String,
    /// JSON Schema of the input object, as canonical JSON (see `canonical_json`).
    pub input_schema: String,
    pub binding: Binding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    ReadFile { param: String, prefix: String },
    HttpGet { url: String, #[serde(default)] query: Vec<String> },
    HttpPost { url: String },
}

pub const MAX_NATIVE_TOOLS: usize = 64;

/// Canonical form of a JSON text (sorted keys, minimal escapes).
pub fn canonical_json(text: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    let mut out = String::new();
    json_value(&mut out, &v);
    Ok(out)
}

fn valid_name(n: &str) -> bool {
    (1..=64).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl ToolMode {
    pub fn is_native(&self) -> bool {
        matches!(self, ToolMode::Native(_))
    }

    pub fn validate(&self) -> Result<(), String> {
        let ToolMode::Native(tools) = self else { return Ok(()) };
        if tools.is_empty() || tools.len() > MAX_NATIVE_TOOLS {
            return Err(format!("native mode needs 1 to {MAX_NATIVE_TOOLS} tools"));
        }
        for (i, t) in tools.iter().enumerate() {
            if !valid_name(&t.name) {
                return Err(format!("tool name {:?} must match [A-Za-z0-9_-]{{1,64}}", t.name));
            }
            if tools[..i].iter().any(|u| u.name == t.name) {
                return Err(format!("duplicate tool {}", t.name));
            }
            if t.description.len() > 4096 {
                return Err(format!("tool {}: description too long", t.name));
            }
            let canon = canonical_json(&t.input_schema).map_err(|e| format!("tool {}: schema: {e}", t.name))?;
            if canon != t.input_schema || !t.input_schema.starts_with('{') {
                return Err(format!("tool {}: input_schema must be a canonical JSON object", t.name));
            }
            match &t.binding {
                Binding::ReadFile { param, prefix } => {
                    if param.is_empty() || !prefix.starts_with('/') || !prefix.ends_with('/') {
                        return Err(format!("tool {}: read_file needs a param and a /prefix/", t.name));
                    }
                }
                Binding::HttpGet { url, query } => {
                    crate::policy::validate_url(url)?;
                    if url.contains('?') && !query.is_empty() {
                        return Err(format!("tool {}: url already has a query", t.name));
                    }
                    if query.iter().any(|q| !valid_name(q)) {
                        return Err(format!("tool {}: bad query field", t.name));
                    }
                }
                Binding::HttpPost { url } => crate::policy::validate_url(url)?,
            }
        }
        Ok(())
    }

    /// The `tools` array of every request (empty in code mode).
    pub fn tools_json(&self) -> String {
        let ToolMode::Native(tools) = self else { return String::new() };
        let mut out = String::from("[");
        for (i, t) in tools.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            json_string(&mut out, &t.name);
            out.push_str(",\"description\":");
            json_string(&mut out, &t.description);
            out.push_str(",\"input_schema\":");
            out.push_str(&t.input_schema);
            out.push('}');
        }
        out.push(']');
        out
    }

    pub fn hash(&self) -> Digest {
        let mut h = Hasher::new(domain::TOOL_MODE);
        match self {
            ToolMode::Code => {
                h.u8(0);
            }
            ToolMode::Native(tools) => {
                h.u8(1).u64(tools.len() as u64);
                for t in tools {
                    h.str(&t.name).str(&t.description).str(&t.input_schema);
                    match &t.binding {
                        Binding::ReadFile { param, prefix } => h.u8(1).str(param).str(prefix),
                        Binding::HttpGet { url, query } => h.u8(2).str(url).strs(query),
                        Binding::HttpPost { url } => h.u8(3).str(url),
                    };
                }
            }
        }
        h.finish()
    }

    pub fn tool(&self, name: &str) -> Option<&NativeTool> {
        match self {
            ToolMode::Native(tools) => tools.iter().find(|t| t.name == name),
            ToolMode::Code => None,
        }
    }
}

/// Percent-encode a query value (RFC 3986 unreserved characters stay).
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The harness call (tool, args) for a `tool_use` input, or an error message
/// for the model (a malformed call is the model's mistake, not a fatal error).
pub fn harness_call(binding: &Binding, input: &serde_json::Value) -> Result<(&'static str, Vec<String>), String> {
    let text_of = |v: &serde_json::Value| -> Option<String> {
        match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    };
    match binding {
        Binding::ReadFile { param, prefix } => {
            let name = input.get(param).and_then(|v| v.as_str()).ok_or_else(|| format!("missing string field {param}"))?;
            Ok(("read_file", vec![format!("{prefix}{}", name.trim_start_matches('/'))]))
        }
        Binding::HttpGet { url, query } => {
            let mut u = url.clone();
            let mut first = true;
            for q in query {
                if let Some(v) = input.get(q).filter(|v| !v.is_null()) {
                    let v = text_of(v).ok_or_else(|| format!("field {q} must be a string, number or boolean"))?;
                    u.push(if first { '?' } else { '&' });
                    u.push_str(q);
                    u.push('=');
                    u.push_str(&pct(&v));
                    first = false;
                }
            }
            Ok(("http_get", vec![u]))
        }
        Binding::HttpPost { url } => {
            let mut body = String::new();
            json_value(&mut body, input);
            Ok(("http_post", vec![url.clone(), body]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::{blocks_json, blocks_of, parse_reply, request_body, Block};
    use crate::protocol::{Message, Role};

    fn tool(name: &str, binding: Binding) -> NativeTool {
        NativeTool {
            name: name.into(),
            description: format!("{name} tool"),
            input_schema: canonical_json(r#"{"type":"object","properties":{"x":{"type":"string"}}}"#).unwrap(),
            binding,
        }
    }

    #[test]
    fn bindings_map_inputs_to_harness_calls() {
        let rf = Binding::ReadFile { param: "file_path".into(), prefix: "/files/".into() };
        assert_eq!(
            harness_call(&rf, &serde_json::json!({"file_path": "bill.txt"})).unwrap(),
            ("read_file", vec!["/files/bill.txt".to_string()])
        );
        assert!(harness_call(&rf, &serde_json::json!({"other": 1})).is_err());
        let get = Binding::HttpGet { url: "https://b.example/api/tx".into(), query: vec!["n".into(), "q".into()] };
        assert_eq!(
            harness_call(&get, &serde_json::json!({"n": 5, "q": "a b&c=d", "zz": 1})).unwrap().1,
            vec!["https://b.example/api/tx?n=5&q=a%20b%26c%3Dd".to_string()]
        );
        assert_eq!(harness_call(&get, &serde_json::json!({})).unwrap().1, vec!["https://b.example/api/tx".to_string()]);
        let post = Binding::HttpPost { url: "https://b.example/api/send".into() };
        let (t, args) = harness_call(&post, &serde_json::json!({"b": 98.7, "a": "\u{e9}\n"})).unwrap();
        assert_eq!((t, args[1].as_str()), ("http_post", "{\"a\":\"\u{e9}\\n\",\"b\":98.7}"));
    }

    #[test]
    fn validation_and_definitions() {
        let ok = ToolMode::Native(vec![tool("get_balance", Binding::HttpGet { url: "https://b.example/api/balance".into(), query: vec![] })]);
        ok.validate().unwrap();
        assert_eq!(
            ok.tools_json(),
            "[{\"name\":\"get_balance\",\"description\":\"get_balance tool\",\"input_schema\":{\"properties\":{\"x\":{\"type\":\"string\"}},\"type\":\"object\"}}]"
        );
        assert_eq!(ToolMode::Code.tools_json(), "");
        assert_ne!(ok.hash(), ToolMode::Code.hash());
        let mut bad = ok.clone();
        if let ToolMode::Native(t) = &mut bad {
            t[0].input_schema = r#"{"type": "object"}"#.into(); // not canonical
        }
        assert!(bad.validate().is_err());
        let dup = ToolMode::Native(vec![tool("a", Binding::HttpPost { url: "https://b.example/x".into() }); 2]);
        assert!(dup.validate().is_err());
        let name = ToolMode::Native(vec![tool("a b", Binding::HttpPost { url: "https://b.example/x".into() })]);
        assert!(name.validate().is_err());
        assert!(ToolMode::Native(vec![]).validate().is_err());
        // Changing a binding changes the hash (verifiers pin bindings too).
        let mut other = ok.clone();
        if let ToolMode::Native(t) = &mut other {
            t[0].binding = Binding::HttpGet { url: "https://evil.example/".into(), query: vec![] };
        }
        assert_ne!(ok.hash(), other.hash());
    }

    #[test]
    fn native_wire_format() {
        let body = br#"{"type":"message","role":"assistant","model":"m","stop_reason":"tool_use","content":[
            {"type":"thinking","thinking":"plan","signature":"sig=="},
            {"type":"text","text":"Paying."},
            {"type":"tool_use","id":"toolu_1","name":"send","input":{"z":1,"a":[true,null,"x"]}}]}"#;
        assert!(parse_reply(body, false).is_err(), "code mode rejects tool_use");
        let r = parse_reply(body, true).unwrap();
        let blocks = blocks_of(&r.text).unwrap();
        assert_eq!(blocks_json(&blocks), r.text, "canonical form is a fixed point");
        assert!(matches!(&blocks[2], Block::ToolUse { id, input, .. } if id == "toolu_1" && input["z"] == 1));
        assert!(r.text.contains("\"signature\":\"sig==\""), "thinking is echoed verbatim");
        assert!(r.text.contains("\"input\":{\"a\":[true,null,\"x\"],\"z\":1}"));
        assert!(parse_reply(br#"{"type":"message","role":"assistant","model":"m","content":[{"type":"server_tool_use","id":"x"}]}"#, true).is_err());
        // The request carries the tools and the block turns as raw JSON, in API roles.
        let mut results = String::from("[");
        crate::anthropic::tool_result_block(&mut results, "toolu_1", "ok", false);
        results.push(']');
        let msgs = vec![
            Message { role: Role::User, content: "task".into() },
            Message { role: Role::AssistantBlocks, content: r.text.clone() },
            Message { role: Role::ToolResults, content: results },
        ];
        let tools = "[{\"name\":\"send\",\"description\":\"d\",\"input_schema\":{\"type\":\"object\"}}]";
        let b = request_body("m", 64, "sys", tools, &msgs, &[1; 32], 1);
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["tools"][0]["name"], "send");
        let roles: Vec<&str> = v["messages"].as_array().unwrap().iter().map(|m| m["role"].as_str().unwrap()).collect();
        assert_eq!(roles, ["user", "assistant", "user"]);
        assert_eq!(v["messages"][2]["content"][0]["tool_use_id"], "toolu_1");
        assert_eq!(v["messages"][1]["content"][0]["type"], "thinking");
        assert!(!request_body("m", 64, "sys", "", &msgs[..1], &[1; 32], 0).contains("\"tools\""));
    }
}
