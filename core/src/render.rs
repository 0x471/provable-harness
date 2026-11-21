//! Deterministic text rendering for everything that enters the transcript.
//!
//! Anything that becomes part of a hashed message must render identically in the
//! host build and the zkVM build. `{:?}` on strings depends on the std Unicode
//! tables of the compiler that built the binary, so it is never used here.

use core::fmt::Write as _;

use crate::script::{CallOutcome, CallRecord, ScriptReport};

/// Quote a string with a fixed, minimal escape set.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    push_escaped(&mut out, s);
    out.push('"');
    out
}

fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Quote, but cap the quoted content at `max_chars` characters.
pub fn quote_preview(s: &str, max_chars: usize) -> String {
    let n = s.chars().count();
    if n <= max_chars {
        return quote(s);
    }
    let head: String = s.chars().take(max_chars).collect();
    format!("{}...({} chars)", quote(&head), n)
}

/// Truncate to at most `max_chars` characters (not bytes), marking the cut.
pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((byte_idx, _)) => {
            let mut out = s[..byte_idx].to_string();
            out.push_str("\n[truncated]");
            out
        }
    }
}

fn render_call(out: &mut String, i: usize, c: &CallRecord) {
    // Only the target (path / URL) is echoed. Payload arguments (file contents,
    // POST bodies) are summarised by size: echoing them would copy data the
    // script never chose to return (e.g. a secret it tried to send) into the
    // model's context and the transcript.
    let args: Vec<String> = c
        .args
        .iter()
        .enumerate()
        .map(|(j, a)| {
            if j == 0 {
                quote_preview(a, 160)
            } else {
                format!("<{} chars>", a.chars().count())
            }
        })
        .collect();
    let _ = write!(out, "  {}. {}({}) -> ", i + 1, c.tool, args.join(", "));
    match &c.outcome {
        CallOutcome::Ok { chars } => {
            let _ = writeln!(out, "ok ({chars} chars)");
        }
        // Reasons can echo long URLs or service output; bound them so one call
        // line cannot push later calls out of the (truncated) tool message.
        CallOutcome::Failed(e) => {
            let _ = writeln!(out, "failed: {}", quote_preview(e, 300));
        }
        CallOutcome::Denied(e) => {
            let _ = writeln!(out, "DENIED by policy: {}", quote_preview(e, 300));
        }
    }
}

/// The tool message the model reads after a script ran.
///
/// The calls section is never truncated (each line is bounded, and the number of
/// calls per script is bounded by the tool budget plus `MAX_DENIED_PER_SCRIPT`),
/// so every executed call is visible in the transcript; only stdout and the
/// value share what is left of `max_chars`.
pub fn render_report(r: &ScriptReport, max_chars: usize) -> String {
    let mut calls = String::from("[code-mode result]\ncalls:\n");
    if r.calls.is_empty() {
        calls.push_str("  (none)\n");
    }
    for (i, c) in r.calls.iter().enumerate() {
        render_call(&mut calls, i, c);
    }
    let mut out = String::new();
    out.push_str("stdout:\n");
    if r.stdout.is_empty() {
        out.push_str("  (empty)\n");
    } else {
        out.push_str(&r.stdout);
        if r.stdout_truncated {
            out.push_str("[stdout truncated]\n");
        }
    }
    match (&r.value, &r.error) {
        (Some(v), _) => {
            out.push_str("value:\n");
            out.push_str(v);
            out.push('\n');
        }
        (None, Some(e)) => {
            out.push_str("error:\n");
            out.push_str(e);
            out.push('\n');
        }
        (None, None) => {}
    }
    let room = max_chars.saturating_sub(calls.chars().count());
    calls.push_str(&truncate_chars(&out, room));
    calls
}

// ------------------------------------------------------------- script values --
//
// Rhai renders arrays, maps and debug strings with Rust's `{:?}`, whose escaping
// depends on the std Unicode tables of the compiler, and its `to_json` is not
// valid JSON for every string. The harness overrides those functions (see
// `script::build_engine`) with the renderer below: JSON with a fixed escape set.

use rhai::{Array, Dynamic, EvalAltResult, ImmutableString, Map, Position};

/// A JSON string literal: `"`, `\` and control characters escaped, nothing else.
pub fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render a Rhai value as JSON (strings quoted).
pub fn value_json(v: &Dynamic) -> String {
    let mut out = String::new();
    push_json(&mut out, v);
    out
}

fn push_json(out: &mut String, v: &Dynamic) {
    if v.is_unit() {
        out.push_str("null");
    } else if let Ok(b) = v.as_bool() {
        out.push_str(if b { "true" } else { "false" });
    } else if let Ok(i) = v.as_int() {
        let _ = write!(out, "{i}");
    } else if let Ok(c) = v.as_char() {
        out.push_str(&json_quote(c.encode_utf8(&mut [0u8; 4])));
    } else if let Some(s) = v.read_lock::<ImmutableString>() {
        out.push_str(&json_quote(s.as_str()));
    } else if let Some(a) = v.read_lock::<Array>() {
        out.push('[');
        for (i, x) in a.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_json(out, x);
        }
        out.push(']');
    } else if let Some(m) = v.read_lock::<Map>() {
        // Rhai maps are ordered by key, so the output is canonical.
        out.push('{');
        for (i, (k, x)) in m.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&json_quote(k.as_str()));
            out.push(':');
            push_json(out, x);
        }
        out.push('}');
    } else if let Some(b) = v.read_lock::<rhai::Blob>() {
        out.push('[');
        for (i, x) in b.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{x}");
        }
        out.push(']');
    } else if let Some(f) = v.read_lock::<rhai::FnPtr>() {
        out.push_str(&json_quote(f.fn_name()));
    } else {
        out.push_str(&json_quote(v.type_name()));
    }
}

/// Render a value as text: strings and characters as themselves, everything
/// else as JSON. Used for script results, `print`, `+`, interpolation, and the
/// payload arguments of `write_file` / `http_post`.
pub fn value_text(v: &Dynamic) -> String {
    if let Some(s) = v.read_lock::<ImmutableString>() {
        return s.to_string();
    }
    if let Ok(c) = v.as_char() {
        return c.to_string();
    }
    value_json(v)
}

/// Render a script error. Rhai's own `Display` formats `Dynamic` payloads with
/// `{:?}`; those variants are rendered here, the rest carry only text, numbers
/// and positions.
pub fn error_text(e: &EvalAltResult) -> String {
    let pos = |p: &Position| if p.is_none() { String::new() } else { format!(" ({p})") };
    match e {
        EvalAltResult::ErrorRuntime(d, p) => {
            let empty = d.is_unit() || d.read_lock::<ImmutableString>().is_some_and(|s| s.is_empty());
            if empty {
                format!("Runtime error{}", pos(p))
            } else {
                format!("Runtime error: {}{}", value_text(d), pos(p))
            }
        }
        EvalAltResult::ErrorIndexNotFound(d, p) => format!("Invalid index: {}{}", value_text(d), pos(p)),
        EvalAltResult::ErrorInFunctionCall(name, src, inner, p) => {
            let what = if name.starts_with("anon$") {
                "in closure call".to_string()
            } else {
                format!("in call to function '{name}'")
            };
            let from = if src.is_empty() { String::new() } else { format!(" (from '{src}')") };
            format!("{}\n{what}{from}{}", error_text(inner), pos(p))
        }
        other => other.to_string(),
    }
}

/// `parse_json` for scripts: any JSON value (Rhai's own accepts only objects).
/// Integers become INT; other numbers (no floats in this engine) become their
/// JSON text as a string.
pub fn parse_json(s: &str) -> Result<Dynamic, String> {
    fn conv(v: serde_json::Value) -> Dynamic {
        use serde_json::Value;
        match v {
            Value::Null => Dynamic::UNIT,
            Value::Bool(b) => Dynamic::from(b),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Dynamic::from(i),
                None => Dynamic::from(n.to_string()),
            },
            Value::String(s) => Dynamic::from(s),
            Value::Array(a) => Dynamic::from_array(a.into_iter().map(conv).collect()),
            Value::Object(o) => {
                Dynamic::from_map(o.into_iter().map(|(k, v)| (k.into(), conv(v))).collect())
            }
        }
    }
    serde_json::from_str::<serde_json::Value>(s).map(conv).map_err(|e| format!("parse_json: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_is_fixed() {
        assert_eq!(quote("a\"b\\c\n\u{1}\u{e9}"), "\"a\\\"b\\\\c\\n\\u{1}\u{e9}\"");
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate_chars("h\u{e9}llo", 2), "h\u{e9}\n[truncated]");
        assert_eq!(truncate_chars("h\u{e9}", 2), "h\u{e9}");
        assert_eq!(quote_preview("abcdef", 3), "\"abc\"...(6 chars)");
    }
}
