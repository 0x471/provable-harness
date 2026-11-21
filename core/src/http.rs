//! HTTP/1.1 wire format shared by both zkTLS uses: strict response parsing, and
//! the canonical request bytes of the `http_get` / `http_post` tools.
//!
//! In zkTLS tool mode the request bytes are a pure function of the tool call
//! (URL, body): the guest rebuilds them and requires the notarized `sent` bytes
//! to be identical. No free bytes exist, so nothing can be injected.
//!
//! Responses are parsed strictly. A response that is truncated or ambiguously
//! framed is an *error* (fatal for the session), never a "failed call" result:
//! the operator controls the connection and could otherwise cut a genuine
//! response short and make the proof report a failure the server never sent.

use crate::policy::validate_url;
use crate::protocol::{ToolCall, ToolResult};
use crate::render::quote_preview;

pub const USER_AGENT: &str = "provable-harness/0.1";

// ------------------------------------------------------------------ responses --

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    /// Header (name, value) pairs in wire order; names as sent.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse exactly one HTTP/1.1 response that fills `recv` completely.
///
/// - Framing must be unambiguous: Content-Length XOR `chunked`; no duplicate
///   framing headers, no chunk extensions, no trailers, no trailing bytes.
///   Close-delimited bodies are rejected (a truncated one would look valid).
/// - 1xx, 204 and 304 responses carry no body.
/// - `skip_informational`: interim 1xx responses (except 101) before the final
///   one are skipped. The model path must NOT skip them: its notary releases a
///   slot when the first status line is not 200, so a `103` followed by `200`
///   would otherwise be a re-roll.
pub fn parse_response(recv: &[u8], skip_informational: bool) -> Result<HttpResponse, String> {
    let mut rest = recv;
    loop {
        let head_end = find(rest, b"\r\n\r\n").ok_or("no end of response headers")?;
        let head =
            std::str::from_utf8(&rest[..head_end]).map_err(|_| "response head is not UTF-8")?;
        let after = &rest[head_end + 4..];
        let mut lines = head.split("\r\n");
        let status_line = lines.next().ok_or("empty response")?;
        let status_part = status_line
            .strip_prefix("HTTP/1.1 ")
            .ok_or("not an HTTP/1.1 response")?;
        if status_part.len() < 3 || !status_part.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            return Err("bad status code".into());
        }
        if status_part.len() > 3 && status_part.as_bytes()[3] != b' ' {
            return Err("bad status line".into());
        }
        let status: u16 = status_part[..3].parse().map_err(|_| "bad status code")?;
        if !(100..=599).contains(&status) {
            return Err("bad status code".into());
        }

        let mut headers = Vec::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut te_seen = false;
        for line in lines {
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err("obsolete header folding".into());
            }
            let (name, value) = line.split_once(':').ok_or("malformed header")?;
            if name.is_empty() || name.bytes().any(|b| b <= b' ' || b == 0x7f) {
                return Err("malformed header name".into());
            }
            let value = value.trim_matches(|c| c == ' ' || c == '\t');
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err("duplicate content-length".into());
                }
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) || value.len() > 9 {
                    return Err("bad content-length".into());
                }
                content_length = Some(value.parse().map_err(|_| "bad content-length")?);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                if te_seen {
                    return Err("duplicate transfer-encoding".into());
                }
                te_seen = true;
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err("unsupported transfer-encoding".into());
                }
                chunked = true;
            }
            headers.push((name.to_string(), value.to_string()));
        }

        if (100..200).contains(&status) {
            if status == 101 {
                return Err("unexpected protocol switch (101)".into());
            }
            if content_length.is_some() || chunked {
                return Err("informational response with a body".into());
            }
            if skip_informational {
                rest = after;
                continue;
            }
            if !after.is_empty() {
                return Err("data after an informational response".into());
            }
            return Ok(HttpResponse { status, headers, body: vec![] });
        }
        if status == 204 || status == 304 {
            if !after.is_empty() {
                return Err("data after a response without body".into());
            }
            return Ok(HttpResponse { status, headers, body: vec![] });
        }
        let body = match (content_length, chunked) {
            (Some(_), true) => return Err("both content-length and chunked".into()),
            (None, false) => {
                return Err("response has no explicit framing (close-delimited bodies are not accepted)".into())
            }
            (Some(n), false) => {
                if after.len() != n {
                    return Err("body length differs from content-length (or trailing data)".into());
                }
                after.to_vec()
            }
            (None, true) => decode_chunked(after)?,
        };
        return Ok(HttpResponse { status, headers, body });
    }
}

fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = find(data, b"\r\n").ok_or("unterminated chunk size")?;
        let size_str = std::str::from_utf8(&data[..line_end]).map_err(|_| "bad chunk size")?;
        if size_str.is_empty() || size_str.len() > 8 || !size_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("bad chunk size (extensions are not accepted)".into());
        }
        let size = usize::from_str_radix(size_str, 16).map_err(|_| "bad chunk size")?;
        data = &data[line_end + 2..];
        if size == 0 {
            // No trailers accepted: the message must end right here.
            if data != b"\r\n" {
                return Err("trailers or trailing data after last chunk".into());
            }
            return Ok(out);
        }
        if data.len() < size + 2 || &data[size..size + 2] != b"\r\n" {
            return Err("truncated chunk".into());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

// ------------------------------------------------------------------ requests --

/// An `https://` URL as the zkTLS tools use it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsUrl {
    /// DNS name: TLS server name and certificate identity.
    pub host: String,
    pub port: u16,
    /// `host[:port]` exactly as written in the URL (the Host header).
    pub authority: String,
    /// Path and query (the fragment is never sent).
    pub target: String,
}

fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > 253 {
        return Err("bad host length".into());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err("host must be a lowercase DNS name".into());
        }
    }
    if host.rsplit('.').next().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return Err("IP-address hosts are not supported (TLS identity is a DNS name)".into());
    }
    Ok(())
}

pub fn parse_https_url(url: &str) -> Result<HttpsUrl, String> {
    validate_url(url)?;
    let rest = url
        .strip_prefix("https://")
        .ok_or("zkTLS tools support https:// URLs only")?;
    let slash = rest.find('/').ok_or("url needs a path after the host")?;
    let (authority, path) = rest.split_at(slash);
    let (host, port) = match authority.split_once(':') {
        None => (authority, 443u16),
        Some((h, p)) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) || p.starts_with('0') {
                return Err("bad port".into());
            }
            let port: u32 = p.parse().map_err(|_| "bad port")?;
            if port == 0 || port > 65535 {
                return Err("bad port".into());
            }
            (h, port as u16)
        }
    };
    validate_host(host)?;
    let target = path.split('#').next().unwrap_or("/");
    Ok(HttpsUrl {
        host: host.to_string(),
        port,
        authority: authority.to_string(),
        target: target.to_string(),
    })
}

/// `application/json` for bodies that are a JSON object or array, else text.
pub fn content_type(body: &str) -> &'static str {
    let t = body.trim_start();
    if (t.starts_with('{') || t.starts_with('[')) && serde_json::from_str::<serde_json::Value>(body).is_ok() {
        "application/json"
    } else {
        "text/plain; charset=utf-8"
    }
}

/// The exact request bytes for an `http_get` / `http_post` tool call.
pub fn tool_request(call: &ToolCall) -> Result<(HttpsUrl, Vec<u8>), String> {
    let common = |u: &HttpsUrl, method: &str| {
        format!(
            "{method} {} HTTP/1.1\r\nhost: {}\r\nuser-agent: {USER_AGENT}\r\naccept: */*\r\naccept-encoding: identity\r\nconnection: close\r\n",
            u.target, u.authority
        )
    };
    match (call.tool.as_str(), call.args.as_slice()) {
        ("http_get", [url]) => {
            let u = parse_https_url(url)?;
            let mut r = common(&u, "GET");
            r.push_str("\r\n");
            Ok((u, r.into_bytes()))
        }
        ("http_post", [url, body]) => {
            let u = parse_https_url(url)?;
            let mut r = common(&u, "POST");
            r.push_str(&format!(
                "content-type: {}\r\ncontent-length: {}\r\n\r\n",
                content_type(body),
                body.len()
            ));
            let mut bytes = r.into_bytes();
            bytes.extend_from_slice(body.as_bytes());
            Ok((u, bytes))
        }
        _ => Err(format!("{} is not an HTTP tool call", call.tool)),
    }
}

/// The tool result for a complete, authenticated HTTP response. Errors mean the
/// transcript is not one well-formed response (fatal for the session).
pub fn tool_result(recv: &[u8]) -> Result<ToolResult, String> {
    let r = parse_response(recv, true)?;
    if let Some(enc) = r
        .header_values("content-encoding")
        .find(|v| !v.eq_ignore_ascii_case("identity"))
    {
        return Ok(ToolResult {
            ok: false,
            output: format!("HTTP {}: unsupported content-encoding {}", r.status, quote_preview(enc, 64)),
        });
    }
    let body = String::from_utf8_lossy(&r.body).into_owned();
    let ok = (200..300).contains(&r.status);
    Ok(ToolResult {
        ok,
        output: if ok { body } else { format!("HTTP {}: {body}", r.status) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(tool: &str, args: &[&str]) -> ToolCall {
        ToolCall {
            session_id: [1; 32],
            seq: 0,
            tool: tool.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn urls() {
        let u = parse_https_url("https://api.example.com/v1/x?q=1#frag").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.authority.as_str(), u.target.as_str()),
            ("api.example.com", 443, "api.example.com", "/v1/x?q=1"));
        let u = parse_https_url("https://h.example:8443/").unwrap();
        assert_eq!((u.port, u.authority.as_str()), (8443, "h.example:8443"));
        for bad in [
            "http://h.example/", "https://h.example", "https://H.example/", "https://user@h.example/",
            "https://h.example:0/", "https://h.example:08/", "https://h.example:65536/", "https://h.example:/",
            "https://1.2.3.4/", "https://-h.example/", "https://h..example/", "https://h.example/a b",
            "https://h_x.example/",
        ] {
            assert!(parse_https_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn request_bytes() {
        let (u, r) = tool_request(&call("http_get", &["https://h.example/a?b=1#x"])).unwrap();
        assert_eq!(u.host, "h.example");
        assert_eq!(
            String::from_utf8(r).unwrap(),
            "GET /a?b=1 HTTP/1.1\r\nhost: h.example\r\nuser-agent: provable-harness/0.1\r\naccept: */*\r\naccept-encoding: identity\r\nconnection: close\r\n\r\n"
        );
        let (_, r) = tool_request(&call("http_post", &["https://h.example:8443/p", "{\"a\": 1}"])).unwrap();
        let r = String::from_utf8(r).unwrap();
        assert!(r.starts_with("POST /p HTTP/1.1\r\nhost: h.example:8443\r\n"), "{r}");
        assert!(r.ends_with("content-type: application/json\r\ncontent-length: 8\r\n\r\n{\"a\": 1}"), "{r}");
        let (_, r) = tool_request(&call("http_post", &["https://h.example/p", "{not json"])).unwrap();
        assert!(String::from_utf8(r).unwrap().contains("content-type: text/plain; charset=utf-8\r\n"));
        assert!(tool_request(&call("http_get", &["https://h.example/", "x"])).is_err());
        assert!(tool_request(&call("read_file", &["/x"])).is_err());
    }

    #[test]
    fn results() {
        let ok = tool_result(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").unwrap();
        assert_eq!(ok, ToolResult { ok: true, output: "hi".into() });
        let nf = tool_result(b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope").unwrap();
        assert_eq!(nf, ToolResult { ok: false, output: "HTTP 404: nope".into() });
        let early = tool_result(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx").unwrap();
        assert_eq!(early.output, "x");
        let nc = tool_result(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(nc, ToolResult { ok: true, output: String::new() });
        let gz = tool_result(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx").unwrap();
        assert!(!gz.ok && gz.output.contains("content-encoding"), "{gz:?}");
        let ch = tool_result(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n1\r\n!\r\n0\r\n\r\n").unwrap();
        assert_eq!(ch.output, "hi!");
        // Truncation and ambiguity are errors, not "failed" results.
        for bad in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nclose-delimited",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiEXTRA",
            b"HTTP/1.1 204 No Content\r\n\r\nx",
            b"HTTP/1.1 101 Switching\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 1\r\n\r\nx",
            b"HTTP/1.1 999 Odd\r\nContent-Length: 1\r\n\r\nx",
        ] {
            assert!(tool_result(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        // The model path does not skip interim responses.
        assert!(parse_response(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", false).is_err());
    }
}
