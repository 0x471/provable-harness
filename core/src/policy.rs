//! The policy the harness enforces on every tool call, at call time, on the
//! concrete (runtime-computed) arguments.
//!
//! Matching is deliberately simple and fail-closed:
//! - paths must be absolute, canonical (`/a/b`), with no `.`/`..`/empty segments;
//!   a path is under a directory only on a segment boundary;
//! - URLs must be printable ASCII and start with an allowlisted prefix of the form
//!   `scheme://host/...`. Because the prefix contains the first `/` after the host,
//!   a matching URL has exactly that authority (no `@`, port, or suffix tricks).

use serde::{Deserialize, Serialize};

use crate::hash::{domain, Digest, Hasher};
use crate::render::quote;

pub const MAX_PATH_LEN: usize = 512;
pub const MAX_URL_LEN: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Maximum number of model turns.
    pub max_steps: u32,
    /// Maximum number of allowed (executed) tool calls in the whole session.
    pub max_tool_calls: u32,
    /// Rhai operation budget per script.
    pub max_script_operations: u64,
    /// Rhai operation budget for the whole session (all scripts together).
    pub max_session_operations: u64,
    /// Largest string a script may hold, in bytes (tool outputs included). The
    /// zkVM cost of one operation grows with the size of the strings it
    /// touches, so this and the operation budgets bound the proving cost of any
    /// script, including one written under prompt injection (docs/DESIGN.md).
    pub max_string_bytes: u32,
    /// Data-volume budget for the whole session, in units of string bytes plus
    /// array and map elements touched (metered by the patched Rhai in
    /// vendor/rhai): arguments and results of every function call, cloned
    /// values, indexed strings. Together with the operation budget this bounds
    /// the zkVM cycles any script can cost.
    pub max_session_data: u64,
    /// Maximum size of the tool message fed back to the model per script.
    pub max_output_chars: u32,
    /// Directories the agent may read (and list).
    pub fs_read: Vec<String>,
    /// Directories the agent may write.
    pub fs_write: Vec<String>,
    /// Directories whose contents are secret. Reading one taints the session.
    pub secret_paths: Vec<String>,
    /// URL prefixes allowed for `http_get`.
    pub net_get: Vec<String>,
    /// URL prefixes allowed for `http_post`.
    pub net_post: Vec<String>,
    /// If set, once the session has read secret data no network call is allowed.
    pub deny_egress_after_secret_read: bool,
}

/// Upper limit for `Policy::max_string_bytes`.
pub const MAX_STRING_BYTES: u32 = 1 << 20;

impl Policy {
    pub fn hash(&self) -> Digest {
        let mut h = Hasher::new(domain::POLICY);
        h.u64(self.max_steps as u64)
            .u64(self.max_tool_calls as u64)
            .u64(self.max_script_operations)
            .u64(self.max_session_operations)
            .u64(self.max_string_bytes as u64)
            .u64(self.max_session_data)
            .u64(self.max_output_chars as u64)
            .strs(&self.fs_read)
            .strs(&self.fs_write)
            .strs(&self.secret_paths)
            .strs(&self.net_get)
            .strs(&self.net_post)
            .bool(self.deny_egress_after_secret_read);
        h.finish()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_steps == 0 || self.max_steps > 256 {
            return Err("max_steps must be in 1..=256".into());
        }
        if self.max_script_operations == 0 || self.max_session_operations == 0 || self.max_session_data == 0 {
            return Err("operation budgets must be > 0".into());
        }
        if !(1024..=MAX_STRING_BYTES).contains(&self.max_string_bytes) {
            return Err(format!("max_string_bytes must be in 1024..={MAX_STRING_BYTES}"));
        }
        if self.max_output_chars < 256 {
            return Err("max_output_chars must be >= 256".into());
        }
        for d in self
            .fs_read
            .iter()
            .chain(&self.fs_write)
            .chain(&self.secret_paths)
        {
            validate_dir(d).map_err(|e| format!("policy directory {}: {e}", quote(d)))?;
        }
        for p in self.net_get.iter().chain(&self.net_post) {
            validate_url_prefix(p).map_err(|e| format!("policy url prefix {}: {e}", quote(p)))?;
        }
        Ok(())
    }

    pub fn is_secret(&self, path: &str) -> bool {
        self.secret_paths.iter().any(|d| is_under(path, d))
    }

    pub fn check_read(&self, path: &str) -> Result<(), String> {
        validate_file_path(path)?;
        if self.fs_read.iter().any(|d| is_under(path, d)) {
            Ok(())
        } else {
            Err(format!("read of {path} is outside fs_read"))
        }
    }

    pub fn check_list(&self, dir: &str) -> Result<(), String> {
        validate_dir(dir)?;
        // Listing is allowed if the directory is readable, or contains a readable
        // directory (results are filtered to readable files by the caller).
        if self
            .fs_read
            .iter()
            .any(|d| is_under(dir, d) || is_under(d, dir))
        {
            Ok(())
        } else {
            Err(format!("list of {dir} is outside fs_read"))
        }
    }

    pub fn check_write(&self, path: &str) -> Result<(), String> {
        validate_file_path(path)?;
        if self.fs_write.iter().any(|d| is_under(path, d)) {
            Ok(())
        } else {
            Err(format!("write of {path} is outside fs_write"))
        }
    }

    pub fn check_net(&self, method: NetMethod, url: &str, tainted: bool) -> Result<(), String> {
        validate_url(url)?;
        if tainted && self.deny_egress_after_secret_read {
            return Err("network egress is blocked after the session read secret data".into());
        }
        let allow = match method {
            NetMethod::Get => &self.net_get,
            NetMethod::Post => &self.net_post,
        };
        validate_request_url(url)?;
        if allow.iter().any(|p| url_under_prefix(url, p)) {
            Ok(())
        } else {
            Err(format!("{} {url} is not on the allowlist", method.as_str()))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetMethod {
    Get,
    Post,
}

impl NetMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            NetMethod::Get => "GET",
            NetMethod::Post => "POST",
        }
    }
}

fn is_ascii_control(c: char) -> bool {
    (c as u32) < 0x20 || c as u32 == 0x7f
}

/// A file path: `/seg(/seg)*`, no empty, `.` or `..` segments, no control characters.
pub fn validate_file_path(p: &str) -> Result<(), String> {
    if p.len() > MAX_PATH_LEN {
        return Err("path too long".into());
    }
    let Some(rest) = p.strip_prefix('/') else {
        return Err(format!("path {} must be absolute", quote(p)));
    };
    if rest.is_empty() {
        return Err("path must name a file, not /".into());
    }
    for seg in rest.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(format!("path {} is not canonical", quote(p)));
        }
        if seg.chars().any(is_ascii_control) {
            return Err(format!("path {} contains control characters", quote(p)));
        }
    }
    Ok(())
}

/// A directory: `/` or a canonical path without a trailing slash.
pub fn validate_dir(d: &str) -> Result<(), String> {
    if d == "/" {
        Ok(())
    } else {
        validate_file_path(d)
    }
}

/// Segment-boundary containment: `/a/b` is under `/a` and `/a/b`, not under `/a/bc`.
pub fn is_under(path: &str, dir: &str) -> bool {
    if dir == "/" {
        return path.starts_with('/');
    }
    path == dir || (path.starts_with(dir) && path.as_bytes().get(dir.len()) == Some(&b'/'))
}

pub fn validate_url(u: &str) -> Result<(), String> {
    if u.len() > MAX_URL_LEN {
        return Err("url too long".into());
    }
    if !u.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("url must be printable ASCII without spaces".into());
    }
    Ok(())
}

/// `url` matches allowlist entry `prefix` only at a path boundary:
/// `https://h/v1/report` admits `https://h/v1/report?x=1` and `.../report/a`,
/// but not `.../reports-export`.
pub fn url_under_prefix(url: &str, prefix: &str) -> bool {
    match url.strip_prefix(prefix) {
        None => false,
        Some(rest) => {
            rest.is_empty()
                || prefix.ends_with(['/', '?', '&', '='])
                || rest.starts_with(['/', '?', '#'])
        }
    }
}

/// Reject URLs whose path a real HTTP client would normalise differently from
/// the string the policy matched: dot segments, encoded dots/slashes and
/// backslashes (WHATWG parsers treat `\` as `/` and resolve `%2e%2e`).
pub fn validate_request_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    for bad in ["%2e", "%2f", "%5c", "\\"] {
        if lower.contains(bad) {
            return Err(format!("url contains {bad}"));
        }
    }
    let after_scheme = lower.split_once("://").map_or(lower.as_str(), |(_, r)| r);
    let path = after_scheme.split(['?', '#']).next().unwrap_or("");
    if path.split('/').skip(1).any(|seg| seg == "." || seg == "..") {
        return Err("url path contains a dot segment".into());
    }
    Ok(())
}

/// `http(s)://host/...` where host is lowercase `[a-z0-9.-]` (optionally `:port`).
pub fn validate_url_prefix(p: &str) -> Result<(), String> {
    validate_url(p)?;
    let rest = p
        .strip_prefix("https://")
        .or_else(|| p.strip_prefix("http://"))
        .ok_or("must start with https:// or http://")?;
    let slash = rest
        .find('/')
        .ok_or("must contain '/' after the host to pin the authority")?;
    let host = &rest[..slash];
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b':')
    {
        return Err("host must be lowercase [a-z0-9.-] with optional :port".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            max_steps: 8,
            max_tool_calls: 16,
            max_script_operations: 10_000,
            max_session_operations: 30_000,
            max_string_bytes: 65_536,
            max_session_data: 1 << 24,
            max_output_chars: 4096,
            fs_read: vec!["/docs".into(), "/secrets".into()],
            fs_write: vec!["/out".into()],
            secret_paths: vec!["/secrets".into()],
            net_get: vec!["https://api.weather.example/".into()],
            net_post: vec!["https://api.weather.example/v1/report".into()],
            deny_egress_after_secret_read: true,
        }
    }

    #[test]
    fn paths() {
        assert!(validate_file_path("/a/b.txt").is_ok());
        for bad in ["a", "/", "//a", "/a//b", "/a/", "/a/../b", "/./a", "/a/..", "/a\u{0}b", "/a\nb"] {
            assert!(validate_file_path(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(is_under("/out/x", "/out"));
        assert!(is_under("/out", "/out"));
        assert!(!is_under("/outside/x", "/out"));
        assert!(is_under("/anything", "/"));
    }

    #[test]
    fn fs_checks() {
        let p = policy();
        p.validate().unwrap();
        assert!(p.check_read("/docs/a.md").is_ok());
        assert!(p.check_read("/out/a.md").is_err());
        assert!(p.check_read("/docs/../secrets/k").is_err());
        assert!(p.check_write("/out/r.md").is_ok());
        assert!(p.check_write("/docs/a.md").is_err());
        assert!(p.check_write("/outx/a.md").is_err());
        assert!(p.check_list("/").is_ok());
        assert!(p.check_list("/docs").is_ok());
        assert!(p.check_list("/out").is_err());
        assert!(p.is_secret("/secrets/api_key"));
        assert!(!p.is_secret("/secretsx"));
    }

    #[test]
    fn net_checks() {
        let p = policy();
        let ok = "https://api.weather.example/v1/today?city=paris";
        assert!(p.check_net(NetMethod::Get, ok, false).is_ok());
        assert!(p.check_net(NetMethod::Get, ok, true).is_err(), "taint blocks egress");
        for bad in [
            "https://api.weather.example.evil.com/x",
            "https://api.weather.example@evil.com/x",
            "https://api.weather.example:8443/x",
            "http://api.weather.example/x",
            "HTTPS://api.weather.example/x",
            "https://evil.example/https://api.weather.example/",
            "https://api.weather.example/ x",
        ] {
            assert!(p.check_net(NetMethod::Get, bad, false).is_err(), "{bad} must be rejected");
        }
        assert!(p
            .check_net(NetMethod::Post, "https://api.weather.example/v1/report", false)
            .is_ok());
        assert!(p
            .check_net(NetMethod::Post, "https://api.weather.example/v1/today", false)
            .is_err());
    }

    #[test]
    fn prefix_validation() {
        assert!(validate_url_prefix("https://a.example/").is_ok());
        assert!(validate_url_prefix("https://a.example").is_err());
        assert!(validate_url_prefix("https://A.example/").is_err());
        assert!(validate_url_prefix("https://u@a.example/").is_err());
        assert!(validate_url_prefix("ftp://a.example/").is_err());
    }

    #[test]
    fn policy_hash_binds_fields() {
        let a = policy();
        let mut b = policy();
        b.deny_egress_after_secret_read = false;
        let mut c = policy();
        c.net_get.push("https://x.example/".into());
        assert_ne!(a.hash(), b.hash());
        assert_ne!(a.hash(), c.hash());
    }
}
