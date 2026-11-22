#![no_main]
//! URL policy: never panics; a URL that passes the request checks and matches
//! a (valid) policy prefix really starts with it, and its *path* (what clients
//! normalise; queries are not normalised) has no dot segments or encoded
//! dots, slashes or backslashes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (prefix, url) = s.split_once('\n').unwrap_or(("https://a.example/api/", s));
    let _ = ph_core::policy::validate_url(url);
    let _ = ph_core::policy::validate_url_prefix(prefix);
    let _ = ph_core::http::parse_https_url(url);
    if ph_core::policy::validate_url_prefix(prefix).is_ok()
        && ph_core::policy::validate_url(url).is_ok()
        && ph_core::policy::validate_request_url(url).is_ok()
        && ph_core::policy::url_under_prefix(url, prefix)
    {
        assert!(url.starts_with(prefix));
        let lower = url.to_ascii_lowercase();
        let after = lower.split_once("://").map_or(lower.as_str(), |(_, r)| r);
        let path = after.split(['?', '#']).next().unwrap_or("");
        assert!(!path.split('/').skip(1).any(|seg| seg == "." || seg == ".."), "{url}");
        for bad in ["%2e", "%2f", "%5c"] {
            assert!(!path.contains(bad), "{url}");
        }
        assert!(!lower.contains('\\'), "{url}");
    }
});
