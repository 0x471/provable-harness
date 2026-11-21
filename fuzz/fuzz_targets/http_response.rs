#![no_main]
//! Strict HTTP/1.1 response parsing (model and tool replies, in the guest):
//! never panics, and an accepted body is a subsequence-sized slice of the input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for skip in [false, true] {
        if let Ok(r) = ph_core::http::parse_response(data, skip) {
            assert!(r.body.len() <= data.len());
            assert!((100..=599).contains(&r.status));
        }
    }
    let _ = ph_core::anthropic::parse_http_response(data);
});
