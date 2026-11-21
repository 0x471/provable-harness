#![no_main]
//! Messages API reply parsing in both modes: never panics, and the canonical
//! blocks form is a fixed point (what the harness echoes is what it parsed).
use libfuzzer_sys::fuzz_target;
use ph_core::anthropic::{blocks_json, blocks_of, parse_reply};

fuzz_target!(|data: &[u8]| {
    let _ = parse_reply(data, false);
    if let Ok(r) = parse_reply(data, true) {
        let blocks = blocks_of(&r.text).expect("canonical blocks parse");
        assert_eq!(blocks_json(&blocks), r.text);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(blocks) = blocks_of(s) {
            let c = blocks_json(&blocks);
            assert_eq!(blocks_json(&blocks_of(&c).unwrap()), c);
        }
        if let Ok(c) = ph_core::native::canonical_json(s) {
            assert_eq!(ph_core::native::canonical_json(&c).unwrap(), c);
        }
    }
});
