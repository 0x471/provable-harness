//! SP1 guest for the provable harness.
//!
//! Input:  one byte vector, the bincode-encoded `ph_core::GuestInput`: either a
//!         single session's witness, or an eval batch (every run of a suite).
//! Output: the bincode-encoded `ph_core::GuestOutput` as public values (the
//!         session's claim, or the eval report).
//!
//! The guest never performs I/O beyond reading its input: model replies and tool
//! results were recorded by the host and are accepted only with valid evidence
//! for digests and requests the guest computes itself (see `ph_core::witness`,
//! `ph_core::eval`). Any rejection panics, so no proof can exist for it.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input = ph_core::GuestInput::from_bytes(&bytes).unwrap_or_else(|e| panic!("{e}"));
    let out = ph_core::verify_guest_input(&input).unwrap_or_else(|e| panic!("input rejected: {e}"));
    sp1_zkvm::io::commit_slice(&out.to_bytes());
}
