# Verify-only fork of TLSNotary v0.1.0-beta.1

Upstream: https://github.com/tlsnotary/tlsn, tag `v0.1.0-beta.1` (commit `40a069565a2eaecbb5e691dbc634be20e8498daf`).

Vendored crates: `tls-core`, `core`, `attestation`. Every change in a source file is marked `[ph fork]`; `attestation` is unchanged apart from its manifest.

**Purpose.** These crates verify TLSNotary *presentations* natively and inside the SP1 zkVM. Upstream depends on `ring` (C and assembly), which cannot be built for `riscv64im-succinct-zkvm-elf`.

**What is not touched.** Types, serialization, commitment and Merkle verification, and attestation signature checks are unchanged. Presentations produced by upstream TLSNotary verify with this fork; see `core/tests/zktls.rs` and `zktls/tests/e2e.rs`.

## Changes

| File | Change |
|---|---|
| `tls-core/Cargo.toml`, `core/Cargo.toml`, `attestation/Cargo.toml` | Drop `ring` and `sct`. `rustls-webpki` is built without the `ring` feature. Add `ph-webpki-algs` (RustCrypto). Dev-dependencies and test fixtures (not vendored) removed, so upstream's own unit tests in these crates do not build here; the fork is tested from `core/tests/zktls.rs`, `zktls/tests/e2e.rs` and `webpki-algs/tests/`. |
| `tls-core/src/verify.rs` | `webpki::ring::*` and `webpki::ALL_VERIFICATION_ALGS` are replaced by `ph_webpki_algs::*`. Ed25519 server signatures are **unsupported** and fail closed. The Certificate Transparency policy (which needs `sct`, which needs `ring`) is replaced by a stub that always errors; it is client-side and unused by presentation verification. `ring::digest::Digest` is replaced by `[u8]`. |
| `tls-core/src/error.rs` | `InvalidSct(sct::Error)` becomes `InvalidSct(String)`. |
| `tls-core/src/x509.rs` | `ring::io::der` is dropped; its `Tag::Sequence` constant becomes the literal `0x30`. |
| `tls-core/src/msgs/base.rs` | Removed `ring::hkdf` glue (TLS 1.3 key schedule, unused). |
| `tls-core/src/prf.rs` | Removed a test that compared against `ring`'s HMAC. |
| `core/src/webpki.rs` | Certificate path validation uses `ph_webpki_algs::ALL_VERIFICATION_ALGS`. **A verified-chain cache** (changes verification logic): after a full verification succeeds, the exact (chain, server name) is remembered with the intersection of the validity windows of every presented certificate, and a later check of the same chain and name at a time inside that window is accepted without re-verifying. It is sound only because the validity window is the only time-dependent check; test `chain_cache::cached_and_uncached_decisions_agree`. |
| `core/src/connection.rs` | The handshake (ServerKeyExchange) signature uses `ph_webpki_algs`. Ed25519 fails closed. |

## Trust-critical replacement

`../../webpki-algs` implements the `rustls-webpki` `SignatureVerificationAlgorithm` trait with RustCrypto (`p256`, `p384`, `rsa`, `sha2`). Its tests (`webpki-algs/tests/differential.rs`) require **identical accept/reject decisions** to ring's for:
- random ECDSA and RSA vectors;
- tampered messages, signatures and keys;
- encoding edge cases: compressed points, high-S, raw signatures, trailing bytes, wrong PSS salt, key sizes;
- 9 real certificate chains captured from live sites, including tampered and wrong-name cases.

These tests, and the `sig_differential` fuzz target, run the plain RustCrypto crates on the host. Inside the guest, `p256`, `rsa` and `sha2` are SP1's patched versions (precompiles), which they do not cover; guest executions of real presentations (docs/ZKTLS.md, section 6) are the check there.

## Randomness

Inside the SP1 guest, `std::collections::HashMap` seeding pulls from SP1's `sys_rand`, which is a deterministic fixed-seed PRNG. In the verify path, `HashMap`/`HashSet` are used only for keyed lookups (algorithm registries) and duplicate detection (`merkle.rs`, `transcript/proof.rs`). No outcome depends on iteration order.

## Licenses

Upstream declares `core` and `attestation` as `MIT OR Apache-2.0`, and `tls-core` (a rustls fork) as `Apache-2.0 OR ISC OR MIT`. It ships no license texts at this tag. This fork is distributed under MIT or Apache-2.0: see `LICENSE-MIT` (with the copyright notices) and `LICENSE-APACHE`.
