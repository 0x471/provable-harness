# Verify-only fork of TLSNotary v0.1.0-beta.1

Upstream: https://github.com/tlsnotary/tlsn, tag `v0.1.0-beta.1`, commit in `UPSTREAM_COMMIT`.

Vendored crates: `tls-core`, `core`, `attestation`. Every change is marked `[ph fork]` in the source.

**Purpose.** These crates verify TLSNotary *presentations* natively and inside the SP1 zkVM. Upstream depends on `ring` (C and assembly), which cannot be built for `riscv64im-succinct-zkvm-elf`.

**What is not touched.** Types, serialization, commitment and Merkle verification, and attestation signature checks are unchanged. Presentations produced by upstream TLSNotary verify with this fork; see `core/tests/zktls.rs` and `zktls/tests/e2e.rs`.

## Changes

| File | Change |
|---|---|
| `tls-core/Cargo.toml`, `core/Cargo.toml` | Drop `ring` and `sct`. `rustls-webpki` is built without the `ring` feature. Add `ph-webpki-algs` (RustCrypto). Dev-dependencies and test fixtures (not vendored) removed. |
| `tls-core/src/verify.rs` | `webpki::ring::*` and `webpki::ALL_VERIFICATION_ALGS` are replaced by `ph_webpki_algs::*`. Ed25519 server signatures are **unsupported** and fail closed. The Certificate Transparency policy (which needs `sct`, which needs `ring`) is replaced by a stub that always errors; it is client-side and unused by presentation verification. `ring::digest::Digest` is replaced by `[u8]`. |
| `tls-core/src/error.rs` | `InvalidSct(sct::Error)` becomes `InvalidSct(String)`. |
| `tls-core/src/x509.rs` | The `ring::io::der::Tag::Sequence` constant becomes the literal `0x30`. |
| `tls-core/src/msgs/base.rs` | Removed `ring::hkdf` glue (TLS 1.3 key schedule, unused). |
| `tls-core/src/prf.rs` | Removed a test that compared against `ring`'s HMAC. |
| `core/src/webpki.rs` | Certificate path validation uses `ph_webpki_algs::ALL_VERIFICATION_ALGS`. |
| `core/src/connection.rs` | The handshake (ServerKeyExchange) signature uses `ph_webpki_algs`. Ed25519 fails closed. |

## Trust-critical replacement

`../../webpki-algs` implements the `rustls-webpki` `SignatureVerificationAlgorithm` trait with RustCrypto (`p256`, `p384`, `rsa`, `sha2`). Its tests (`webpki-algs/tests/differential.rs`) require **identical accept/reject decisions** to ring's for:
- random ECDSA and RSA vectors;
- tampered messages, signatures and keys;
- encoding edge cases: compressed points, high-S, raw signatures, trailing bytes, wrong PSS salt, key sizes;
- 9 real certificate chains captured from live sites, including tampered and wrong-name cases.

## Randomness

Inside the SP1 guest, `std::collections::HashMap` seeding pulls from SP1's `sys_rand`, which is a deterministic fixed-seed PRNG. In the verify path, `HashMap`/`HashSet` are used only for keyed lookups (algorithm registries) and duplicate detection (`merkle.rs`, `transcript/proof.rs`). No outcome depends on iteration order.

## Licenses

Upstream declares `core` and `attestation` as `MIT OR Apache-2.0`, and `tls-core` (a rustls fork) as `Apache-2.0 OR ISC OR MIT`. It ships no license texts at this tag. This fork is distributed under MIT or Apache-2.0: see `LICENSE-MIT` (with the copyright notices) and `LICENSE-APACHE`.
