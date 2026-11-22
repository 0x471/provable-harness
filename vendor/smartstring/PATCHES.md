# smartstring 1.0.1, patched for provable-harness

Unmodified crates.io `smartstring 1.0.1` (MPL-2.0, see `LICENCE.md`; the
patched file stays under MPL-2.0) plus one change, marked
`(provable-harness patch)`:

- `src/boxed.rs`, `BoxedString::ensure_capacity`: call `realloc` only when the
  capacity grows. Upstream calls it on every push. The SP1 zkVM's allocator has
  no in-place realloc, so each call copied the whole buffer and appending one
  character at a time cost time quadratic in the string length (a single
  `pad(65536, 'x')` in a script took 1.25 B cycles).

Rhai depends on this copy through a path dependency (`vendor/rhai/Cargo.toml`).
